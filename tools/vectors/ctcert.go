// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"time"

	"github.com/home-mandate/spec/internal/ctid"
)

// identity is a vector of the identity of a certificate, as in conformance/ct-v0.json; DER
// is written in base64 with padding.
type identity struct {
	ID     string `json:"id"`
	Why    string `json:"why"`
	DER    []byte `json:"der"`
	Digest string `json:"digest"`
}

// sctTime is the time of the SCT embedded in the certificate of the vectors.
var sctTime = time.Date(2026, 11, 1, 0, 0, 5, 0, time.UTC)

// runCTCert prints the identity vectors of conformance/ct-v0.json: a precertificate, its
// certificate and a certificate without Certificate Transparency extensions, signed with
// fixed Ed25519 keys so that the output is the same on every run (SPEC-v0 section 11.7 item 7).
func runCTCert(stdout io.Writer) error {
	out, err := ctIdentities()
	if err != nil {
		return err
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func ctIdentities() ([]identity, error) {
	caKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0xca}, ed25519.SeedSize))
	leafKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x1e}, ed25519.SeedSize))
	notBefore := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test CA"},
		NotBefore: notBefore, NotAfter: notBefore.AddDate(1, 0, 0),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	leaf := func(serial int64, extra ...pkix.Extension) ([]byte, error) {
		t := &x509.Certificate{
			SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "home.example.net"},
			DNSNames:  []string{"home.example.net"},
			NotBefore: notBefore, NotAfter: notBefore.AddDate(0, 0, 90),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			ExtraExtensions: extra,
		}
		return x509.CreateCertificate(nil, t, ca, leafKey.Public(), caKey)
	}
	null, err := asn1.Marshal(asn1.NullRawValue)
	if err != nil {
		return nil, err
	}
	scts, err := asn1.Marshal(sctList(sctTime))
	if err != nil {
		return nil, err
	}
	pre, err := leaf(4242, pkix.Extension{Id: ctid.OIDPoison, Critical: true, Value: null})
	if err != nil {
		return nil, err
	}
	final, err := leaf(4242, pkix.Extension{Id: ctid.OIDSCTList, Value: scts})
	if err != nil {
		return nil, err
	}
	plain, err := leaf(4343)
	if err != nil {
		return nil, err
	}
	out := []identity{
		{ID: "pre", Why: "a precertificate: the poison extension (OID 1.3.6.1.4.1.11129.2.4.3) is removed from its TBSCertificate", DER: pre},
		{ID: "cert", Why: "the certificate of the precertificate pre: the SCT list extension (OID 1.3.6.1.4.1.11129.2.4.2) is removed from its TBSCertificate, and the identity is that of pre; its SCT has the time 2026-11-01T00:00:05Z", DER: final},
		{ID: "plain", Why: "a certificate without either extension: its identity is the SHA-256 of its TBSCertificate as it is", DER: plain},
	}
	for i := range out {
		if out[i].Digest, err = ctid.Digest(out[i].DER); err != nil {
			return nil, fmt.Errorf("%s: %w", out[i].ID, err)
		}
	}
	return out, nil
}

// sctList is a SignedCertificateTimestampList (RFC 6962 section 3.3) with one SCT of
// version 1 at the given time; log ID and signature are fixed test bytes.
func sctList(at time.Time) []byte {
	sct := []byte{0} // version v1
	sct = append(sct, bytes.Repeat([]byte{0x11}, 32)...)
	sct = binary.BigEndian.AppendUint64(sct, uint64(at.UnixMilli()))
	sct = binary.BigEndian.AppendUint16(sct, 0) // no extensions
	sct = append(sct, 4, 3)                     // SHA-256, ECDSA
	sig := bytes.Repeat([]byte{0x22}, 8)
	sct = binary.BigEndian.AppendUint16(sct, uint16(len(sig)))
	sct = append(sct, sig...)
	item := binary.BigEndian.AppendUint16(nil, uint16(len(sct)))
	item = append(item, sct...)
	list := binary.BigEndian.AppendUint16(nil, uint16(len(item)))
	return append(list, item...)
}

// SPDX-License-Identifier: Apache-2.0

package ctid_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/home-mandate/spec/internal/ctid"
)

type vector struct {
	ID       string `json:"id"`
	DER      []byte `json:"der"`
	IssuedBy []byte `json:"issued_by"`
	Digest   string `json:"digest"`
}

func vectors(t *testing.T) map[string]vector {
	t.Helper()
	data, err := os.ReadFile("../../conformance/ct-v0.json")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Identities []vector `json:"identities"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	out := map[string]vector{}
	for _, v := range file.Identities {
		out[v.ID] = v
	}
	if len(out) != 5 {
		t.Fatalf("%d identities, want 5", len(out))
	}
	return out
}

func TestTheVectorsOfCTCases(t *testing.T) {
	for id, v := range vectors(t) {
		var got string
		var err error
		if v.IssuedBy != nil {
			got, err = ctid.DigestIssuedBy(v.DER, v.IssuedBy)
		} else {
			got, err = ctid.Digest(v.DER)
		}
		if err != nil || got != v.Digest {
			t.Errorf("%s: digest = %q, %v; want %q", id, got, err, v.Digest)
		}
	}
}

func TestAPrecertificateOfASigningCertificateIsOneWithItsCertificate(t *testing.T) {
	v := vectors(t)
	pre, final := v["pscpre"], v["psccert"]
	if pre.IssuedBy == nil || final.IssuedBy != nil {
		t.Fatal("pscpre needs issued_by, psccert none")
	}
	if pre.Digest != final.Digest {
		t.Errorf("pscpre %s, psccert %s", pre.Digest, final.Digest)
	}
	// Without the replacement the precertificate names another issuer.
	if alone, err := ctid.Digest(pre.DER); err != nil || alone == final.Digest {
		t.Errorf("Digest of pscpre alone = %q, %v; want another identity", alone, err)
	}
}

func TestASigningCertificateMustBeOne(t *testing.T) {
	v := vectors(t)
	pre := v["pscpre"].DER
	for name, signing := range map[string][]byte{
		"no precertificate signing certificate": v["plain"].DER,
		"not a certificate":                     {0x04, 0x01, 0x00},
	} {
		if _, err := ctid.DigestIssuedBy(pre, signing); !errors.Is(err, ctid.ErrCertificate) {
			t.Errorf("%s: err = %v, want ErrCertificate", name, err)
		}
	}
	if _, err := ctid.DigestIssuedBy(v["plain"].DER, v["pscpre"].IssuedBy); !errors.Is(err, ctid.ErrCertificate) {
		t.Errorf("a certificate without poison: err = %v, want ErrCertificate", err)
	}
}

func TestAPrecertificateAndItsCertificateAreOne(t *testing.T) {
	v := vectors(t)
	if v["pre"].Digest != v["cert"].Digest || v["pre"].Digest == v["plain"].Digest {
		t.Errorf("pre %s, cert %s, plain %s", v["pre"].Digest, v["cert"].Digest, v["plain"].Digest)
	}
	pre, err := x509.ParseCertificate(v["pre"].DER)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(v["cert"].DER)
	if err != nil {
		t.Fatal(err)
	}
	if !hasExtension(pre, ctid.OIDPoison) || hasExtension(pre, ctid.OIDSCTList) ||
		!hasExtension(cert, ctid.OIDSCTList) || hasExtension(cert, ctid.OIDPoison) {
		t.Error("the vectors do not carry the extensions they are about")
	}
}

func TestACertificateWithoutCTExtensionsKeepsItsTBSCertificate(t *testing.T) {
	plain := vectors(t)["plain"]
	cert, err := x509.ParseCertificate(plain.DER)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(cert.RawTBSCertificate)
	if want := base64.RawURLEncoding.EncodeToString(sum[:]); plain.Digest != want {
		t.Errorf("digest %s, want SHA-256 of the TBSCertificate %s", plain.Digest, want)
	}
}

func TestInputThatIsNoCertificate(t *testing.T) {
	plain := vectors(t)["plain"].DER
	octets := []byte{0x04, 0x01, 0x00}
	for name, der := range map[string][]byte{
		"empty":          nil,
		"trailing data":  append(append([]byte{}, plain...), 0),
		"cut":            plain[:len(plain)-10],
		"not a sequence": octets,
		// A certificate whose TBSCertificate is an octet string.
		"TBS not a sequence": {0x30, 0x09, 0x04, 0x01, 0x00, 0x04, 0x01, 0x00, 0x04, 0x01, 0x00},
		// Extensions [3] that hold an octet string instead of a sequence.
		"extensions not a sequence": {0x30, 0x0d, 0x30, 0x05, 0xa3, 0x03, 0x04, 0x01, 0x00, 0x04, 0x01, 0x00, 0x04, 0x01, 0x00},
		// An extension that is an octet string.
		"extension not a sequence": {0x30, 0x0f, 0x30, 0x07, 0xa3, 0x05, 0x30, 0x03, 0x04, 0x01, 0x00, 0x04, 0x01, 0x00, 0x04, 0x01, 0x00},
		// A field of the TBSCertificate whose length runs past its end.
		"cut TBS field": {0x30, 0x0b, 0x30, 0x03, 0x04, 0x05, 0x00, 0x04, 0x01, 0x00, 0x04, 0x01, 0x00},
	} {
		if _, err := ctid.Digest(der); !errors.Is(err, ctid.ErrCertificate) {
			t.Errorf("%s: err = %v, want ErrCertificate", name, err)
		}
	}
}

func hasExtension(cert *x509.Certificate, id asn1.ObjectIdentifier) bool {
	for _, e := range cert.Extensions {
		if e.Id.Equal(id) {
			return true
		}
	}
	return false
}

// A self-signed precertificate signing certificate has no authority key identifier to put in
// place of the precertificate's.
func TestASigningCertificateWithoutAuthorityKeyIdentifier(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x5a}, ed25519.SeedSize))
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: "Self-signed PSC"},
		NotBefore: at, NotAfter: at.AddDate(1, 0, 0),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
		UnknownExtKeyUsage: []asn1.ObjectIdentifier{ctid.OIDPrecertificateSigning},
		SubjectKeyId:       bytes.Repeat([]byte{0x5a}, 20),
	}
	psc, err := x509.CreateCertificate(nil, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ctid.DigestIssuedBy(vectors(t)["pscpre"].DER, psc); !errors.Is(err, ctid.ErrCertificate) {
		t.Errorf("err = %v, want ErrCertificate", err)
	}
}

// A precertificate that another CA issued, or one whose authority key identifier names
// another key, is not the precertificate of this signing certificate.
func TestAPrecertificateOfAnotherIssuer(t *testing.T) {
	v := vectors(t)
	psc := v["pscpre"].IssuedBy
	if _, err := ctid.DigestIssuedBy(v["pre"].DER, psc); !errors.Is(err, ctid.ErrCertificate) {
		t.Errorf("another issuer: err = %v, want ErrCertificate", err)
	}
	signing, err := x509.ParseCertificate(psc)
	if err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x77}, ed25519.SeedSize))
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	parent := &x509.Certificate{
		SerialNumber: big.NewInt(10), Subject: signing.Subject, RawSubject: signing.RawSubject,
		NotBefore: at, NotAfter: at.AddDate(1, 0, 0), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign, SubjectKeyId: bytes.Repeat([]byte{0x77}, 20),
	}
	null, _ := asn1.Marshal(asn1.NullRawValue)
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(11), Subject: pkix.Name{CommonName: "home.example.net"},
		DNSNames: []string{"home.example.net"}, NotBefore: at, NotAfter: at.AddDate(0, 0, 90),
		ExtraExtensions: []pkix.Extension{{Id: ctid.OIDPoison, Critical: true, Value: null}},
	}
	pre, err := x509.CreateCertificate(nil, leaf, parent, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ctid.DigestIssuedBy(pre, psc); !errors.Is(err, ctid.ErrCertificate) {
		t.Errorf("another key identifier: err = %v, want ErrCertificate", err)
	}
}

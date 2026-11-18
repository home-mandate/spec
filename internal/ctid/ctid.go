// SPDX-License-Identifier: Apache-2.0

// Package ctid computes the identity of a certificate in Certificate Transparency monitoring
// (SPEC-v0 section 11.7 item 7): the SHA-256 digest of the DER of its TBSCertificate with the
// poison and the SCT list removed, so that a precertificate and its certificate have one
// identity. It checks the vectors in conformance/ct-v0.json and is not part of the public API.
// For a precertificate that a precertificate signing certificate issued, the issuer and the
// authority key identifier are first replaced by those of that certificate (RFC 6962 section 3.1).
package ctid

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
)

// ErrCertificate means the input is not a certificate in DER this package can read.
var ErrCertificate = errors.New("ctid: not a certificate")

var (
	// OIDPoison marks a precertificate (RFC 6962 section 3.1).
	OIDPoison = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 3}
	// OIDSCTList carries the SCTs embedded in a certificate (RFC 6962 section 3.3).
	OIDSCTList = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}
	// OIDPrecertificateSigning is the extended key usage of a precertificate signing
	// certificate (RFC 6962 section 3.1).
	OIDPrecertificateSigning = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 4}
	// oidAuthorityKeyID is the authority key identifier extension (RFC 5280 section 4.2.1.1).
	oidAuthorityKeyID = asn1.ObjectIdentifier{2, 5, 29, 35}
)

// issuerField is the position of the issuer among the fields of a TBSCertificate after the
// optional version: serialNumber, signature, issuer (RFC 5280 section 4.1).
const issuerField = 2

// replacement is what a precertificate signing certificate puts in place of the issuer and
// the authority key identifier of a precertificate; nil replaces nothing.
type replacement struct {
	issuer []byte // DER of the Name
	aki    []byte // value of the extension; nil if the signing certificate has none
	// subject and keyID are those of the signing certificate: the precertificate must name
	// them as its issuer and its authority key identifier.
	subject []byte
	keyID   []byte
}

// extensionsTag is the context-specific tag of the extensions of a TBSCertificate
// (RFC 5280 section 4.1).
const extensionsTag = 3

// Digest returns the identity of a certificate or precertificate in DER: base64url without
// padding of SHA-256 over its TBSCertificate with the poison and the SCT list removed. If no
// extension remains, the extensions field is removed as well.
func Digest(der []byte) (string, error) {
	return digest(der, nil)
}

// DigestIssuedBy returns the identity of a precertificate in DER that the precertificate
// signing certificate signing (DER) issued: as Digest, after its issuer and its authority key
// identifier were replaced by those of signing, which are those of the final certificate.
func DigestIssuedBy(der, signing []byte) (string, error) {
	psc, err := x509.ParseCertificate(signing)
	if err != nil {
		return "", fmt.Errorf("%w: signing certificate: %w", ErrCertificate, err)
	}
	if !signsPrecertificates(psc) {
		return "", fmt.Errorf("%w: no precertificate signing certificate", ErrCertificate)
	}
	r := &replacement{issuer: psc.RawIssuer, subject: psc.RawSubject, keyID: psc.SubjectKeyId}
	for _, e := range psc.Extensions {
		if e.Id.Equal(oidAuthorityKeyID) {
			r.aki = e.Value
		}
	}
	return digest(der, r)
}

// signsPrecertificates reports whether cert carries the extended key usage of a
// precertificate signing certificate.
func signsPrecertificates(cert *x509.Certificate) bool {
	for _, u := range cert.UnknownExtKeyUsage {
		if u.Equal(OIDPrecertificateSigning) {
			return true
		}
	}
	return false
}

func digest(der []byte, r *replacement) (string, error) {
	var cert struct {
		TBS       asn1.RawValue
		Algorithm asn1.RawValue
		Signature asn1.RawValue
	}
	rest, err := asn1.Unmarshal(der, &cert)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrCertificate, err)
	}
	if len(rest) > 0 {
		return "", fmt.Errorf("%w: data after the certificate", ErrCertificate)
	}
	tbs, err := withoutCTExtensions(cert.TBS, r)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(tbs)
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// withoutCTExtensions re-encodes a TBSCertificate without the two extensions, and with the
// issuer and the authority key identifier of r if r is not nil.
func withoutCTExtensions(tbs asn1.RawValue, r *replacement) ([]byte, error) {
	if tbs.Class != asn1.ClassUniversal || tbs.Tag != asn1.TagSequence || !tbs.IsCompound {
		return nil, fmt.Errorf("%w: TBSCertificate is not a sequence", ErrCertificate)
	}
	var fields []byte
	poisoned, sawExtensions := false, false
	universal := 0
	for rest := tbs.Bytes; len(rest) > 0; {
		var field asn1.RawValue
		var err error
		if rest, err = asn1.Unmarshal(rest, &field); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrCertificate, err)
		}
		switch {
		case field.Class == asn1.ClassContextSpecific && field.Tag == extensionsTag:
			if sawExtensions {
				return nil, fmt.Errorf("%w: two extensions fields", ErrCertificate)
			}
			sawExtensions = true
			kept, hadPoison, err := keptExtensions(field, r)
			if err != nil {
				return nil, err
			}
			poisoned = hadPoison
			fields = append(fields, kept...)
		case field.Class == asn1.ClassUniversal:
			if universal == issuerField && r != nil {
				if !bytes.Equal(field.FullBytes, r.subject) {
					return nil, fmt.Errorf("%w: the precertificate does not name the signing certificate as its issuer", ErrCertificate)
				}
				fields = append(fields, r.issuer...)
			} else {
				fields = append(fields, field.FullBytes...)
			}
			universal++
		default:
			fields = append(fields, field.FullBytes...)
		}
	}
	if r != nil && !poisoned {
		return nil, fmt.Errorf("%w: a certificate a signing certificate issued has no poison", ErrCertificate)
	}
	return asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: fields})
}

// extension is an Extension of RFC 5280 section 4.1.
type extension struct {
	ID       asn1.ObjectIdentifier
	Critical bool `asn1:"optional"`
	Value    []byte
}

// keptExtensions re-encodes the [3] extensions field without poison and SCT list, with the
// authority key identifier of r if r is not nil; nil if none remains. It also reports whether
// the poison was there.
func keptExtensions(field asn1.RawValue, r *replacement) (kept []byte, poisoned bool, err error) {
	var list asn1.RawValue
	rest, err := asn1.Unmarshal(field.Bytes, &list)
	if err != nil || len(rest) > 0 || list.Tag != asn1.TagSequence {
		return nil, false, fmt.Errorf("%w: extensions", ErrCertificate)
	}
	for rest := list.Bytes; len(rest) > 0; {
		var raw asn1.RawValue
		if rest, err = asn1.Unmarshal(rest, &raw); err != nil {
			return nil, false, fmt.Errorf("%w: extension: %w", ErrCertificate, err)
		}
		var ext extension
		if _, err := asn1.Unmarshal(raw.FullBytes, &ext); err != nil {
			return nil, false, fmt.Errorf("%w: extension: %w", ErrCertificate, err)
		}
		switch {
		case ext.ID.Equal(OIDPoison):
			poisoned = true
		case ext.ID.Equal(OIDSCTList):
		case r != nil && ext.ID.Equal(oidAuthorityKeyID):
			replaced, err := replacedAKI(ext, r)
			if err != nil {
				return nil, false, err
			}
			kept = append(kept, replaced...)
		default:
			kept = append(kept, raw.FullBytes...)
		}
	}
	if len(kept) == 0 {
		return nil, poisoned, nil
	}
	seq, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: kept})
	if err != nil {
		return nil, false, err
	}
	out, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: extensionsTag, IsCompound: true, Bytes: seq})
	return out, poisoned, err
}

// replacedAKI re-encodes an authority key identifier extension with the value of r.
func replacedAKI(ext extension, r *replacement) ([]byte, error) {
	var aki struct {
		KeyID []byte `asn1:"optional,tag:0"`
	}
	if _, err := asn1.Unmarshal(ext.Value, &aki); err != nil || (r.keyID != nil && !bytes.Equal(aki.KeyID, r.keyID)) {
		return nil, fmt.Errorf("%w: the authority key identifier of the precertificate is not the signing certificate's", ErrCertificate)
	}
	if r.aki == nil {
		return nil, fmt.Errorf("%w: the signing certificate has no authority key identifier", ErrCertificate)
	}
	ext.Value = r.aki
	return asn1.Marshal(ext)
}

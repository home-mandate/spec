// SPDX-License-Identifier: Apache-2.0

// Package ctid computes the identity of a certificate in Certificate Transparency monitoring
// (SPEC-v0 section 11.7 item 7): the SHA-256 digest of the DER of its TBSCertificate with the
// poison and the SCT list removed, so that a precertificate and its certificate have one
// identity. It checks the vectors in conformance/ct-v0.json and is not part of the public API.
// It does not handle a precertificate that a precertificate signing certificate issued, whose
// issuer and authority key identifier would first be replaced (RFC 6962 section 3.1).
package ctid

import (
	"crypto/sha256"
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
)

// extensionsTag is the context-specific tag of the extensions of a TBSCertificate
// (RFC 5280 section 4.1).
const extensionsTag = 3

// Digest returns the identity of a certificate or precertificate in DER: base64url without
// padding of SHA-256 over its TBSCertificate with the poison and the SCT list removed. If no
// extension remains, the extensions field is removed as well.
func Digest(der []byte) (string, error) {
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
	tbs, err := withoutCTExtensions(cert.TBS)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(tbs)
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// withoutCTExtensions re-encodes a TBSCertificate without the two extensions.
func withoutCTExtensions(tbs asn1.RawValue) ([]byte, error) {
	if tbs.Class != asn1.ClassUniversal || tbs.Tag != asn1.TagSequence || !tbs.IsCompound {
		return nil, fmt.Errorf("%w: TBSCertificate is not a sequence", ErrCertificate)
	}
	var fields []byte
	for rest := tbs.Bytes; len(rest) > 0; {
		var field asn1.RawValue
		var err error
		if rest, err = asn1.Unmarshal(rest, &field); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrCertificate, err)
		}
		if field.Class != asn1.ClassContextSpecific || field.Tag != extensionsTag {
			fields = append(fields, field.FullBytes...)
			continue
		}
		kept, err := keptExtensions(field)
		if err != nil {
			return nil, err
		}
		fields = append(fields, kept...)
	}
	return asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: fields})
}

// extension is an Extension of RFC 5280 section 4.1.
type extension struct {
	ID       asn1.ObjectIdentifier
	Critical bool `asn1:"optional"`
	Value    []byte
}

// keptExtensions re-encodes the [3] extensions field without poison and SCT list; nil if
// none remains.
func keptExtensions(field asn1.RawValue) ([]byte, error) {
	var list asn1.RawValue
	rest, err := asn1.Unmarshal(field.Bytes, &list)
	if err != nil || len(rest) > 0 || list.Tag != asn1.TagSequence {
		return nil, fmt.Errorf("%w: extensions", ErrCertificate)
	}
	var kept []byte
	for rest := list.Bytes; len(rest) > 0; {
		var raw asn1.RawValue
		if rest, err = asn1.Unmarshal(rest, &raw); err != nil {
			return nil, fmt.Errorf("%w: extension: %w", ErrCertificate, err)
		}
		var ext extension
		if _, err := asn1.Unmarshal(raw.FullBytes, &ext); err != nil {
			return nil, fmt.Errorf("%w: extension: %w", ErrCertificate, err)
		}
		if ext.ID.Equal(OIDPoison) || ext.ID.Equal(OIDSCTList) {
			continue
		}
		kept = append(kept, raw.FullBytes...)
	}
	if len(kept) == 0 {
		return nil, nil
	}
	seq, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: kept})
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: extensionsTag, IsCompound: true, Bytes: seq})
}

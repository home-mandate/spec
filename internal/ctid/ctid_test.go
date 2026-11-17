// SPDX-License-Identifier: Apache-2.0

package ctid_test

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/home-mandate/spec/internal/ctid"
)

type vector struct {
	ID     string `json:"id"`
	DER    []byte `json:"der"`
	Digest string `json:"digest"`
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
	if len(out) != 3 {
		t.Fatalf("%d identities, want 3", len(out))
	}
	return out
}

func TestTheVectorsOfCTCases(t *testing.T) {
	for id, v := range vectors(t) {
		got, err := ctid.Digest(v.DER)
		if err != nil || got != v.Digest {
			t.Errorf("%s: Digest = %q, %v; want %q", id, got, err, v.Digest)
		}
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

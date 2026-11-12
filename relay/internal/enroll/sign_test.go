// SPDX-License-Identifier: Apache-2.0

package enroll_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/home-mandate/spec/jws"
	"github.com/home-mandate/spec/relay/internal/enroll"
)

const (
	pairURL = "https://op.example.net/enroll/pair"
	instURL = "https://op.example.net/enroll/installation/abcdefghijklmnopqrstuvwxyz"
	keyURL  = "https://op.example.net/enroll/key-change"
)

func gen(t *testing.T, alg string) *enroll.Signer {
	t.Helper()
	s, err := enroll.Generate(alg)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestSignerKeys(t *testing.T) {
	ed, es := gen(t, enroll.AlgEdDSA), gen(t, enroll.AlgES256)
	if ed.Alg() != "EdDSA" || es.Alg() != "ES256" {
		t.Error("algorithms")
	}
	for _, s := range []*enroll.Signer{ed, es} {
		der, err := s.PKCS8()
		if err != nil {
			t.Fatal(err)
		}
		back, err := enroll.ParseSigner(der)
		if err != nil || back.Thumbprint() != s.Thumbprint() || back.Private() == nil {
			t.Errorf("round trip: %v", err)
		}
		pub, err := jws.ParseJWK([]byte(s.JWK()))
		if err != nil || pub == nil {
			t.Errorf("JWK %s: %v", s.JWK(), err)
		}
		if s.Public() == nil {
			t.Error("Public")
		}
	}
	// RFC 7638: the thumbprint is the SHA-256 of the members in lexical order.
	k := ed.Public().(ed25519.PublicKey)
	sum := sha256.Sum256([]byte(`{"crv":"Ed25519","kty":"OKP","x":"` + base64.RawURLEncoding.EncodeToString(k) + `"}`))
	if ed.Thumbprint() != base64.RawURLEncoding.EncodeToString(sum[:]) || ed.Thumbprint() == es.Thumbprint() {
		t.Error("thumbprint")
	}
	if enroll.B64([]byte{0xfb, 0xff}) != "-_8" {
		t.Error("B64")
	}
}

func TestSignerRefusesOtherKeys(t *testing.T) {
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 1024)
	for name, key := range map[string]any{"P-384": p384, "RSA": rsaKey, "string": "x"} {
		if _, err := enroll.NewSigner(key); !errors.Is(err, enroll.ErrKey) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := enroll.ParseSigner([]byte("junk")); !errors.Is(err, enroll.ErrKey) {
		t.Error("junk")
	}
	der, _ := x509.MarshalPKCS8PrivateKey(rsaKey)
	if _, err := enroll.ParseSigner(der); !errors.Is(err, enroll.ErrKey) {
		t.Error("RSA DER")
	}
	// Generate falls back to Ed25519 for an unknown algorithm name.
	if s, err := enroll.Generate("other"); err != nil || s.Alg() != "EdDSA" {
		t.Error("Generate")
	}
}

func TestRegularRequestsVerifyWithPackageJWS(t *testing.T) {
	nonce := enroll.RandomToken(16)
	for _, alg := range []string{enroll.AlgEdDSA, enroll.AlgES256} {
		s := gen(t, alg)
		pair := enroll.Spec{Signer: s, JWK: true, Nonce: nonce, URL: pairURL, Payload: `{"code":"X"}`}.Compact()
		if h, _, err := jws.VerifyRequest(pair, nil); err != nil || h.URL != pairURL || h.JWK == nil {
			t.Errorf("%s pair: %v", alg, err)
		}
		read := enroll.Spec{Signer: s, Kid: instURL, Nonce: nonce, URL: instURL}.Compact()
		if h, payload, err := jws.VerifyRequest(read, s.Public()); err != nil || h.Kid != instURL || len(payload) != 0 {
			t.Errorf("%s read: %v", alg, err)
		}
		// Signed by another key of the same algorithm: a good spelling, a bad signature.
		forged := enroll.Spec{Signer: s, SignWith: gen(t, alg), Kid: instURL, Nonce: nonce, URL: instURL}.Compact()
		if _, _, err := jws.VerifyRequest(forged, s.Public()); !errors.Is(err, jws.ErrSignature) {
			t.Errorf("%s forged: %v", alg, err)
		}
	}
}

func TestEachDefectIsMalformed(t *testing.T) {
	nonce := enroll.RandomToken(16)
	for name, defect := range map[string]enroll.Defect{
		"extra header member": enroll.ExtraHeaderMember, "duplicate member": enroll.DuplicateMember,
		"padded signature": enroll.PaddedSignature, "short nonce": enroll.ShortNonce, "member case": enroll.MemberCase,
		"array payload": enroll.ArrayPayload, "duplicate payload member": enroll.DuplicatePayloadMember,
		"unknown alg": enroll.UnknownAlg, "kid and jwk": enroll.KidAndJWK, "missing url": enroll.MissingURL,
		"padded payload": enroll.PaddedPayload,
	} {
		spec := enroll.Spec{Signer: gen(t, enroll.AlgEdDSA), Kid: instURL, Nonce: nonce, URL: instURL, Payload: `{"own_domain":null}`, Defect: defect}
		if _, _, err := jws.ParseRequest(spec.Compact()); !errors.Is(err, jws.ErrMalformed) {
			t.Errorf("%s: %v", name, err)
		}
	}
	private := enroll.Spec{Signer: gen(t, enroll.AlgEdDSA), JWK: true, Nonce: nonce, URL: pairURL, Payload: `{}`, Defect: enroll.PrivateJWK}
	if _, _, err := jws.ParseRequest(private.Compact()); !errors.Is(err, jws.ErrMalformed) {
		t.Errorf("private jwk: %v", err)
	}
	// The higher S matters for ES256 only; for EdDSA the defect changes nothing.
	for alg, want := range map[string]bool{enroll.AlgES256: true, enroll.AlgEdDSA: false} {
		spec := enroll.Spec{Signer: gen(t, alg), Kid: instURL, Nonce: nonce, URL: instURL, Defect: enroll.HighS}
		_, _, err := jws.ParseRequest(spec.Compact())
		if got := errors.Is(err, jws.ErrMalformed); got != want {
			t.Errorf("%s high S: malformed %v, %v", alg, got, err)
		}
	}
	// An algorithm outside the profile, because an ES256 signature passes the form checks of
	// EdDSA by chance (its S is below the group order in about one of 16 cases).
	if _, _, err := jws.ParseRequest(enroll.Spec{Signer: gen(t, enroll.AlgES256), Kid: instURL, Nonce: nonce, URL: instURL, Alg: "RS256"}.Compact()); !errors.Is(err, jws.ErrMalformed) {
		t.Errorf("alg override: %v", err)
	}
}

func TestKeyChangeJWSVerifiesWithPackageJWS(t *testing.T) {
	old, fresh := gen(t, enroll.AlgEdDSA), gen(t, enroll.AlgES256)
	inner := enroll.KeyChangeJWS(fresh, old.JWK(), instURL, keyURL)
	h, payload, err := jws.VerifyKeyChange(inner)
	if err != nil || h.URL != keyURL || len(payload) == 0 {
		t.Fatalf("%v", err)
	}
}

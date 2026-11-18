// SPDX-License-Identifier: Apache-2.0

package jws

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"testing"
)

// A protocol on top of the specification builds its own header and signs it with the
// building blocks; what it signs verifies with the checks of SPEC-v0 section 7.1.
func TestSignCompactAndVerifySignature(t *testing.T) {
	for _, signer := range []any{rfcKey(t), ecKey(t)} {
		alg, public, err := SignerAlgorithm(signer)
		if err != nil {
			t.Fatal(err)
		}
		if got, ok := KeyAlgorithm(public); !ok || got != alg {
			t.Errorf("KeyAlgorithm = %s, %v; want %s", got, ok, alg)
		}
		header := []byte(`{"alg":"` + alg + `","nonce":"n"}`)
		payload := []byte(`{"a":1}`)
		compact, err := SignCompact(header, payload, alg, signer)
		if err != nil {
			t.Fatal(err)
		}
		head, body, sig, err := SplitCompact(compact)
		if err != nil {
			t.Fatal(err)
		}
		decodedHead, err := DecodeSegment(head)
		if err != nil || string(decodedHead) != string(header) {
			t.Errorf("header = %s, %v", decodedHead, err)
		}
		decodedBody, err := DecodeSegment(body)
		if err != nil || string(decodedBody) != string(payload) {
			t.Errorf("payload = %s, %v", decodedBody, err)
		}
		raw, err := DecodeSegment(sig)
		if err != nil || !CanonicalSignature(alg, raw) {
			t.Fatalf("signature %v, canonical %v", err, CanonicalSignature(alg, raw))
		}
		if !VerifySignature(alg, public, SigningInput(head, payload), raw) {
			t.Errorf("%s: the signature does not verify", alg)
		}
		if VerifySignature(alg, public, SigningInput(head, []byte(`{"a":2}`)), raw) {
			t.Errorf("%s: the signature verifies another payload", alg)
		}
		other := AlgEdDSA
		if alg == AlgEdDSA {
			other = AlgES256
		}
		if _, err := SignCompact(header, payload, other, signer); !errors.Is(err, ErrKey) {
			t.Errorf("%s key signing as %s: %v, want ErrKey", alg, other, err)
		}
	}
	if _, err := DecodeSegment("AA="); !errors.Is(err, ErrMalformed) {
		t.Errorf("DecodeSegment with padding = %v, want ErrMalformed", err)
	}
}

func TestCanonicalSignature(t *testing.T) {
	le := func(n *big.Int) []byte {
		out := make([]byte, 32)
		for i, b := range n.FillBytes(make([]byte, 32)) {
			out[31-i] = b
		}
		return out
	}
	r := make([]byte, 32)
	r[0] = 9 // a canonical encoding: y = 9
	sig := func(r, s []byte) []byte { return append(append([]byte{}, r...), s...) }
	belowL := le(new(big.Int).Sub(ed25519Order, big.NewInt(1)))
	nonCanonicalR := le(new(big.Int).Add(ed25519FieldPrime, big.NewInt(1)))
	n := elliptic.P256().Params().N
	for name, tt := range map[string]struct {
		alg  string
		sig  []byte
		want bool
	}{
		"EdDSA, S = L - 1":        {AlgEdDSA, sig(r, belowL), true},
		"EdDSA, S = L":            {AlgEdDSA, sig(r, le(ed25519Order)), false},
		"EdDSA, R with y = p + 1": {AlgEdDSA, sig(nonCanonicalR, le(big.NewInt(1))), false},
		"ES256, lower s":          {AlgES256, sig(r, new(big.Int).Rsh(n, 1).FillBytes(make([]byte, 32))), true},
		"ES256, higher s":         {AlgES256, sig(r, new(big.Int).Sub(n, big.NewInt(1)).FillBytes(make([]byte, 32))), false},
		"63 octets":               {AlgEdDSA, make([]byte, 63), false},
		"unknown alg":             {"HS256", sig(r, belowL), false},
	} {
		if got := CanonicalSignature(tt.alg, tt.sig); got != tt.want {
			t.Errorf("%s: %v, want %v", name, got, tt.want)
		}
	}
}

func TestKeyAlgorithmOfOtherKeys(t *testing.T) {
	p384, err := ecdsa.GenerateKey(elliptic.P384(), randReader{})
	if err != nil {
		t.Fatal(err)
	}
	var none *ecdsa.PublicKey
	for _, key := range []crypto.PublicKey{nil, "key", none, &p384.PublicKey} {
		if alg, ok := KeyAlgorithm(key); ok {
			t.Errorf("KeyAlgorithm(%T) = %s", key, alg)
		}
	}
}

func TestParseJWKAndMarshalJWK(t *testing.T) {
	ed, ec := rfcKey(t), ecKey(t)
	for _, key := range []crypto.PublicKey{ed.Public(), ec.Public()} {
		data, err := MarshalJWK(key)
		if err != nil {
			t.Fatal(err)
		}
		var members map[string]any
		if err := json.Unmarshal(data, &members); err != nil || members["kid"] != nil {
			t.Errorf("MarshalJWK = %s", data)
		}
		back, err := ParseJWK(data)
		if err != nil || !back.(interface{ Equal(crypto.PublicKey) bool }).Equal(key) {
			t.Errorf("ParseJWK(%s) = %v, %v", data, back, err)
		}
	}
	var none *ecdsa.PublicKey
	for _, key := range []crypto.PublicKey{nil, "key", none, ed25519.PublicKey(make([]byte, 31))} {
		if _, err := MarshalJWK(key); !errors.Is(err, ErrKey) {
			t.Errorf("MarshalJWK(%v) = %v, want ErrKey", key, err)
		}
	}
	ecJWK, err := MarshalJWK(ec.Public())
	if err != nil {
		t.Fatal(err)
	}
	var ecMembers struct{ X, Y string }
	if err := json.Unmarshal(ecJWK, &ecMembers); err != nil {
		t.Fatal(err)
	}
	for name, tt := range map[string]struct{ doc, reason string }{
		"duplicate x":  {`{"kty":"OKP","crv":"Ed25519","x":"` + rfc8037Public + `","x":"` + rfc8037Public + `"}`, "duplicate key"},
		"with kid":     {`{"kty":"OKP","crv":"Ed25519","kid":"k","x":"` + rfc8037Public + `"}`, "members other than"},
		"with d":       {`{"kty":"OKP","crv":"Ed25519","x":"` + rfc8037Public + `","d":"` + rfc8037Seed + `"}`, "members other than"},
		"upper X":      {`{"kty":"OKP","crv":"Ed25519","X":"` + rfc8037Public + `"}`, "x must be a string"},
		"x null":       {`{"kty":"OKP","crv":"Ed25519","x":null}`, "x must be a string"},
		"no kty":       {`{"crv":"Ed25519","x":"` + rfc8037Public + `","y":"` + rfc8037Public + `"}`, "kty must be a string"},
		"OKP with y":   {`{"kty":"OKP","crv":"Ed25519","x":"` + rfc8037Public + `","y":"` + rfc8037Public + `"}`, "members other than"},
		"EC short y":   {`{"kty":"EC","crv":"P-256","x":"` + rfc8037Public + `","y":"AQAB"}`, "y is not 32 bytes"},
		"EC off curve": {`{"kty":"EC","crv":"P-256","x":"` + ecMembers.X + `","y":"` + ecMembers.X + `"}`, "not on curve"},
		"x padded":     {`{"kty":"OKP","crv":"Ed25519","x":"` + rfc8037Public[:42] + `="}`, "illegal base64"},
		"not JSON":     {`nope`, "malformed JSON"},
		"null":         {`null`, "not a JSON object"},
	} {
		if _, err := ParseJWK([]byte(tt.doc)); !errors.Is(err, ErrKey) || !strings.Contains(err.Error(), tt.reason) {
			t.Errorf("%s: ParseJWK = %v, want ErrKey with %q", name, err, tt.reason)
		}
	}
}

// randReader is a deterministic source for a key that only has to exist.
type randReader struct{}

func (randReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(i + 1)
	}
	return len(p), nil
}

// Review of the building blocks: a key on another curve verifies nothing, a header must name
// the alg it is signed with, a JWK is bounded, and a key off its curve cannot be written.
func TestBuildingBlocksRefuse(t *testing.T) {
	p384, err := ecdsa.GenerateKey(elliptic.P384(), randReader{})
	if err != nil {
		t.Fatal(err)
	}
	if VerifySignature(AlgES256, &p384.PublicKey, []byte("x"), make([]byte, 64)) {
		t.Error("a P-384 key verified an ES256 signature")
	}
	ed := rfcKey(t)
	for name, header := range map[string]string{
		"no alg":    `{"nonce":"n"}`,
		"other alg": `{"alg":"ES256"}`,
		"alg twice": `{"alg":"EdDSA","alg":"EdDSA"}`,
		"not JSON":  `nope`,
	} {
		if _, err := SignCompact([]byte(header), nil, AlgEdDSA, ed); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: SignCompact = %v, want ErrMalformed", name, err)
		}
	}
	if _, err := ParseJWK([]byte(`{"kty":"OKP","pad":"` + strings.Repeat("x", maxJWKBytes) + `"}`)); !errors.Is(err, ErrKey) || !strings.Contains(err.Error(), "at most") {
		t.Errorf("ParseJWK of a large JWK = %v", err)
	}
	keys, err := ParseJWKS([]byte(`{"keys":[{"kty":"EC","crv":"P-256","kid":"k","x":"` + rfc8037Public + `","y":"` + rfc8037Public + `"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := MarshalJWKS(keys); err == nil || !strings.Contains(err.Error(), "not a point of its curve") {
		t.Errorf("MarshalJWKS of a key off its curve = %v", err)
	}
}

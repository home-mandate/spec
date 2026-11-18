// SPDX-License-Identifier: Apache-2.0

package jws

// The building blocks of a JWS in compact serialization that other protocols on top of this
// specification share, such as the requests of the Relay Specification (home-mandate/relay-spec):
// splitting and decoding, signing a header of their own, verifying a signature with every check
// of SPEC-v0 section 7.1, and a single public key as JWK. The header rules of such a protocol
// belong to it, not to this package.

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"github.com/home-mandate/spec/ijson"
	"github.com/home-mandate/spec/internal/errquote"
)

// ed25519Order is L, the order of the Ed25519 base point; S of a signature is below it
// (RFC 8032 section 5.1.7).
var ed25519Order, _ = new(big.Int).SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)

// jwkCoordinateChars is the length of a 32-byte coordinate in base64url without padding.
const jwkCoordinateChars = 43

// maxJWKBytes bounds a single JWK: its members need about 150 bytes.
const maxJWKBytes = 1024

// SplitCompact splits a JWS in compact serialization into its three segments. It checks the
// length first, at most MaxCompactBytes, so that a long input allocates nothing, and checks
// nothing else.
func SplitCompact(compact string) (header, payload, signature string, err error) {
	return split(compact)
}

// DecodeSegment decodes one segment of a compact JWS: base64url without padding, line breaks
// or other characters, in its one spelling (SPEC-v0 section 7.1). The caller bounds the input,
// for example by splitting it with SplitCompact.
func DecodeSegment(segment string) ([]byte, error) {
	decoded, err := decodeSegment(segment)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	return decoded, nil
}

// SigningInput is what a signature covers: the header segment, a dot and the payload in
// base64url (RFC 7515 section 5.1).
func SigningInput(header string, payload []byte) []byte {
	return signingInput(header, payload)
}

// SignCompact signs a protected header, given as its JSON text, and a payload, and returns
// the compact JWS. alg is the algorithm of signer, as SignerAlgorithm returns it, and a key
// that SignerAlgorithm refuses or that alg does not fit gives ErrKey; the header is the
// caller's and has to name that alg.
func SignCompact(header, payload []byte, alg string, signer any) (string, error) {
	signerAlg, _, err := SignerAlgorithm(signer)
	if err != nil {
		return "", err
	}
	if signerAlg != alg {
		return "", fmt.Errorf("%w: algorithm %s for a %s key", ErrKey, quote(alg), signerAlg)
	}
	if err := ijson.Check(header); err != nil {
		return "", fmt.Errorf("%w: header: %w", ErrMalformed, err)
	}
	var named struct {
		Alg *string `json:"alg"`
	}
	if err := json.Unmarshal(header, &named); err != nil || named.Alg == nil || *named.Alg != alg {
		return "", fmt.Errorf("%w: the header does not name alg %s", ErrMalformed, alg)
	}
	head := b64.EncodeToString(header)
	raw, err := signInput(alg, signer, signingInput(head, payload))
	if err != nil {
		return "", err
	}
	return head + "." + b64.EncodeToString(payload) + "." + b64.EncodeToString(raw), nil
}

// VerifySignature reports whether sig is a signature of input by key under alg, with every
// check of SPEC-v0 section 7.1: alg matches the type of key, an Ed25519 key and R are
// canonical and not of small order and the equation holds without the cofactor, an ES256
// signature has the lower s. A key that is not on its curve verifies nothing.
func VerifySignature(alg string, key crypto.PublicKey, input, sig []byte) bool {
	return verifyInput(alg, key, input, sig)
}

// CanonicalSignature reports whether a signature is written in its one form (SPEC-v0 section
// 7.1): 64 octets, for EdDSA a canonical R and S below the group order, for ES256 the lower s.
// A signature that verifies is canonical; the check lets a protocol tell a signature that is
// malformed from one that does not verify.
func CanonicalSignature(alg string, sig []byte) bool {
	if len(sig) != 2*p256Bytes {
		return false
	}
	switch alg {
	case AlgEdDSA:
		s := make([]byte, ed25519.PublicKeySize)
		for i, b := range sig[ed25519.PublicKeySize:] {
			s[len(s)-1-i] = b
		}
		return canonicalEd25519(sig[:ed25519.PublicKeySize]) && new(big.Int).SetBytes(s).Cmp(ed25519Order) < 0
	case AlgES256:
		return new(big.Int).SetBytes(sig[p256Bytes:]).Cmp(halfOrder) <= 0
	}
	return false
}

// KeyAlgorithm returns the algorithm of SPEC-v0 section 7.1 for a public key: EdDSA for an
// Ed25519 key, ES256 for a key on P-256; ok is false for any other key.
func KeyAlgorithm(key crypto.PublicKey) (alg string, ok bool) {
	switch k := key.(type) {
	case ed25519.PublicKey:
		return AlgEdDSA, true
	case *ecdsa.PublicKey:
		return AlgES256, k != nil && k.Curve == elliptic.P256()
	}
	return "", false
}

// SignerAlgorithm returns the algorithm and the public key of a private key: an
// ed25519.PrivateKey of 64 bytes, or an *ecdsa.PrivateKey on P-256 whose scalar fits its
// public key. Any other key gives ErrKey.
func SignerAlgorithm(signer any) (alg string, public crypto.PublicKey, err error) {
	switch key := signer.(type) {
	case ed25519.PrivateKey:
		if len(key) != ed25519.PrivateKeySize {
			return "", nil, fmt.Errorf("%w: Ed25519 private key of %d bytes", ErrKey, len(key))
		}
		return AlgEdDSA, key.Public(), nil
	case *ecdsa.PrivateKey:
		if key == nil || key.Curve == nil {
			return "", nil, fmt.Errorf("%w: ECDSA private key without a curve", ErrKey)
		}
		if key.Curve != elliptic.P256() {
			return "", nil, fmt.Errorf("%w: curve %s", ErrKey, key.Curve.Params().Name)
		}
		if !usableP256(key) {
			return "", nil, fmt.Errorf("%w: P-256 private key that does not fit its public key", ErrKey)
		}
		return AlgES256, key.Public(), nil
	}
	return "", nil, fmt.Errorf("%w: %T", ErrKey, signer)
}

// usableP256 reports whether a private key on P-256 has a scalar in 1..n-1 and the public
// key of that scalar. crypto/ecdsa would panic on a missing D, X or Y.
func usableP256(key *ecdsa.PrivateKey) bool {
	//lint:ignore SA1019 a nil D must be caught here: ECDH, Bytes and Equal would panic on it.
	if key.D == nil || key.X == nil || key.Y == nil {
		return false
	}
	private, err := key.ECDH()
	if err != nil {
		return false
	}
	public, err := key.PublicKey.ECDH()
	return err == nil && private.PublicKey().Equal(public)
}

// MarshalJWK writes a public key as a JWK without kid: kty, crv and x, and y for P-256,
// nothing else.
func MarshalJWK(key crypto.PublicKey) ([]byte, error) {
	k, err := publicJWK("", key)
	if err != nil {
		return nil, err
	}
	if k.Kty == "OKP" {
		return json.Marshal(struct {
			Kty string `json:"kty"`
			Crv string `json:"crv"`
			X   string `json:"x"`
		}{k.Kty, k.Crv, k.X})
	}
	return json.Marshal(struct {
		Kty string `json:"kty"`
		Crv string `json:"crv"`
		X   string `json:"x"`
		Y   string `json:"y"`
	}{k.Kty, k.Crv, k.X, k.Y})
}

// ParseJWK reads a public key in the form MarshalJWK writes: an Ed25519 or P-256 key with
// exactly its members, without a private part or a kid, in I-JSON, of at most
// maxJWKBytes. Any other input, a P-256 key that is not on its curve included, gives ErrKey.
func ParseJWK(data []byte) (crypto.PublicKey, error) {
	if len(data) > maxJWKBytes {
		return nil, fmt.Errorf("%w: JWK of %d bytes, at most %d", ErrKey, len(data), maxJWKBytes)
	}
	if err := ijson.Check(data); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrKey, err)
	}
	key, err := readStrictJWK(data)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrKey, err)
	}
	return key, nil
}

// readStrictJWK reads exactly kty, crv and x, and y for P-256.
func readStrictJWK(data []byte) (crypto.PublicKey, error) {
	var members map[string]json.RawMessage
	if err := json.Unmarshal(data, &members); err != nil || members == nil {
		return nil, errors.New("not a JSON object")
	}
	kty, err := readString(members, "kty")
	if err != nil {
		return nil, err
	}
	names := []string{"kty", "crv", "x"}
	if kty == "EC" {
		names = append(names, "y")
	}
	if len(members) != len(names) {
		return nil, errors.New("members other than " + fmt.Sprint(names))
	}
	k := jwk{Kty: kty}
	for _, field := range []struct {
		name string
		to   *string
	}{{"crv", &k.Crv}, {"x", &k.X}, {"y", &k.Y}} {
		if field.name == "y" && kty != "EC" {
			continue
		}
		if *field.to, err = readString(members, field.name); err != nil {
			return nil, err
		}
		if field.name != "crv" && len(*field.to) != jwkCoordinateChars {
			return nil, fmt.Errorf("%s is not 32 bytes in base64url", field.name)
		}
	}
	return publicKey(k)
}

// readString reads a member that must be a JSON string; null is not one.
func readString(members map[string]json.RawMessage, name string) (string, error) {
	raw, ok := members[name]
	var s string
	if !ok || len(raw) == 0 || raw[0] != '"' || json.Unmarshal(raw, &s) != nil {
		return "", fmt.Errorf("%s must be a string", name)
	}
	return s, nil
}

// quote quotes a value from input or a caller for an error message, at most its first
// errquote.MaxBytes bytes, so that a sender cannot fill logs through the errors.
func quote(s string) string { return errquote.Quote(s) }

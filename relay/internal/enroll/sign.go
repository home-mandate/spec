// SPDX-License-Identifier: Apache-2.0

// Package enroll is the client of the enrollment endpoint (RELAY-v0 section 5) of the live
// test tool relay-conformance. It has a small signer of its own for Ed25519 and ES256 and
// builds requests as text, so that it can also build requests with deliberate defects. The
// reference operator checks requests with package jws; the tool and the reference share no
// code for the request format, so that they have no blind spot in common.
package enroll

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"math/big"
)

// Algorithms of requests (RFC 7518, RFC 8037).
const (
	AlgEdDSA = "EdDSA"
	AlgES256 = "ES256"
)

var b64 = base64.RawURLEncoding

// B64 encodes without padding.
func B64(data []byte) string { return b64.EncodeToString(data) }

// Signer holds a private key of an installation.
type Signer struct {
	alg  string
	priv crypto.Signer
}

// ErrKey is returned for a key that is neither Ed25519 nor P-256.
var ErrKey = errors.New("enroll: unsupported key")

// NewSigner returns a signer for an Ed25519 or P-256 private key.
func NewSigner(key crypto.PrivateKey) (*Signer, error) {
	switch k := key.(type) {
	case ed25519.PrivateKey:
		return &Signer{AlgEdDSA, k}, nil
	case *ecdsa.PrivateKey:
		if k.Curve == elliptic.P256() {
			return &Signer{AlgES256, k}, nil
		}
	}
	return nil, ErrKey
}

// ParseSigner reads a private key in PKCS #8 DER, as the state file holds it.
func ParseSigner(der []byte) (*Signer, error) {
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, ErrKey
	}
	return NewSigner(key)
}

// Generate makes a signer with a new key of the algorithm.
func Generate(alg string) (*Signer, error) {
	if alg == AlgES256 {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		return NewSigner(k)
	}
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return NewSigner(k)
}

// PKCS8 returns the private key in PKCS #8 DER.
func (s *Signer) PKCS8() ([]byte, error) { return x509.MarshalPKCS8PrivateKey(s.priv) }

// Alg returns the algorithm of the key.
func (s *Signer) Alg() string { return s.alg }

// Public returns the public key.
func (s *Signer) Public() crypto.PublicKey { return s.priv.Public() }

// Private returns the key, for the certificate requests of the tool.
func (s *Signer) Private() crypto.Signer { return s.priv }

// JWK returns the public key as the JSON text of $defs/jwk.
func (s *Signer) JWK() string {
	switch k := s.priv.Public().(type) {
	case ed25519.PublicKey:
		return `{"kty":"OKP","crv":"Ed25519","x":"` + B64(k) + `"}`
	case *ecdsa.PublicKey:
		raw, _ := k.Bytes()
		return `{"kty":"EC","crv":"P-256","x":"` + B64(raw[1:33]) + `","y":"` + B64(raw[33:]) + `"}`
	}
	panic("enroll: signer of an unknown type")
}

// Thumbprint returns the JWK thumbprint (RFC 7638, SHA-256) of the public key, base64url.
func (s *Signer) Thumbprint() string {
	var canonical string
	switch k := s.priv.Public().(type) {
	case ed25519.PublicKey:
		canonical = `{"crv":"Ed25519","kty":"OKP","x":"` + B64(k) + `"}`
	case *ecdsa.PublicKey:
		raw, _ := k.Bytes()
		canonical = `{"crv":"P-256","kty":"EC","x":"` + B64(raw[1:33]) + `","y":"` + B64(raw[33:]) + `"}`
	}
	sum := sha256.Sum256([]byte(canonical))
	return B64(sum[:])
}

// Sign returns the signature of input in the form of a JWS: Ed25519, or R and S of 32 bytes
// each with the lower S for ES256.
func (s *Signer) Sign(input []byte) []byte {
	if k, ok := s.priv.(ed25519.PrivateKey); ok {
		return ed25519.Sign(k, input)
	}
	digest := sha256.Sum256(input)
	der, err := ecdsa.SignASN1(rand.Reader, s.priv.(*ecdsa.PrivateKey), digest[:])
	if err != nil {
		panic("enroll: " + err.Error())
	}
	var rs struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(der, &rs); err != nil {
		panic("enroll: " + err.Error())
	}
	n := elliptic.P256().Params().N
	if rs.S.Cmp(new(big.Int).Rsh(n, 1)) > 0 {
		rs.S.Sub(n, rs.S)
	}
	return append(rs.R.FillBytes(make([]byte, 32)), rs.S.FillBytes(make([]byte, 32))...)
}

// highS returns the signature with S replaced by N-S, the spelling that an operator refuses.
func highS(sig []byte) []byte {
	n := elliptic.P256().Params().N
	s := new(big.Int).Sub(n, new(big.Int).SetBytes(sig[32:]))
	return append(append([]byte{}, sig[:32]...), s.FillBytes(make([]byte, 32))...)
}

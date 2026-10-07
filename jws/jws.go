// SPDX-License-Identifier: Apache-2.0

// Package jws signs and verifies the two signatures of the Home-Mandate Specification v0: checkpoints of
// an audit log (SPEC-v0 section 9.5) and signed mandates (section 7). It implements the
// small part of JSON Web Signature (RFC 7515) the specification uses: the compact
// serialization, also with detached payload, with the algorithms EdDSA (Ed25519,
// RFC 8037) and ES256, and public keys as a JWK Set (RFC 7517). It uses only the
// standard library.
package jws

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"slices"
	"strings"

	"github.com/home-mandate/spec/internal/ijson"
)

// Algorithms of SPEC-v0. Every implementation that verifies signatures supports EdDSA.
const (
	AlgEdDSA = "EdDSA"
	AlgES256 = "ES256"
)

// Errors returned by the verifying functions; check them with errors.Is.
var (
	ErrMalformed = errors.New("jws: malformed")
	ErrSignature = errors.New("jws: signature does not verify")
	ErrKey       = errors.New("jws: unsupported or unknown key")
)

// maxCompactBytes bounds a JWS: a signed mandate is at most 256 KiB before encoding.
const maxCompactBytes = 512 << 10

const p256Bytes = 32

// halfOrder is half the order of P-256. An ES256 signature (r, s) is accepted only with
// s in the lower half, so that a signature has exactly one form.
var halfOrder = new(big.Int).Rsh(elliptic.P256().Params().N, 1)

// MaxCompactBytes is the largest JWS the package accepts.
const MaxCompactBytes = maxCompactBytes

var kidPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

var b64 = base64.RawURLEncoding.Strict()

// decodeSegment decodes one segment of a compact JWS. Go's decoder skips line breaks,
// so the segment is compared with its re-encoding: every byte string has exactly one
// accepted spelling.
func decodeSegment(segment string) ([]byte, error) {
	decoded, err := b64.DecodeString(segment)
	if err != nil {
		return nil, err
	}
	if b64.EncodeToString(decoded) != segment {
		return nil, errors.New("not canonical base64url")
	}
	return decoded, nil
}

// Keys are public keys by key ID: ed25519.PublicKey or *ecdsa.PublicKey on P-256.
type Keys map[string]crypto.PublicKey

type protectedHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
}

// Sign returns the compact JWS of payload: header.payload.signature. signer is an
// ed25519.PrivateKey or an *ecdsa.PrivateKey on P-256.
func Sign(payload []byte, kid string, signer any) (string, error) {
	head, sig, err := sign(payload, kid, signer)
	if err != nil {
		return "", err
	}
	return head + "." + b64.EncodeToString(payload) + "." + sig, nil
}

// SignDetached returns the compact JWS with detached payload: header..signature
// (RFC 7515 appendix F).
func SignDetached(payload []byte, kid string, signer any) (string, error) {
	head, sig, err := sign(payload, kid, signer)
	if err != nil {
		return "", err
	}
	return head + ".." + sig, nil
}

func sign(payload []byte, kid string, signer any) (head, sig string, err error) {
	if !kidPattern.MatchString(kid) {
		return "", "", fmt.Errorf("%w: key ID %q", ErrKey, kid)
	}
	alg := ""
	switch key := signer.(type) {
	case ed25519.PrivateKey:
		alg = AlgEdDSA
	case *ecdsa.PrivateKey:
		if key.Curve != elliptic.P256() {
			return "", "", fmt.Errorf("%w: curve %s", ErrKey, key.Curve.Params().Name)
		}
		alg = AlgES256
	default:
		return "", "", fmt.Errorf("%w: %T", ErrKey, signer)
	}
	encoded, err := json.Marshal(protectedHeader{Alg: alg, Kid: kid})
	if err != nil {
		return "", "", fmt.Errorf("jws: %w", err)
	}
	head = b64.EncodeToString(encoded)
	raw, err := signInput(alg, signer, signingInput(head, payload))
	if err != nil {
		return "", "", err
	}
	return head, b64.EncodeToString(raw), nil
}

func signingInput(head string, payload []byte) []byte {
	return []byte(head + "." + b64.EncodeToString(payload))
}

func signInput(alg string, signer any, input []byte) ([]byte, error) {
	switch key := signer.(type) {
	case ed25519.PrivateKey:
		if alg == AlgEdDSA {
			return ed25519.Sign(key, input), nil
		}
	case *ecdsa.PrivateKey:
		if alg == AlgES256 {
			digest := sha256.Sum256(input)
			r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
			if err != nil {
				return nil, fmt.Errorf("jws: sign: %w", err)
			}
			// Of the two valid values s and n-s, the lower one is used (as in verifyInput).
			if s.Cmp(halfOrder) > 0 {
				s.Sub(elliptic.P256().Params().N, s)
			}
			out := make([]byte, 2*p256Bytes)
			r.FillBytes(out[:p256Bytes])
			s.FillBytes(out[p256Bytes:])
			return out, nil
		}
	}
	return nil, fmt.Errorf("%w: %T with %s", ErrKey, signer, alg)
}

func verifyInput(alg string, key crypto.PublicKey, input, sig []byte) bool {
	switch k := key.(type) {
	case ed25519.PublicKey:
		return alg == AlgEdDSA && len(sig) == ed25519.SignatureSize && ed25519.Verify(k, input, sig)
	case *ecdsa.PublicKey:
		if alg != AlgES256 || len(sig) != 2*p256Bytes {
			return false
		}
		digest := sha256.Sum256(input)
		r, s := new(big.Int).SetBytes(sig[:p256Bytes]), new(big.Int).SetBytes(sig[p256Bytes:])
		return s.Cmp(halfOrder) <= 0 && ecdsa.Verify(k, digest[:], r, s)
	}
	return false
}

// Verify checks a compact JWS and returns its payload and the key ID.
func Verify(compact string, keys Keys) (payload []byte, kid string, err error) {
	head, body, sig, err := split(compact)
	if err != nil {
		return nil, "", err
	}
	if body == "" {
		return nil, "", fmt.Errorf("%w: no payload", ErrMalformed)
	}
	payload, err = decodeSegment(body)
	if err != nil {
		return nil, "", fmt.Errorf("%w: payload: %w", ErrMalformed, err)
	}
	kid, err = verify(head, payload, sig, keys)
	if err != nil {
		return nil, "", err
	}
	return payload, kid, nil
}

// VerifyDetached checks a compact JWS with detached payload against payload and
// returns the key ID.
func VerifyDetached(detached string, payload []byte, keys Keys) (kid string, err error) {
	head, body, sig, err := split(detached)
	if err != nil {
		return "", err
	}
	if body != "" {
		return "", fmt.Errorf("%w: payload is not detached", ErrMalformed)
	}
	return verify(head, payload, sig, keys)
}

func split(compact string) (head, body, sig string, err error) {
	parts := strings.Split(compact, ".")
	if len(compact) > maxCompactBytes || len(parts) != 3 {
		return "", "", "", fmt.Errorf("%w: not a compact JWS", ErrMalformed)
	}
	return parts[0], parts[1], parts[2], nil
}

func verify(head string, payload []byte, sig string, keys Keys) (string, error) {
	h, err := parseHeader(head)
	if err != nil {
		return "", err
	}
	raw, err := decodeSegment(sig)
	if err != nil {
		return "", fmt.Errorf("%w: signature: %w", ErrMalformed, err)
	}
	key, ok := keys[h.Kid]
	if !ok {
		return "", fmt.Errorf("%w: key ID %q", ErrKey, h.Kid)
	}
	if !verifyInput(h.Alg, key, signingInput(head, payload), raw) {
		return "", ErrSignature
	}
	return h.Kid, nil
}

// parseHeader accepts exactly the members alg and kid. Anything else, such as crit,
// b64, jwk or jku, would change how the signature must be checked.
func parseHeader(head string) (protectedHeader, error) {
	var h protectedHeader
	encoded, err := decodeSegment(head)
	if err != nil {
		return h, fmt.Errorf("%w: header: %w", ErrMalformed, err)
	}
	if err := ijson.Check(encoded); err != nil {
		return h, fmt.Errorf("%w: header: %w", ErrMalformed, err)
	}
	// encoding/json matches member names without regard to case; the members are read
	// by their exact names instead.
	var members map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &members); err != nil || len(members) != 2 {
		return h, fmt.Errorf("%w: header must have exactly alg and kid", ErrMalformed)
	}
	if json.Unmarshal(members["alg"], &h.Alg) != nil || json.Unmarshal(members["kid"], &h.Kid) != nil {
		return h, fmt.Errorf("%w: header must have exactly alg and kid", ErrMalformed)
	}
	if h.Alg != AlgEdDSA && h.Alg != AlgES256 {
		return h, fmt.Errorf("%w: algorithm %q", ErrMalformed, h.Alg)
	}
	if !kidPattern.MatchString(h.Kid) {
		return h, fmt.Errorf("%w: key ID %q", ErrMalformed, h.Kid)
	}
	return h, nil
}

type jwk struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	Kid string `json:"kid"`
	X   string `json:"x"`
	Y   string `json:"y,omitempty"`
	D   string `json:"d,omitempty"`
}

type jwks struct {
	Keys []jwk `json:"keys"`
}

// ParseJWKS reads public keys from a JWK Set. Every key needs a kid; private keys and
// key types other than Ed25519 and P-256 are rejected.
func ParseJWKS(data []byte) (Keys, error) {
	var set jwks
	if err := ijson.Check(data); err != nil {
		return nil, fmt.Errorf("%w: JWK Set: %w", ErrMalformed, err)
	}
	if err := json.Unmarshal(data, &set); err != nil {
		return nil, fmt.Errorf("%w: JWK Set: %w", ErrMalformed, err)
	}
	if len(set.Keys) == 0 {
		return nil, fmt.Errorf("%w: JWK Set without keys", ErrMalformed)
	}
	keys := make(Keys, len(set.Keys))
	for _, k := range set.Keys {
		if !kidPattern.MatchString(k.Kid) {
			return nil, fmt.Errorf("%w: key ID %q", ErrKey, k.Kid)
		}
		if _, dup := keys[k.Kid]; dup {
			return nil, fmt.Errorf("%w: duplicate key ID %q", ErrKey, k.Kid)
		}
		if k.D != "" {
			return nil, fmt.Errorf("%w: key %q is a private key", ErrKey, k.Kid)
		}
		key, err := publicKey(k)
		if err != nil {
			return nil, fmt.Errorf("%w: key %q: %w", ErrKey, k.Kid, err)
		}
		keys[k.Kid] = key
	}
	return keys, nil
}

func publicKey(k jwk) (crypto.PublicKey, error) {
	x, err := b64.DecodeString(k.X)
	if err != nil {
		return nil, err
	}
	switch {
	case k.Kty == "OKP" && k.Crv == "Ed25519":
		if len(x) != ed25519.PublicKeySize {
			return nil, errors.New("wrong length")
		}
		return ed25519.PublicKey(x), nil
	case k.Kty == "EC" && k.Crv == "P-256":
		y, err := b64.DecodeString(k.Y)
		if err != nil {
			return nil, err
		}
		if len(x) != p256Bytes || len(y) != p256Bytes {
			return nil, errors.New("wrong length")
		}
		// The uncompressed point encoding lets the standard library check that the
		// point lies on the curve.
		point := append(append([]byte{4}, x...), y...)
		return ecdsa.ParseUncompressedPublicKey(elliptic.P256(), point)
	}
	return nil, fmt.Errorf("key type %q with curve %q", k.Kty, k.Crv)
}

// MarshalJWKS writes public keys as a JWK Set, sorted by key ID.
func MarshalJWKS(keys Keys) ([]byte, error) {
	set := jwks{Keys: []jwk{}}
	for kid, key := range keys {
		switch k := key.(type) {
		case ed25519.PublicKey:
			set.Keys = append(set.Keys, jwk{Kty: "OKP", Crv: "Ed25519", Kid: kid, X: b64.EncodeToString(k)})
		case *ecdsa.PublicKey:
			point, err := k.Bytes()
			if err != nil || len(point) != 1+2*p256Bytes {
				return nil, fmt.Errorf("%w: key %q", ErrKey, kid)
			}
			set.Keys = append(set.Keys, jwk{Kty: "EC", Crv: "P-256", Kid: kid,
				X: b64.EncodeToString(point[1 : 1+p256Bytes]), Y: b64.EncodeToString(point[1+p256Bytes:])})
		default:
			return nil, fmt.Errorf("%w: key %q: %T", ErrKey, kid, key)
		}
	}
	slices.SortFunc(set.Keys, func(a, b jwk) int { return strings.Compare(a.Kid, b.Kid) })
	return json.MarshalIndent(set, "", "  ")
}

// SPDX-License-Identifier: Apache-2.0

package jws

// Requests of the Home-Mandate Relay Specification (RELAY-v0.md, draft): the JWS that a
// gateway sends to the enrollment endpoint of an operator (section 5.1) and the inner JWS of
// a key change (section 5.5). Unlike a signed mandate, a request names its key by the
// installation URL (kid) or carries it (jwk), so the header is parsed before the key is known.
//
// ErrMalformed stands for the error malformed of RELAY-v0 section 5.1, ErrSignature for
// bad-signature. ErrKey means that the caller gave no usable key.

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"regexp"

	"github.com/home-mandate/spec/internal/ijson"
)

// RequestHeader is the protected header of a request (RELAY-v0 section 5.1): exactly alg,
// nonce, url and one of jwk and kid.
type RequestHeader struct {
	Alg   string
	Nonce string
	URL   string
	// JWK is the public key of a pairing request: ed25519.PublicKey or *ecdsa.PublicKey on
	// P-256. It is nil when Kid is set.
	JWK crypto.PublicKey
	// Kid is the installation URL; empty when JWK is set.
	Kid string
}

// KeyChangeHeader is the protected header of the inner JWS of a key change (RELAY-v0
// section 5.5): exactly alg, jwk (the new key) and url, no nonce.
type KeyChangeHeader struct {
	Alg string
	JWK crypto.PublicKey
	URL string
}

const (
	// minNonceBytes: a nonce has at least 128 random bits (RELAY-v0 section 5.1).
	minNonceBytes = 16
	// maxNonceChars and maxURLChars are the bounds of the enrollment schema.
	maxNonceChars = 128
	maxURLChars   = 2048
	// maxKeyChangeBytes is the bound of $defs/compact_jws of the enrollment schema.
	maxKeyChangeBytes = 16 << 10
)

// httpsURL is $defs/https_url of the metadata schema: a lower-case DNS host, an optional
// port, a path of unreserved characters, no user info, query, fragment or percent-encoding.
var httpsURL = regexp.MustCompile(`^https://([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?[.])+[a-z]([a-z0-9-]{0,61}[a-z0-9])?(:[1-9][0-9]{0,4})?(/[A-Za-z0-9._~/-]*)?$`)

// ed25519Order is L, the order of the Ed25519 base point; S of a signature is below it
// (RFC 8032 section 5.1.7).
var ed25519Order, _ = new(big.Int).SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)

// SignRequest returns the compact JWS of a request. payload is a JSON object or empty for
// a read (POST-as-GET); an empty payload gives an empty payload segment, not a detached
// one. h.Alg may be empty and is then taken from signer; h.JWK, if set, is the public key
// of signer.
func SignRequest(payload []byte, h RequestHeader, signer any) (string, error) {
	alg, public, err := signerAlg(signer)
	if err != nil {
		return "", err
	}
	if h.Alg != "" && h.Alg != alg {
		return "", fmt.Errorf("%w: algorithm %q for a %s key", ErrKey, h.Alg, alg)
	}
	if (h.JWK == nil) == (h.Kid == "") {
		return "", fmt.Errorf("%w: header needs exactly one of jwk and kid", ErrMalformed)
	}
	head := requestHeaderJSON{Alg: alg, Nonce: h.Nonce, URL: h.URL, Kid: h.Kid}
	if h.JWK != nil {
		if !sameKey(h.JWK, public) {
			return "", fmt.Errorf("%w: jwk is not the key of the signer", ErrKey)
		}
		if head.JWK, err = MarshalJWK(public); err != nil {
			return "", err
		}
	} else if err := checkURL("kid", h.Kid); err != nil {
		return "", err
	}
	if err := checkNonce(h.Nonce); err != nil {
		return "", err
	}
	if err := checkURL("url", h.URL); err != nil {
		return "", err
	}
	if err := checkPayload(payload, true); err != nil {
		return "", err
	}
	return signCompact(head, payload, alg, signer)
}

// ParseRequest checks everything about a request that needs no key: the compact form,
// the header profile (RELAY-v0 section 5.1 step 1) and the spelling rules (step 4) of all
// three segments. It does not verify the signature, so that an operator can look up the
// installation that kid names first; VerifyRequest does both.
func ParseRequest(compact string) (RequestHeader, []byte, error) {
	p, err := parseRequest(compact)
	if err != nil {
		return RequestHeader{}, nil, err
	}
	return p.header, p.payload, nil
}

// VerifyRequest checks a request like ParseRequest and verifies its signature with key: the
// installation key that kid names, or, for a header with jwk, nil (or that same key).
func VerifyRequest(compact string, key crypto.PublicKey) (RequestHeader, []byte, error) {
	p, err := parseRequest(compact)
	if err != nil {
		return RequestHeader{}, nil, err
	}
	verifier := key
	switch {
	case p.header.JWK != nil && key == nil:
		verifier = p.header.JWK
	case p.header.JWK != nil && !sameKey(key, p.header.JWK):
		return RequestHeader{}, nil, fmt.Errorf("%w: key is not the jwk of the header", ErrKey)
	}
	if err := verifySigned(p.signed, verifier); err != nil {
		return RequestHeader{}, nil, err
	}
	return p.header, p.payload, nil
}

// SignKeyChange returns the inner JWS of a key change (RELAY-v0 section 5.5), signed with
// the new key. h.Alg may be empty; h.JWK may be nil and is then the public key of signer.
func SignKeyChange(payload []byte, h KeyChangeHeader, signer any) (string, error) {
	alg, public, err := signerAlg(signer)
	if err != nil {
		return "", err
	}
	if h.Alg != "" && h.Alg != alg {
		return "", fmt.Errorf("%w: algorithm %q for a %s key", ErrKey, h.Alg, alg)
	}
	if h.JWK != nil && !sameKey(h.JWK, public) {
		return "", fmt.Errorf("%w: jwk is not the key of the signer", ErrKey)
	}
	if err := checkURL("url", h.URL); err != nil {
		return "", err
	}
	if err := checkPayload(payload, false); err != nil {
		return "", err
	}
	encoded, err := MarshalJWK(public)
	if err != nil {
		return "", err
	}
	compact, err := signCompact(keyChangeHeaderJSON{Alg: alg, JWK: encoded, URL: h.URL}, payload, alg, signer)
	if err == nil && len(compact) > maxKeyChangeBytes {
		return "", fmt.Errorf("%w: key change larger than %d bytes", ErrMalformed, maxKeyChangeBytes)
	}
	return compact, err
}

// ParseKeyChange checks the inner JWS of a key change without verifying its signature: the
// compact form with a payload, the header profile and the spelling rules.
func ParseKeyChange(compact string) (KeyChangeHeader, []byte, error) {
	p, err := parseKeyChange(compact)
	if err != nil {
		return KeyChangeHeader{}, nil, err
	}
	return p.header, p.payload, nil
}

// VerifyKeyChange checks the inner JWS of a key change like ParseKeyChange and verifies its
// signature with the new key, the jwk of its header. Whether url, installation and old_key
// fit the outer request is for the caller (RELAY-v0 section 5.5).
func VerifyKeyChange(compact string) (KeyChangeHeader, []byte, error) {
	p, err := parseKeyChange(compact)
	if err != nil {
		return KeyChangeHeader{}, nil, err
	}
	if err := verifySigned(p.signed, p.header.JWK); err != nil {
		return KeyChangeHeader{}, nil, err
	}
	return p.header, p.payload, nil
}

// MarshalJWK writes a public key in the form of $defs/jwk of the enrollment schema: kty,
// crv and x, and y for P-256, nothing else.
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

// ParseJWK reads a public key in the form of $defs/jwk of the enrollment schema: an
// Ed25519 or P-256 key with exactly its members, without a private part or a kid.
func ParseJWK(data []byte) (crypto.PublicKey, error) {
	if err := ijson.Check(data); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrKey, err)
	}
	key, err := readStrictJWK(data)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrKey, err)
	}
	return key, nil
}

type requestHeaderJSON struct {
	Alg   string          `json:"alg"`
	Nonce string          `json:"nonce"`
	URL   string          `json:"url"`
	JWK   json.RawMessage `json:"jwk,omitempty"`
	Kid   string          `json:"kid,omitempty"`
}

type keyChangeHeaderJSON struct {
	Alg string          `json:"alg"`
	JWK json.RawMessage `json:"jwk"`
	URL string          `json:"url"`
}

// signed is what verifying a parsed JWS needs.
type signed struct {
	alg   string
	input []byte
	sig   []byte
}

type parsedRequest struct {
	header  RequestHeader
	payload []byte
	signed
}

type parsedKeyChange struct {
	header  KeyChangeHeader
	payload []byte
	signed
}

func signCompact(header any, payload []byte, alg string, signer any) (string, error) {
	encoded, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("jws: %w", err)
	}
	head := b64.EncodeToString(encoded)
	raw, err := signInput(alg, signer, signingInput(head, payload))
	if err != nil {
		return "", err
	}
	return head + "." + b64.EncodeToString(payload) + "." + b64.EncodeToString(raw), nil
}

func parseRequest(compact string) (parsedRequest, error) {
	head, body, sig, err := split(compact)
	if err != nil {
		return parsedRequest{}, err
	}
	h, err := parseRequestHeader(head)
	if err != nil {
		return parsedRequest{}, err
	}
	payload, s, err := readSigned(h.Alg, head, body, sig, true)
	if err != nil {
		return parsedRequest{}, err
	}
	return parsedRequest{header: h, payload: payload, signed: s}, nil
}

func parseKeyChange(compact string) (parsedKeyChange, error) {
	if len(compact) > maxKeyChangeBytes {
		return parsedKeyChange{}, fmt.Errorf("%w: key change larger than %d bytes", ErrMalformed, maxKeyChangeBytes)
	}
	head, body, sig, err := split(compact)
	if err != nil {
		return parsedKeyChange{}, err
	}
	h, err := parseKeyChangeHeader(head)
	if err != nil {
		return parsedKeyChange{}, err
	}
	payload, s, err := readSigned(h.Alg, head, body, sig, false)
	if err != nil {
		return parsedKeyChange{}, err
	}
	return parsedKeyChange{header: h, payload: payload, signed: s}, nil
}

// readSigned decodes payload and signature and checks their spelling.
func readSigned(alg, head, body, sig string, emptyPayload bool) ([]byte, signed, error) {
	if body == "" && !emptyPayload {
		return nil, signed{}, fmt.Errorf("%w: no payload", ErrMalformed)
	}
	payload, err := decodeSegment(body)
	if err != nil {
		return nil, signed{}, fmt.Errorf("%w: payload: %w", ErrMalformed, err)
	}
	if err := checkPayload(payload, emptyPayload); err != nil {
		return nil, signed{}, err
	}
	raw, err := decodeSegment(sig)
	if err != nil {
		return nil, signed{}, fmt.Errorf("%w: signature: %w", ErrMalformed, err)
	}
	if err := checkSignatureForm(alg, raw); err != nil {
		return nil, signed{}, err
	}
	return payload, signed{alg: alg, input: signingInput(head, payload), sig: raw}, nil
}

// verifySigned verifies with key, whose type alg has to match (RELAY-v0 section 5.1).
func verifySigned(s signed, key crypto.PublicKey) error {
	alg, ok := keyAlg(key)
	if !ok {
		return fmt.Errorf("%w: %T", ErrKey, key)
	}
	if alg != s.alg {
		return fmt.Errorf("%w: algorithm %s for a %s key", ErrMalformed, s.alg, alg)
	}
	if !verifyInput(s.alg, key, s.input, s.sig) {
		return ErrSignature
	}
	return nil
}

func parseRequestHeader(segment string) (RequestHeader, error) {
	var h RequestHeader
	members, err := readMembers(segment)
	if err != nil {
		return h, err
	}
	_, hasJWK := members["jwk"]
	_, hasKid := members["kid"]
	if len(members) != 4 || hasJWK == hasKid {
		return h, fmt.Errorf("%w: header must have exactly alg, nonce, url and one of jwk and kid", ErrMalformed)
	}
	if h.Alg, err = readAlg(members); err != nil {
		return h, err
	}
	if h.Nonce, err = readString(members, "nonce"); err != nil {
		return h, err
	}
	if err := checkNonce(h.Nonce); err != nil {
		return h, err
	}
	if h.URL, err = readURL(members, "url"); err != nil {
		return h, err
	}
	if hasKid {
		h.Kid, err = readURL(members, "kid")
		return h, err
	}
	h.JWK, err = readHeaderJWK(members, h.Alg)
	return h, err
}

func parseKeyChangeHeader(segment string) (KeyChangeHeader, error) {
	var h KeyChangeHeader
	members, err := readMembers(segment)
	if err != nil {
		return h, err
	}
	_, hasJWK := members["jwk"]
	if len(members) != 3 || !hasJWK {
		return h, fmt.Errorf("%w: header must have exactly alg, jwk and url", ErrMalformed)
	}
	if h.Alg, err = readAlg(members); err != nil {
		return h, err
	}
	if h.URL, err = readURL(members, "url"); err != nil {
		return h, err
	}
	h.JWK, err = readHeaderJWK(members, h.Alg)
	return h, err
}

// readMembers decodes a protected header; its members are read by their exact names.
func readMembers(segment string) (map[string]json.RawMessage, error) {
	encoded, err := decodeSegment(segment)
	if err != nil {
		return nil, fmt.Errorf("%w: header: %w", ErrMalformed, err)
	}
	if err := ijson.Check(encoded); err != nil {
		return nil, fmt.Errorf("%w: header: %w", ErrMalformed, err)
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &members); err != nil || members == nil {
		return nil, fmt.Errorf("%w: header is not a JSON object", ErrMalformed)
	}
	return members, nil
}

// readString reads a member that must be a JSON string; null is not one.
func readString(members map[string]json.RawMessage, name string) (string, error) {
	raw, ok := members[name]
	var s string
	if !ok || !bytes.HasPrefix(raw, []byte(`"`)) || json.Unmarshal(raw, &s) != nil {
		return "", fmt.Errorf("%w: %s must be a string", ErrMalformed, name)
	}
	return s, nil
}

func readAlg(members map[string]json.RawMessage) (string, error) {
	alg, err := readString(members, "alg")
	if err != nil {
		return "", err
	}
	if alg != AlgEdDSA && alg != AlgES256 {
		return "", fmt.Errorf("%w: algorithm %q", ErrMalformed, alg)
	}
	return alg, nil
}

func readURL(members map[string]json.RawMessage, name string) (string, error) {
	s, err := readString(members, name)
	if err != nil {
		return "", err
	}
	return s, checkURL(name, s)
}

// readHeaderJWK reads the key of a header; alg has to match its type.
func readHeaderJWK(members map[string]json.RawMessage, alg string) (crypto.PublicKey, error) {
	key, err := readStrictJWK(members["jwk"])
	if err != nil {
		return nil, fmt.Errorf("%w: jwk: %w", ErrMalformed, err)
	}
	if got, _ := keyAlg(key); got != alg {
		return nil, fmt.Errorf("%w: algorithm %s for a %s key", ErrMalformed, alg, got)
	}
	return key, nil
}

// readStrictJWK reads $defs/jwk: exactly kty, crv and x, and y for P-256. A private part, a
// kid or any other member makes it invalid.
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
		if field.name != "crv" && len(*field.to) != 43 {
			return nil, fmt.Errorf("%s is not 32 bytes in base64url", field.name)
		}
	}
	return publicKey(k)
}

func checkNonce(nonce string) error {
	decoded, err := decodeSegment(nonce)
	if err != nil || len(nonce) > maxNonceChars || len(decoded) < minNonceBytes {
		return fmt.Errorf("%w: nonce %q is not base64url of at least %d bytes", ErrMalformed, nonce, minNonceBytes)
	}
	return nil
}

func checkURL(name, s string) error {
	if len(s) > maxURLChars || !httpsURL.MatchString(s) {
		return fmt.Errorf("%w: %s %q is not an HTTPS URL of the schema", ErrMalformed, name, s)
	}
	return nil
}

// checkPayload: a payload is a JSON object in I-JSON, or empty for a read.
func checkPayload(payload []byte, emptyAllowed bool) error {
	if len(payload) == 0 {
		if emptyAllowed {
			return nil
		}
		return fmt.Errorf("%w: no payload", ErrMalformed)
	}
	if err := ijson.Check(payload); err != nil {
		return fmt.Errorf("%w: payload: %w", ErrMalformed, err)
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(payload, &object); err != nil || object == nil {
		return fmt.Errorf("%w: payload is not a JSON object", ErrMalformed)
	}
	return nil
}

// checkSignatureForm checks the spelling of a signature (SPEC-v0 section 7.1, applied by
// RELAY-v0 section 5.1): for EdDSA a canonical R and S < L, for ES256 the lower s.
func checkSignatureForm(alg string, sig []byte) error {
	if len(sig) != 2*p256Bytes {
		return fmt.Errorf("%w: signature of %d bytes", ErrMalformed, len(sig))
	}
	if alg == AlgEdDSA {
		s := make([]byte, 32)
		for i, b := range sig[32:] {
			s[31-i] = b
		}
		if !canonicalEd25519(sig[:32]) || new(big.Int).SetBytes(s).Cmp(ed25519Order) >= 0 {
			return fmt.Errorf("%w: EdDSA signature not canonical", ErrMalformed)
		}
		return nil
	}
	if new(big.Int).SetBytes(sig[p256Bytes:]).Cmp(halfOrder) > 0 {
		return fmt.Errorf("%w: ES256 signature with the higher s", ErrMalformed)
	}
	return nil
}

// signerAlg returns the algorithm and public key of a private key.
func signerAlg(signer any) (string, crypto.PublicKey, error) {
	switch key := signer.(type) {
	case ed25519.PrivateKey:
		return AlgEdDSA, key.Public(), nil
	case *ecdsa.PrivateKey:
		if key.Curve != elliptic.P256() {
			return "", nil, fmt.Errorf("%w: curve %s", ErrKey, key.Curve.Params().Name)
		}
		return AlgES256, key.Public(), nil
	}
	return "", nil, fmt.Errorf("%w: %T", ErrKey, signer)
}

// keyAlg returns the algorithm of a public key.
func keyAlg(key crypto.PublicKey) (string, bool) {
	switch k := key.(type) {
	case ed25519.PublicKey:
		return AlgEdDSA, true
	case *ecdsa.PublicKey:
		return AlgES256, k != nil && k.Curve == elliptic.P256()
	}
	return "", false
}

func sameKey(a, b crypto.PublicKey) bool {
	k, ok := a.(interface{ Equal(crypto.PublicKey) bool })
	return ok && k.Equal(b)
}

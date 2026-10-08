// SPDX-License-Identifier: Apache-2.0

package evaluator

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/home-mandate/spec/internal/ijson"
	"github.com/home-mandate/spec/jcs"
	"github.com/home-mandate/spec/jws"
)

// ErrSignature means a signed mandate is not a compact JWS over the canonical form of a
// mandate, signed by a key that is trusted for the mandate's issuer.
var ErrSignature = errors.New("evaluator: signed mandate not accepted")

// Issuers are the public keys a verifier trusts, by issuer. How a verifier comes to
// trust a key is outside the specification.
type Issuers map[string]jws.Keys

// Canonical returns the canonical form (RFC 8785) of a JSON text that is I-JSON.
func Canonical(data []byte) ([]byte, error) {
	if err := ijson.Check(data); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	v, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	out, err := jcs.Canonicalize(v)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	return out, nil
}

// Sign returns a signed mandate (SPEC-v0 section 7): the compact JWS over the canonical
// form of a valid mandate that names its issuer and version. signer is an
// ed25519.PrivateKey or an *ecdsa.PrivateKey on P-256.
func Sign(mandate []byte, kid string, signer any) (string, error) {
	m, err := Parse(mandate)
	if err != nil {
		return "", err
	}
	if m.issuer == "" {
		return "", fmt.Errorf("%w: a signed mandate needs issuer and version", ErrSemantic)
	}
	payload, err := Canonical(mandate)
	if err != nil {
		return "", err
	}
	return jws.Sign(payload, kid, signer)
}

// ParseSigned verifies a signed mandate and returns the mandate. The signature must be
// made with a key trusted for the issuer the mandate names, and the payload must be
// the canonical form of the mandate, so that one mandate has exactly one signed form.
func ParseSigned(compact string, trusted Issuers) (*Mandate, error) {
	issuer, err := unverifiedIssuer(compact)
	if err != nil {
		return nil, err
	}
	keys, ok := trusted[issuer]
	if !ok || issuer == "" {
		return nil, fmt.Errorf("%w: issuer %q is not trusted", ErrSignature, issuer)
	}
	payload, _, err := jws.Verify(compact, keys)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSignature, err)
	}
	canonical, err := Canonical(payload)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(canonical, payload) {
		return nil, fmt.Errorf("%w: payload is not in canonical form", ErrSignature)
	}
	m, err := Parse(payload)
	if err != nil {
		return nil, err
	}
	if m.issuer != issuer {
		return nil, fmt.Errorf("%w: issuer changed during parsing", ErrSignature)
	}
	return m, nil
}

// unverifiedIssuer reads the issuer from the payload before the signature is checked,
// only to choose the keys; nothing else of the payload is used unverified.
func unverifiedIssuer(compact string) (string, error) {
	parts := strings.Split(compact, ".")
	if len(compact) > jws.MaxCompactBytes || len(parts) != 3 || parts[1] == "" {
		return "", fmt.Errorf("%w: not a compact JWS with payload", ErrSignature)
	}
	payload, err := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if err != nil || strings.ContainsAny(parts[1], "\r\n") {
		return "", fmt.Errorf("%w: payload is not base64url", ErrSignature)
	}
	if err := ijson.Check(payload); err != nil {
		return "", fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	var loose struct {
		Issuer string `json:"issuer"`
	}
	if err := json.Unmarshal(payload, &loose); err != nil {
		return "", fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	return loose.Issuer, nil
}

// CheckSuccessor reports whether offered may replace stored as the next version of a
// mandate (SPEC-v0 section 3.5). It protects against rollback: an older version with a
// valid digest or signature is not accepted again. stored is nil if nothing is stored
// and nothing was stored before: an implementation keeps the highest version it has
// seen per mandate, also after the mandate was revoked or deleted, and passes it here.
// The check does not decide whether the issuer may issue mandates for the principal;
// that is the caller's decision (SPEC-v0 section 7.1).
func CheckSuccessor(stored, offered *Mandate) error {
	switch {
	case offered == nil || !offered.valid:
		return fmt.Errorf("%w: no valid mandate offered", ErrSemantic)
	case stored == nil:
		return nil
	case offered.id != stored.id:
		return fmt.Errorf("%w: mandate %q does not replace %q", ErrSemantic, offered.id, stored.id)
	case offered.clientID != stored.clientID || offered.principal != stored.principal:
		return fmt.Errorf("%w: a replacement keeps agent and principal", ErrSemantic)
	case stored.version == 0:
		return nil // the stored mandate has no version; anything may follow
	case offered.issuer != stored.issuer:
		return fmt.Errorf("%w: issuer %q does not replace issuer %q", ErrSemantic, offered.issuer, stored.issuer)
	case offered.version <= stored.version:
		return fmt.Errorf("%w: version %d does not follow version %d", ErrSemantic, offered.version, stored.version)
	}
	return nil
}

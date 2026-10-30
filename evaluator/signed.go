// SPDX-License-Identifier: Apache-2.0

package evaluator

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

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
	if err := signable(m); err != nil {
		return "", fmt.Errorf("%w: %w", ErrSemantic, err)
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
	if err := signable(m); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSignature, err)
	}
	return m, nil
}

// signable reports why a valid mandate cannot be a signed mandate: it needs issuer and
// version, the audience it is for and an expiry (SPEC-v0 section 7.1). Whether the
// audience is the verifier's own is the verifier's decision, like the trust in the issuer.
func signable(m *Mandate) error {
	switch {
	case m.issuer == "":
		return errors.New("SPEC-v0 section 7.1: a signed mandate needs issuer and version")
	case m.audience == "":
		return errors.New("SPEC-v0 section 7.1: a signed mandate names its audience")
	case !m.hasExpires:
		return errors.New("SPEC-v0 section 7.1: a signed mandate expires")
	}
	return nil
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
// valid digest or signature is not accepted again. stored is the mandate the
// implementation holds or remembers under the id, also after it was revoked, removed or
// expired; nil only if no mandate was ever accepted under the id. Whether an accepted
// successor takes effect at once or only after a human confirmed it is NeedsConfirmation.
// The check does not decide whether the issuer may issue mandates for the principal and
// the audience; that is the caller's decision (SPEC-v0 section 7.1).
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

// NeedsConfirmation reports whether an accepted successor takes effect only after a human
// confirmed exactly this version (SPEC-v0 sections 3.5 and 11.6): it switches audit mode
// on (EntersAuditMode), its predecessor is revoked (the issuer cannot undo a revocation
// of the household), or it does not merely narrow the stored mandate (Narrows). A zero at
// means the stored mandate counts as in force if it is valid and active. Whether the
// approvers of a signed mandate are known to the implementation (SPEC-v0 section 3.5) is
// the caller's check; this package does not know the approvers.
func NeedsConfirmation(stored *Mandate, status MandateStatus, at time.Time, offered *Mandate) bool {
	if offered == nil || !offered.valid {
		return false
	}
	if EntersAuditMode(stored, status, at, offered) {
		return true
	}
	if stored == nil {
		return false
	}
	return status == StatusRevoked || !Narrows(stored, offered)
}

// Narrows reports whether offered differs from stored only in ways that take nothing
// away from the household's protection (SPEC-v0 section 3.5): removed allow rules, added
// deny rules, added ask rules without their own approval, an earlier or added expiry, a
// later start, a lower rate limit, audit mode switched off, and the issuer's version.
// Everything else, a changed rule or displayed text included, is a weakening, so that a
// successor from outside cannot expand what an agent may do, or change what a human
// reads, without a human. Both mandates must be valid and name the same id, agent and
// principal.
func Narrows(stored, offered *Mandate) bool {
	if stored == nil || offered == nil || !stored.valid || !offered.valid ||
		stored.id != offered.id || stored.clientID != offered.clientID || stored.principal != offered.principal {
		return false
	}
	if offered.auditMode && !stored.auditMode || offered.name != stored.name || offered.displayName != stored.displayName || offered.audience != stored.audience ||
		offered.approvalText != stored.approvalText || offered.maxActions > stored.maxActions || offered.validFrom.Before(stored.validFrom) {
		return false
	}
	if stored.hasExpires && (!offered.hasExpires || offered.expires.After(stored.expires)) {
		return false
	}
	kept := make(map[string]bool, len(stored.ruleTexts))
	for _, r := range stored.ruleTexts {
		kept[r.text] = false
	}
	for _, r := range offered.ruleTexts {
		if _, ok := kept[r.text]; ok {
			kept[r.text] = true
			continue
		}
		if r.decision != Deny && !(r.decision == Ask && !r.ownApproval) {
			return false // an added or changed allow rule, or an ask rule that names approvers
		}
	}
	for _, r := range stored.ruleTexts {
		if !kept[r.text] && r.decision != Allow {
			return false // a removed or changed deny or ask rule
		}
	}
	return true
}

// EntersAuditMode reports whether adopting offered switches audit mode on: offered is in
// audit mode ("enforce": false) and no mandate in audit mode is in force for it. stored
// is the mandate the implementation holds under the same id, with its status, and at is
// the point in time; stored counts only if it is valid, active and valid at at (SPEC-v0
// section 4, step 1); a zero at skips the check of the validity period. A predecessor that is revoked, expired or not yet valid counts as
// none, and offered then arrives as if from outside. Such a mandate takes effect only
// after a human of the household confirmed exactly this version (its digest), and every
// approver is notified, also for a signed successor that passed CheckSuccessor (SPEC-v0
// sections 3.5 and 11.6). Switching audit mode off needs no confirmation.
func EntersAuditMode(stored *Mandate, status MandateStatus, at time.Time, offered *Mandate) bool {
	if offered == nil || offered.Enforce() {
		return false
	}
	return !stored.inForce(status, at) || stored.Enforce()
}

// inForce reports whether m is a valid mandate that is active and valid at t; a zero t
// asks only whether it is valid and active.
func (m *Mandate) inForce(status MandateStatus, t time.Time) bool {
	if m == nil || !m.valid || status != StatusActive {
		return false
	}
	return t.IsZero() || !t.Before(m.validFrom) && (!m.hasExpires || t.Before(m.expires))
}

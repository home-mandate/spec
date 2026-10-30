// SPDX-License-Identifier: Apache-2.0

package evaluator_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io/fs"
	"strings"
	"testing"
	"time"

	"github.com/home-mandate/spec"
	"github.com/home-mandate/spec/evaluator"
	"github.com/home-mandate/spec/jws"
)

const testIssuer = "https://issuer.example/mandates"

// issuedMandate is the test mandate as an issuer signs it: with issuer and version, the
// audience it is for and an expiry (SPEC-v0 section 7.1).
func issuedMandate(version string) []byte {
	return mandateReplacing(`"created_by":"a-1"`, `"issuer":"`+testIssuer+`","version":`+version+
		`,"audience":"hm-verifier:test-0001","expires":"2030-01-01T00:00:00+01:00","created_by":"a-1"`)
}

func issuerKey() ed25519.PrivateKey { return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, 32)) }

func trusted() evaluator.Issuers {
	return evaluator.Issuers{testIssuer: jws.Keys{"issuer-key-1": issuerKey().Public()}}
}

func TestMandateExposesIssuerAndVersion(t *testing.T) {
	m, err := evaluator.Parse(issuedMandate("7"))
	if err != nil {
		t.Fatal(err)
	}
	if m.Issuer() != testIssuer || m.Version() != 7 {
		t.Errorf("Issuer() = %q, Version() = %d", m.Issuer(), m.Version())
	}
	plain, _ := evaluator.Parse(mandateNamed("Test"))
	var none *evaluator.Mandate
	if plain.Issuer() != "" || plain.Version() != 0 || none.Issuer() != "" || none.Version() != 0 {
		t.Error("a mandate without issuer and version must report empty values")
	}
}

func TestIssuerAndVersionOnlyTogether(t *testing.T) {
	for name, data := range map[string][]byte{
		"issuer only":      mandateReplacing(`"created_by":"a-1"`, `"issuer":"`+testIssuer+`","created_by":"a-1"`),
		"version only":     mandateReplacing(`"created_by":"a-1"`, `"version":1,"created_by":"a-1"`),
		"version zero":     issuedMandate("0"),
		"version negative": issuedMandate("-1"),
		"version fraction": issuedMandate("1.5"),
		"version string":   issuedMandate(`"1"`),
		"version too big":  issuedMandate("9007199254740992"),
		"issuer no URI":    mandateReplacing(`"created_by":"a-1"`, `"issuer":"someone","version":1,"created_by":"a-1"`),
		"issuer http":      mandateReplacing(`"created_by":"a-1"`, `"issuer":"http://issuer.example/x","version":1,"created_by":"a-1"`),
	} {
		if _, err := evaluator.Parse(data); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if m, err := evaluator.Parse(issuedMandate("1e1")); err != nil || m.Version() != 10 {
		t.Errorf("version 1e1: %v, %v", m.Version(), err)
	}
}

func TestSignAndParseSigned(t *testing.T) {
	compact, err := evaluator.Sign(issuedMandate("3"), "issuer-key-1", issuerKey())
	if err != nil {
		t.Fatal(err)
	}
	m, err := evaluator.ParseSigned(compact, trusted())
	if err != nil {
		t.Fatal(err)
	}
	plain, _ := evaluator.Parse(issuedMandate("3"))
	if m.Digest() != plain.Digest() || m.Version() != 3 {
		t.Errorf("signed mandate: digest %s version %d, want %s and 3", m.Digest(), m.Version(), plain.Digest())
	}
}

func TestSignRejects(t *testing.T) {
	if _, err := evaluator.Sign(mandateNamed("Test"), "issuer-key-1", issuerKey()); !errors.Is(err, evaluator.ErrSemantic) {
		t.Errorf("mandate without issuer and version: %v, want ErrSemantic", err)
	}
	if _, err := evaluator.Sign([]byte(`{}`), "issuer-key-1", issuerKey()); err == nil {
		t.Error("invalid mandate signed")
	}
	if _, err := evaluator.Sign(issuedMandate("3"), "bad kid", issuerKey()); err == nil {
		t.Error("bad key ID accepted")
	}
}

func TestParseSignedRejects(t *testing.T) {
	key := issuerKey()
	canonical := func(data []byte) []byte {
		compact, err := evaluator.Sign(data, "issuer-key-1", key)
		if err != nil {
			t.Fatal(err)
		}
		payload, _, err := jws.Verify(compact, trusted()[testIssuer])
		if err != nil {
			t.Fatal(err)
		}
		return payload
	}
	sign := func(payload []byte, signer ed25519.PrivateKey) string {
		compact, err := jws.Sign(payload, "issuer-key-1", signer)
		if err != nil {
			t.Fatal(err)
		}
		return compact
	}
	good := sign(canonical(issuedMandate("3")), key)
	if _, err := evaluator.ParseSigned(good, trusted()); err != nil {
		t.Fatalf("good signed mandate rejected: %v", err)
	}
	otherIssuer := mandateReplacing(`"created_by":"a-1"`, `"issuer":"https://other.example/m","version":3,"created_by":"a-1"`)
	for name, tt := range map[string]struct {
		compact string
		want    error
	}{
		"not canonical":      {sign(issuedMandate("3"), key), evaluator.ErrSignature},
		"signed by another":  {sign(canonical(issuedMandate("3")), ed25519.NewKeyFromSeed(make([]byte, 32))), evaluator.ErrSignature},
		"without issuer":     {sign([]byte(strings.TrimSpace(string(mustCanonical(t, mandateNamed("Test"))))), key), evaluator.ErrSignature},
		"issuer not trusted": {sign(canonical2(t, otherIssuer), key), evaluator.ErrSignature},
		"invalid mandate":    {sign([]byte(`{"issuer":"`+testIssuer+`"}`), key), evaluator.ErrSchema},
		"payload not JSON":   {sign([]byte(`nope`), key), evaluator.ErrMalformed},
		"not a JWS":          {"nope", evaluator.ErrSignature},
		"detached":           {strings.Replace(good, good[strings.Index(good, "."):strings.LastIndex(good, ".")+1], "..", 1), evaluator.ErrSignature},
	} {
		t.Run(name, func(t *testing.T) {
			m, err := evaluator.ParseSigned(tt.compact, trusted())
			if m != nil || !errors.Is(err, tt.want) {
				t.Errorf("ParseSigned = %v, %v; want %v", m, err, tt.want)
			}
		})
	}
	if _, err := evaluator.ParseSigned(good, nil); !errors.Is(err, evaluator.ErrSignature) {
		t.Errorf("without trusted issuers: %v", err)
	}
}

// mustCanonical returns the canonical form of any JSON value.
func mustCanonical(t *testing.T, data []byte) []byte {
	t.Helper()
	out, err := evaluator.Canonical(data)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func canonical2(t *testing.T, data []byte) []byte { return mustCanonical(t, data) }

func TestCheckSuccessor(t *testing.T) {
	parse := func(data []byte) *evaluator.Mandate {
		m, err := evaluator.Parse(data)
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	v3, v4 := parse(issuedMandate("3")), parse(issuedMandate("4"))
	plain := parse(mandateNamed("Test"))
	otherID := parse(bytes.Replace(issuedMandate("9"), []byte(`"id":"m-test"`), []byte(`"id":"m-else"`), 1))
	otherIssuer := parse(bytes.Replace(issuedMandate("9"), []byte(testIssuer), []byte("https://other.example/m"), 1))
	for name, tt := range map[string]struct {
		stored, offered *evaluator.Mandate
		ok              bool
	}{
		"higher version":           {v3, v4, true},
		"same version":             {v3, v3, false},
		"lower version (rollback)": {v4, v3, false},
		"versioned replaces plain": {plain, v3, true},
		"plain replaces versioned": {v3, plain, false},
		"plain replaces plain":     {plain, plain, true},
		"another issuer":           {v3, otherIssuer, false},
		"another mandate ID":       {v3, otherID, false},
		"nothing stored":           {nil, v3, true},
		"nothing offered":          {v3, nil, false},
	} {
		if err := evaluator.CheckSuccessor(tt.stored, tt.offered); (err == nil) != tt.ok {
			t.Errorf("%s: CheckSuccessor = %v, want ok = %v", name, err, tt.ok)
		}
	}
}

type signedCase struct {
	ID       string `json:"id"`
	JWS      string `json:"jws"`
	Keys     string `json:"keys"`
	Issuer   string `json:"issuer"`
	Expected string `json:"expected"`
	Digest   string `json:"digest"`
	Why      string `json:"why"`
}

func TestConformanceSignedMandates(t *testing.T) {
	for _, c := range loadCases[signedCase](t, spec.SignedCasesPath, "cases") {
		t.Run(c.ID, func(t *testing.T) {
			data, err := fs.ReadFile(spec.FS(), c.Keys)
			if err != nil {
				t.Fatal(err)
			}
			keys, err := jws.ParseJWKS(data)
			if err != nil {
				t.Fatal(err)
			}
			m, err := evaluator.ParseSigned(c.JWS, evaluator.Issuers{c.Issuer: keys})
			switch c.Expected {
			case "valid":
				if err != nil || m.Digest() != c.Digest {
					t.Errorf("ParseSigned = %s, %v; want digest %s (%s)", m.Digest(), err, c.Digest, c.Why)
				}
			case "invalid":
				if err == nil {
					t.Errorf("ParseSigned accepted (%s)", c.Why)
				}
			default:
				t.Fatalf("unknown expectation %q", c.Expected)
			}
		})
	}
}

type successionCase struct {
	ID            string          `json:"id"`
	Stored        json.RawMessage `json:"stored"`
	StoredRevoked bool            `json:"stored_revoked"`
	Offered       json.RawMessage `json:"offered"`
	Expected      string          `json:"expected"`
	Confirm       bool            `json:"confirm"`
	Why           string          `json:"why"`
}

func TestConformanceSuccession(t *testing.T) {
	for _, c := range loadCases[successionCase](t, spec.SuccessionCasesPath, "cases") {
		t.Run(c.ID, func(t *testing.T) {
			stored, err := evaluator.Parse(c.Stored)
			if err != nil {
				t.Fatalf("stored: %v", err)
			}
			offered, err := evaluator.Parse(c.Offered)
			if err != nil {
				t.Fatalf("offered: %v", err)
			}
			err = evaluator.CheckSuccessor(stored, offered)
			if (err == nil) != (c.Expected == "accept") {
				t.Errorf("CheckSuccessor = %v, want %s (%s)", err, c.Expected, c.Why)
			}
			if err != nil {
				return
			}
			status := evaluator.StatusActive
			if c.StoredRevoked {
				status = evaluator.StatusRevoked
			}
			if got := evaluator.NeedsConfirmation(stored, status, time.Time{}, offered); got != c.Confirm {
				t.Errorf("NeedsConfirmation = %t, want %t (%s)", got, c.Confirm, c.Why)
			}
		})
	}
}

func TestCanonicalRejectsWhatIsNotIJSON(t *testing.T) {
	for _, in := range []string{``, `{`, `{"a":1,"a":2}`, `{"n":0.5}`, `[1] [2]`} {
		if _, err := evaluator.Canonical([]byte(in)); !errors.Is(err, evaluator.ErrMalformed) {
			t.Errorf("Canonical(%q) = %v, want ErrMalformed", in, err)
		}
	}
	out, err := evaluator.Canonical([]byte(`{ "b": [1, 2.0], "a": null }`))
	if err != nil || string(out) != `{"a":null,"b":[1,2]}` {
		t.Errorf("Canonical = %s, %v", out, err)
	}
}

func TestCheckSuccessorKeepsAgentAndPrincipal(t *testing.T) {
	parse := func(data []byte) *evaluator.Mandate {
		m, err := evaluator.Parse(data)
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	stored := parse(mandateNamed("Test"))
	otherAgent := parse(bytes.Replace(issuedMandate("1"), []byte("hm-client:test-0001"), []byte("hm-client:test-0002"), 1))
	otherPrincipal := parse(bytes.Replace(issuedMandate("1"), []byte("household:t"), []byte("household:u"), 1))
	if evaluator.CheckSuccessor(stored, otherAgent) == nil {
		t.Error("a mandate for another agent replaced the stored one")
	}
	if evaluator.CheckSuccessor(stored, otherPrincipal) == nil {
		t.Error("a mandate for another principal replaced the stored one")
	}
}

func TestParseSignedBoundsItsInput(t *testing.T) {
	huge := "a." + strings.Repeat("A", 600<<10) + ".b"
	if _, err := evaluator.ParseSigned(huge, trusted()); !errors.Is(err, evaluator.ErrSignature) {
		t.Errorf("oversized signed mandate: %v, want ErrSignature", err)
	}
}

// TestNarrowsAndNeedsConfirmation covers the edges of SPEC-v0 section 3.5 that the
// conformance cases leave out: every change that is not listed as narrowing weakens.
func TestNarrowsAndNeedsConfirmation(t *testing.T) {
	parse := func(data []byte) *evaluator.Mandate {
		m, err := evaluator.Parse(data)
		if err != nil {
			t.Fatalf("%s: %v", data, err)
		}
		return m
	}
	stored := parse(issuedMandate("3"))
	next := func(old, replacement string) *evaluator.Mandate {
		return parse(bytes.Replace(issuedMandate("4"), []byte(old), []byte(replacement), 1))
	}
	same := parse(issuedMandate("4"))
	for name, offered := range map[string]*evaluator.Mandate{
		"a name":                            next(`"id":"m-test"`, `"id":"m-test","name":"Trial"`),
		"another audience":                  next(`"audience":"hm-verifier:test-0001"`, `"audience":"hm-verifier:other"`),
		"an earlier start":                  next(`"valid_from":"2026-01-01T00:00:00+01:00"`, `"valid_from":"2025-01-01T00:00:00+01:00"`),
		"a later expiry":                    next(`"expires":"2030-01-01T00:00:00+01:00"`, `"expires":"2031-01-01T00:00:00+01:00"`),
		"no expiry any more":                next(`,"expires":"2030-01-01T00:00:00+01:00"`, ``),
		"another display name":              next(`"display_name":"Test"`, `"display_name":"Trusted Assistant"`),
		"other approvers":                   next(`"approvers":["a-1"]`, `"approvers":["a-1","a-2"]`),
		"audit mode switched on":            next(`"default":"deny"`, `"enforce":false,"default":"deny"`),
		"a changed allow rule":              next(`"actions":["turn_on"]`, `"actions":["turn_on","turn_off"]`),
		"an ask rule with its own approval": next(`"decision":"allow"}`, `"decision":"allow"},{"id":"r-2","resource":{"category":"cover"},"actions":["open"],"decision":"ask","approval":{"timeout":"PT1M","approvers":["a-2"]}}`),
	} {
		if evaluator.Narrows(stored, offered) {
			t.Errorf("%s: Narrows = true", name)
		}
		if !evaluator.NeedsConfirmation(stored, evaluator.StatusActive, time.Time{}, offered) {
			t.Errorf("%s: NeedsConfirmation = false", name)
		}
	}
	if !evaluator.Narrows(stored, same) || evaluator.NeedsConfirmation(stored, evaluator.StatusActive, time.Time{}, same) {
		t.Error("the same content under the next version is not a weakening")
	}
	// A stored deny rule that disappears is a weakening; a disappearing allow rule is not.
	withDeny := parse(bytes.Replace(issuedMandate("3"), []byte(`"decision":"allow"}`),
		[]byte(`"decision":"allow"},{"id":"r-no","resource":{"category":"lock"},"actions":["*"],"decision":"deny"}`), 1))
	if evaluator.Narrows(withDeny, same) {
		t.Error("removing a deny rule narrows")
	}
	if !evaluator.Narrows(withDeny, withDeny) {
		t.Error("the same mandate narrows itself")
	}
	// Nothing stored, nothing invalid: only audit mode asks for a confirmation.
	invalid, _ := evaluator.Parse([]byte(`{}`))
	if evaluator.NeedsConfirmation(nil, evaluator.StatusActive, time.Time{}, same) || evaluator.NeedsConfirmation(stored, evaluator.StatusActive, time.Time{}, invalid) ||
		evaluator.Narrows(nil, same) || evaluator.Narrows(stored, invalid) {
		t.Error("nil or invalid mandates")
	}
	// A revoked predecessor asks for a confirmation even without any change.
	if !evaluator.NeedsConfirmation(stored, evaluator.StatusRevoked, time.Time{}, same) {
		t.Error("a successor of a revoked mandate takes effect only after a confirmation")
	}
}

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

	mandatespec "github.com/mandate-spec/mandate-spec"
	"github.com/mandate-spec/mandate-spec/evaluator"
	"github.com/mandate-spec/mandate-spec/jws"
)

const testIssuer = "https://issuer.example/mandates"

func issuedMandate(version string) []byte {
	return mandateReplacing(`"created_by":"a-1"`, `"issuer":"`+testIssuer+`","version":`+version+`,"created_by":"a-1"`)
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
	for _, c := range loadCases[signedCase](t, mandatespec.SignedCasesPath, "cases") {
		t.Run(c.ID, func(t *testing.T) {
			data, err := fs.ReadFile(mandatespec.FS(), c.Keys)
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
	ID       string          `json:"id"`
	Stored   json.RawMessage `json:"stored"`
	Offered  json.RawMessage `json:"offered"`
	Expected string          `json:"expected"`
	Why      string          `json:"why"`
}

func TestConformanceSuccession(t *testing.T) {
	for _, c := range loadCases[successionCase](t, mandatespec.SuccessionCasesPath, "cases") {
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

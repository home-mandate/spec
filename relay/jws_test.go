// SPDX-License-Identifier: Apache-2.0

package relay_test

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/home-mandate/spec/jws"
)

const jwsCasesPath = "conformance/jws-v0.json"

type jwsCase struct {
	ID       string          `json:"id"`
	Kind     string          `json:"kind"`
	JWS      string          `json:"jws"`
	Key      json.RawMessage `json:"key"`
	URL      string          `json:"url"`
	Expected string          `json:"expected"`
	Why      string          `json:"why"`
}

func loadJWSCases(t *testing.T) []jwsCase {
	t.Helper()
	data, err := os.ReadFile(jwsCasesPath)
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Cases []jwsCase `json:"cases"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	return file.Cases
}

// verdict maps the result of the jws package to the errors of RELAY-v0 section 5.1: header,
// spelling and url are malformed, a signature that does not verify is bad-signature.
func verdict(t *testing.T, c jwsCase) string {
	t.Helper()
	var key crypto.PublicKey
	if string(c.Key) != "null" {
		k, err := jws.ParseJWK(c.Key)
		if err != nil {
			t.Fatalf("%s: key: %v", c.ID, err)
		}
		key = k
	}
	var url string
	var err error
	switch c.Kind {
	case "request":
		var h jws.RequestHeader
		h, _, err = jws.VerifyRequest(c.JWS, key)
		url = h.URL
	case "key-change":
		var h jws.KeyChangeHeader
		h, _, err = jws.VerifyKeyChange(c.JWS)
		url = h.URL
	default:
		t.Fatalf("%s: kind %q", c.ID, c.Kind)
	}
	switch {
	case errors.Is(err, jws.ErrMalformed):
		return "malformed"
	case errors.Is(err, jws.ErrSignature):
		return "bad-signature"
	case err != nil:
		t.Fatalf("%s: %v", c.ID, err)
	case c.URL != "" && url != c.URL:
		return "malformed"
	}
	return "valid"
}

func TestJWSCases(t *testing.T) {
	cases := loadJWSCases(t)
	if len(cases) == 0 {
		t.Fatal("no cases")
	}
	for _, c := range cases {
		if got := verdict(t, c); got != c.Expected {
			t.Errorf("%s (%s): %s, want %s", c.ID, c.Why, got, c.Expected)
		}
	}
}

// TestValidJWSHeadersMatchTheSchema: the header of every valid case is valid against the
// enrollment schema, so that the jws package and the schema agree.
func TestValidJWSHeadersMatchTheSchema(t *testing.T) {
	defs := map[string]string{"request": "protected_header", "key-change": "key_change_header"}
	for _, c := range loadJWSCases(t) {
		if c.Expected != "valid" {
			continue
		}
		head, err := base64.RawURLEncoding.DecodeString(c.JWS[:strings.Index(c.JWS, ".")])
		if err != nil {
			t.Fatalf("%s: %v", c.ID, err)
		}
		var doc any
		if err := json.Unmarshal(head, &doc); err != nil {
			t.Fatalf("%s: %v", c.ID, err)
		}
		if err := compileEnrollmentDef(t, defs[c.Kind]).Validate(doc); err != nil {
			t.Errorf("%s: header violates %s: %v", c.ID, defs[c.Kind], err)
		}
	}
}

func TestJWSCaseKeysAreTestKeys(t *testing.T) {
	data, err := os.ReadFile("conformance/keys/test-keys.json")
	if err != nil {
		t.Fatal(err)
	}
	keys, err := jws.ParseJWKS(data)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range loadJWSCases(t) {
		if string(c.Key) == "null" {
			continue
		}
		key, err := jws.ParseJWK(c.Key)
		if err != nil {
			t.Fatalf("%s: %v", c.ID, err)
		}
		found := false
		for _, k := range keys {
			found = found || key.(interface{ Equal(crypto.PublicKey) bool }).Equal(k)
		}
		if !found {
			t.Errorf("%s: key is not in conformance/keys/test-keys.json", c.ID)
		}
	}
}

// SPDX-License-Identifier: Apache-2.0

package relay_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"

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
	case url != c.URL:
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

// schemaAcceptedJWSHeaders are the malformed cases whose header is valid against the
// enrollment schema: their defect is outside the header, or in a rule of the header that
// the schema cannot express. Every other malformed case has a defect in the shape of its
// header, which the schema rejects as well.
var schemaAcceptedJWSHeaders = map[string]string{
	"r06": "url differs from the URL the request was sent to",
	"r16": "member twice: the schema sees one",
	"r17": "defect in the payload",
	"r23": "alg against the key that kid names",
	"r24": "alg against the key that kid names",
	"r29": "jwk of small order",
	"r30": "x of jwk not canonical",
	"r32": "nonce not canonical",
	"r38": "spelling of the header segment",
	"r39": "spelling of the payload segment",
	"r40": "spelling of the signature segment",
	"r41": "spelling of the signature segment",
	"r42": "spelling of the signature",
	"r43": "spelling of the signature",
	"r44": "defect in the payload",
	"r46": "number of segments",
	"r48": "jwk not on the curve",
	"k04": "url differs from the URL of key_change",
	"k11": "defect in the payload",
	"k12": "defect in the payload",
	"k13": "spelling of the signature",
}

// TestJWSHeadersAgreeWithTheSchema: the header of every valid case, and of every
// malformed case in schemaAcceptedJWSHeaders, is valid against the enrollment schema; the
// header of every other malformed case is not, so that the jws package and the schema
// agree in both directions.
func TestJWSHeadersAgreeWithTheSchema(t *testing.T) {
	defs := map[string]string{"request": "protected_header", "key-change": "key_change_header"}
	schemas := map[string]*jsonschema.Schema{}
	for kind, def := range defs {
		schemas[kind] = compileEnrollmentDef(t, def)
	}
	seen := map[string]bool{}
	for _, c := range loadJWSCases(t) {
		if c.Expected == "bad-signature" {
			continue
		}
		head, err := base64.RawURLEncoding.DecodeString(c.JWS[:strings.Index(c.JWS, ".")])
		if err != nil {
			t.Fatalf("%s: %v", c.ID, err)
		}
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(head))
		if err != nil {
			t.Fatalf("%s: %v", c.ID, err)
		}
		err = schemas[c.Kind].Validate(doc)
		_, accepted := schemaAcceptedJWSHeaders[c.ID]
		seen[c.ID] = accepted
		switch {
		case (c.Expected == "valid" || accepted) && err != nil:
			t.Errorf("%s: header violates %s: %v", c.ID, defs[c.Kind], err)
		case c.Expected == "malformed" && !accepted && err == nil:
			t.Errorf("%s (%s): header is valid against %s", c.ID, c.Why, defs[c.Kind])
		}
	}
	for id := range schemaAcceptedJWSHeaders {
		if !seen[id] {
			t.Errorf("%s in schemaAcceptedJWSHeaders is not a malformed case", id)
		}
	}
}

// jwsDefectsAfterSignature are the malformed cases that are signed correctly: r06 and k04
// fail after the signature (the url, RELAY-v0 sections 5.1 step 4 and 5.5), r44 and k11
// before it (a payload that is not an object, section 5.1 step 1 and the inner header
// check of section 5.5). Every other malformed case has a signature that does not verify.
var jwsDefectsAfterSignature = []string{"r06", "r44", "k04", "k11"}

// TestJWSCaseSignatures checks the signatures of the cases with the standard library alone:
// valid cases and those of jwsDefectsAfterSignature verify, bad-signature cases do not.
func TestJWSCaseSignatures(t *testing.T) {
	mustVerify := map[string]bool{}
	for _, id := range jwsDefectsAfterSignature {
		mustVerify[id] = true
	}
	for _, c := range loadJWSCases(t) {
		switch {
		case c.Expected == "valid" || mustVerify[c.ID]:
			if !rawVerifies(t, c) {
				t.Errorf("%s (%s): signature does not verify", c.ID, c.Why)
			}
			delete(mustVerify, c.ID)
		case c.Expected == "bad-signature":
			if rawVerifies(t, c) {
				t.Errorf("%s (%s): signature verifies", c.ID, c.Why)
			}
		}
	}
	for id := range mustVerify {
		t.Errorf("%s in jwsDefectsAfterSignature is not a case", id)
	}
}

// rawVerifies verifies the signature of a case over its first two segments as they are,
// with the key of the case or the jwk of its header, without the spelling rules.
func rawVerifies(t *testing.T, c jwsCase) bool {
	t.Helper()
	parts := strings.Split(c.JWS, ".")
	if len(parts) != 3 {
		t.Fatalf("%s: %d segments", c.ID, len(parts))
	}
	keyData := []byte(c.Key)
	if string(c.Key) == "null" {
		head, err := base64.RawURLEncoding.DecodeString(parts[0])
		var h struct {
			JWK json.RawMessage `json:"jwk"`
		}
		if err != nil || json.Unmarshal(head, &h) != nil {
			t.Fatalf("%s: header", c.ID)
		}
		keyData = h.JWK
	}
	key, err := jws.ParseJWK(keyData)
	if err != nil {
		t.Fatalf("%s: key: %v", c.ID, err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sig) != 64 {
		return false
	}
	input := []byte(parts[0] + "." + parts[1])
	switch k := key.(type) {
	case ed25519.PublicKey:
		return ed25519.Verify(k, input, sig)
	case *ecdsa.PublicKey:
		digest := sha256.Sum256(input)
		return ecdsa.Verify(k, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:]))
	}
	t.Fatalf("%s: key %T", c.ID, key)
	return false
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

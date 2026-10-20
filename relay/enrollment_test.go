// SPDX-License-Identifier: Apache-2.0

package relay_test

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

const (
	enrollmentSchemaPath = "schema/enrollment-v0.schema.json"
	enrollmentSchemaID   = "https://home-mandate.org/relay-enrollment/v0/enrollment.schema.json"
)

// enrollmentExamples maps every example of RELAY-v0 Section 5 to the definition it must match.
var enrollmentExamples = map[string]string{
	"examples/directory.json":                  "directory",
	"examples/protected-header-pair.json":      "protected_header",
	"examples/protected-header-kid.json":       "protected_header",
	"examples/pair-request.json":               "pair_request",
	"examples/pair-response.json":              "pair_response",
	"examples/installation.json":               "installation",
	"examples/installation-update-acme.json":   "installation_update",
	"examples/installation-update-unpair.json": "installation_update",
	"examples/certificate-request.json":        "certificate_request",
	"examples/certificate-response.json":       "certificate_response",
	"examples/acme-challenge-request.json":     "acme_challenge_request",
	"examples/key-change.json":                 "key_change",
	"examples/key-change-request.json":         "key_change_request",
	"examples/key-change-header.json":          "key_change_header",
	"examples/problem.json":                    "problem",
}

func loadJSON(t *testing.T, path string) any {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	doc, err := jsonschema.UnmarshalJSON(f)
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return doc
}

// compileEnrollmentDef compiles one definition of the enrollment schema; the schema refers
// to the metadata schema for domains and URLs.
func compileEnrollmentDef(t *testing.T, def string) *jsonschema.Schema {
	t.Helper()
	c := jsonschema.NewCompiler()
	for id, path := range map[string]string{metadataSchemaID: metadataSchemaPath, enrollmentSchemaID: enrollmentSchemaPath} {
		if err := c.AddResource(id, loadJSON(t, path)); err != nil {
			t.Fatal(err)
		}
	}
	s, err := c.Compile(enrollmentSchemaID + "#/$defs/" + def)
	if err != nil {
		t.Fatalf("%s: %v", def, err)
	}
	return s
}

// loadObject returns a fresh, mutable copy of an example.
func loadObject(t *testing.T, path string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return doc
}

func TestEnrollmentSchemaDeclaresItsID(t *testing.T) {
	var doc struct {
		ID string `json:"$id"`
	}
	data, err := os.ReadFile(enrollmentSchemaPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.ID != enrollmentSchemaID {
		t.Errorf("$id = %q, want %q", doc.ID, enrollmentSchemaID)
	}
}

func TestEnrollmentExamplesAreValid(t *testing.T) {
	for path, def := range enrollmentExamples {
		if err := compileEnrollmentDef(t, def).Validate(loadJSON(t, path)); err != nil {
			t.Errorf("%s as %s: %v", path, def, err)
		}
	}
}

func TestEveryEnrollmentExampleIsListed(t *testing.T) {
	entries, err := os.ReadDir("examples")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		path := "examples/" + e.Name()
		if _, ok := enrollmentExamples[path]; !ok && path != metadataExamplePath {
			t.Errorf("%s is not tested", path)
		}
	}
}

func TestResponsesTolerateUnknownMembers(t *testing.T) {
	for _, tt := range []struct{ path, def string }{
		{"examples/directory.json", "directory"},
		{"examples/pair-response.json", "pair_response"},
		{"examples/installation.json", "installation"},
		{"examples/certificate-response.json", "certificate_response"},
		{"examples/problem.json", "problem"},
	} {
		doc := loadObject(t, tt.path)
		doc["later_member"] = "x"
		if err := compileEnrollmentDef(t, tt.def).Validate(doc); err != nil {
			t.Errorf("%s: unknown member refused: %v", tt.def, err)
		}
	}
}

func TestPairingStrings(t *testing.T) {
	s := compileEnrollmentDef(t, "pairing_string")
	for _, ok := range []string{
		"relay-operator.example/ABCD-EFGH-IJKL-MNOP",
		"relay-operator.example/abcd-efgh-ijkl-mnop",
		"relay-operator.example/ABCDEFGHIJKLMNOP",
		"relay-operator.example/ABCD2345-IJKL-MNOP",
	} {
		if err := s.Validate(ok); err != nil {
			t.Errorf("%q refused: %v", ok, err)
		}
	}
	for _, bad := range []string{
		"ABCD-EFGH-IJKL-MNOP",
		"relay-operator.example/ABCD-EFGH-IJKL-MNO",
		"relay-operator.example/ABCD-EFGH-IJKL-MNOP1",
		"relay-operator.example/ABCD-EFGH-IJKL-MN0P",
		"relay-operator.example/ABCD--EFGH-IJKL-MNOP",
		"https://relay-operator.example/ABCD-EFGH-IJKL-MNOP",
		"Relay-Operator.example/ABCD-EFGH-IJKL-MNOP",
		"relay-operator.example/ABCD EFGH IJKL MNOP",
		"localhost/ABCD-EFGH-IJKL-MNOP",
	} {
		if err := s.Validate(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestInvalidEnrollmentMessagesAreRejected(t *testing.T) {
	const (
		key43   = "D2b8F_GX1LDUCLAX71MunV_C2JgmQFt4ySMODw89vnQ"
		pairHdr = "examples/protected-header-pair.json"
		kidHdr  = "examples/protected-header-kid.json"
	)
	type obj = map[string]any
	for name, tt := range map[string]struct {
		path, def string
		mutate    func(obj)
	}{
		"header with jwk and kid":             {pairHdr, "protected_header", func(d obj) { d["kid"] = "https://relay-operator.example/enroll/installation/1" }},
		"header without jwk or kid":           {kidHdr, "protected_header", func(d obj) { delete(d, "kid") }},
		"header with crit":                    {kidHdr, "protected_header", func(d obj) { d["crit"] = []any{"b64"} }},
		"header with typ":                     {kidHdr, "protected_header", func(d obj) { d["typ"] = "JWT" }},
		"header alg none":                     {kidHdr, "protected_header", func(d obj) { d["alg"] = "none" }},
		"header alg RS256":                    {kidHdr, "protected_header", func(d obj) { d["alg"] = "RS256" }},
		"header alg HS256":                    {kidHdr, "protected_header", func(d obj) { d["alg"] = "HS256" }},
		"header without nonce":                {kidHdr, "protected_header", func(d obj) { delete(d, "nonce") }},
		"header short nonce":                  {kidHdr, "protected_header", func(d obj) { d["nonce"] = "abc" }},
		"header nonce with padding":           {kidHdr, "protected_header", func(d obj) { d["nonce"] = "AAAAAAAAAAAAAAAAAAAAAA==" }},
		"header without url":                  {kidHdr, "protected_header", func(d obj) { delete(d, "url") }},
		"header url over http":                {kidHdr, "protected_header", func(d obj) { d["url"] = "http://relay-operator.example/enroll/cert" }},
		"header kid over http":                {kidHdr, "protected_header", func(d obj) { d["kid"] = "http://relay-operator.example/i/1" }},
		"jwk with private part":               {pairHdr, "protected_header", func(d obj) { d["jwk"].(obj)["d"] = key43 }},
		"jwk with kid":                        {pairHdr, "protected_header", func(d obj) { d["jwk"].(obj)["kid"] = "k1" }},
		"jwk X25519":                          {pairHdr, "protected_header", func(d obj) { d["jwk"].(obj)["crv"] = "X25519" }},
		"jwk short x":                         {pairHdr, "protected_header", func(d obj) { d["jwk"].(obj)["x"] = "abc" }},
		"jwk EC P-384":                        {pairHdr, "protected_header", func(d obj) { d["jwk"] = obj{"kty": "EC", "crv": "P-384", "x": key43, "y": key43} }},
		"jwk EC without y":                    {pairHdr, "protected_header", func(d obj) { d["jwk"] = obj{"kty": "EC", "crv": "P-256", "x": key43} }},
		"alg ES256 with Ed25519 key":          {pairHdr, "protected_header", func(d obj) { d["alg"] = "ES256" }},
		"jwk RSA":                             {pairHdr, "protected_header", func(d obj) { d["jwk"] = obj{"kty": "RSA", "n": key43, "e": "AQAB"} }},
		"pair code lower case":                {"examples/pair-request.json", "pair_request", func(d obj) { d["code"] = "abcdefghijklmnop" }},
		"pair code with hyphens":              {"examples/pair-request.json", "pair_request", func(d obj) { d["code"] = "ABCD-EFGH-IJKL-MNOP" }},
		"pair code too short":                 {"examples/pair-request.json", "pair_request", func(d obj) { d["code"] = "ABCDEFGHIJKLMNO" }},
		"pair code with 0":                    {"examples/pair-request.json", "pair_request", func(d obj) { d["code"] = "ABCDEFGHIJKLMN0P" }},
		"pair without csr":                    {"examples/pair-request.json", "pair_request", func(d obj) { delete(d, "csr") }},
		"pair unknown member":                 {"examples/pair-request.json", "pair_request", func(d obj) { d["name"] = "home" }},
		"csr with padding":                    {"examples/certificate-request.json", "certificate_request", func(d obj) { d["csr"] = d["csr"].(string) + "=" }},
		"csr in standard base64":              {"examples/certificate-request.json", "certificate_request", func(d obj) { d["csr"] = "MH8w+/" + d["csr"].(string) }},
		"csr too short":                       {"examples/certificate-request.json", "certificate_request", func(d obj) { d["csr"] = "MH8w" }},
		"certificate unknown member":          {"examples/certificate-request.json", "certificate_request", func(d obj) { d["san"] = "x" }},
		"pair response without installation":  {"examples/pair-response.json", "pair_response", func(d obj) { delete(d, "installation") }},
		"installation status removed":         {"examples/installation.json", "installation", func(d obj) { d["status"] = "removed" }},
		"installation caa identity with port": {"examples/installation.json", "installation", func(d obj) { d["caa_identity"] = "acme.example:443" }},
		"installation upper-case home id":     {"examples/installation.json", "installation", func(d obj) { d["home_id"] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ" }},
		"installation short home id":          {"examples/installation.json", "installation", func(d obj) { d["home_id"] = "abcdefghijklmnopqrstuvwxy" }},
		"installation home id with 1":         {"examples/installation.json", "installation", func(d obj) { d["home_id"] = "abcdefghijklmnopqrstuvwxy1" }},
		"installation max offline 6":          {"examples/installation.json", "installation", func(d obj) { d["max_offline_days"] = 6.0 }},
		"installation max offline 91":         {"examples/installation.json", "installation", func(d obj) { d["max_offline_days"] = 91.0 }},
		"installation http url":               {"examples/installation.json", "installation", func(d obj) { d["certificate"] = "http://relay-operator.example/c" }},
		"installation without public name":    {"examples/installation.json", "installation", func(d obj) { delete(d, "public_name") }},
		"chain empty":                         {"examples/certificate-response.json", "certificate_response", func(d obj) { d["chain"] = []any{} }},
		"chain of five":                       {"examples/certificate-response.json", "certificate_response", func(d obj) { c := d["chain"].([]any)[0]; d["chain"] = []any{c, c, c, c, c} }},
		"not_after with offset":               {"examples/certificate-response.json", "certificate_response", func(d obj) { d["not_after"] = "2026-10-21T08:03:32+00:00" }},
		"not_after with fraction":             {"examples/certificate-response.json", "certificate_response", func(d obj) { d["not_after"] = "2026-10-21T08:03:32.5Z" }},
		"update with both members":            {"examples/installation-update-acme.json", "installation_update", func(d obj) { d["status"] = "unpaired" }},
		"update to paused":                    {"examples/installation-update-unpair.json", "installation_update", func(d obj) { d["status"] = "paused" }},
		"update empty":                        {"examples/installation-update-unpair.json", "installation_update", func(d obj) { delete(d, "status") }},
		"update acme without caa identity":    {"examples/installation-update-acme.json", "installation_update", func(d obj) { delete(d, "caa_identity") }},
		"update caa identity upper case":      {"examples/installation-update-acme.json", "installation_update", func(d obj) { d["caa_identity"] = "ACME.example" }},
		"update acme account over http":       {"examples/installation-update-acme.json", "installation_update", func(d obj) { d["acme_account"] = "http://acme.example/acct/1" }},
		"challenge three values": {"examples/acme-challenge-request.json", "acme_challenge_request", func(d obj) {
			d["values"] = []any{key43, "Ljw1T6tIW5zlLN6aE5H2nZXgRQ8u1QYxv6CqUvd_hRo", "LoqXcYV8q5ONbJQxbmR7SCTNo3tiAXDfowyjxAjEuX0"}
		}},
		"challenge duplicate values":      {"examples/acme-challenge-request.json", "acme_challenge_request", func(d obj) { d["values"] = []any{key43, key43} }},
		"challenge value of 42":           {"examples/acme-challenge-request.json", "acme_challenge_request", func(d obj) { d["values"] = []any{key43[:42]} }},
		"challenge without values":        {"examples/acme-challenge-request.json", "acme_challenge_request", func(d obj) { delete(d, "values") }},
		"challenge with name":             {"examples/acme-challenge-request.json", "acme_challenge_request", func(d obj) { d["name"] = "_acme-challenge.other.example" }},
		"key change request two segments": {"examples/key-change-request.json", "key_change_request", func(d obj) { d["jws"] = "eyJhbGciOiJFZERTQSJ9.e30" }},
		"key change request with padding": {"examples/key-change-request.json", "key_change_request", func(d obj) { d["jws"] = d["jws"].(string) + "=" }},
		"key change request extra member": {"examples/key-change-request.json", "key_change_request", func(d obj) { d["kid"] = "x" }},
		"key change header with nonce":    {"examples/key-change-header.json", "key_change_header", func(d obj) { d["nonce"] = "oFvnlFP1wIhRlYS2jTaXbA" }},
		"key change header with kid":      {"examples/key-change-header.json", "key_change_header", func(d obj) { d["kid"] = "https://relay-operator.example/i/1" }},
		"key change header without jwk":   {"examples/key-change-header.json", "key_change_header", func(d obj) { delete(d, "jwk") }},
		"key change header alg mismatch":  {"examples/key-change-header.json", "key_change_header", func(d obj) { d["alg"] = "ES256" }},
		"key change header private key":   {"examples/key-change-header.json", "key_change_header", func(d obj) { d["jwk"].(obj)["d"] = key43 }},
		"key change without old key":      {"examples/key-change.json", "key_change", func(d obj) { delete(d, "old_key") }},
		"key change private old key":      {"examples/key-change.json", "key_change", func(d obj) { d["old_key"].(obj)["d"] = key43 }},
		"key change http installation":    {"examples/key-change.json", "key_change", func(d obj) { d["installation"] = "http://relay-operator.example/i/1" }},
		"problem foreign type":            {"examples/problem.json", "problem", func(d obj) { d["type"] = "urn:ietf:params:acme:error:badNonce" }},
		"problem unknown error":           {"examples/problem.json", "problem", func(d obj) { d["type"] = "https://home-mandate.org/relay/errors/teapot" }},
		"problem without type":            {"examples/problem.json", "problem", func(d obj) { delete(d, "type") }},
		"directory without pair":          {"examples/directory.json", "directory", func(d obj) { delete(d, "pair") }},
		"directory http nonce url":        {"examples/directory.json", "directory", func(d obj) { d["new_nonce"] = "http://relay-operator.example/n" }},
	} {
		doc := loadObject(t, tt.path)
		tt.mutate(doc)
		if err := compileEnrollmentDef(t, tt.def).Validate(doc); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestEnrollmentSchemaDefinesEveryErrorOfTheTable(t *testing.T) {
	spec, err := os.ReadFile("../RELAY-v0.md")
	if err != nil {
		t.Fatal(err)
	}
	s := compileEnrollmentDef(t, "problem")
	var named int
	for _, line := range strings.Split(string(spec), "\n") {
		if !strings.HasPrefix(line, "| `") || !strings.Contains(line, "| 4") && !strings.Contains(line, "| 5") {
			continue
		}
		name := strings.TrimSuffix(strings.TrimPrefix(strings.Fields(line)[1], "`"), "`")
		named++
		problem := map[string]any{"type": "https://home-mandate.org/relay/errors/" + name}
		if err := s.Validate(problem); err != nil {
			t.Errorf("error %q of the table is not in the schema: %v", name, err)
		}
	}
	if named != 12 {
		t.Errorf("found %d errors in the table of Section 5.1, want 12", named)
	}
}

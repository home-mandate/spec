// SPDX-License-Identifier: Apache-2.0

package harness_test

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"strings"
	"testing"

	mandatespec "github.com/mandate-spec/mandate-spec"
	"github.com/mandate-spec/mandate-spec/internal/harness"
)

func ask(t *testing.T, requests ...harness.Request) []harness.Response {
	t.Helper()
	var in bytes.Buffer
	for _, r := range requests {
		line, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		in.Write(append(line, '\n'))
	}
	var out bytes.Buffer
	if err := harness.Serve(&in, &out); err != nil {
		t.Fatal(err)
	}
	var responses []harness.Response
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		var r harness.Response
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("response %q: %v", line, err)
		}
		responses = append(responses, r)
	}
	if len(responses) != len(requests) {
		t.Fatalf("%d responses for %d requests", len(responses), len(requests))
	}
	return responses
}

func example(t *testing.T) *string {
	t.Helper()
	data, err := fs.ReadFile(mandatespec.FS(), "examples/voice-assistant.json")
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	return &s
}

func TestCapabilitiesListEveryOperation(t *testing.T) {
	r := ask(t, harness.Request{Op: harness.OpCapabilities})[0]
	if r.Name == "" || len(r.Ops) != 7 {
		t.Errorf("capabilities = %+v", r)
	}
}

func TestValidateAndEvaluate(t *testing.T) {
	bad := `{"type":"x"}`
	rs := ask(t,
		harness.Request{Op: harness.OpValidate, Mandate: example(t)},
		harness.Request{Op: harness.OpValidate, Mandate: &bad},
		harness.Request{Op: harness.OpEvaluate, Mandate: example(t), Request: &harness.Evaluation{
			Resource: harness.Resource{EntityID: "lock.haustuer", Category: "lock", Area: "flur"},
			Action:   "unlock", Time: "2026-10-12T19:00:00+02:00"}},
		harness.Request{Op: harness.OpEvaluate, Mandate: &bad, Request: &harness.Evaluation{
			Resource: harness.Resource{EntityID: "a", Category: "light"}, Action: "read", Time: "2026-10-12T19:00:00+02:00"}},
		harness.Request{Op: harness.OpEvaluate, Mandate: example(t), Request: &harness.Evaluation{
			Resource: harness.Resource{EntityID: "a", Category: "light"}, Action: "read", Time: "yesterday"}},
		harness.Request{Op: harness.OpEvaluate, Mandate: example(t), Request: &harness.Evaluation{
			Resource: harness.Resource{EntityID: "a", Category: "light"}, Action: "set", Time: "2026-10-12T19:00:00+02:00",
			Parameters: map[string]json.Number{"brightness": "1.5"}}},
	)
	if rs[0].Valid == nil || !*rs[0].Valid || !strings.HasPrefix(rs[0].Digest, "sha256:") {
		t.Errorf("validate = %+v", rs[0])
	}
	if rs[1].Valid == nil || *rs[1].Valid || rs[1].Digest != "" {
		t.Errorf("validate of an invalid mandate = %+v", rs[1])
	}
	if rs[2].Decision != "ask" || rs[2].Reason != "rule" || rs[2].RuleID == nil || *rs[2].RuleID != "r-locks" ||
		rs[2].ApprovalTimeout != "PT2M" || len(rs[2].Approvers) == 0 || rs[2].MandateDigest != rs[0].Digest {
		t.Errorf("evaluate = %+v", rs[2])
	}
	if rs[3].Decision != "deny" || rs[3].Reason != "invalid_mandate" || rs[3].RuleID != nil {
		t.Errorf("evaluate with an invalid mandate = %+v", rs[3])
	}
	for _, r := range rs[4:] {
		if r.Decision != "deny" || r.Reason != "invalid_request" {
			t.Errorf("evaluate with an invalid request = %+v", r)
		}
	}
}

func TestMalformedAndUnsupportedRequests(t *testing.T) {
	var out bytes.Buffer
	if err := harness.Serve(strings.NewReader("nope\n\n"+`{"op":"dance"}`+"\n"+`{"op":"evaluate"}`+"\n"), &out); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 3 || !strings.Contains(lines[0], `"error"`) || !strings.Contains(lines[1], harness.ErrorUnsupported) ||
		!strings.Contains(lines[2], `"error"`) {
		t.Errorf("responses = %q", lines)
	}
}

func TestRequestsWithMissingOrBrokenMembers(t *testing.T) {
	text := func(s string) *string { return &s }
	eval := &harness.Evaluation{Resource: harness.Resource{EntityID: "a", Category: "light"}, Action: "read", Time: "2026-10-12T19:00:00+02:00"}
	for name, req := range map[string]harness.Request{
		"validate without mandate":   {Op: harness.OpValidate},
		"evaluate without request":   {Op: harness.OpEvaluate, Mandate: example(t)},
		"select without subject":     {Op: harness.OpSelect, Request: eval},
		"succession without offered": {Op: harness.OpSuccession, Stored: example(t)},
		"succession, stored invalid": {Op: harness.OpSuccession, Stored: text("{}"), Offered: example(t)},
		"verify_signed without keys": {Op: harness.OpVerifySigned, JWS: "a.b.c"},
		"verify_audit, broken keys":  {Op: harness.OpVerifyAudit, Keys: []byte(`{"keys":[]}`)},
		"entry_digest without entry": {Op: harness.OpEntryDigest},
	} {
		if r := harness.Answer(req); r.Error == "" || r.Error == harness.ErrorUnsupported {
			t.Errorf("%s: response %+v, want an error", name, r)
		}
	}
	// A request the PEP cannot express, with an invalid mandate: the mandate comes first.
	bad := "{}"
	r := harness.Answer(harness.Request{Op: harness.OpEvaluate, Mandate: &bad, Request: &harness.Evaluation{Time: "never"}})
	if r.Decision != "deny" || r.Reason != "invalid_mandate" {
		t.Errorf("invalid mandate and invalid request = %+v", r)
	}
	r = harness.Answer(harness.Request{Op: harness.OpSelect, Subject: &harness.Subject{}, Request: &harness.Evaluation{Time: "never"}})
	if r.Decision != "deny" || r.Reason != "invalid_request" {
		t.Errorf("select with an invalid request = %+v", r)
	}
	// Offered mandate invalid: not accepted.
	r = harness.Answer(harness.Request{Op: harness.OpSuccession, Stored: example(t), Offered: &bad})
	if r.Accept == nil || *r.Accept {
		t.Errorf("succession with an invalid offer = %+v", r)
	}
	// Audit log in the exchange format, with and without keys.
	keys := []byte(`{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"k","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}]}`)
	empty := ""
	for _, req := range []harness.Request{
		{Op: harness.OpVerifyAudit, JSONL: &empty},
		{Op: harness.OpVerifyAudit, JSONL: &empty, Keys: keys},
	} {
		if r := harness.Answer(req); r.Valid == nil || !*r.Valid || r.Entries == nil || *r.Entries != 0 {
			t.Errorf("empty log = %+v", r)
		}
	}
	entry := "{"
	if r := harness.Answer(harness.Request{Op: harness.OpEntryDigest, Entry: &entry}); r.Valid == nil || *r.Valid {
		t.Errorf("digest of a broken entry = %+v", r)
	}
}

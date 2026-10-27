// SPDX-License-Identifier: Apache-2.0

package evaluator_test

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"testing"
	"time"

	"github.com/home-mandate/spec"
	"github.com/home-mandate/spec/evaluator"
)

// mandateSource is the common shape conformance files use to refer to a mandate.
type mandateSource struct {
	Mandate       string          `json:"mandate"`
	MandateInline json.RawMessage `json:"mandate_inline"`
	MandateRaw    *string         `json:"mandate_raw"`
}

func (s mandateSource) bytes(t *testing.T) []byte {
	t.Helper()
	switch {
	case s.Mandate != "":
		data, err := fs.ReadFile(spec.FS(), s.Mandate)
		if err != nil {
			t.Fatalf("read mandate %s: %v", s.Mandate, err)
		}
		return data
	case s.MandateInline != nil:
		return s.MandateInline
	case s.MandateRaw != nil:
		return []byte(*s.MandateRaw)
	}
	t.Fatal("case has no mandate")
	return nil
}

type conformanceCase struct {
	ID string `json:"id"`
	mandateSource
	Resource struct {
		EntityID string   `json:"entity_id"`
		Category string   `json:"category"`
		Areas    []string `json:"areas"`
		Critical bool     `json:"critical"`
	} `json:"resource"`
	Action          string                     `json:"action"`
	Parameters      map[string]json.RawMessage `json:"parameters"`
	Time            string                     `json:"time"`
	Timezone        string                     `json:"timezone"`
	Revoked         bool                       `json:"revoked"`
	Expected        string                     `json:"expected"`
	Reason          string                     `json:"reason"`
	RuleID          json.RawMessage            `json:"rule_id"`
	ApprovalTimeout string                     `json:"approval_timeout"`
	Enforced        *bool                      `json:"enforced"`
	Confirm         bool                       `json:"confirm"`
	Why             string                     `json:"why"`
}

func loadCases[T any](t *testing.T, path, key string) []T {
	t.Helper()
	data, err := fs.ReadFile(spec.FS(), path)
	if err != nil {
		t.Fatal(err)
	}
	var file map[string]json.RawMessage
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(file[key]))
	dec.DisallowUnknownFields()
	var cases []T
	if err := dec.Decode(&cases); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	if len(cases) == 0 {
		t.Fatalf("%s: no cases", path)
	}
	return cases
}

func TestConformanceCases(t *testing.T) {
	for _, c := range loadCases[conformanceCase](t, spec.CasesPath, "cases") {
		t.Run(c.ID, func(t *testing.T) {
			m, err := evaluator.Parse(c.bytes(t))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			at, err := time.Parse(time.RFC3339, c.Time)
			if err != nil {
				t.Fatalf("case time: %v", err)
			}
			parameters, expressible := parameterValues(c.Parameters)
			if !expressible {
				// A PEP cannot pass such a request on; the result is fixed (SPEC-v0 section 4.5).
				if c.Expected != "deny" || c.Reason != "invalid_request" {
					t.Fatalf("case with a parameter that is neither an integer nor a string expects (%s, %s)", c.Expected, c.Reason)
				}
				return
			}
			got := evaluator.Evaluate(m, evaluator.Request{
				Resource:   evaluator.Resource{EntityID: c.Resource.EntityID, Category: c.Resource.Category, Areas: c.Resource.Areas, Critical: c.Resource.Critical},
				Action:     c.Action,
				Parameters: parameters,
				Time:       at,
				TimeZone:   c.Timezone,
				Status:     statusOf(c.Revoked),
			})
			assertResult(t, c, m, got)
		})
	}
}

// statusOf maps the revoked field of the conformance cases to the status (SPEC-v0 section 8).
func statusOf(revoked bool) evaluator.MandateStatus {
	if revoked {
		return evaluator.StatusRevoked
	}
	return evaluator.StatusActive
}

func assertResult(t *testing.T, c conformanceCase, m *evaluator.Mandate, got evaluator.Result) {
	t.Helper()
	if string(got.Decision) != c.Expected {
		t.Errorf("decision = %q, want %q (%s)", got.Decision, c.Expected, c.Why)
	}
	if string(got.Reason) != c.Reason {
		t.Errorf("reason = %q, want %q (%s)", got.Reason, c.Reason, c.Why)
	}
	if c.RuleID != nil {
		var want *string
		if err := json.Unmarshal(c.RuleID, &want); err != nil {
			t.Fatalf("rule_id: %v", err)
		}
		wantID := ""
		if want != nil {
			wantID = *want
		}
		if got.RuleID != wantID {
			t.Errorf("rule_id = %q, want %q", got.RuleID, wantID)
		}
	}
	if got.Decision == evaluator.Ask || got.Confirm {
		if got.Approval == nil {
			t.Fatalf("%s without approval settings", got.Decision)
		}
		if c.ApprovalTimeout != "" && got.Approval.Timeout != c.ApprovalTimeout {
			t.Errorf("approval timeout = %q, want %q", got.Approval.Timeout, c.ApprovalTimeout)
		}
	} else if got.Approval != nil {
		t.Errorf("approval settings on %q", got.Decision)
	}
	if got.MandateDigest != m.Digest() {
		t.Errorf("mandate digest = %q, want %q", got.MandateDigest, m.Digest())
	}
	// A case without enforced expects an enforced result (SPEC-v0 sections 4.6 and 8).
	if wantNotEnforced := c.Enforced != nil && !*c.Enforced; got.NotEnforced != wantNotEnforced {
		t.Errorf("not enforced = %t, want %t (%s)", got.NotEnforced, wantNotEnforced, c.Why)
	}
	if got.Confirm != c.Confirm {
		t.Errorf("confirm = %t, want %t (%s)", got.Confirm, c.Confirm, c.Why)
	}
}

type invalidCase struct {
	ID string `json:"id"`
	mandateSource
	Why string `json:"why"`
}

func TestConformanceInvalidMandates(t *testing.T) {
	for _, c := range loadCases[invalidCase](t, spec.InvalidCasesPath, "cases") {
		t.Run(c.ID, func(t *testing.T) {
			m, err := evaluator.Parse(c.bytes(t))
			if err == nil {
				t.Fatalf("Parse accepted invalid mandate (%s)", c.Why)
			}
			if m != nil {
				t.Errorf("Parse returned a mandate together with error %v", err)
			}
		})
	}
}

type digestCase struct {
	ID string `json:"id"`
	mandateSource
	Digest string `json:"digest"`
	Why    string `json:"why"`
}

func TestConformanceDigests(t *testing.T) {
	for _, c := range loadCases[digestCase](t, spec.DigestCasesPath, "cases") {
		t.Run(c.ID, func(t *testing.T) {
			m, err := evaluator.Parse(c.bytes(t))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if m.Digest() != c.Digest {
				t.Errorf("digest = %s, want %s (%s)", m.Digest(), c.Digest, c.Why)
			}
		})
	}
}

// parameterValues converts the parameters of a case; ok is false if one is neither an
// integer nor a string.
func parameterValues(raw map[string]json.RawMessage) (map[string]evaluator.Value, bool) {
	out := make(map[string]evaluator.Value, len(raw))
	for name, data := range raw {
		var v evaluator.Value
		if err := json.Unmarshal(data, &v); err != nil {
			return nil, false
		}
		out[name] = v
	}
	return out, true
}

// SPDX-License-Identifier: Apache-2.0

package evaluator_test

import (
	"encoding/json"
	"testing"
	"time"

	mandatespec "github.com/mandate-spec/mandate-spec"
	"github.com/mandate-spec/mandate-spec/evaluator"
)

type selectionCase struct {
	ID       string `json:"id"`
	Mandates []struct {
		MandateInline json.RawMessage `json:"mandate_inline"`
		Revoked       bool            `json:"revoked"`
	} `json:"mandates"`
	Subject struct {
		ClientID  string `json:"client_id"`
		Principal string `json:"principal"`
	} `json:"subject"`
	Resource struct {
		EntityID string `json:"entity_id"`
		Category string `json:"category"`
		Area     string `json:"area"`
		Critical bool   `json:"critical"`
	} `json:"resource"`
	Action   string          `json:"action"`
	Time     string          `json:"time"`
	Timezone string          `json:"timezone"`
	Expected string          `json:"expected"`
	Reason   string          `json:"reason"`
	RuleID   json.RawMessage `json:"rule_id"`
	Selected *string         `json:"selected"`
	Why      string          `json:"why"`
}

func TestConformanceSelection(t *testing.T) {
	for _, c := range loadCases[selectionCase](t, mandatespec.SelectionCasesPath, "cases") {
		t.Run(c.ID, func(t *testing.T) {
			at, err := time.Parse(time.RFC3339, c.Time)
			if err != nil {
				t.Fatalf("case time: %v", err)
			}
			stored := make([]evaluator.Stored, len(c.Mandates))
			for i, s := range c.Mandates {
				stored[i] = evaluator.NewStored(s.MandateInline, statusOf(s.Revoked))
			}
			selected, got := evaluator.SelectAndEvaluate(stored, c.Subject.ClientID, c.Subject.Principal, evaluator.Request{
				Resource: evaluator.Resource{EntityID: c.Resource.EntityID, Category: c.Resource.Category, Area: c.Resource.Area, Critical: c.Resource.Critical},
				Action:   c.Action, Time: at, TimeZone: c.Timezone,
			})
			if string(got.Decision) != c.Expected || string(got.Reason) != c.Reason {
				t.Errorf("got (%s, %s), want (%s, %s): %s", got.Decision, got.Reason, c.Expected, c.Reason, c.Why)
			}
			wantSelected := ""
			if c.Selected != nil {
				wantSelected = *c.Selected
			}
			if selected.ID() != wantSelected {
				t.Errorf("selected %q, want %q", selected.ID(), wantSelected)
			}
			if got.MandateDigest != selected.Digest() {
				t.Errorf("mandate digest %q, want %q", got.MandateDigest, selected.Digest())
			}
			if c.RuleID != nil {
				var want string
				_ = json.Unmarshal(c.RuleID, &want)
				if got.RuleID != want {
					t.Errorf("rule_id = %q, want %q", got.RuleID, want)
				}
			}
		})
	}
}

func TestMandateExposesAgentAndPrincipal(t *testing.T) {
	m, err := evaluator.Parse(mandateNamed("Test"))
	if err != nil {
		t.Fatal(err)
	}
	if m.ClientID() != "hm-client:test-0001" || m.Principal() != "household:t" {
		t.Errorf("ClientID() = %q, Principal() = %q", m.ClientID(), m.Principal())
	}
	var none *evaluator.Mandate
	if none.ClientID() != "" || none.Principal() != "" {
		t.Error("accessors of a nil mandate are not empty")
	}
}

func TestSelectIgnoresTheStatusInTheRequest(t *testing.T) {
	// The status comes from the stored mandate, never from the caller's request.
	stored := []evaluator.Stored{evaluator.NewStored(mandateNamed("Test"), evaluator.StatusActive)}
	req := request("light", "flur", "turn_on")
	req.Status = evaluator.StatusRevoked
	_, got := evaluator.SelectAndEvaluate(stored, "hm-client:test-0001", "household:t", req)
	assertDecision(t, got, evaluator.Allow, evaluator.ReasonRule, "r-1")
}

func TestSelectTreatsAnUnknownStatusAsACandidateThatDenies(t *testing.T) {
	stored := []evaluator.Stored{evaluator.NewStored(mandateNamed("Test"), evaluator.MandateStatus("paused"))}
	_, got := evaluator.SelectAndEvaluate(stored, "hm-client:test-0001", "household:t", request("light", "flur", "turn_on"))
	assertDecision(t, got, evaluator.Deny, evaluator.ReasonInvalidRequest, "")
}

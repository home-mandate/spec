// SPDX-License-Identifier: Apache-2.0

package evaluator

import (
	"errors"
	"testing"
	"time"
)

// Parse admits only allow, ask and deny; these tests additionally guard decide in case
// a mandate is created some other way (Go review, week 1).
func TestDecideTreatsUnknownDecisionAsDeny(t *testing.T) {
	m := &Mandate{valid: true, digest: "sha256:x", approval: Approval{Timeout: "PT2M"}}
	for _, d := range []Decision{"permit", "Deny", "", "ALLOW"} {
		matched := []*rule{
			{id: "r-allow", decision: Allow},
			{id: "r-odd", decision: d},
		}
		got := decide(m, matched, false)
		if got.Decision != Deny || got.RuleID != "r-odd" {
			t.Errorf("decision %q: got (%s, %q), want (deny, r-odd)", d, got.Decision, got.RuleID)
		}
	}
}

func TestBuildRuleRejectsUnknownDecision(t *testing.T) {
	_, err := buildRule(rawRule{ID: "r-1", Actions: []string{"read"}, Decision: "permit"})
	if !errors.Is(err, ErrSemantic) {
		t.Fatalf("err = %v, want ErrSemantic", err)
	}
}

func TestParseApprovalTimeout(t *testing.T) {
	tests := map[string]time.Duration{
		"PT10S": 10 * time.Second, "PT2M": 2 * time.Minute, "PT1M30S": 90 * time.Second, "PT60M": time.Hour,
	}
	for in, want := range tests {
		got, err := parseApprovalTimeout(in)
		if err != nil || got != want {
			t.Errorf("parseApprovalTimeout(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, in := range []string{"PT9S", "PT0M", "PT61M", "PT60M1S", "PT", "P1D", "PT1H", "PTxM", "PT-5S", "PT99999999999999999999M"} {
		if _, err := parseApprovalTimeout(in); err == nil {
			t.Errorf("parseApprovalTimeout(%q) accepted", in)
		}
	}
}

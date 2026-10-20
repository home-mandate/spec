// SPDX-License-Identifier: Apache-2.0

package evaluator_test

import (
	"strings"
	"testing"

	"github.com/home-mandate/spec/evaluator"
)

// auditMode builds a valid mandate in audit mode (SPEC-v0 section 4.6) with the given rules.
func auditMode(t *testing.T, rules string) *evaluator.Mandate {
	t.Helper()
	data := mandateReplacing(baseRules, rules)
	data = []byte(strings.Replace(string(data), `"default":"deny"`, `"enforce":false,"default":"deny"`, 1))
	m, err := evaluator.Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return m
}

func TestMandateEnforce(t *testing.T) {
	if !mandateWithRules(t, baseRules).Enforce() {
		t.Error("a mandate without enforce does not enforce")
	}
	if auditMode(t, baseRules).Enforce() {
		t.Error("a mandate with enforce false enforces")
	}
	var nilMandate *evaluator.Mandate
	if !nilMandate.Enforce() {
		t.Error("nil does not enforce")
	}
}

func TestParseRejectsEnforceOtherThanFalse(t *testing.T) {
	for _, value := range []string{"true", `"false"`, "0", "null", "[]"} {
		data := strings.Replace(string(mandateNamed("Test")), `"default":"deny"`, `"enforce":`+value+`,"default":"deny"`, 1)
		if _, err := evaluator.Parse([]byte(data)); err == nil {
			t.Errorf("enforce %s accepted", value)
		}
	}
}

func TestAuditModeEnforcesOnlyDenialsByTheRules(t *testing.T) {
	m := auditMode(t, `[{"id":"r-lights","resource":{"category":"light"},"actions":["turn_on"],"decision":"allow"},`+
		`{"id":"r-deny","resource":{"category":"media"},"actions":["*"],"decision":"deny"},`+
		`{"id":"r-ask","resource":{"category":"cover"},"actions":["open"],"decision":"ask"}]`)
	critical := request("switch", "", "turn_on")
	critical.Resource.Critical = true
	criticalRead := request("media", "", "read")
	criticalRead.Resource.Critical = true
	criticalPlay := request("media", "", "play")
	criticalPlay.Resource.Critical = true
	revoked := request("switch", "", "turn_on")
	revoked.Status = evaluator.StatusRevoked
	for name, tt := range map[string]struct {
		req         evaluator.Request
		decision    evaluator.Decision
		reason      evaluator.Reason
		notEnforced bool
	}{
		"no match":                {request("switch", "", "turn_on"), evaluator.Deny, evaluator.ReasonNoMatch, true},
		"deny rule":               {request("media", "", "play"), evaluator.Deny, evaluator.ReasonRule, true},
		"deny rule, critical":     {criticalPlay, evaluator.Deny, evaluator.ReasonRule, false},
		"read on critical":        {criticalRead, evaluator.Deny, evaluator.ReasonRule, true},
		"critical resource":       {critical, evaluator.Deny, evaluator.ReasonNoMatch, false},
		"critical action":         {request("lock", "", "unlock"), evaluator.Deny, evaluator.ReasonNoMatch, false},
		"allow":                   {request("light", "", "turn_on"), evaluator.Allow, evaluator.ReasonRule, false},
		"ask":                     {request("cover", "", "open"), evaluator.Ask, evaluator.ReasonRule, false},
		"revoked":                 {revoked, evaluator.Deny, evaluator.ReasonRevoked, false},
		"unknown action":          {request("light", "", "unlock"), evaluator.Deny, evaluator.ReasonUnknownAction, false},
		"unknown resource":        {request("", "", "turn_on"), evaluator.Deny, evaluator.ReasonUnknownResource, false},
		"invalid request (areas)": {request("switch", "hall way", "turn_on"), evaluator.Deny, evaluator.ReasonInvalidRequest, false},
	} {
		t.Run(name, func(t *testing.T) {
			got := evaluator.Evaluate(m, tt.req)
			if got.Decision != tt.decision || got.Reason != tt.reason || got.NotEnforced != tt.notEnforced {
				t.Errorf("got (%s, %s, not enforced %t), want (%s, %s, not enforced %t)",
					got.Decision, got.Reason, got.NotEnforced, tt.decision, tt.reason, tt.notEnforced)
			}
		})
	}
}

func TestEnforcingMandateEnforcesEveryDeny(t *testing.T) {
	m := mandateWithRules(t, `[{"id":"r-deny","resource":{"category":"media"},"actions":["*"],"decision":"deny"}]`)
	for _, req := range []evaluator.Request{request("media", "", "play"), request("switch", "", "turn_on")} {
		if got := evaluator.Evaluate(m, req); got.Decision != evaluator.Deny || got.NotEnforced {
			t.Errorf("%s: got (%s, not enforced %t)", req.Action, got.Decision, got.NotEnforced)
		}
	}
	if got := evaluator.Evaluate(nil, request("media", "", "play")); got.NotEnforced {
		t.Error("an invalid mandate is not enforced")
	}
}

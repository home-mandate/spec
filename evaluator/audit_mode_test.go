// SPDX-License-Identifier: Apache-2.0

package evaluator_test

import (
	"errors"
	"strings"
	"testing"
	"time"

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

// A duplicate enforce key makes the mandate invalid, also when both values agree: a
// mandate is I-JSON (SPEC-v0 section 3.1 item 1), so no reader picks one of them.
func TestParseRejectsDuplicateEnforce(t *testing.T) {
	for _, members := range []string{`"enforce":false,"enforce":false`, `"enforce":true,"enforce":false`, `"enforce":false,"enforce":true`} {
		data := strings.Replace(string(mandateNamed("Test")), `"default":"deny"`, members+`,"default":"deny"`, 1)
		if _, err := evaluator.Parse([]byte(data)); !errors.Is(err, evaluator.ErrMalformed) {
			t.Errorf("%s: err = %v, want ErrMalformed", members, err)
		}
	}
}

func TestEntersAuditMode(t *testing.T) {
	enforcing, trying := mandateWithRules(t, baseRules), auditMode(t, baseRules)
	before := noon.AddDate(-1, 0, 0) // before valid_from of every test mandate
	active, revoked := evaluator.StatusActive, evaluator.StatusRevoked
	for _, tt := range []struct {
		name    string
		stored  *evaluator.Mandate
		status  evaluator.MandateStatus
		at      time.Time
		offered *evaluator.Mandate
		want    bool
	}{
		{"switched on", enforcing, active, noon, trying, true},
		{"arrives without a predecessor", nil, active, noon, trying, true},
		{"stays in audit mode", trying, active, noon, trying, false},
		{"switched off", trying, active, noon, enforcing, false},
		{"enforces", enforcing, active, noon, enforcing, false},
		{"nothing offered", enforcing, active, noon, nil, false},
		{"predecessor in audit mode was revoked", trying, revoked, noon, trying, true},
		{"predecessor in audit mode is not yet valid", trying, active, before, trying, true},
		{"predecessor with an unknown status", trying, "", noon, trying, true},
	} {
		if got := evaluator.EntersAuditMode(tt.stored, tt.status, tt.at, tt.offered); got != tt.want {
			t.Errorf("%s: EntersAuditMode = %t, want %t", tt.name, got, tt.want)
		}
	}
}

func TestEntersAuditModeAfterTheTrialExpired(t *testing.T) {
	data := strings.Replace(string(mandateReplacing(baseRules, baseRules)), `"default":"deny"`,
		`"enforce":false,"expires":"2026-06-01T00:00:00+02:00","default":"deny"`, 1)
	expired, err := evaluator.Parse([]byte(data))
	if err != nil {
		t.Fatal(err)
	}
	if !evaluator.EntersAuditMode(expired, evaluator.StatusActive, noon, auditMode(t, baseRules)) {
		t.Error("an expired predecessor in audit mode lets a new mandate in audit mode take effect without a confirmation")
	}
	if evaluator.EntersAuditMode(expired, evaluator.StatusActive, noon.AddDate(0, -6, 0), auditMode(t, baseRules)) {
		t.Error("a predecessor in audit mode that is still in force requires a confirmation")
	}
}

// A deny that audit mode does not enforce keeps the confirmation a matching ask rule asks
// for (SPEC-v0 sections 4 step 6, 4.1 and 4.6; issue #59).
func TestAuditModeAsksWhenAnAskRuleMatchesTheDeny(t *testing.T) {
	m := auditMode(t, `[{"id":"r-ask-lights","resource":{"category":"light"},"actions":["turn_on","turn_off"],"decision":"ask"},`+
		`{"id":"r-ask-own","resource":{"category":"light"},"actions":["turn_off"],"decision":"ask","approval":{"timeout":"PT5M","approvers":["user-2"]}},`+
		`{"id":"r-no-lights","resource":{"category":"light"},"actions":["turn_on","turn_off"],"decision":"deny"},`+
		`{"id":"r-media","resource":{"category":"media"},"actions":["play"],"decision":"allow"},`+
		`{"id":"r-no-media","resource":{"category":"media"},"actions":["play"],"decision":"deny"}]`)
	criticalOn := request("light", "", "turn_on")
	criticalOn.Resource.Critical = true
	for name, tt := range map[string]struct {
		req         evaluator.Request
		rule        string
		notEnforced bool
		confirm     bool
		timeout     string
	}{
		"ask and deny":              {request("light", "", "turn_on"), "r-no-lights", true, true, "PT2M"},
		"approval of the first own": {request("light", "", "turn_off"), "r-no-lights", true, true, "PT5M"},
		"allow and deny":            {request("media", "", "play"), "r-no-media", true, false, ""},
		"ask and deny on critical":  {criticalOn, "r-no-lights", false, false, ""},
		"no match":                  {request("switch", "", "turn_on"), "", true, false, ""},
	} {
		t.Run(name, func(t *testing.T) {
			got := evaluator.Evaluate(m, tt.req)
			if got.Decision != evaluator.Deny || got.RuleID != tt.rule || got.NotEnforced != tt.notEnforced || got.Confirm != tt.confirm {
				t.Fatalf("got (%s, %q, not enforced %t, confirm %t), want (deny, %q, %t, %t)",
					got.Decision, got.RuleID, got.NotEnforced, got.Confirm, tt.rule, tt.notEnforced, tt.confirm)
			}
			if tt.timeout == "" {
				if got.Approval != nil {
					t.Errorf("approval settings %+v without a confirmation", got.Approval)
				}
				return
			}
			if got.Approval == nil || got.Approval.Timeout != tt.timeout {
				t.Errorf("approval settings %+v, want timeout %s", got.Approval, tt.timeout)
			}
		})
	}
	enforcing := mandateWithRules(t, `[{"id":"r-ask-lights","resource":{"category":"light"},"actions":["turn_on"],"decision":"ask"},`+
		`{"id":"r-no-lights","resource":{"category":"light"},"actions":["turn_on"],"decision":"deny"}]`)
	if got := evaluator.Evaluate(enforcing, request("light", "", "turn_on")); got.NotEnforced || got.Confirm || got.Approval != nil {
		t.Errorf("an enforcing mandate: %+v", got)
	}
}

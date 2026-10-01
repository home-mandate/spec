// SPDX-License-Identifier: Apache-2.0

package evaluator_test

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mandate-spec/mandate-spec/evaluator"
)

const baseRules = `[{"id":"r-1","resource":{"category":"light"},"actions":["turn_on"],"decision":"allow"}]`

// mandateWithRules baut ein gültiges Mandat (gültig ab 2026-01-01, ohne Ablauf) mit den Regeln rules.
func mandateWithRules(t *testing.T, rules string) *evaluator.Mandate {
	t.Helper()
	m, err := evaluator.Parse(mandateReplacing(baseRules, rules))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return m
}

var noon = time.Date(2026, 10, 12, 12, 0, 0, 0, time.FixedZone("CEST", 2*60*60))

func request(category, area, action string) evaluator.Request {
	return evaluator.Request{
		Resource: evaluator.Resource{EntityID: "device.test", Category: category, Area: area},
		Action:   action,
		Time:     noon,
		Status:   evaluator.StatusActive,
	}
}

func assertDecision(t *testing.T, got evaluator.Result, decision evaluator.Decision, reason evaluator.Reason, ruleID string) {
	t.Helper()
	if got.Decision != decision || got.Reason != reason || got.RuleID != ruleID {
		t.Errorf("got (%s, %s, %q), want (%s, %s, %q)", got.Decision, got.Reason, got.RuleID, decision, reason, ruleID)
	}
}

func TestEvaluateNilMandateIsDenied(t *testing.T) {
	got := evaluator.Evaluate(nil, request("light", "flur", "turn_on"))
	assertDecision(t, got, evaluator.Deny, evaluator.ReasonInvalidMandate, "")
	if got.MandateDigest != "" || got.Approval != nil {
		t.Errorf("unexpected details: %+v", got)
	}
}

func TestEvaluateInvalidRequest(t *testing.T) {
	m := mandateWithRules(t, `[{"id":"r-all","resource":{"any":true},"actions":["*"],"decision":"allow"}]`)
	missingCategory := request("", "flur", "turn_on")
	zeroTime := request("light", "flur", "turn_on")
	zeroTime.Time = time.Time{}
	unknownZone := request("light", "flur", "turn_on")
	unknownZone.TimeZone = "Mars/Olympus_Mons"
	for name, req := range map[string]evaluator.Request{
		"missing category": missingCategory, "zero time": zeroTime, "unknown zone": unknownZone,
	} {
		t.Run(name, func(t *testing.T) {
			assertDecision(t, evaluator.Evaluate(m, req), evaluator.Deny, evaluator.ReasonInvalidRequest, "")
		})
	}
}

func TestEvaluateUnknownCategoryAndAction(t *testing.T) {
	m := mandateWithRules(t, `[{"id":"r-all","resource":{"any":true},"actions":["*"],"decision":"allow"}]`)
	tests := []struct {
		name string
		req  evaluator.Request
		want evaluator.Reason
	}{
		{"unknown category", request("toaster", "kueche", "read"), evaluator.ReasonUnknownCategory},
		{"extension without vocabulary", request("paperless:document", "buero", "read"), evaluator.ReasonUnknownCategory},
		{"action outside vocabulary", request("light", "flur", "unlock"), evaluator.ReasonUnknownAction},
		{"wildcard as requested action", request("light", "flur", "*"), evaluator.ReasonUnknownAction},
		{"empty action", request("light", "flur", ""), evaluator.ReasonUnknownAction},
		{"case differs", request("Light", "flur", "turn_on"), evaluator.ReasonUnknownCategory},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertDecision(t, evaluator.Evaluate(m, tt.req), evaluator.Deny, tt.want, "")
		})
	}
}

func TestEvaluateValidityAndRevocation(t *testing.T) {
	m, err := evaluator.Parse(mandateReplacing(`"valid_from":"2026-01-01T00:00:00+01:00"`,
		`"valid_from":"2026-01-01T00:00:00+01:00","expires":"2027-01-01T00:00:00+01:00"`))
	if err != nil {
		t.Fatal(err)
	}
	at := func(s string) evaluator.Request {
		req := request("light", "flur", "turn_on")
		req.Time = mustParseTime(t, s)
		return req
	}
	revoked := at("2026-06-01T12:00:00+02:00")
	revoked.Status = evaluator.StatusRevoked
	tests := []struct {
		name     string
		req      evaluator.Request
		decision evaluator.Decision
		reason   evaluator.Reason
		ruleID   string
	}{
		{"before valid_from", at("2025-12-31T23:59:59+01:00"), evaluator.Deny, evaluator.ReasonNotYetValid, ""},
		{"at valid_from", at("2026-01-01T00:00:00+01:00"), evaluator.Allow, evaluator.ReasonRule, "r-1"},
		{"just before expires", at("2026-12-31T23:59:59+01:00"), evaluator.Allow, evaluator.ReasonRule, "r-1"},
		{"at expires", at("2027-01-01T00:00:00+01:00"), evaluator.Deny, evaluator.ReasonExpired, ""},
		{"at expires other offset", at("2026-12-31T23:00:00Z"), evaluator.Deny, evaluator.ReasonExpired, ""},
		{"revoked", revoked, evaluator.Deny, evaluator.ReasonRevoked, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertDecision(t, evaluator.Evaluate(m, tt.req), tt.decision, tt.reason, tt.ruleID)
		})
	}
}

func TestEvaluateReasonPrecedence(t *testing.T) {
	m := mandateWithRules(t, baseRules)
	revokedUnknown := request("toaster", "kueche", "read")
	revokedUnknown.Status = evaluator.StatusRevoked
	revokedEarly := request("light", "flur", "turn_on")
	revokedEarly.Status = evaluator.StatusRevoked
	revokedEarly.Time = mustParseTime(t, "2025-06-01T00:00:00Z")
	unknownActionEarly := request("light", "flur", "unlock")
	unknownActionEarly.Time = mustParseTime(t, "2025-06-01T00:00:00Z")
	invalidAndUnknown := request("toaster", "kueche", "read")
	invalidAndUnknown.TimeZone = "Local"
	assertDecision(t, evaluator.Evaluate(m, revokedUnknown), evaluator.Deny, evaluator.ReasonUnknownCategory, "")
	assertDecision(t, evaluator.Evaluate(m, revokedEarly), evaluator.Deny, evaluator.ReasonRevoked, "")
	assertDecision(t, evaluator.Evaluate(m, unknownActionEarly), evaluator.Deny, evaluator.ReasonUnknownAction, "")
	assertDecision(t, evaluator.Evaluate(m, invalidAndUnknown), evaluator.Deny, evaluator.ReasonInvalidRequest, "")
}

func TestEvaluateNoMatchIsDefaultDeny(t *testing.T) {
	m := mandateWithRules(t, baseRules)
	assertDecision(t, evaluator.Evaluate(m, request("light", "flur", "turn_off")), evaluator.Deny, evaluator.ReasonNoMatch, "")
	assertDecision(t, evaluator.Evaluate(m, request("light", "flur", "read")), evaluator.Deny, evaluator.ReasonNoMatch, "")
	empty := mandateWithRules(t, `[]`)
	assertDecision(t, evaluator.Evaluate(empty, request("light", "flur", "turn_on")), evaluator.Deny, evaluator.ReasonNoMatch, "")
}

func TestEvaluateSelectors(t *testing.T) {
	m := mandateWithRules(t, `[
		{"id":"r-living-light","resource":{"category":"light","area":"wohnzimmer"},"actions":["turn_on"],"decision":"allow"},
		{"id":"r-entity","resource":{"entity_id":"switch.pumpe"},"actions":["turn_on"],"decision":"allow"},
		{"id":"r-area","resource":{"area":"garten"},"actions":["read"],"decision":"allow"}]`)
	pump := request("switch", "keller", "turn_on")
	pump.Resource.EntityID = "switch.pumpe"
	otherSwitch := request("switch", "keller", "turn_on")
	otherSwitch.Resource.EntityID = "switch.andere"
	tests := []struct {
		name     string
		req      evaluator.Request
		decision evaluator.Decision
		ruleID   string
	}{
		{"category and area match", request("light", "wohnzimmer", "turn_on"), evaluator.Allow, "r-living-light"},
		{"category matches, area differs", request("light", "kueche", "turn_on"), evaluator.Deny, ""},
		{"area missing in request", request("light", "", "turn_on"), evaluator.Deny, ""},
		{"entity matches", pump, evaluator.Allow, "r-entity"},
		{"entity differs", otherSwitch, evaluator.Deny, ""},
		{"area only, any category", request("sensor", "garten", "read"), evaluator.Allow, "r-area"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := evaluator.Evaluate(m, tt.req)
			if got.Decision != tt.decision || got.RuleID != tt.ruleID {
				t.Errorf("got (%s, %q), want (%s, %q)", got.Decision, got.RuleID, tt.decision, tt.ruleID)
			}
		})
	}
}

func TestEvaluateStrictestDecisionWinsAndFirstRuleIsReported(t *testing.T) {
	m := mandateWithRules(t, `[
		{"id":"r-allow","resource":{"any":true},"actions":["*"],"decision":"allow"},
		{"id":"r-ask-1","resource":{"category":"media"},"actions":["play"],"decision":"ask"},
		{"id":"r-ask-2","resource":{"area":"bad"},"actions":["play"],"decision":"ask"},
		{"id":"r-deny-1","resource":{"category":"switch"},"actions":["turn_on"],"decision":"deny"},
		{"id":"r-deny-2","resource":{"area":"kueche"},"actions":["*"],"decision":"deny"}]`)
	assertDecision(t, evaluator.Evaluate(m, request("media", "bad", "play")), evaluator.Ask, evaluator.ReasonRule, "r-ask-1")
	assertDecision(t, evaluator.Evaluate(m, request("switch", "kueche", "turn_on")), evaluator.Deny, evaluator.ReasonRule, "r-deny-1")
	assertDecision(t, evaluator.Evaluate(m, request("switch", "flur", "turn_off")), evaluator.Allow, evaluator.ReasonRule, "r-allow")
	assertDecision(t, evaluator.Evaluate(m, request("media", "kueche", "play")), evaluator.Deny, evaluator.ReasonRule, "r-deny-2")
}

func TestEvaluateConditionsUseHouseholdZone(t *testing.T) {
	m := mandateWithRules(t, `[{"id":"r-night","resource":{"category":"light"},"actions":["turn_on"],"decision":"allow",
		"conditions":{"time_window":"22:00-06:00","weekdays":["mon"]}}]`)
	req := request("light", "flur", "turn_on")
	req.Time = mustParseTime(t, "2026-10-12T20:30:00Z") // Montag 22:30 in Berlin
	assertDecision(t, evaluator.Evaluate(m, req), evaluator.Deny, evaluator.ReasonNoMatch, "")
	req.TimeZone = "Europe/Berlin"
	assertDecision(t, evaluator.Evaluate(m, req), evaluator.Allow, evaluator.ReasonRule, "r-night")
}

func TestEvaluateCriticalActions(t *testing.T) {
	broad := `{"id":"r-broad","resource":{"category":"lock"},"actions":["*"],"decision":"allow"}`
	door := `{"id":"r-door","resource":{"entity_id":"lock.haustuer"},"actions":["unlock"],"decision":"allow","allow_critical":true}`
	unlockDoor := request("lock", "flur", "unlock")
	unlockDoor.Resource.EntityID = "lock.haustuer"

	onlyCritical := mandateWithRules(t, "["+door+"]")
	assertDecision(t, evaluator.Evaluate(onlyCritical, unlockDoor), evaluator.Allow, evaluator.ReasonRule, "r-door")

	mixed := mandateWithRules(t, "["+door+","+broad+"]")
	got := evaluator.Evaluate(mixed, unlockDoor)
	assertDecision(t, got, evaluator.Ask, evaluator.ReasonCriticalDemotion, "r-broad")
	if got.Approval == nil || got.Approval.Timeout != "PT2M" {
		t.Errorf("demotion must use the mandate approval, got %+v", got.Approval)
	}

	noFlag := mandateWithRules(t, "["+broad+"]")
	assertDecision(t, evaluator.Evaluate(noFlag, request("lock", "flur", "lock")), evaluator.Allow, evaluator.ReasonRule, "r-broad")
	assertDecision(t, evaluator.Evaluate(noFlag, request("lock", "flur", "open")), evaluator.Ask, evaluator.ReasonCriticalDemotion, "r-broad")

	for _, c := range []struct{ category, action string }{
		{"gate", "open"}, {"alarm", "disarm"}, {"camera", "snapshot"}, {"script", "run"}, {"other", "set"},
	} {
		m := mandateWithRules(t, `[{"id":"r-x","resource":{"any":true},"actions":["*"],"decision":"allow"}]`)
		got := evaluator.Evaluate(m, request(c.category, "flur", c.action))
		if got.Decision != evaluator.Ask || got.Reason != evaluator.ReasonCriticalDemotion {
			t.Errorf("%s.%s: got (%s, %s), want critical demotion", c.category, c.action, got.Decision, got.Reason)
		}
	}
}

func TestEvaluateApprovalSettings(t *testing.T) {
	m := mandateWithRules(t, `[
		{"id":"r-ask-plain","resource":{"category":"media"},"actions":["set_volume"],"decision":"ask"},
		{"id":"r-ask-own","resource":{"area":"bad"},"actions":["set_volume"],"decision":"ask",
		 "approval":{"timeout":"PT30S","approvers":["a-2","a-3"]}}]`)
	own := evaluator.Evaluate(m, request("media", "bad", "set_volume"))
	assertDecision(t, own, evaluator.Ask, evaluator.ReasonRule, "r-ask-plain")
	if own.Approval == nil || own.Approval.Timeout != "PT30S" || strings.Join(own.Approval.Approvers, ",") != "a-2,a-3" {
		t.Fatalf("approval = %+v, want PT30S [a-2 a-3]", own.Approval)
	}
	fallback := evaluator.Evaluate(m, request("media", "flur", "set_volume"))
	if fallback.Approval == nil || fallback.Approval.Timeout != "PT2M" || strings.Join(fallback.Approval.Approvers, ",") != "a-1" {
		t.Fatalf("approval = %+v, want mandate default", fallback.Approval)
	}
	// Ergebnis darf das Mandat nicht verändern lassen.
	own.Approval.Approvers[0] = "attacker"
	again := evaluator.Evaluate(m, request("media", "bad", "set_volume"))
	if again.Approval.Approvers[0] != "a-2" {
		t.Errorf("mutating a result changed the mandate: %v", again.Approval.Approvers)
	}
	if allow := evaluator.Evaluate(mandateWithRules(t, baseRules), request("light", "flur", "turn_on")); allow.Approval != nil {
		t.Errorf("approval on allow: %+v", allow.Approval)
	}
}

func TestEvaluateReportsMandateDigest(t *testing.T) {
	m := mandateWithRules(t, baseRules)
	for _, req := range []evaluator.Request{request("light", "flur", "turn_on"), request("toaster", "flur", "read")} {
		if got := evaluator.Evaluate(m, req); got.MandateDigest != m.Digest() {
			t.Errorf("digest = %q, want %q", got.MandateDigest, m.Digest())
		}
	}
}

func TestEvaluateRejectsMalformedRequestFields(t *testing.T) {
	// Ohne Prüfung der Anfrage würde eine abweichende Schreibweise die deny-Regel umgehen
	// und über r-locks bei allow landen (Security-Review, Woche 1).
	m := mandateWithRules(t, `[
		{"id":"r-cellar","resource":{"entity_id":"lock.keller"},"actions":["*"],"decision":"deny"},
		{"id":"r-kitchen","resource":{"area":"kueche"},"actions":["*"],"decision":"deny"},
		{"id":"r-locks","resource":{"category":"lock"},"actions":["*"],"decision":"allow","allow_critical":true}]`)
	req := func(entity, area string) evaluator.Request {
		r := request("lock", area, "unlock")
		r.Resource.EntityID = entity
		return r
	}
	assertDecision(t, evaluator.Evaluate(m, req("lock.keller", "flur")), evaluator.Deny, evaluator.ReasonRule, "r-cellar")
	assertDecision(t, evaluator.Evaluate(m, req("lock.haustuer", "")), evaluator.Allow, evaluator.ReasonRule, "r-locks")
	for name, r := range map[string]evaluator.Request{
		"upper case entity":  req("Lock.keller", "flur"),
		"trailing space":     req("lock.keller ", "flur"),
		"leading space":      req(" lock.keller", "flur"),
		"empty entity":       req("", "flur"),
		"nul byte":           req("lock.keller\x00", "flur"),
		"newline":            req("lock.keller\n", "flur"),
		"missing domain":     req("keller", "flur"),
		"two dots":           req("lock.keller.x", "flur"),
		"non-ascii":          req("lock.k"+string(rune(0xe4))+"ller", "flur"),
		"upper case area":    req("lock.haustuer", "Kueche"),
		"area with space":    req("lock.haustuer", "kueche "),
		"area with hyphen":   req("lock.haustuer", "kue-che"),
		"area too long":      req("lock.haustuer", strings.Repeat("a", 65)),
		"wildcard as entity": req("*", "flur"),
	} {
		t.Run(name, func(t *testing.T) {
			assertDecision(t, evaluator.Evaluate(m, r), evaluator.Deny, evaluator.ReasonInvalidRequest, "")
		})
	}
}

func TestEvaluateRequiresMandateStatus(t *testing.T) {
	m := mandateWithRules(t, baseRules)
	for _, status := range []evaluator.MandateStatus{"", "Active", "ACTIVE", "unknown", "revoked "} {
		req := request("light", "flur", "turn_on")
		req.Status = status
		assertDecision(t, evaluator.Evaluate(m, req), evaluator.Deny, evaluator.ReasonInvalidRequest, "")
	}
}

func TestEvaluateZeroMandateIsInvalid(t *testing.T) {
	got := evaluator.Evaluate(&evaluator.Mandate{}, request("light", "flur", "turn_on"))
	assertDecision(t, got, evaluator.Deny, evaluator.ReasonInvalidMandate, "")
	if got.MandateDigest != "" {
		t.Errorf("digest on invalid mandate: %q", got.MandateDigest)
	}
	var nilMandate *evaluator.Mandate
	if nilMandate.ID() != "" || nilMandate.Digest() != "" {
		t.Error("nil mandate accessors must return empty strings")
	}
}

func TestEvaluateDemotionApprovalIsACopy(t *testing.T) {
	m := mandateWithRules(t, `[{"id":"r-x","resource":{"any":true},"actions":["*"],"decision":"allow"}]`)
	first := evaluator.Evaluate(m, request("lock", "flur", "unlock"))
	if first.Reason != evaluator.ReasonCriticalDemotion || first.Approval == nil {
		t.Fatalf("expected critical demotion, got %+v", first)
	}
	first.Approval.Approvers[0] = "attacker"
	first.Approval.Timeout = "PT59M"
	again := evaluator.Evaluate(m, request("lock", "flur", "unlock"))
	if again.Approval.Approvers[0] != "a-1" || again.Approval.Timeout != "PT2M" {
		t.Errorf("mutating a result changed the mandate: %+v", again.Approval)
	}
}

func TestEvaluateConcurrentUse(t *testing.T) {
	m := mandateWithRules(t, `[
		{"id":"r-night","resource":{"category":"light"},"actions":["turn_on"],"decision":"allow","conditions":{"time_window":"22:00-06:00"}},
		{"id":"r-lock","resource":{"category":"lock"},"actions":["*"],"decision":"ask","approval":{"timeout":"PT1M","approvers":["a-2"]}}]`)
	zones := []string{"", "UTC", "Europe/Berlin", "America/New_York", "Asia/Kathmandu", "Australia/Lord_Howe"}
	var wg sync.WaitGroup
	for g := range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 200 {
				req := request("lock", "flur", "unlock")
				req.TimeZone = zones[(g+i)%len(zones)]
				req.Time = noon.Add(time.Duration(i) * time.Hour)
				got := evaluator.Evaluate(m, req)
				if got.Decision != evaluator.Ask || got.RuleID != "r-lock" || got.Approval.Approvers[0] != "a-2" {
					t.Errorf("goroutine %d: unexpected %+v", g, got)
					return
				}
				got.Approval.Approvers[0] = "changed" // darf andere Goroutinen nicht beeinflussen
			}
		}()
	}
	wg.Wait()
}

func mustParseTime(t *testing.T, s string) time.Time {
	t.Helper()
	at, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatal(err)
	}
	return at
}

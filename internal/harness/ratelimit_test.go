// SPDX-License-Identifier: Apache-2.0

package harness_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/home-mandate/spec/internal/harness"
)

// limitMandate is a valid mandate for the agent hm-client:pdp-0001 with N and the given rules.
func limitMandate(id string, n int, rules string) string {
	return fmt.Sprintf(`{"type":"https://home-mandate.org/mandate/v0","id":%q,"principal":"household:pdp",`+
		`"agent":{"client_id":"hm-client:pdp-0001","display_name":"PDP"},"rules":%s,"default":"deny",`+
		`"approval":{"timeout":"PT2M","approvers":["user-1"]},"limits":{"max_actions_per_hour":%d},`+
		`"valid_from":"2026-10-01T00:00:00+02:00","created_by":"user-1","created_at":"2026-10-01T09:00:00+02:00"}`, id, rules, n)
}

type pdpAnswer struct {
	Decision bool           `json:"decision"`
	Context  map[string]any `json:"context"`
}

// limitPDP starts the reference PDP with mandates and a directory, at a fixed point in time.
func limitPDP(t *testing.T, mandates ...string) (ask func(clientID, entity, action string) pdpAnswer, put func()) {
	t.Helper()
	server := httptest.NewServer((&harness.ReferencePDP{}).Handler())
	t.Cleanup(server.Close)
	state := harness.State{Time: "2026-10-12T19:00:00+02:00", Timezone: "Europe/Berlin", Directory: []harness.Resource{
		{EntityID: "light.kitchen", Category: "light"}, {EntityID: "lock.front_door", Category: "lock"},
		{EntityID: "climate.hall", Category: "climate"}}}
	for _, m := range mandates {
		state.Mandates = append(state.Mandates, harness.StoredMandate{Mandate: m})
	}
	put = func() {
		body, _ := json.Marshal(state)
		req, _ := http.NewRequest(http.MethodPut, server.URL+"/test/state", bytes.NewReader(body))
		resp, err := server.Client().Do(req)
		if err != nil || resp.StatusCode != http.StatusNoContent {
			t.Fatalf("state: %v %v", err, resp)
		}
		_ = resp.Body.Close()
	}
	put()
	ask = func(clientID, entity, action string) pdpAnswer {
		t.Helper()
		body := fmt.Sprintf(`{"subject":{"type":"agent","id":%q,"properties":{"principal":"household:pdp"}},`+
			`"action":{"name":%q},"resource":{"type":"x","id":%q}}`, clientID, action, entity)
		resp, err := server.Client().Post(server.URL+"/access/v1/evaluation", "application/json", bytes.NewBufferString(body))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var a pdpAnswer
		if err := json.NewDecoder(resp.Body).Decode(&a); err != nil {
			t.Fatal(err)
		}
		return a
	}
	return ask, put
}

const agent = "hm-client:pdp-0001"

// A PDP apart from its PEP enforces N (SPEC-v0 sections 6 and 11.2): beyond it, decision false
// with denied_by and the mandate, but no outcome and no reason, since nothing was evaluated.
// Every request counts, whatever its result.
func TestReferencePDPEnforcesTheLimitOfTheMandate(t *testing.T) {
	ask, put := limitPDP(t, limitMandate("m-pdp", 3, `[{"id":"r-light","resource":{"category":"light"},"actions":["turn_on"],"decision":"allow"}]`))
	for i, action := range []string{"turn_on", "turn_off", "turn_on"} { // turn_off is denied by the rules and counts as well
		a := ask(agent, "light.kitchen", action)
		if a.Context["denied_by"] != nil || a.Decision != (action == "turn_on") {
			t.Fatalf("request %d: %+v", i+1, a)
		}
	}
	a := ask(agent, "light.kitchen", "turn_on")
	if a.Decision || a.Context["denied_by"] != "rate_limit" || a.Context["mandate_id"] != "m-pdp" || a.Context["mandate_digest"] == nil {
		t.Fatalf("fourth request: %+v", a)
	}
	if _, has := a.Context["outcome"]; has {
		t.Errorf("outcome without an evaluation: %+v", a)
	}
	if _, has := a.Context["reason"]; has {
		t.Errorf("reason without an evaluation: %+v", a)
	}
	put() // a new state of the test interface starts the counts again
	if a := ask(agent, "light.kitchen", "turn_on"); !a.Decision {
		t.Errorf("after a new state: %+v", a)
	}
}

// The limits of a rule (SPEC-v0 sections 6 and 11.2): after an allow, decision false with the
// context of the allow and denied_by, so that the PEP records the evaluation.
func TestReferencePDPEnforcesTheLimitsOfARule(t *testing.T) {
	ask, _ := limitPDP(t, limitMandate("m-pdp", 100, `[
		{"id":"r-unlock","resource":{"entity_id":"lock.front_door"},"actions":["unlock"],"decision":"allow","allow_critical":true,"limits":{"max_actions_per_day":2}},
		{"id":"r-heating","resource":{"category":"climate"},"actions":["read"],"decision":"allow","limits":{"min_interval":"PT10M"}}]`))
	for i := range 2 {
		if a := ask(agent, "lock.front_door", "unlock"); !a.Decision {
			t.Fatalf("unlock %d: %+v", i+1, a)
		}
	}
	a := ask(agent, "lock.front_door", "unlock")
	want := map[string]any{"outcome": "allow", "reason": "rule", "rule_id": "r-unlock", "denied_by": "rate_limit", "mandate_id": "m-pdp"}
	for k, v := range want {
		if a.Context[k] != v {
			t.Errorf("third unlock: context %s = %v, want %v (%+v)", k, a.Context[k], v, a)
		}
	}
	if a.Decision || a.Context["mandate_digest"] == nil {
		t.Errorf("third unlock: %+v", a)
	}
	// The clock of the state stands still: a second read lies within min_interval.
	if a := ask(agent, "climate.hall", "read"); !a.Decision {
		t.Fatalf("first read: %+v", a)
	}
	if a := ask(agent, "climate.hall", "read"); a.Decision || a.Context["denied_by"] != "rate_limit" {
		t.Errorf("second read within min_interval: %+v", a)
	}
}

// Requests without a single valid mandate have no N of their own: they count against a limit
// of the implementation for the agent and principal, 60 per hour (SPEC-v0 section 11.2).
func TestReferencePDPLimitsRequestsWithoutAMandate(t *testing.T) {
	ask, _ := limitPDP(t, limitMandate("m-pdp", 3, `[]`))
	const stranger = "hm-client:pdp-9999"
	for i := range 60 {
		if a := ask(stranger, "light.kitchen", "turn_on"); a.Context["reason"] != "no_mandate" {
			t.Fatalf("request %d: %+v", i+1, a)
		}
	}
	a := ask(stranger, "light.kitchen", "turn_on")
	if a.Decision || a.Context["denied_by"] != "rate_limit" || a.Context["reason"] != nil || a.Context["mandate_id"] != nil {
		t.Errorf("61st request: %+v", a)
	}
	// The agent with a mandate keeps its own N.
	if a := ask(agent, "light.kitchen", "turn_on"); a.Context["denied_by"] != nil {
		t.Errorf("another agent's limit applied: %+v", a)
	}
}

// For ambiguous_mandate the limit is at most the smallest N of the valid candidates.
func TestReferencePDPLimitsAmbiguousMandatesByTheSmallestN(t *testing.T) {
	rules := `[{"id":"r-light","resource":{"category":"light"},"actions":["turn_on"],"decision":"allow"}]`
	ask, _ := limitPDP(t, limitMandate("m-pdp-a", 2, rules), limitMandate("m-pdp-b", 5, rules))
	for i := range 2 {
		if a := ask(agent, "light.kitchen", "turn_on"); a.Context["reason"] != "ambiguous_mandate" {
			t.Fatalf("request %d: %+v", i+1, a)
		}
	}
	if a := ask(agent, "light.kitchen", "turn_on"); a.Decision || a.Context["denied_by"] != "rate_limit" {
		t.Errorf("third ambiguous request: %+v", a)
	}
}

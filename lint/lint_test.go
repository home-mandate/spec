// SPDX-License-Identifier: Apache-2.0

package lint_test

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/home-mandate/spec/evaluator"
	"github.com/home-mandate/spec/lint"
)

func mandate(rules string, extra string) []byte {
	return []byte(`{"type":"https://home-mandate.org/mandate/v0","id":"m-test","principal":"household:t",` +
		`"agent":{"client_id":"hm-client:test-0001","display_name":"Test"},"rules":` + rules + `,` +
		`"default":"deny","approval":{"timeout":"PT2M","approvers":["a-1"]},"limits":{"max_actions_per_hour":10},` +
		`"valid_from":"2026-01-01T00:00:00+01:00","created_by":"a-1","created_at":"2025-12-31T12:00:00+01:00"` + extra + `}`)
}

func codes(t *testing.T, data []byte) []string {
	t.Helper()
	findings, err := lint.Mandate(data)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, f := range findings {
		if f.Section == "" || f.Message == "" {
			t.Errorf("finding %+v without section or message", f)
		}
		out = append(out, f.Code)
	}
	return out
}

func TestEachPatternOfSection12_4(t *testing.T) {
	for name, tc := range map[string]struct {
		rules, extra string
		want         []string
	}{
		"narrow and safe": {`[{"id":"r-1","resource":{"category":"light"},"actions":["turn_on"],"decision":"allow"}]`, "", nil},
		"any with every action": {`[{"id":"r-1","resource":{"any":true},"actions":["*"],"decision":"allow"}]`, "",
			[]string{lint.AnyEveryAction, lint.EveryAction, lint.ReadAny, lint.NoExpiry}},
		"every action of a category": {`[{"id":"r-1","resource":{"category":"light"},"actions":["*"],"decision":"allow"}]`, "", []string{lint.EveryAction}},
		"read on any":                {`[{"id":"r-1","resource":{"any":true},"actions":["read"],"decision":"allow"}]`, "", []string{lint.ReadAny}},
		"allow_critical without expires": {`[{"id":"r-1","resource":{"category":"lock"},"actions":["unlock"],"decision":"allow","allow_critical":true}]`, "",
			[]string{lint.CriticalNoExpiry}},
		"allow_critical with expires": {`[{"id":"r-1","resource":{"category":"lock"},"actions":["unlock"],"decision":"allow","allow_critical":true}]`,
			`,"expires":"2026-02-01T00:00:00+01:00"`, nil},
		"deny with conditions": {`[{"id":"r-1","resource":{"category":"lock"},"actions":["unlock"],"decision":"deny","conditions":{"time_window":"22:00-06:00"}}]`, "",
			[]string{lint.ConditionalRestriction}},
		"ask by area only": {`[{"id":"r-1","resource":{"area":"kids_room"},"actions":["turn_on"],"decision":"ask"}]`, "", []string{lint.AreaOnlyRestriction}},
		"audit mode without expires": {`[{"id":"r-1","resource":{"category":"light"},"actions":["turn_on"],"decision":"allow"}]`, `,"enforce":false`,
			[]string{lint.AuditModeLong}},
		"audit mode for long": {`[{"id":"r-1","resource":{"category":"light"},"actions":["turn_on"],"decision":"allow"}]`, `,"enforce":false,"expires":"2026-06-01T00:00:00+01:00"`,
			[]string{lint.AuditModeLong}},
		"audit mode for exactly 30 days": {`[{"id":"r-1","resource":{"category":"light"},"actions":["turn_on"],"decision":"allow"}]`, `,"enforce":false,"expires":"2026-01-31T00:00:00+01:00"`, nil},
		"audit mode for a week":          {`[{"id":"r-1","resource":{"category":"light"},"actions":["turn_on"],"decision":"allow"}]`, `,"enforce":false,"expires":"2026-01-08T00:00:00+01:00"`, nil},
	} {
		t.Run(name, func(t *testing.T) {
			got := codes(t, mandate(tc.rules, tc.extra))
			slices.Sort(got)
			want := slices.Clone(tc.want)
			slices.Sort(want)
			if !slices.Equal(got, want) {
				t.Errorf("codes = %v, want %v", got, want)
			}
		})
	}
}

func TestFindingsNameTheirRule(t *testing.T) {
	findings, err := lint.Mandate(mandate(`[{"id":"r-ok","resource":{"category":"light"},"actions":["turn_on"],"decision":"allow"},`+
		`{"id":"r-broad","resource":{"category":"light"},"actions":["*"],"decision":"allow"}]`, ""))
	if err != nil || len(findings) != 1 || findings[0].RuleID != "r-broad" || !strings.Contains(findings[0].String(), "r-broad") {
		t.Fatalf("findings = %+v, %v", findings, err)
	}
}

func TestAnInvalidMandateIsAnError(t *testing.T) {
	if _, err := lint.Mandate([]byte(`{}`)); err == nil || !errors.Is(err, evaluator.ErrSchema) {
		t.Errorf("err = %v, want the error of evaluator.Parse", err)
	}
}

// SPDX-License-Identifier: Apache-2.0

// Package lint reports patterns of a mandate that are valid but risky, as SPEC-v0 section 12.4
// names them, so that a user interface can warn before a household stores the mandate. A
// finding is a warning: it changes no verdict of the evaluation.
package lint

import (
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"github.com/home-mandate/spec/evaluator"
	"github.com/home-mandate/spec/rfc3339"
)

// The codes of the findings.
const (
	// AnyEveryAction: a rule for every resource and every action.
	AnyEveryAction = "any_every_action"
	// EveryAction: "*" contains every action a later vocabulary adds.
	EveryAction = "every_action"
	// ReadAny: read for every resource reveals presence, door contacts and cameras.
	ReadAny = "read_any"
	// NoExpiry: a broad mandate without expires.
	NoExpiry = "no_expiry"
	// CriticalNoExpiry: allow_critical in a mandate without expires.
	CriticalNoExpiry = "critical_no_expiry"
	// ConditionalRestriction: a deny or ask with conditions does not apply outside them.
	ConditionalRestriction = "conditional_restriction"
	// AreaOnlyRestriction: a deny or ask by area alone stops when a resource leaves the area.
	AreaOnlyRestriction = "area_only_restriction"
	// AuditModeLong: audit mode without expires, or for longer than MaxAuditMode.
	AuditModeLong = "audit_mode_long"
)

// MaxAuditMode is how long audit mode may last before the linter warns.
const MaxAuditMode = 30 * 24 * time.Hour

// Finding is one risky pattern.
type Finding struct {
	Code string `json:"code"`
	// RuleID is the rule the finding is about; empty for the mandate as a whole.
	RuleID  string `json:"rule_id,omitempty"`
	Section string `json:"section"`
	Message string `json:"message"`
}

func (f Finding) String() string {
	if f.RuleID == "" {
		return fmt.Sprintf("%s: %s (SPEC-v0 section %s)", f.Code, f.Message, f.Section)
	}
	return fmt.Sprintf("%s: rule %s: %s (SPEC-v0 section %s)", f.Code, f.RuleID, f.Message, f.Section)
}

type rule struct {
	ID       string `json:"id"`
	Resource struct {
		Any      bool   `json:"any"`
		Category string `json:"category"`
		EntityID string `json:"entity_id"`
		Area     string `json:"area"`
	} `json:"resource"`
	Actions       []string        `json:"actions"`
	Decision      string          `json:"decision"`
	Conditions    json.RawMessage `json:"conditions"`
	AllowCritical bool            `json:"allow_critical"`
}

type mandate struct {
	Enforce   *bool  `json:"enforce"`
	Rules     []rule `json:"rules"`
	ValidFrom string `json:"valid_from"`
	Expires   string `json:"expires"`
}

// Mandate reports the risky patterns of a mandate, in the order of its rules, then those of the
// mandate as a whole. A mandate that is not valid gives the error of evaluator.Parse.
func Mandate(data []byte) ([]Finding, error) {
	if _, err := evaluator.Parse(data); err != nil {
		return nil, err
	}
	var m mandate
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("lint: %w", err)
	}
	var out []Finding
	broad, critical := false, false
	for _, r := range m.Rules {
		fs := ruleFindings(r)
		out = append(out, fs...)
		broad = broad || slices.ContainsFunc(fs, func(f Finding) bool { return f.Code == AnyEveryAction })
		critical = critical || r.AllowCritical
	}
	switch {
	case m.Expires == "" && broad:
		out = append(out, Finding{Code: NoExpiry, Section: "12.4", Message: "a mandate for every resource and every action has no expires"})
	case m.Expires == "" && critical:
		out = append(out, Finding{Code: CriticalNoExpiry, Section: "12.4", Message: "the mandate allows critical actions without an approval and has no expires"})
	}
	if m.Enforce != nil && !*m.Enforce && !shortEnough(m.ValidFrom, m.Expires) {
		out = append(out, Finding{Code: AuditModeLong, Section: "12.4", Message: "audit mode should end soon: give the mandate an expires within 30 days"})
	}
	return out, nil
}

func ruleFindings(r rule) []Finding {
	var out []Finding
	add := func(code, msg string) {
		out = append(out, Finding{Code: code, RuleID: r.ID, Section: "12.4", Message: msg})
	}
	every := slices.Contains(r.Actions, "*")
	allows := r.Decision == "allow"
	if r.Resource.Any && every && allows {
		add(AnyEveryAction, "allows every action on every resource")
	}
	if every && allows {
		add(EveryAction, `"*" also allows every action a later vocabulary adds; name the actions for a closed list`)
	}
	if r.Resource.Any && allows && (every || slices.Contains(r.Actions, "read")) {
		add(ReadAny, "allows read on every resource, presence sensors and cameras included; allow read per category")
	}
	restricts := r.Decision == "deny" || r.Decision == "ask"
	if restricts && len(r.Conditions) > 0 {
		add(ConditionalRestriction, "a rule with conditions does not apply outside them, so this restriction is lifted there")
	}
	if restricts && r.Resource.Area != "" && r.Resource.Category == "" && r.Resource.EntityID == "" {
		add(AreaOnlyRestriction, "a restriction by area alone stops when a resource leaves the area; name the category or the resource")
	}
	return out
}

// shortEnough reports whether audit mode ends within MaxAuditMode of the start of the mandate.
func shortEnough(validFrom, expires string) bool {
	if expires == "" {
		return false
	}
	from, err1 := rfc3339.Parse(validFrom)
	until, err2 := rfc3339.Parse(expires)
	return err1 == nil && err2 == nil && until.Sub(from) <= MaxAuditMode
}

// SPDX-License-Identifier: Apache-2.0

package evaluator

import (
	"encoding/json"
	"fmt"
	"slices"
	"time"
)

// Mandate ist ein gültiges Mandat. Es entsteht nur über Parse und ist danach unveränderlich.
type Mandate struct {
	id         string
	digest     string
	validFrom  time.Time
	expires    time.Time
	hasExpires bool
	rules      []rule
	approval   Approval
}

// ID liefert die ID des Mandats.
func (m *Mandate) ID() string { return m.id }

// Digest liefert den Fingerabdruck nach SPEC-v0 Abschnitt 3.2.
func (m *Mandate) Digest() string { return m.digest }

type selector struct {
	any      bool
	entityID string
	category string
	area     string
}

// weekdaySet hat ein Bit je time.Weekday; 0 heißt: keine Bedingung.
type weekdaySet uint8

type rule struct {
	id            string
	selector      selector
	actions       []string
	decision      Decision
	window        timeWindow
	weekdays      weekdaySet
	approval      *Approval
	allowCritical bool
}

// raw* spiegeln das Schema; sie werden erst nach erfolgreicher Schema-Prüfung befüllt.
type rawApproval struct {
	Timeout   string   `json:"timeout"`
	Approvers []string `json:"approvers"`
}

type rawRule struct {
	ID       string `json:"id"`
	Resource struct {
		EntityID string `json:"entity_id"`
		Category string `json:"category"`
		Area     string `json:"area"`
		Any      bool   `json:"any"`
	} `json:"resource"`
	Actions    []string `json:"actions"`
	Decision   string   `json:"decision"`
	Conditions *struct {
		TimeWindow string   `json:"time_window"`
		Weekdays   []string `json:"weekdays"`
	} `json:"conditions"`
	Approval      *rawApproval `json:"approval"`
	AllowCritical bool         `json:"allow_critical"`
}

type rawMandate struct {
	Type      string `json:"type"`
	ID        string `json:"id"`
	Principal string `json:"principal"`
	Agent     struct {
		ClientID    string `json:"client_id"`
		DisplayName string `json:"display_name"`
	} `json:"agent"`
	Rules    []rawRule   `json:"rules"`
	Default  string      `json:"default"`
	Approval rawApproval `json:"approval"`
	Limits   struct {
		MaxActionsPerHour json.Number `json:"max_actions_per_hour"`
	} `json:"limits"`
	ValidFrom string `json:"valid_from"`
	Expires   string `json:"expires"`
	CreatedBy string `json:"created_by"`
	CreatedAt string `json:"created_at"`
}

var weekdayNames = map[string]time.Weekday{
	"sun": time.Sunday, "mon": time.Monday, "tue": time.Tuesday, "wed": time.Wednesday,
	"thu": time.Thursday, "fri": time.Friday, "sat": time.Saturday,
}

func buildMandate(raw rawMandate, digest string) (*Mandate, error) {
	validFrom, err := parseTimestamp("valid_from", raw.ValidFrom)
	if err != nil {
		return nil, err
	}
	if _, err := parseTimestamp("created_at", raw.CreatedAt); err != nil {
		return nil, err
	}
	m := &Mandate{id: raw.ID, digest: digest, validFrom: validFrom, approval: copyApproval(raw.Approval)}
	if raw.Expires != "" {
		if m.expires, err = parseTimestamp("expires", raw.Expires); err != nil {
			return nil, err
		}
		m.hasExpires = true
	}
	seen := make(map[string]struct{}, len(raw.Rules))
	for _, rr := range raw.Rules {
		if _, dup := seen[rr.ID]; dup {
			return nil, fmt.Errorf("%w: duplicate rule id %q", ErrSemantic, rr.ID)
		}
		seen[rr.ID] = struct{}{}
		r, err := buildRule(rr)
		if err != nil {
			return nil, err
		}
		m.rules = append(m.rules, r)
	}
	return m, nil
}

func buildRule(rr rawRule) (rule, error) {
	if err := checkRuleVocabulary(rr); err != nil {
		return rule{}, err
	}
	r := rule{
		id: rr.ID,
		selector: selector{
			any: rr.Resource.Any, entityID: rr.Resource.EntityID,
			category: rr.Resource.Category, area: rr.Resource.Area,
		},
		actions:       slices.Clone(rr.Actions),
		decision:      Decision(rr.Decision),
		allowCritical: rr.AllowCritical,
	}
	if rr.Approval != nil {
		a := copyApproval(*rr.Approval)
		r.approval = &a
	}
	if rr.Conditions == nil {
		return r, nil
	}
	if rr.Conditions.TimeWindow != "" {
		w, err := parseTimeWindow(rr.Conditions.TimeWindow)
		if err != nil {
			return rule{}, fmt.Errorf("rule %q: %w", rr.ID, err)
		}
		r.window = w
	}
	for _, name := range rr.Conditions.Weekdays {
		day, ok := weekdayNames[name]
		if !ok {
			return rule{}, fmt.Errorf("%w: rule %q: unknown weekday %q", ErrSchema, rr.ID, name)
		}
		r.weekdays |= 1 << day
	}
	return r, nil
}

// checkRuleVocabulary setzt SPEC-v0 Abschnitt 3.1 Nr. 4 um.
func checkRuleVocabulary(rr rawRule) error {
	category := rr.Resource.Category
	if _, known := vocabularyV0[category]; !known {
		return nil // keine Kategorie oder unbekannte Erweiterung: keine Prüfung
	}
	for _, action := range rr.Actions {
		if action == "*" {
			continue
		}
		if _, actionKnown, _ := lookupAction(category, action); !actionKnown {
			return fmt.Errorf("%w: rule %q: action %q not in vocabulary of %q", ErrSemantic, rr.ID, action, category)
		}
	}
	return nil
}

func parseTimestamp(field, value string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: %s: %v", ErrSchema, field, err)
	}
	return t, nil
}

func copyApproval(a rawApproval) Approval {
	return Approval{Timeout: a.Timeout, Approvers: slices.Clone(a.Approvers)}
}

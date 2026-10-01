// SPDX-License-Identifier: Apache-2.0

package evaluator

import (
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// Grenzen für approval.timeout (SPEC-v0 Abschnitt 3.1 Nr. 7).
const (
	minApprovalTimeout = 10 * time.Second
	maxApprovalTimeout = time.Hour
)

// Mandate ist ein gültiges Mandat. Es entsteht nur über Parse und ist danach unveränderlich.
// Der Nullwert ist kein gültiges Mandat; Evaluate liefert dafür ReasonInvalidMandate.
type Mandate struct {
	valid      bool
	id         string
	digest     string
	validFrom  time.Time
	expires    time.Time
	hasExpires bool
	rules      []rule
	approval   Approval
}

// ID liefert die ID des Mandats; leer bei nil.
func (m *Mandate) ID() string {
	if m == nil {
		return ""
	}
	return m.id
}

// Digest liefert den Fingerabdruck nach SPEC-v0 Abschnitt 3.2; leer bei nil.
func (m *Mandate) Digest() string {
	if m == nil {
		return ""
	}
	return m.digest
}

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
	m := &Mandate{id: raw.ID, digest: digest, rules: make([]rule, 0, len(raw.Rules))}
	if err := m.setValidity(raw); err != nil {
		return nil, err
	}
	if err := checkDisplayedText("agent.display_name", raw.Agent.DisplayName); err != nil {
		return nil, err
	}
	if err := checkDisplayedText("created_by", raw.CreatedBy); err != nil {
		return nil, err
	}
	approval, err := buildApproval("approval", raw.Approval)
	if err != nil {
		return nil, err
	}
	m.approval = approval
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
	m.valid = true
	return m, nil
}

// setValidity liest den Gültigkeitszeitraum (SPEC-v0 Abschnitt 3.1 Nr. 0 und 6).
func (m *Mandate) setValidity(raw rawMandate) error {
	var err error
	if m.validFrom, err = parseTimestamp("valid_from", raw.ValidFrom); err != nil {
		return err
	}
	if _, err := parseTimestamp("created_at", raw.CreatedAt); err != nil {
		return err
	}
	if raw.Expires == "" {
		return nil
	}
	if m.expires, err = parseTimestamp("expires", raw.Expires); err != nil {
		return err
	}
	if !m.expires.After(m.validFrom) {
		return fmt.Errorf("%w: expires must be after valid_from", ErrSemantic)
	}
	m.hasExpires = true
	return nil
}

func buildRule(rr rawRule) (rule, error) {
	decision := Decision(rr.Decision)
	if decision != Allow && decision != Ask && decision != Deny {
		return rule{}, fmt.Errorf("%w: rule %q: unknown decision %q", ErrSemantic, rr.ID, rr.Decision)
	}
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
		decision:      decision,
		allowCritical: rr.AllowCritical,
	}
	if rr.Approval != nil {
		a, err := buildApproval("rule "+strconv.Quote(rr.ID)+" approval", *rr.Approval)
		if err != nil {
			return rule{}, err
		}
		r.approval = &a
	}
	if err := r.setConditions(rr); err != nil {
		return rule{}, err
	}
	return r, nil
}

func (r *rule) setConditions(rr rawRule) error {
	if rr.Conditions == nil {
		return nil
	}
	if rr.Conditions.TimeWindow != "" {
		w, err := parseTimeWindow(rr.Conditions.TimeWindow)
		if err != nil {
			return fmt.Errorf("rule %q: %w", rr.ID, err)
		}
		r.window = w
	}
	for _, name := range rr.Conditions.Weekdays {
		day, ok := weekdayNames[name]
		if !ok {
			return fmt.Errorf("%w: rule %q: unknown weekday %q", ErrSchema, rr.ID, name)
		}
		r.weekdays |= 1 << day
	}
	return nil
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

// buildApproval prüft Timeout (Nr. 7) und Freigebende (Nr. 8) und kopiert die Liste.
func buildApproval(field string, a rawApproval) (Approval, error) {
	if _, err := parseApprovalTimeout(a.Timeout); err != nil {
		return Approval{}, fmt.Errorf("%s: %w", field, err)
	}
	for _, approver := range a.Approvers {
		if err := checkDisplayedText(field+".approvers", approver); err != nil {
			return Approval{}, err
		}
	}
	return Approval{Timeout: a.Timeout, Approvers: slices.Clone(a.Approvers)}, nil
}

// parseApprovalTimeout liest PTnM, PTnS oder PTnMnS und prüft die Grenzen 10 s bis 1 h.
func parseApprovalTimeout(s string) (time.Duration, error) {
	rest, ok := strings.CutPrefix(s, "PT")
	if !ok || rest == "" {
		return 0, fmt.Errorf("%w: timeout %q", ErrSchema, s)
	}
	var total time.Duration
	if minutes, after, found := strings.Cut(rest, "M"); found {
		n, err := strconv.ParseUint(minutes, 10, 32)
		if err != nil {
			return 0, fmt.Errorf("%w: timeout %q", ErrSchema, s)
		}
		total, rest = time.Duration(n)*time.Minute, after
	}
	if rest != "" {
		seconds, ok := strings.CutSuffix(rest, "S")
		n, err := strconv.ParseUint(seconds, 10, 32)
		if !ok || err != nil {
			return 0, fmt.Errorf("%w: timeout %q", ErrSchema, s)
		}
		total += time.Duration(n) * time.Second
	}
	if total < minApprovalTimeout || total > maxApprovalTimeout {
		return 0, fmt.Errorf("%w: timeout %q outside 10s..1h", ErrSemantic, s)
	}
	return total, nil
}

// checkDisplayedText setzt SPEC-v0 Abschnitt 3.1 Nr. 8 um: keine Steuer-, Format-,
// Zeilen- oder Absatztrenner in Texten, die Menschen angezeigt werden.
func checkDisplayedText(field, s string) error {
	for _, r := range s {
		if unicode.In(r, unicode.Cc, unicode.Cf, unicode.Zl, unicode.Zp) {
			return fmt.Errorf("%w: %s contains U+%04X", ErrSemantic, field, r)
		}
	}
	return nil
}

func parseTimestamp(field, value string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: %s: %w", ErrSchema, field, err)
	}
	return t, nil
}

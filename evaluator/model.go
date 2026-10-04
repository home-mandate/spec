// SPDX-License-Identifier: Apache-2.0

package evaluator

import (
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/mandate-spec/mandate-spec/displaytext"
)

// Limits for approval.timeout (SPEC-v0 section 3.1 item 7).
const (
	minApprovalTimeout = 10 * time.Second
	maxApprovalTimeout = time.Hour
)

// Mandate is a valid mandate. It is created only by Parse and is immutable afterwards.
// The zero value is not a valid mandate; Evaluate returns ReasonInvalidMandate for it.
type Mandate struct {
	valid      bool
	id         string
	clientID   string
	principal  string
	digest     string
	validFrom  time.Time
	expires    time.Time
	hasExpires bool
	rules      []rule
	approval   Approval
}

// ID returns the mandate ID; empty for nil.
func (m *Mandate) ID() string {
	if m == nil {
		return ""
	}
	return m.id
}

// ClientID returns agent.client_id; empty for nil.
func (m *Mandate) ClientID() string {
	if m == nil {
		return ""
	}
	return m.clientID
}

// Principal returns the principal; empty for nil.
func (m *Mandate) Principal() string {
	if m == nil {
		return ""
	}
	return m.principal
}

// Digest returns the digest according to SPEC-v0 section 3.2; empty for nil.
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

// weekdaySet has one bit per time.Weekday; 0 means no condition.
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

// The raw* types mirror the schema; they are filled only after schema validation succeeds.
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
	m := &Mandate{id: raw.ID, clientID: raw.Agent.ClientID, principal: raw.Principal, digest: digest,
		rules: make([]rule, 0, len(raw.Rules))}
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

// setValidity reads the validity period (SPEC-v0 section 3.1 items 0 and 6).
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

// checkRuleVocabulary implements SPEC-v0 section 3.1 item 4. A rule that names a
// category of the vocabulary may use that category's actions; a rule without a category
// may use any action of the vocabulary. This keeps a misspelled action from silently
// disabling a rule. Rules for an extension category are not checked.
func checkRuleVocabulary(rr rawRule) error {
	category := rr.Resource.Category
	_, categoryKnown := vocabularyV0()[category]
	if category != "" && !categoryKnown {
		return nil // extension: its vocabulary is not known here
	}
	for _, action := range rr.Actions {
		if action == "*" {
			continue
		}
		known := knownAction(action)
		if categoryKnown {
			_, known, _ = lookupAction(category, action)
		}
		if !known {
			return fmt.Errorf("%w: rule %q: action %q not in the vocabulary", ErrSemantic, rr.ID, action)
		}
	}
	return nil
}

// buildApproval checks the timeout (item 7) and approvers (item 8) and copies the list.
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

// Duration returns the timeout as a duration; 0 if Timeout is not a valid timeout.
// Approval settings returned by Evaluate always carry a valid one.
func (a Approval) Duration() time.Duration {
	d, err := parseApprovalTimeout(a.Timeout)
	if err != nil {
		return 0
	}
	return d
}

// timeoutUnits are the components of a timeout in the order the schema requires.
var timeoutUnits = []struct {
	suffix string
	unit   time.Duration
}{{"H", time.Hour}, {"M", time.Minute}, {"S", time.Second}}

// maxTimeoutDigits matches the schema: at most 5 digits per component.
const maxTimeoutDigits = 5

// parseApprovalTimeout reads PT[nH][nM][nS] with at least one component and checks the
// limits of 10 s to 1 h.
func parseApprovalTimeout(s string) (time.Duration, error) {
	rest, ok := strings.CutPrefix(s, "PT")
	if !ok || rest == "" {
		return 0, fmt.Errorf("%w: timeout %q", ErrSchema, s)
	}
	var total time.Duration
	for _, u := range timeoutUnits {
		digits, after, found := strings.Cut(rest, u.suffix)
		if !found {
			continue
		}
		n, err := strconv.ParseUint(digits, 10, 32)
		if err != nil || len(digits) > maxTimeoutDigits || digits[0] == '+' {
			return 0, fmt.Errorf("%w: timeout %q", ErrSchema, s)
		}
		total, rest = total+time.Duration(n)*u.unit, after
	}
	if rest != "" {
		return 0, fmt.Errorf("%w: timeout %q", ErrSchema, s)
	}
	if total < minApprovalTimeout || total > maxApprovalTimeout {
		return 0, fmt.Errorf("%w: timeout %q outside 10s..1h", ErrSemantic, s)
	}
	return total, nil
}

// checkDisplayedText implements SPEC-v0 section 3.1 item 8 for text displayed to humans.
func checkDisplayedText(field, s string) error {
	if err := displaytext.Check(s); err != nil {
		return fmt.Errorf("%w: %s: %w", ErrSemantic, field, err)
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

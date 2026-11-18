// SPDX-License-Identifier: Apache-2.0

package evaluator

import (
	"encoding/json"
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/home-mandate/spec/displaytext"
	"github.com/home-mandate/spec/jcs"
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
	issuer     string
	version    int64 // 0 if the mandate has no version
	digest     string
	validFrom  time.Time
	expires    time.Time
	hasExpires bool
	// kid is the key ID by which ParseSigned accepted the mandate; empty for one that was not
	// signed.
	kid string
	// auditMode is true for "enforce": false (SPEC-v0 section 4.6).
	auditMode bool
	rules     []rule
	approval  Approval
	// What Narrows compares (SPEC-v0 section 3.5): the name, the audience, the rate
	// limit, the canonical form of the mandate's approval and of every rule.
	name         string
	displayName  string
	audience     string
	maxActions   int64
	approvalText string
	ruleTexts    []ruleText
}

// ruleText is a rule as Narrows sees it: its canonical form and what decides whether
// adding it can weaken a mandate.
type ruleText struct {
	id          string
	decision    Decision
	ownApproval bool
	text        string
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

// Issuer returns the issuer; empty for nil and for a mandate without issuer.
func (m *Mandate) Issuer() string {
	if m == nil {
		return ""
	}
	return m.issuer
}

// Version returns the version; 0 for nil and for a mandate without version.
func (m *Mandate) Version() int64 {
	if m == nil {
		return 0
	}
	return m.version
}

// Enforce reports whether the PEP enforces every deny of the mandate. It is false only for
// a mandate in audit mode ("enforce": false, SPEC-v0 section 4.6); nil enforces.
// Implementations show the household which mandates are in audit mode.
func (m *Mandate) Enforce() bool {
	return m == nil || !m.auditMode
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
	constraints   []constraint
	// period is the rule's own validity (SPEC-v0 section 4, step 2); the zero value has no
	// bounds.
	period period
	// dates are the ranges of calendar dates of conditions.dates (SPEC-v0 section 4.2); nil
	// means no condition.
	dates []dateRange
	// limits are the rule's own limits (SPEC-v0 section 11.2); nil if it has none.
	limits *RuleLimits
}

// RuleLimits are the limits a rule sets of its own (SPEC-v0 section 11.2), in addition to
// the limit of the mandate. A zero field does not limit; at least one is set.
type RuleLimits struct {
	// PerHour bounds the requests the rule lets through in every period of 3600 seconds.
	PerHour int
	// PerDay bounds them in every period of 86 400 seconds.
	PerDay int
	// MinInterval is the shortest time between two requests the rule lets through.
	MinInterval time.Duration
}

// period is a validity period: valid for points in time t with from ≤ t < until, where a
// bound that is not set does not restrict.
type period struct {
	from, until       time.Time
	hasFrom, hasUntil bool
}

// contains reports whether t lies in the period. Points in time are compared, not clock times.
func (p period) contains(t time.Time) bool {
	return (!p.hasFrom || !t.Before(p.from)) && (!p.hasUntil || t.Before(p.until))
}

// dateRange is a range of calendar dates, both inclusive, as YYYY-MM-DD; the text form
// orders like the dates.
type dateRange struct {
	from, to string
}

// constraint restricts one parameter of the action (SPEC-v0 section 4.5): an integer
// range, where a limit that the rule does not give is the smallest or largest int64; if
// oneOf is not nil, the permitted values; if noneOf is not nil, the excluded values.
type constraint struct {
	parameter string
	min, max  int64
	oneOf     []Value
	noneOf    []Value
}

// permits reports whether v satisfies the constraint. A range permits only integers, a
// list of permitted values only the values it contains, compared exactly, and a list of
// excluded values only values of its type that it does not contain: an integer never
// satisfies a list of strings, so a list that does not fit the parameter permits nothing.
func (c constraint) permits(v Value) bool {
	switch {
	case c.oneOf != nil:
		return slices.Contains(c.oneOf, v)
	case c.noneOf != nil:
		return v.kind == c.noneOf[0].kind && !slices.Contains(c.noneOf, v)
	}
	n, ok := v.AsInteger()
	return ok && n >= c.min && n <= c.max
}

// values returns the list of the constraint, permitted or excluded; nil for a range.
func (c constraint) values() []Value {
	if c.oneOf != nil {
		return c.oneOf
	}
	return c.noneOf
}

// fits reports whether the constraint fits the parameter's declaration in the vocabulary
// (SPEC-v0 section 3.1 item 10): a range only an integer parameter, a list only values the
// parameter admits.
func (c constraint) fits(p parameterInfo) bool {
	list := c.values()
	if list == nil {
		return p.Type == typeInteger
	}
	for _, v := range list {
		if !p.declares(v) {
			return false
		}
	}
	return true
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
	Actions   []string `json:"actions"`
	Decision  string   `json:"decision"`
	Note      string   `json:"note"`
	ValidFrom string   `json:"valid_from"`
	Expires   string   `json:"expires"`
	Limits    *struct {
		MaxActionsPerHour json.Number `json:"max_actions_per_hour"`
		MaxActionsPerDay  json.Number `json:"max_actions_per_day"`
		MinInterval       string      `json:"min_interval"`
	} `json:"limits"`
	Conditions *struct {
		TimeWindow string   `json:"time_window"`
		Weekdays   []string `json:"weekdays"`
		Dates      []struct {
			From string `json:"from"`
			To   string `json:"to"`
		} `json:"dates"`
	} `json:"conditions"`
	Constraints   map[string]rawConstraint `json:"constraints"`
	Approval      *rawApproval             `json:"approval"`
	AllowCritical bool                     `json:"allow_critical"`
}

type rawConstraint struct {
	Min    *json.Number      `json:"min"`
	Max    *json.Number      `json:"max"`
	OneOf  []json.RawMessage `json:"one_of"`
	NoneOf []json.RawMessage `json:"none_of"`
}

type rawMandate struct {
	Type      string `json:"type"`
	ID        string `json:"id"`
	Name      string `json:"name"`
	Principal string `json:"principal"`
	Agent     struct {
		ClientID    string `json:"client_id"`
		DisplayName string `json:"display_name"`
	} `json:"agent"`
	Enforce  *bool       `json:"enforce"`
	Rules    []rawRule   `json:"rules"`
	Default  string      `json:"default"`
	Approval rawApproval `json:"approval"`
	Limits   struct {
		MaxActionsPerHour json.Number `json:"max_actions_per_hour"`
	} `json:"limits"`
	Issuer    string      `json:"issuer"`
	Version   json.Number `json:"version"`
	Audience  string      `json:"audience"`
	ValidFrom string      `json:"valid_from"`
	Expires   string      `json:"expires"`
	CreatedBy string      `json:"created_by"`
	CreatedAt string      `json:"created_at"`
}

var weekdayNames = map[string]time.Weekday{
	"sun": time.Sunday, "mon": time.Monday, "tue": time.Tuesday, "wed": time.Wednesday,
	"thu": time.Thursday, "fri": time.Friday, "sat": time.Saturday,
}

func buildMandate(raw rawMandate, digest string, instance any) (*Mandate, error) {
	m := &Mandate{id: raw.ID, clientID: raw.Agent.ClientID, principal: raw.Principal, digest: digest,
		auditMode: raw.Enforce != nil && !*raw.Enforce, rules: make([]rule, 0, len(raw.Rules)),
		name: raw.Name, displayName: raw.Agent.DisplayName, audience: raw.Audience}
	if n, ok := integerValue(raw.Limits.MaxActionsPerHour); ok {
		m.maxActions = n
	}
	if err := m.setTexts(instance); err != nil {
		return nil, err
	}
	if err := m.setValidity(raw); err != nil {
		return nil, err
	}
	if raw.Version != "" {
		version, ok := integerValue(raw.Version)
		if !ok {
			return nil, fmt.Errorf("%w: version is not an integer", ErrSchema)
		}
		m.issuer, m.version = raw.Issuer, version
	}
	if err := checkDisplayedText("agent.display_name", raw.Agent.DisplayName); err != nil {
		return nil, err
	}
	if err := checkDisplayedText("created_by", raw.CreatedBy); err != nil {
		return nil, err
	}
	// name and note are optional; the schema has already rejected an empty one.
	if raw.Name != "" {
		if err := checkDisplayedText("name", raw.Name); err != nil {
			return nil, err
		}
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

// setTexts keeps the canonical form of the approval and of every rule, for Narrows.
// instance is the decoded document the schema validated.
func (m *Mandate) setTexts(instance any) error {
	top, _ := instance.(map[string]any)
	approval, err := jcs.Canonicalize(top["approval"])
	if err != nil {
		return fmt.Errorf("%w: %w", ErrSchema, err)
	}
	m.approvalText = string(approval)
	rules, _ := top["rules"].([]any)
	for _, r := range rules {
		obj, _ := r.(map[string]any)
		text, err := jcs.Canonicalize(obj)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrSchema, err)
		}
		id, _ := obj["id"].(string)
		decision, _ := obj["decision"].(string)
		_, ownApproval := obj["approval"]
		m.ruleTexts = append(m.ruleTexts, ruleText{id: id, decision: Decision(decision), ownApproval: ownApproval, text: string(text)})
	}
	return nil
}

// Audience returns the verifier the mandate is for; empty if it names none or for nil.
func (m *Mandate) Audience() string {
	if m == nil {
		return ""
	}
	return m.audience
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
	if rr.Note != "" {
		if err := checkDisplayedText("rule "+strconv.Quote(rr.ID)+" note", rr.Note); err != nil {
			return rule{}, err
		}
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
	if err := r.setPeriod(rr); err != nil {
		return rule{}, err
	}
	if err := r.setLimits(rr); err != nil {
		return rule{}, err
	}
	if err := r.setConditions(rr); err != nil {
		return rule{}, err
	}
	if err := r.setConstraints(rr); err != nil {
		return rule{}, err
	}
	return r, nil
}

// setConstraints implements SPEC-v0 section 3.1 item 10. The schema already restricts
// constraints to allow rules without "*".
func (r *rule) setConstraints(rr rawRule) error {
	category := rr.Resource.Category
	_, categoryKnown := vocabularyV0()[category]
	checked := category == "" || categoryKnown // extension categories are not checked
	names := make([]string, 0, len(rr.Constraints))
	for name := range rr.Constraints {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		c, err := buildConstraint(rr.ID, name, rr.Constraints[name])
		if err != nil {
			return err
		}
		for _, action := range rr.Actions {
			if checked && !parameterFits(category, action, c) {
				return fmt.Errorf("%w: rule %q: action %q has no parameter %q that the constraint fits", ErrSemantic, rr.ID, action, name)
			}
		}
		r.constraints = append(r.constraints, c)
	}
	return nil
}

// maxValueList is the largest number of values in a one_of or none_of (SPEC-v0 section 4.5).
const maxValueList = 32

// buildConstraint reads one constraint: a list of permitted or excluded values, or limits.
// It checks a list itself, although the schema already does, so that no caller gets a list
// that contradicts SPEC-v0 section 4.5.
func buildConstraint(ruleID, name string, raw rawConstraint) (constraint, error) {
	c := constraint{parameter: name, min: math.MinInt64, max: math.MaxInt64}
	if raw.OneOf != nil || raw.NoneOf != nil {
		member, list := "one_of", raw.OneOf
		if raw.NoneOf != nil {
			member, list = "none_of", raw.NoneOf
		}
		if raw.Min != nil || raw.Max != nil || raw.OneOf != nil && raw.NoneOf != nil {
			return constraint{}, fmt.Errorf("%w: rule %q: constraint %q has %s together with another form", ErrSemantic, ruleID, name, member)
		}
		values, err := buildValueList(member, list)
		if err != nil {
			return constraint{}, fmt.Errorf("rule %q: constraint %q: %w", ruleID, name, err)
		}
		if raw.NoneOf != nil {
			c.noneOf = values
		} else {
			c.oneOf = values
		}
		return c, nil
	}
	for _, limit := range []struct {
		raw    *json.Number
		target *int64
	}{{raw.Min, &c.min}, {raw.Max, &c.max}} {
		if limit.raw == nil {
			continue
		}
		value, ok := integerValue(*limit.raw)
		if !ok {
			return constraint{}, fmt.Errorf("%w: rule %q: constraint %q is not an integer", ErrSchema, ruleID, name)
		}
		*limit.target = value
	}
	if c.min > c.max {
		return constraint{}, fmt.Errorf("%w: rule %q: constraint %q has min greater than max", ErrSemantic, ruleID, name)
	}
	return c, nil
}

// buildValueList reads the values of a one_of or none_of (member): 1 to 32 distinct valid
// values of one type.
func buildValueList(member string, raw []json.RawMessage) ([]Value, error) {
	if len(raw) == 0 || len(raw) > maxValueList {
		return nil, fmt.Errorf("%w: %s has %d values, permitted are 1 to %d", ErrSemantic, member, len(raw), maxValueList)
	}
	values := make([]Value, len(raw))
	for i, data := range raw {
		v := &values[i]
		if err := v.UnmarshalJSON(data); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrSchema, err)
		}
		switch {
		case !v.valid():
			return nil, fmt.Errorf("%w: %s value %s is no valid parameter value", ErrSemantic, member, data)
		case v.kind != values[0].kind:
			return nil, fmt.Errorf("%w: %s mixes integers and strings", ErrSemantic, member)
		case slices.Contains(values[:i], *v):
			return nil, fmt.Errorf("%w: %s has the value %s twice", ErrSemantic, member, data)
		}
	}
	return values, nil
}

// integerValue reads an integer by its exact value: 20, 20.0 and 2e1 are the same number,
// 20.000000000000000001 and 1e-400 are no integers. The magnitude is below 2^53, the
// integers that are exact in every JSON implementation (RFC 7493).
func integerValue(n json.Number) (int64, bool) {
	value, err := exactInteger(n.String())
	return value, err == nil
}

// constraintsMet reports whether the request carries every constrained parameter with
// a value the constraint permits: within the limits, both inclusive, or one of the
// listed values.
func (r *rule) constraintsMet(parameters map[string]Value) bool {
	for _, c := range r.constraints {
		value, ok := parameters[c.parameter]
		if !ok || !c.permits(value) {
			return false
		}
	}
	return true
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
	for _, d := range rr.Conditions.Dates {
		if err := checkDates(d.From, d.To); err != nil {
			return fmt.Errorf("rule %q: %w", rr.ID, err)
		}
		r.dates = append(r.dates, dateRange{from: d.From, to: d.To})
	}
	return nil
}

// dateLayout is the form of a calendar date (RFC 3339 full-date).
const dateLayout = "2006-01-02"

// checkDates checks a range of dates (SPEC-v0 section 3.1 items 0 and 3): two dates that
// exist, not in year 0000, from not after to. The schema has checked the form already; the
// check is repeated so that no caller gets a range that contradicts the specification.
func checkDates(from, to string) error {
	for _, d := range []string{from, to} {
		if t, err := time.Parse(dateLayout, d); err != nil || t.Year() == 0 || t.Format(dateLayout) != d {
			return fmt.Errorf("%w: date %q", ErrSchema, d)
		}
	}
	if from > to {
		return fmt.Errorf("%w: dates: from %s is after to %s", ErrSemantic, from, to)
	}
	return nil
}

// setPeriod reads the rule's own validity (SPEC-v0 section 3.1 items 0 and 6).
func (r *rule) setPeriod(rr rawRule) error {
	if rr.ValidFrom != "" {
		from, err := parseTimestamp("rule "+strconv.Quote(rr.ID)+" valid_from", rr.ValidFrom)
		if err != nil {
			return err
		}
		r.period.from, r.period.hasFrom = from, true
	}
	if rr.Expires != "" {
		until, err := parseTimestamp("rule "+strconv.Quote(rr.ID)+" expires", rr.Expires)
		if err != nil {
			return err
		}
		if r.period.hasFrom && !until.After(r.period.from) {
			return fmt.Errorf("%w: rule %q: expires must be after valid_from", ErrSemantic, rr.ID)
		}
		r.period.until, r.period.hasUntil = until, true
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
	total, err := parseDuration(s)
	if err != nil {
		return 0, err
	}
	if total < minApprovalTimeout || total > maxApprovalTimeout {
		return 0, fmt.Errorf("%w: timeout %q outside 10s..1h", ErrSemantic, s)
	}
	return total, nil
}

// Limits of a rule's min_interval (SPEC-v0 section 3.1 item 12).
const (
	minRuleInterval = time.Second
	maxRuleInterval = 24 * time.Hour
)

// setLimits reads the rule's own limits (SPEC-v0 section 3.1 item 12). The schema already
// restricts them to allow rules and bounds the counts; the interval is checked here.
func (r *rule) setLimits(rr rawRule) error {
	if rr.Limits == nil {
		return nil
	}
	if r.decision != Allow {
		return fmt.Errorf("%w: rule %q: limits only on an allow rule", ErrSemantic, rr.ID)
	}
	var limits RuleLimits
	for _, count := range []struct {
		raw    json.Number
		target *int
	}{{rr.Limits.MaxActionsPerHour, &limits.PerHour}, {rr.Limits.MaxActionsPerDay, &limits.PerDay}} {
		if count.raw == "" {
			continue
		}
		n, ok := integerValue(count.raw)
		if !ok || n < 1 {
			return fmt.Errorf("%w: rule %q: limit %s", ErrSchema, rr.ID, count.raw)
		}
		*count.target = int(n)
	}
	if rr.Limits.MinInterval != "" {
		interval, err := parseDuration(rr.Limits.MinInterval)
		if err != nil {
			return fmt.Errorf("rule %q: min_interval: %w", rr.ID, err)
		}
		if interval < minRuleInterval || interval > maxRuleInterval {
			return fmt.Errorf("%w: rule %q: min_interval %q outside 1s..24h", ErrSemantic, rr.ID, rr.Limits.MinInterval)
		}
		limits.MinInterval = interval
	}
	if limits == (RuleLimits{}) {
		return fmt.Errorf("%w: rule %q: limits without a member", ErrSemantic, rr.ID)
	}
	r.limits = &limits
	return nil
}

// parseDuration reads PT[nH][nM][nS] with at least one component, each of 1 to 5 digits,
// in this order; its value is the sum of the components.
func parseDuration(s string) (time.Duration, error) {
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
		if err != nil || len(digits) > maxTimeoutDigits {
			return 0, fmt.Errorf("%w: timeout %q", ErrSchema, s)
		}
		total, rest = total+time.Duration(n)*u.unit, after
	}
	if rest != "" {
		return 0, fmt.Errorf("%w: timeout %q", ErrSchema, s)
	}
	return total, nil
}

// RuleLimits returns the limits the rule with ruleID sets of its own (SPEC-v0 section 11.2);
// false if the mandate is nil or has no such rule, or the rule has none.
func (m *Mandate) RuleLimits(ruleID string) (RuleLimits, bool) {
	if m == nil {
		return RuleLimits{}, false
	}
	for i := range m.rules {
		if r := &m.rules[i]; r.id == ruleID && r.limits != nil {
			return *r.limits, true
		}
	}
	return RuleLimits{}, false
}

// MaxActionsPerHour returns limits.max_actions_per_hour, N of SPEC-v0 section 11.2; 0 for nil.
func (m *Mandate) MaxActionsPerHour() int {
	if m == nil {
		return 0
	}
	return int(m.maxActions)
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

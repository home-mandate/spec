// SPDX-License-Identifier: Apache-2.0

// Package evaluator is the reference evaluator of mandate-spec v0 (SPEC-v0.md
// sections 3.1, 3.2 and 4). It uses only the standard library and a
// JSON Schema validator. When in doubt, the result is always Deny.
package evaluator

import (
	"regexp"
	"slices"
	"time"
)

// Patterns for entity_id and area from schema/mandate-v0.schema.json; they apply to the
// request as well (SPEC-v0 section 4, step 0). In Go regexps, $ matches only the end of text.
var (
	entityIDPattern = regexp.MustCompile(`^[a-z0-9_]+\.[a-z0-9_]+$`)
	areaPattern     = regexp.MustCompile(`^[a-z0-9_]{1,64}$`)
)

// Decision is the decision of the evaluation.
type Decision string

// Decisions according to SPEC-v0 section 2.
const (
	Allow Decision = "allow"
	Ask   Decision = "ask"
	Deny  Decision = "deny"
)

// Reason is the reason code according to SPEC-v0 section 4.1.
type Reason string

// Reason codes in the precedence order from SPEC-v0 section 4.1.
const (
	ReasonInvalidMandate   Reason = "invalid_mandate"
	ReasonInvalidRequest   Reason = "invalid_request"
	ReasonUnknownCategory  Reason = "unknown_category"
	ReasonUnknownAction    Reason = "unknown_action"
	ReasonRevoked          Reason = "revoked"
	ReasonNotYetValid      Reason = "not_yet_valid"
	ReasonExpired          Reason = "expired"
	ReasonNoMatch          Reason = "no_match"
	ReasonCriticalDemotion Reason = "critical_demotion"
	ReasonRule             Reason = "rule"
)

// Resource is the requested resource with category and area already resolved.
type Resource struct {
	EntityID string
	Category string
	Area     string
}

// MandateStatus is the status of the mandate as managed by the PEP.
type MandateStatus string

// Permitted statuses according to SPEC-v0 section 4. Any other value, including the empty one, is invalid.
const (
	StatusActive  MandateStatus = "active"
	StatusRevoked MandateStatus = "revoked"
)

// Request is the input to the evaluation. Category, area, time, time zone and status
// come from the PEP, never from the agent (SPEC-v0 section 4, origin of inputs).
type Request struct {
	Resource Resource
	Action   string
	Time     time.Time
	// TimeZone is the household's time zone as an IANA name. If empty, the offset of Time applies.
	TimeZone string
	// Status is required; a missing status leads to Deny, never to an active mandate.
	Status MandateStatus
}

// Approval holds the approval settings for an approval request.
type Approval struct {
	Timeout   string
	Approvers []string
}

// Result is the result of the evaluation according to SPEC-v0 section 4.1.
type Result struct {
	Decision Decision
	Reason   Reason
	// RuleID is empty if no rule determines the decision.
	RuleID string
	// Approval is set only for Ask.
	Approval *Approval
	// MandateDigest is empty for ReasonInvalidMandate.
	MandateDigest string
}

// Evaluate evaluates req against m according to SPEC-v0 section 4. The result contains
// copies; changing them does not affect m.
func Evaluate(m *Mandate, req Request) Result {
	if m == nil || !m.valid {
		return Result{Decision: Deny, Reason: ReasonInvalidMandate}
	}
	local, critical, reason := precheck(m, req)
	if reason != "" {
		return Result{Decision: Deny, Reason: reason, MandateDigest: m.digest}
	}
	matched := matchingRules(m, req, local)
	if len(matched) == 0 {
		return Result{Decision: Deny, Reason: ReasonNoMatch, MandateDigest: m.digest}
	}
	return decide(m, matched, critical)
}

// precheck implements steps 0 and 1 of SPEC-v0 section 4 in the precedence order of
// section 4.1. It returns the household local time, whether the action is critical and,
// on denial, the reason.
func precheck(m *Mandate, req Request) (local time.Time, critical bool, reason Reason) {
	local, ok := localTime(req.Time, req.TimeZone)
	if !ok || !validRequest(req) {
		return time.Time{}, false, ReasonInvalidRequest
	}
	categoryKnown, actionKnown, critical := lookupAction(req.Resource.Category, req.Action)
	switch {
	case !categoryKnown:
		return time.Time{}, false, ReasonUnknownCategory
	case !actionKnown:
		return time.Time{}, false, ReasonUnknownAction
	case req.Status == StatusRevoked:
		return time.Time{}, false, ReasonRevoked
	case req.Time.Before(m.validFrom):
		return time.Time{}, false, ReasonNotYetValid
	case m.hasExpires && !req.Time.Before(m.expires):
		return time.Time{}, false, ReasonExpired
	}
	return local, critical, ""
}

// validRequest checks the request fields named in step 0. Without this check,
// "Lock.keller", for example, would bypass a deny rule for "lock.keller".
func validRequest(req Request) bool {
	res := req.Resource
	return res.Category != "" &&
		entityIDPattern.MatchString(res.EntityID) &&
		(res.Area == "" || areaPattern.MatchString(res.Area)) &&
		(req.Status == StatusActive || req.Status == StatusRevoked)
}

// matchingRules implements step 2 and preserves document order.
func matchingRules(m *Mandate, req Request, local time.Time) []*rule {
	var matched []*rule
	for i := range m.rules {
		r := &m.rules[i]
		if r.selector.matches(req.Resource) && r.coversAction(req.Action) && r.conditionsMet(local) {
			matched = append(matched, r)
		}
	}
	return matched
}

func (s selector) matches(res Resource) bool {
	if s.any {
		return true
	}
	return (s.entityID == "" || s.entityID == res.EntityID) &&
		(s.category == "" || s.category == res.Category) &&
		(s.area == "" || s.area == res.Area)
}

func (r *rule) coversAction(action string) bool {
	for _, a := range r.actions {
		if a == "*" || a == action {
			return true
		}
	}
	return false
}

// decide implements steps 4 and 5 and section 4.1; matched is not empty.
func decide(m *Mandate, matched []*rule, critical bool) Result {
	final := Allow
	for _, r := range matched {
		if strictness(r.decision) > strictness(final) {
			final = r.decision
		}
	}
	result := Result{Decision: final, Reason: ReasonRule, MandateDigest: m.digest}
	for _, r := range matched {
		if r.decision == final {
			result.RuleID = r.id
			break
		}
	}
	if strictness(final) == strictness(Deny) {
		result.Decision = Deny // unknown decisions count as deny
	}
	switch {
	case final == Ask:
		result.Approval = askApproval(m, matched)
	case final == Allow && critical:
		for _, r := range matched {
			if !r.allowCritical {
				result.Decision, result.Reason, result.RuleID = Ask, ReasonCriticalDemotion, r.id
				result.Approval = m.approval.clone()
				break
			}
		}
	}
	return result
}

// strictness orders decisions according to step 4; anything other than allow and ask counts as deny.
func strictness(d Decision) int {
	switch d {
	case Allow:
		return 0
	case Ask:
		return 1
	}
	return 2
}

// askApproval returns the approval settings of the first matching ask rule that has its
// own approval, otherwise those of the mandate.
func askApproval(m *Mandate, matched []*rule) *Approval {
	for _, r := range matched {
		if r.decision == Ask && r.approval != nil {
			return r.approval.clone()
		}
	}
	return m.approval.clone()
}

func (a Approval) clone() *Approval {
	return &Approval{Timeout: a.Timeout, Approvers: slices.Clone(a.Approvers)}
}

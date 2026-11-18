// SPDX-License-Identifier: Apache-2.0

package harness

import (
	"time"

	"github.com/home-mandate/spec/evaluator"
	"github.com/home-mandate/spec/ratelimit"
	"github.com/home-mandate/spec/rfc3339"
)

// limitWithoutMandate is the limit per hour for the requests of an agent and principal for
// which the selection yields no single valid mandate, as SPEC-v0 section 11.2 recommends.
const limitWithoutMandate = 60

// denial says whether, and where, a rate limit denied a request (SPEC-v0 sections 6 and 11.2).
type denial int

const (
	notDenied denial = iota
	// deniedBeforeEvaluation: N, or the limit without a mandate; nothing was evaluated.
	deniedBeforeEvaluation
	// deniedAfterEvaluation: the limits of a rule, after an evaluation that allowed.
	deniedAfterEvaluation
)

// pdpLimits are the rate limits a PDP apart from its PEP enforces, since it holds the
// mandates (SPEC-v0 sections 6 and 11.2). The reference PDP of the test interface keeps them
// for one state: a new state, and a restart, start them again. A PDP in service keeps them
// across a restart.
type pdpLimits struct {
	mandates *ratelimit.Limiter
	rules    *ratelimit.RuleLimiter
}

// newPDPLimits returns limits that use the point in time of the state as their clock, as the
// evaluation does; a state without a readable time uses the zero time.
func newPDPLimits(at string) *pdpLimits {
	t, _ := rfc3339.Parse(at)
	now := func() time.Time { return t }
	return &pdpLimits{mandates: ratelimit.New(now), rules: ratelimit.NewRuleLimiter(now)}
}

// check counts the request whose evaluation answer gave and reports whether a rate limit
// denies it. The order is that of SPEC-v0 section 11.2: the mandate is selected, then N is
// checked, and the limits of the rules after an evaluation that allowed.
func (l *pdpLimits) check(state State, subject Subject, answer Response) denial {
	m := ownLimit(state, answer)
	if m == nil {
		limit := limitWithoutMandate
		if answer.Reason == string(evaluator.ReasonAmbiguousMandate) {
			limit = min(limit, smallestN(state, subject))
		}
		// Mandate ids contain no NUL, so the key cannot be the id of a mandate.
		if !l.mandates.Allow("\x00"+subject.ClientID+"\x00"+subject.Principal, limit) {
			return deniedBeforeEvaluation
		}
		return notDenied
	}
	if !l.mandates.Allow(m.ID(), m.MaxActionsPerHour()) {
		return deniedBeforeEvaluation
	}
	if answer.Decision != string(evaluator.Allow) || len(answer.LimitedRules) == 0 {
		return notDenied
	}
	rules := make([]ratelimit.Rule, 0, len(answer.LimitedRules))
	for _, id := range answer.LimitedRules {
		limits, _ := m.RuleLimits(id)
		rules = append(rules, ratelimit.Rule{Key: ratelimit.RuleKey(m.ID(), id),
			PerHour: limits.PerHour, PerDay: limits.PerDay, MinInterval: limits.MinInterval})
	}
	if !l.rules.AllowN(rules, 1) {
		return deniedAfterEvaluation
	}
	return notDenied
}

// ownLimit returns the mandate whose N the request counts against: the single valid mandate
// the selection evaluated. It is nil for no_mandate, ambiguous_mandate, invalid_mandate and
// revoked, which have no N of their own.
func ownLimit(state State, answer Response) *evaluator.Mandate {
	switch evaluator.Reason(answer.Reason) {
	case evaluator.ReasonNoMandate, evaluator.ReasonAmbiguousMandate, evaluator.ReasonInvalidMandate, evaluator.ReasonRevoked:
		return nil
	}
	if answer.Selected == nil || answer.MandateDigest == "" {
		return nil
	}
	for _, s := range state.Mandates {
		if m, err := evaluator.Parse([]byte(s.Mandate)); err == nil && m.Digest() == answer.MandateDigest {
			return m
		}
	}
	return nil
}

// smallestN returns the smallest N of the valid mandates of the agent and principal that are
// not revoked, for ambiguous_mandate (SPEC-v0 section 11.2).
func smallestN(state State, subject Subject) int {
	n := limitWithoutMandate
	for _, s := range state.Mandates {
		m, err := evaluator.Parse([]byte(s.Mandate))
		if err == nil && !s.Revoked && m.ClientID() == subject.ClientID && m.Principal() == subject.Principal {
			n = min(n, m.MaxActionsPerHour())
		}
	}
	return n
}

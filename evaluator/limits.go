// SPDX-License-Identifier: Apache-2.0

package evaluator

import (
	"math"
	"slices"
)

// Limit is what one constraint allows for a parameter (SPEC-v0 section 4.5): either the
// inclusive range of an integer, where a bound the rule does not give is nil, or, if OneOf
// is not nil, the permitted values in the order of the mandate, or, if NoneOf is not nil,
// the excluded values in that order. A Limit with OneOf or NoneOf has neither Min nor Max,
// yet does not permit every value: a caller must check OneOf and NoneOf before it reads nil
// bounds as unbounded.
type Limit struct {
	Min, Max *int64
	OneOf    []Value
	NoneOf   []Value
}

// Limits tells what values a request could be allowed with: for every allow rule that
// matches req apart from its constraints, in document order, the limits the rule sets on
// the parameters (empty for a rule without constraints). The parameters of req are
// ignored. It is nil if no allow rule matches, the mandate is nil, invalid or in audit
// mode, or the request is denied before the rules (steps 0 and 1).
//
// It decides nothing: a deny or ask rule can still decide, and only Evaluate does. A PEP
// uses it to tell an agent its own limits, e.g. after a no_match. A mandate in audit mode
// names none (SPEC-v0 sections 11.5 and 11.6 item 2): an agent that succeeded outside the
// limits it was told would learn that the mandate does not enforce.
func (m *Mandate) Limits(req Request) []map[string]Limit {
	if m == nil || !m.valid || m.auditMode {
		return nil
	}
	// The question is asked before any parameter exists, so the parameters, required or
	// not, are not checked.
	req.Parameters = nil
	local, _, reason := precheckInputs(m, req, false)
	if reason != "" {
		return nil
	}
	var out []map[string]Limit
	for i := range m.rules {
		r := &m.rules[i]
		if r.decision != Allow || !r.selector.matches(req.Resource) || !r.coversAction(req.Action) ||
			!r.period.contains(req.Time) || !r.conditionsMet(local) {
			continue
		}
		limits := map[string]Limit{}
		for _, c := range r.constraints {
			var l Limit
			if c.oneOf != nil {
				limits[c.parameter] = Limit{OneOf: slices.Clone(c.oneOf)}
				continue
			}
			if c.noneOf != nil {
				limits[c.parameter] = Limit{NoneOf: slices.Clone(c.noneOf)}
				continue
			}
			if c.min != math.MinInt64 {
				l.Min = &c.min
			}
			if c.max != math.MaxInt64 {
				l.Max = &c.max
			}
			limits[c.parameter] = l
		}
		out = append(out, limits)
	}
	return out
}

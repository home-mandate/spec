// SPDX-License-Identifier: Apache-2.0

package evaluator

import "math"

// Limit is the inclusive range one constraint allows for a parameter (SPEC-v0 section
// 4.5); a bound the rule does not give is nil.
type Limit struct {
	Min, Max *int64
}

// Limits tells what values a request could be allowed with: for every allow rule that
// matches req apart from its constraints, in document order, the limits the rule sets on
// the parameters (empty for a rule without constraints). The parameters of req are
// ignored. It is nil if no allow rule matches, the mandate is nil or invalid, or the
// request is denied before the rules (steps 0 and 1).
//
// It decides nothing: a deny or ask rule can still decide, and only Evaluate does. A PEP
// uses it to tell an agent its own limits, e.g. after a no_match.
func (m *Mandate) Limits(req Request) []map[string]Limit {
	if m == nil || !m.valid {
		return nil
	}
	req.Parameters = nil
	local, _, reason := precheck(m, req)
	if reason != "" {
		return nil
	}
	var out []map[string]Limit
	for i := range m.rules {
		r := &m.rules[i]
		if r.decision != Allow || !r.selector.matches(req.Resource) || !r.coversAction(req.Action) || !r.conditionsMet(local) {
			continue
		}
		limits := map[string]Limit{}
		for _, c := range r.constraints {
			var l Limit
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

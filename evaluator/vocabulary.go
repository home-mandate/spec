// SPDX-License-Identifier: Apache-2.0

package evaluator

import (
	"encoding/json"
	"slices"
	"sync"

	"github.com/home-mandate/spec/vocabulary"
)

// actionInfo is what the vocabulary says about one action.
type actionInfo struct {
	critical   bool
	parameters map[string]parameterInfo
}

// parameterInfo is what the vocabulary says about one parameter (SPEC-v0 sections 4.5
// and 5): its type, for an integer the inclusive range (nil: not bounded), and for a
// string the permitted values (nil: any string).
type parameterInfo struct {
	Type    string   `json:"type"`
	Minimum *int64   `json:"minimum"`
	Maximum *int64   `json:"maximum"`
	Values  []string `json:"values"`
}

// admits reports whether a request may carry v for the parameter (SPEC-v0 section 4,
// step 0): v fits the declaration and, for an integer with a range, lies within it.
func (p parameterInfo) admits(v Value) bool {
	if !p.declares(v) {
		return false
	}
	n, isInteger := v.AsInteger()
	if !isInteger {
		return true
	}
	return (p.Minimum == nil || n >= *p.Minimum) && (p.Maximum == nil || n <= *p.Maximum)
}

// declares reports whether v has the type of the parameter and, for a string with
// permitted values, is one of them; strings are compared exactly. The range of an
// integer is not part of it: a mandate may name a value outside the range, which no
// valid request carries (SPEC-v0 section 4.5).
func (p parameterInfo) declares(v Value) bool {
	switch p.Type {
	case typeInteger:
		_, ok := v.AsInteger()
		return ok
	case typeString:
		s, ok := v.AsString()
		return ok && (p.Values == nil || slices.Contains(p.Values, s))
	}
	return false
}

// vocabularyV0 reads the vocabulary from SPEC-v0 section 5 out of the normative file:
// category → action → properties. It is read-only. The file is embedded and covered by
// the tests; a file that cannot be read yields an empty vocabulary, so that every
// request is denied.
var vocabularyV0 = sync.OnceValue(func() map[string]map[string]actionInfo {
	var doc struct {
		Categories map[string]struct {
			Actions map[string]struct {
				Critical   bool                     `json:"critical"`
				Parameters map[string]parameterInfo `json:"parameters"`
			} `json:"actions"`
		} `json:"categories"`
	}
	if err := json.Unmarshal(vocabulary.V0(), &doc); err != nil {
		return nil
	}
	out := make(map[string]map[string]actionInfo, len(doc.Categories))
	for category, c := range doc.Categories {
		actions := make(map[string]actionInfo, len(c.Actions))
		for action, a := range c.Actions {
			actions[action] = actionInfo{critical: a.Critical, parameters: a.Parameters}
		}
		out[category] = actions
	}
	return out
})

// lookupAction reports whether the category is known, whether the action belongs to it
// and whether the action is critical.
func lookupAction(category, action string) (categoryKnown, actionKnown, critical bool) {
	actions, ok := vocabularyV0()[category]
	if !ok {
		return false, false, false
	}
	info, actionKnown := actions[action]
	return true, actionKnown, info.critical
}

// knownAction reports whether any category of the vocabulary has the action.
func knownAction(action string) bool {
	for _, actions := range vocabularyV0() {
		if _, ok := actions[action]; ok {
			return true
		}
	}
	return false
}

// parameterFits reports whether the action has the parameter and the constraint fits its
// type and permitted values (SPEC-v0 section 3.1 item 10): in the given category, or with
// an empty category in any category of the vocabulary.
func parameterFits(category, action string, c constraint) bool {
	for name, actions := range vocabularyV0() {
		if category != "" && name != category {
			continue
		}
		if p, ok := actions[action].parameters[c.parameter]; ok && c.fits(p) {
			return true
		}
	}
	return false
}

// parametersAdmitted reports whether every parameter of the request that the action
// declares has its type and lies within its range or is one of its permitted values (SPEC-v0 section 4,
// step 0). Parameters the action does not declare, and every parameter of a category or
// action outside the vocabulary, are not checked here.
func parametersAdmitted(category, action string, parameters map[string]Value) bool {
	declared := vocabularyV0()[category][action].parameters
	for name, value := range parameters {
		if p, ok := declared[name]; ok && !p.admits(value) {
			return false
		}
	}
	return true
}

// IsCritical reports whether action is a critical action of category in vocabulary v0
// (SPEC-v0 section 5), for example to decide how an approval request may be answered.
// Anything outside the vocabulary counts as critical: an unknown action is never
// treated as harmless.
func IsCritical(category, action string) bool {
	_, known, critical := lookupAction(category, action)
	return !known || critical
}

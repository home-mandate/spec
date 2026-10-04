// SPDX-License-Identifier: Apache-2.0

package evaluator

import (
	"encoding/json"
	"sync"

	"github.com/mandate-spec/mandate-spec/vocabulary"
)

// actionInfo is what the vocabulary says about one action.
type actionInfo struct {
	critical   bool
	parameters map[string]struct{}
}

// vocabularyV0 reads the vocabulary from SPEC-v0 section 5 out of the normative file:
// category → action → properties. It is read-only. The file is embedded and covered by
// the tests; a file that cannot be read yields an empty vocabulary, so that every
// request is denied.
var vocabularyV0 = sync.OnceValue(func() map[string]map[string]actionInfo {
	var doc struct {
		Categories map[string]struct {
			Actions map[string]struct {
				Critical   bool                `json:"critical"`
				Parameters map[string]struct{} `json:"parameters"`
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

// hasParameter reports whether the action has the parameter: in the given category, or
// with an empty category in any category of the vocabulary.
func hasParameter(category, action, parameter string) bool {
	for name, actions := range vocabularyV0() {
		if category != "" && name != category {
			continue
		}
		if _, ok := actions[action].parameters[parameter]; ok {
			return true
		}
	}
	return false
}

// IsCritical reports whether action is a critical action of category in vocabulary v0
// (SPEC-v0 section 5), for example to decide how an approval request may be answered.
// Anything outside the vocabulary counts as critical: an unknown action is never
// treated as harmless.
func IsCritical(category, action string) bool {
	_, known, critical := lookupAction(category, action)
	return !known || critical
}

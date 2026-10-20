// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"encoding/json"
	"sync"

	"github.com/home-mandate/spec/vocabulary"
)

// criticalActions maps every category of vocabulary v0 to whether each of its actions is
// critical. A deny that was not enforced (audit mode, SPEC-v0 section 4.6) is never one
// of a critical action, and never one of an action outside the vocabulary of a category
// of v0, which the evaluation denies before the rules.
var criticalActions = sync.OnceValue(func() map[string]map[string]bool {
	var v0 struct {
		Categories map[string]struct {
			Actions map[string]struct {
				Critical bool `json:"critical"`
			} `json:"actions"`
		} `json:"categories"`
	}
	if err := json.Unmarshal(vocabulary.V0(), &v0); err != nil {
		panic("audit: vocabulary v0: " + err.Error()) // embedded and tested
	}
	out := make(map[string]map[string]bool, len(v0.Categories))
	for name, category := range v0.Categories {
		actions := make(map[string]bool, len(category.Actions))
		for action, info := range category.Actions {
			actions[action] = info.Critical
		}
		out[name] = actions
	}
	return out
})

// enforcedConsistent reports whether an entry with evaluation.enforced: false names an
// action the vocabulary permits to be left unenforced (SPEC-v0 section 9.4). The schema
// cannot see the vocabulary. An extension category is not known here and passes; the
// schema already requires the category, and rejects a resource marked critical.
func enforcedConsistent(obj map[string]any) bool {
	evaluation, _ := obj["evaluation"].(map[string]any)
	if _, ok := evaluation["enforced"]; !ok {
		return true
	}
	request, _ := obj["request"].(map[string]any)
	resource, _ := request["resource"].(map[string]any)
	category, _ := resource["category"].(string)
	action, _ := request["action"].(string)
	actions, known := criticalActions()[category]
	if !known {
		return true
	}
	critical, inVocabulary := actions[action]
	return inVocabulary && !critical
}

// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"sync"

	"github.com/home-mandate/spec/vocabulary"
)

// Options adjust a verification.
type Options struct {
	// Anchor, if not nil, verifies the signatures of checkpoints (SPEC-v0 section 9.5).
	Anchor *Anchor
	// Vocabularies are extension vocabularies (SPEC-v0 section 5.1) in the format of
	// vocabulary/v0.json. With them, the verifier checks a deny that was not enforced for
	// an extension category as it does for the categories of v0. Without the vocabulary of
	// an extension, it cannot tell which of its actions are critical.
	Vocabularies [][]byte
}

// VerifyWith is Verify with options.
func VerifyWith(entries [][]byte, opts Options) (Result, error) {
	return verifyEntries(entries, opts)
}

// VerifyJSONLinesWith is VerifyJSONLines with options.
func VerifyJSONLinesWith(r io.Reader, opts Options) (Result, error) {
	return verifyLines(r, opts)
}

// actionsByCategory maps a category to whether each of its actions is critical.
type actionsByCategory map[string]map[string]bool

// readVocabulary reads the categories of a vocabulary file.
func readVocabulary(data []byte) (actionsByCategory, error) {
	var file struct {
		Categories map[string]struct {
			Actions map[string]struct {
				Critical bool `json:"critical"`
			} `json:"actions"`
		} `json:"categories"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, err
	}
	out := make(actionsByCategory, len(file.Categories))
	for name, category := range file.Categories {
		actions := make(map[string]bool, len(category.Actions))
		for action, info := range category.Actions {
			actions[action] = info.Critical
		}
		out[name] = actions
	}
	return out, nil
}

// vocabularyV0 is vocabulary/v0.json, embedded and tested.
var vocabularyV0 = sync.OnceValue(func() actionsByCategory {
	v0, err := readVocabulary(vocabulary.V0())
	if err != nil {
		panic("audit: vocabulary v0: " + err.Error())
	}
	return v0
})

// knownActions returns vocabulary v0 together with the given extensions. An extension
// cannot redefine a category of v0.
func knownActions(extensions [][]byte) (actionsByCategory, error) {
	known := vocabularyV0()
	if len(extensions) == 0 {
		return known, nil
	}
	known = maps.Clone(known)
	for i, data := range extensions {
		extension, err := readVocabulary(data)
		if err != nil {
			return nil, fmt.Errorf("audit: vocabulary %d: %w", i+1, err)
		}
		for name, actions := range extension {
			if _, ok := vocabularyV0()[name]; ok {
				return nil, fmt.Errorf("audit: vocabulary %d redefines category %q of v0", i+1, name)
			}
			known[name] = actions
		}
	}
	return known, nil
}

// enforcedConsistent reports whether an entry with evaluation.enforced: false names an
// action that may be left unenforced (SPEC-v0 sections 9.1 and 9.4): in the vocabulary
// of its category and not critical there. The schema cannot see the vocabulary. A
// category the verifier knows no vocabulary for passes; the schema already requires the
// category and rejects a resource marked critical.
func enforcedConsistent(obj map[string]any, known actionsByCategory) bool {
	evaluation, _ := obj["evaluation"].(map[string]any)
	if _, ok := evaluation["enforced"]; !ok {
		return true
	}
	request, _ := obj["request"].(map[string]any)
	resource, _ := request["resource"].(map[string]any)
	category, _ := resource["category"].(string)
	action, _ := request["action"].(string)
	actions, ok := known[category]
	if !ok {
		return true
	}
	critical, inVocabulary := actions[action]
	return inVocabulary && !critical
}

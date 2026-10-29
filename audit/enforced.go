// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"encoding/json"
	"errors"
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
	// vocabulary/v0.json, each with its id. With them, the verifier checks a deny that was not enforced for
	// an extension category as it does for the categories of v0, and the id a decision
	// names for such a category (SPEC-v0 section 9.1). Without the vocabulary of an
	// extension, it cannot tell which of its actions are critical or which id is its own.
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

// categoryVocabulary is what the verifier knows about one category: the id of the
// vocabulary that defines it and whether each of its actions is critical.
type categoryVocabulary struct {
	id      string
	actions map[string]bool
}

// actionsByCategory maps a category to the vocabulary that defines it.
type actionsByCategory map[string]categoryVocabulary

// readVocabulary reads the id and the categories of a vocabulary file.
func readVocabulary(data []byte) (actionsByCategory, error) {
	var file struct {
		ID         string `json:"id"`
		Categories map[string]struct {
			Actions map[string]struct {
				Critical bool `json:"critical"`
			} `json:"actions"`
		} `json:"categories"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, err
	}
	if file.ID == "" {
		return nil, errors.New("no id")
	}
	out := make(actionsByCategory, len(file.Categories))
	for name, category := range file.Categories {
		actions := make(map[string]bool, len(category.Actions))
		for action, info := range category.Actions {
			actions[action] = info.Critical
		}
		out[name] = categoryVocabulary{id: file.ID, actions: actions}
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

// vocabularyV0ID is the id of vocabulary/v0.json (SPEC-v0 section 5).
var vocabularyV0ID = sync.OnceValue(func() string {
	for _, category := range vocabularyV0() {
		return category.id
	}
	panic("audit: vocabulary v0 has no category")
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
		for name, category := range extension {
			if _, ok := vocabularyV0()[name]; ok {
				return nil, fmt.Errorf("audit: vocabulary %d redefines category %q of v0", i+1, name)
			}
			known[name] = category
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
	category, action := categoryAndAction(obj)
	vocab, ok := known[category]
	if !ok {
		return true
	}
	critical, inVocabulary := vocab.actions[action]
	return inVocabulary && !critical
}

// vocabularyConsistent reports whether the vocabulary a decision entry names fits the
// category of its resource (SPEC-v0 section 9.1): the id of v0 for a category of v0, the
// id of the extension for a category of an extension the verifier knows, and any id but
// that of v0 for another extension category. The schema cannot see the vocabulary.
func vocabularyConsistent(obj map[string]any, known actionsByCategory) bool {
	named, ok := obj["vocabulary"].(map[string]any)
	if !ok {
		return true
	}
	id, _ := named["id"].(string)
	category, _ := categoryAndAction(obj)
	if category == "" {
		return true
	}
	if vocab, ok := known[category]; ok {
		return id == vocab.id
	}
	return id != vocabularyV0ID()
}

// categoryAndAction reads the category of the resource and the action of a request;
// empty if absent.
func categoryAndAction(obj map[string]any) (category, action string) {
	request, _ := obj["request"].(map[string]any)
	resource, _ := request["resource"].(map[string]any)
	category, _ = resource["category"].(string)
	action, _ = request["action"].(string)
	return category, action
}

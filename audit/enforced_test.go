// SPDX-License-Identifier: Apache-2.0

package audit_test

import (
	"strings"
	"testing"

	"github.com/home-mandate/spec/audit"
)

// unenforced is a decision entry with seq 1 whose deny was not enforced (SPEC-v0 section
// 4.6), for the given category and action.
func unenforced(category, action string) []byte {
	return []byte(strings.NewReplacer("CATEGORY", category, "ACTION", action).Replace(
		`{"agent":{"client_id":"urn:example:agent:a"},"evaluation":{"decision":"deny","reason":"no_match","rule_id":null,"enforced":false},` +
			`"event":"decision","id":"01a0f64c-7140-7001-9007-0000e9990001","mandate":{"id":"m-test","digest":"sha256:` +
			strings.Repeat("0", 64) + `"},"prev":null,"principal":"household:t","recorded_at":"2026-10-12T19:00:00+02:00",` +
			`"request":{"time":"2026-10-12T19:00:00+02:00","resource":{"entity_id":"x","category":"CATEGORY","critical":false},"action":"ACTION"},` +
			`"result":{"status":"executed"},"seq":1,"type":"https://home-mandate.org/audit/v0"}`))
}

// The verifier checks a deny that was not enforced against vocabulary v0: never for a
// critical action, never for an action outside the vocabulary of a category of v0. An
// extension category is not known to it and passes.
func TestUnenforcedDenyAgainstTheVocabulary(t *testing.T) {
	for _, tt := range []struct {
		category, action string
		valid            bool
	}{
		{"switch", "turn_on", true},
		{"camera", "read", true},
		{"paperless:document", "delete", true},
		{"lock", "unlock", false},
		{"camera", "snapshot", false},
		{"other", "set", false},
		{"light", "unlock", false},
	} {
		r, err := audit.Verify([][]byte{unenforced(tt.category, tt.action)})
		if err != nil {
			t.Fatal(err)
		}
		if r.Valid != tt.valid {
			t.Errorf("%s.%s: valid = %t, want %t", tt.category, tt.action, r.Valid, tt.valid)
		}
	}
}

// paperless is an extension vocabulary in the format of vocabulary/v0.json (SPEC-v0
// section 5.1).
const paperless = `{"id":"https://example.org/vocabulary/paperless","version":"1","categories":{` +
	`"paperless:document":{"actions":{"read":{},"tag":{},"delete":{"critical":true}}}}}`

// Given the vocabulary of an extension, the verifier checks its actions as it checks v0.
func TestUnenforcedDenyAgainstAnExtensionVocabulary(t *testing.T) {
	opts := audit.Options{Vocabularies: [][]byte{[]byte(paperless)}}
	for _, tt := range []struct {
		category, action string
		valid            bool
	}{
		{"paperless:document", "tag", true},
		{"paperless:document", "delete", false},
		{"paperless:document", "shred", false},
		{"switch", "turn_on", true},
		{"lock", "unlock", false},
		{"other:thing", "anything", true},
	} {
		entry := unenforced(tt.category, tt.action)
		r, err := audit.VerifyWith([][]byte{entry}, opts)
		if err != nil {
			t.Fatal(err)
		}
		lines, err := audit.VerifyJSONLinesWith(strings.NewReader(string(entry)), opts)
		if err != nil {
			t.Fatal(err)
		}
		if r.Valid != tt.valid || lines.Valid != tt.valid {
			t.Errorf("%s.%s: valid = %t (lines %t), want %t", tt.category, tt.action, r.Valid, lines.Valid, tt.valid)
		}
	}
}

func TestVerifyWithRejectsUnreadableVocabularies(t *testing.T) {
	for _, vocabulary := range []string{`not json`, `{"categories":{"x:y":{"actions":{"read":{}}}}}`, `{"id":"urn:x","categories":{"lock":{"actions":{"unlock":{}}}}}`} {
		if _, err := audit.VerifyWith(nil, audit.Options{Vocabularies: [][]byte{[]byte(vocabulary)}}); err == nil {
			t.Errorf("vocabulary %s accepted", vocabulary)
		}
	}
}

// decided is a decision entry with seq 1 for the given category that names the given
// vocabulary id (SPEC-v0 section 9.1). An empty category leaves the resource without one.
func decided(category, vocabularyID string) []byte {
	resource := `"entity_id":"x"`
	if category != "" {
		resource += `,"category":"` + category + `"`
	}
	return []byte(`{"agent":{"client_id":"urn:example:agent:a"},"evaluation":{"decision":"allow","reason":"rule","rule_id":"r-1"},` +
		`"event":"decision","id":"01a0f64c-7140-7001-9007-0000e9990002","mandate":{"id":"m-test","digest":"sha256:` +
		strings.Repeat("0", 64) + `"},"prev":null,"principal":"household:t","recorded_at":"2026-10-12T19:00:00+02:00",` +
		`"request":{"time":"2026-10-12T19:00:00+02:00","resource":{` + resource + `},"action":"read"},` +
		`"result":{"status":"executed"},"seq":1,"type":"https://home-mandate.org/audit/v0","vocabulary":{"id":"` + vocabularyID + `","version":"1"}}`)
}

// The verifier checks the vocabulary id a decision names against the category: v0 for
// the categories of v0, the extension's own id for an extension it knows, and anything
// but v0 for an extension it does not know.
func TestVocabularyOfADecisionFitsTheCategory(t *testing.T) {
	const v0, ext, other = "https://home-mandate.org/vocabulary/v0", "https://example.org/vocabulary/paperless", "urn:example:vocabulary"
	opts := audit.Options{Vocabularies: [][]byte{[]byte(paperless)}}
	for _, tt := range []struct {
		category, id string
		valid        bool
	}{
		{"light", v0, true},
		{"light", ext, false},
		{"paperless:document", ext, true},
		{"paperless:document", v0, false},
		{"paperless:document", other, false},
		{"other:thing", other, true},
		{"other:thing", v0, false},
		{"", ext, true},
	} {
		r, err := audit.VerifyWith([][]byte{decided(tt.category, tt.id)}, opts)
		if err != nil {
			t.Fatal(err)
		}
		if r.Valid != tt.valid {
			t.Errorf("%q with %s: valid = %t, want %t", tt.category, tt.id, r.Valid, tt.valid)
		}
	}
}

// Without the vocabulary of the extension, the verifier cannot tell the extension's id
// and accepts any id other than that of v0.
func TestVocabularyOfAnUnknownExtensionPasses(t *testing.T) {
	r, err := audit.Verify([][]byte{decided("paperless:document", "urn:example:vocabulary")})
	if err != nil {
		t.Fatal(err)
	}
	if !r.Valid {
		t.Error("unknown extension with its own id rejected")
	}
}

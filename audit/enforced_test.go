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
			`"request":{"time":"2026-10-12T19:00:00+02:00","resource":{"entity_id":"x","category":"CATEGORY"},"action":"ACTION"},` +
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

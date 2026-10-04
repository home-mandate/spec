// SPDX-License-Identifier: Apache-2.0

package evaluator_test

import (
	"testing"

	"github.com/mandate-spec/mandate-spec/evaluator"
)

// TestIsCritical checks every critical action of SPEC-v0 section 5, a sample of the
// others, and that anything outside the vocabulary counts as critical.
func TestIsCritical(t *testing.T) {
	cases := []struct {
		category, action string
		want             bool
	}{
		{"gate", "open", true},
		{"lock", "unlock", true},
		{"lock", "open", true},
		{"alarm", "disarm", true},
		{"camera", "snapshot", true},
		{"script", "run", true},
		{"other", "set", true},
		{"scene", "activate", true},

		{"gate", "close", false},
		{"lock", "lock", false},
		{"lock", "read", false},
		{"alarm", "arm", false},
		{"light", "turn_on", false},
		{"light", "set", false},
		{"climate", "set_temperature", false},
		{"cover", "open", false},
		{"media", "set_volume", false},
		{"scene", "read", false},
		{"sensor", "read", false},

		// Outside the vocabulary: treated as critical, never as harmless.
		{"lock", "explode", true},
		{"light", "unlock", true},
		{"vendor:robot", "start", true},
		{"", "", true},
		{"Lock", "unlock", true},
	}
	for _, c := range cases {
		if got := evaluator.IsCritical(c.category, c.action); got != c.want {
			t.Errorf("IsCritical(%q, %q) = %v, want %v", c.category, c.action, got, c.want)
		}
	}
}

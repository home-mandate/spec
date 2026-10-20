// SPDX-License-Identifier: Apache-2.0

package evaluator

import "testing"

// exactInteger is reached through encoding/json, which already rejects malformed
// numbers; this test checks that it rejects them on its own as well.
func TestExactIntegerOnItsOwn(t *testing.T) {
	for input, want := range map[string]int64{
		"0": 0, "-12": -12, "1e+2": 100, "1E2": 100, "12.30e1": 123, "0.0e+99999999999": 0,
		"9007199254740991": 1<<53 - 1, "-9007199254740991": -(1<<53 - 1),
	} {
		if got, ok := exactInteger(input); !ok || got != want {
			t.Errorf("exactInteger(%q) = %d, %v; want %d", input, got, ok, want)
		}
	}
	for _, input := range []string{
		"", "-", "a", "1a", "01", "1.", ".1", "1.a", "1e", "1e+", "1e-", "1ea", "--1", "+1",
		"9007199254740992", "99999999999999999", "1e16", "1e99999999999", "1.5", "1e-1",
	} {
		if got, ok := exactInteger(input); ok {
			t.Errorf("exactInteger(%q) = %d, want rejection", input, got)
		}
	}
}

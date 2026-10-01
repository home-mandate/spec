// SPDX-License-Identifier: Apache-2.0

package evaluator

// vocabularyV0 is the vocabulary from SPEC-v0 section 5: category → action → critical.
// It is read-only.
var vocabularyV0 = map[string]map[string]bool{
	"light":   {"read": false, "turn_on": false, "turn_off": false, "set": false},
	"switch":  {"read": false, "turn_on": false, "turn_off": false},
	"climate": {"read": false, "set_temperature": false, "set_mode": false},
	"cover":   {"read": false, "open": false, "close": false, "stop": false, "set_position": false},
	"gate":    {"read": false, "open": true, "close": false},
	"lock":    {"read": false, "lock": false, "unlock": true, "open": true},
	"alarm":   {"read": false, "arm": false, "disarm": true},
	"camera":  {"read": false, "snapshot": true},
	"media":   {"read": false, "turn_on": false, "turn_off": false, "play": false, "pause": false, "set_volume": false},
	"sensor":  {"read": false},
	"scene":   {"read": false, "activate": false},
	"script":  {"read": false, "run": true},
	"other":   {"read": false, "set": true},
}

// lookupAction reports whether the category is known, whether the action belongs to it
// and whether the action is critical.
func lookupAction(category, action string) (categoryKnown, actionKnown, critical bool) {
	actions, ok := vocabularyV0[category]
	if !ok {
		return false, false, false
	}
	critical, actionKnown = actions[action]
	return true, actionKnown, critical
}

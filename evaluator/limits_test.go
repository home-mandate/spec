// SPDX-License-Identifier: Apache-2.0

package evaluator_test

import (
	"reflect"
	"testing"

	"github.com/home-mandate/spec/evaluator"
)

func bound(v int64) *int64 { return &v }

// Limits tells what values a request could be allowed with: the constraints of the allow
// rules that match it apart from them. It decides nothing.
func TestLimits(t *testing.T) {
	m := mandateWithRules(t, `[
		{"id":"r-heat","resource":{"category":"climate"},"actions":["set_temperature"],"decision":"allow",
		 "constraints":{"temperature":{"min":1600,"max":2300}}},
		{"id":"r-office","resource":{"category":"climate","area":"office"},"actions":["set_temperature"],"decision":"allow",
		 "constraints":{"temperature":{"max":2500}}},
		{"id":"r-night","resource":{"category":"light"},"actions":["set"],"decision":"allow","conditions":{"time_window":"22:00-06:00"},
		 "constraints":{"brightness":{"max":30}}},
		{"id":"r-blind","resource":{"category":"cover"},"actions":["set_position"],"decision":"allow"},
		{"id":"r-ask","resource":{"category":"media"},"actions":["set_volume"],"decision":"ask"},
		{"id":"r-modes","resource":{"category":"climate"},"actions":["set_mode"],"decision":"allow",
		 "constraints":{"mode":{"one_of":["heat","auto"]}}}]`)
	tests := []struct {
		name string
		req  evaluator.Request
		want []map[string]evaluator.Limit
	}{
		{"one rule", request("climate", "", "set_temperature"),
			[]map[string]evaluator.Limit{{"temperature": {Min: bound(1600), Max: bound(2300)}}}},
		{"two rules in document order, an open bound is nil", request("climate", "office", "set_temperature"),
			[]map[string]evaluator.Limit{{"temperature": {Min: bound(1600), Max: bound(2300)}}, {"temperature": {Max: bound(2500)}}}},
		{"a rule outside its time window does not count", request("light", "", "set"), nil},
		{"an allow rule without constraints allows any value", request("cover", "", "set_position"), []map[string]evaluator.Limit{{}}},
		{"permitted values in the order of the mandate", request("climate", "", "set_mode"),
			[]map[string]evaluator.Limit{{"mode": {OneOf: []evaluator.Value{evaluator.StringValue("heat"), evaluator.StringValue("auto")}}}}},
		{"ask and deny rules set no limits", request("media", "", "set_volume"), nil},
		{"unknown category: denied before the rules", request("toaster", "", "set"), nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.req.Parameters = map[string]evaluator.Value{"temperature": evaluator.IntegerValue(1 << 60), "mode": evaluator.StringValue("x y")} // ignored, even invalid
			if got := m.Limits(tt.req); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Limits = %v, want %v", got, tt.want)
			}
		})
	}
	var invalid *evaluator.Mandate
	if got := invalid.Limits(request("climate", "", "set_temperature")); got != nil {
		t.Errorf("nil mandate: %v", got)
	}
}

// SPDX-License-Identifier: Apache-2.0

package evaluator_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/home-mandate/spec/evaluator"
)

func TestValueAccessors(t *testing.T) {
	n, isInteger := evaluator.IntegerValue(2150).AsInteger()
	_, alsoString := evaluator.IntegerValue(2150).AsString()
	if n != 2150 || !isInteger || alsoString {
		t.Errorf("IntegerValue(2150) = (%d, %v), string %v", n, isInteger, alsoString)
	}
	s, isString := evaluator.StringValue("heat").AsString()
	_, alsoInteger := evaluator.StringValue("heat").AsInteger()
	if s != "heat" || !isString || alsoInteger {
		t.Errorf("StringValue(heat) = (%q, %v), integer %v", s, isString, alsoInteger)
	}
	var zero evaluator.Value
	if _, ok := zero.AsInteger(); ok {
		t.Error("the zero Value is an integer")
	}
	if _, ok := zero.AsString(); ok {
		t.Error("the zero Value is a string")
	}
	if evaluator.IntegerValue(0) == zero || evaluator.StringValue("") == zero {
		t.Error("a constructed value equals the zero Value")
	}
	if evaluator.IntegerValue(1) == evaluator.StringValue("1") {
		t.Error("an integer equals a string")
	}
}

func TestValueUnmarshalJSON(t *testing.T) {
	for input, want := range map[string]evaluator.Value{
		`50`:                   evaluator.IntegerValue(50),
		`50.0`:                 evaluator.IntegerValue(50),
		`5e1`:                  evaluator.IntegerValue(50),
		`-9007199254740991`:    evaluator.IntegerValue(-(1<<53 - 1)),
		` 7 `:                  evaluator.IntegerValue(7),
		`"heat"`:               evaluator.StringValue("heat"),
		`"50"`:                 evaluator.StringValue("50"),
		`""`:                   evaluator.StringValue(""), // invalid in a request, but a string
		`"fan only"`:           evaluator.StringValue("fan only"),
		"\"\\u0068eat\"":       evaluator.StringValue("heat"), // an escape in JSON
		`"9007199254740993"`:   evaluator.StringValue("9007199254740993"),
		`-0`:                   evaluator.IntegerValue(0),
		`0e-999999999999`:      evaluator.IntegerValue(0),
		`0.000`:                evaluator.IntegerValue(0),
		`2150.00e0`:            evaluator.IntegerValue(2150),
		`21.5e2`:               evaluator.IntegerValue(2150),
		`215000E-2`:            evaluator.IntegerValue(2150),
		`9.007199254740991e15`: evaluator.IntegerValue(1<<53 - 1),
		"1" + strings.Repeat("0", 20003) + "e-20000": evaluator.IntegerValue(1000),
	} {
		var got evaluator.Value
		if err := json.Unmarshal([]byte(input), &got); err != nil || got != want {
			t.Errorf("Unmarshal(%s) = %+v, %v; want %+v", input, got, err, want)
		}
	}
	for _, input := range []string{`50.5`, `9007199254740992`, `-9007199254740992`, `1e99`, `true`, `null`, `[]`, `{}`, `"a`, ``,
		`1e-400`, `50.00000000000000000001`, `2149.99999999999999999`, `9007199254740991.4`, `5e-1`, `1e999999999999`,
		`1e-999999999999`, `9007199254740.9921e3`, `01`, `+1`, `.5`, `1.`, `0x10`, `NaN`, `1e`} {
		var got evaluator.Value
		if err := got.UnmarshalJSON([]byte(input)); err == nil {
			t.Errorf("Unmarshal(%s) = %+v, want an error", input, got)
		}
	}
}

func TestValueMarshalJSON(t *testing.T) {
	data, err := json.Marshal(map[string]evaluator.Value{"mode": evaluator.StringValue("heat"), "temperature": evaluator.IntegerValue(-2150)})
	if err != nil || string(data) != `{"mode":"heat","temperature":-2150}` {
		t.Errorf("Marshal = %s, %v", data, err)
	}
	if _, err := json.Marshal(evaluator.Value{}); err == nil {
		t.Error("the zero Value was marshalled")
	}
}

func TestEvaluateOneOf(t *testing.T) {
	m := mandateWithRules(t, `[
		{"id":"r-modes","resource":{"category":"climate"},"actions":["set_mode"],"decision":"allow",
		 "constraints":{"mode":{"one_of":["heat","auto"]}}},
		{"id":"r-steps","resource":{"category":"light"},"actions":["set"],"decision":"allow",
		 "constraints":{"brightness":{"one_of":[0,5e1,100]}}},
		{"id":"r-vendor","resource":{"category":"vendor:wallbox"},"actions":["set"],"decision":"allow",
		 "constraints":{"charge_mode":{"one_of":["PV","BOOST"]}}}]`)
	req := func(category, action string, parameters map[string]evaluator.Value) evaluator.Request {
		r := request(category, "", action)
		r.Parameters = parameters
		return r
	}
	str, num := evaluator.StringValue, evaluator.IntegerValue
	for name, tt := range map[string]struct {
		req    evaluator.Request
		reason evaluator.Reason
	}{
		"string listed":             {req("climate", "set_mode", map[string]evaluator.Value{"mode": str("heat")}), evaluator.ReasonRule},
		"second string listed":      {req("climate", "set_mode", map[string]evaluator.Value{"mode": str("auto")}), evaluator.ReasonRule},
		"permitted, not listed":     {req("climate", "set_mode", map[string]evaluator.Value{"mode": str("off")}), evaluator.ReasonNoMatch},
		"absent":                    {req("climate", "set_mode", nil), evaluator.ReasonNoMatch},
		"other case":                {req("climate", "set_mode", map[string]evaluator.Value{"mode": str("HEAT")}), evaluator.ReasonInvalidRequest},
		"not permitted":             {req("climate", "set_mode", map[string]evaluator.Value{"mode": str("eco")}), evaluator.ReasonInvalidRequest},
		"integer for a string":      {req("climate", "set_mode", map[string]evaluator.Value{"mode": num(4)}), evaluator.ReasonInvalidRequest},
		"zero value":                {req("climate", "set_mode", map[string]evaluator.Value{"mode": {}}), evaluator.ReasonInvalidRequest},
		"empty string":              {req("climate", "set_mode", map[string]evaluator.Value{"mode": str("heat"), "x": str("")}), evaluator.ReasonInvalidRequest},
		"65 characters":             {req("climate", "set_mode", map[string]evaluator.Value{"mode": str("heat"), "x": str(longString(65))}), evaluator.ReasonInvalidRequest},
		"64 characters, undeclared": {req("climate", "set_mode", map[string]evaluator.Value{"mode": str("heat"), "x": str(longString(64))}), evaluator.ReasonRule},
		"space":                     {req("climate", "set_mode", map[string]evaluator.Value{"mode": str("heat"), "x": str("a b")}), evaluator.ReasonInvalidRequest},
		"not ASCII":                 {req("climate", "set_mode", map[string]evaluator.Value{"mode": str("heat"), "x": str("wärme")}), evaluator.ReasonInvalidRequest},
		"integer listed":            {req("light", "set", map[string]evaluator.Value{"brightness": num(50)}), evaluator.ReasonRule},
		"zero listed":               {req("light", "set", map[string]evaluator.Value{"brightness": num(0)}), evaluator.ReasonRule},
		"between listed":            {req("light", "set", map[string]evaluator.Value{"brightness": num(51)}), evaluator.ReasonNoMatch},
		"string for an integer":     {req("light", "set", map[string]evaluator.Value{"brightness": str("50")}), evaluator.ReasonInvalidRequest},
		"read ignores parameters":   {req("climate", "read", map[string]evaluator.Value{"mode": num(4)}), evaluator.ReasonNoMatch},
		"unknown category":          {req("vendor:wallbox", "set", map[string]evaluator.Value{"charge_mode": str("PV")}), evaluator.ReasonUnknownCategory},
	} {
		t.Run(name, func(t *testing.T) {
			got := evaluator.Evaluate(m, tt.req)
			if got.Reason != tt.reason || (got.Decision == evaluator.Allow) != (tt.reason == evaluator.ReasonRule) {
				t.Errorf("got (%s, %s), want reason %s", got.Decision, got.Reason, tt.reason)
			}
		})
	}
}

func longString(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = 'a'
	}
	return string(b)
}

// A range constraint never matches a string, and a one_of constraint never matches a
// value of the other type. This matters where the request's action does not declare the
// parameter: a rule without category is valid if any category declares it.
func TestConstraintsOnUndeclaredParametersMatchOnlyTheirType(t *testing.T) {
	m := mandateWithRules(t, `[
		{"id":"r-range","resource":{"entity_id":"dev-1"},"actions":["set"],"decision":"allow",
		 "constraints":{"brightness":{"max":60}}},
		{"id":"r-list","resource":{"entity_id":"dev-2"},"actions":["set"],"decision":"allow",
		 "constraints":{"brightness":{"one_of":[10,20]}}}]`)
	for name, tt := range map[string]struct {
		entity string
		value  evaluator.Value
		reason evaluator.Reason
	}{
		"range, integer": {"dev-1", evaluator.IntegerValue(60), evaluator.ReasonCriticalDemotion},
		"range, string":  {"dev-1", evaluator.StringValue("60"), evaluator.ReasonNoMatch},
		"list, integer":  {"dev-2", evaluator.IntegerValue(20), evaluator.ReasonCriticalDemotion},
		"list, string":   {"dev-2", evaluator.StringValue("20"), evaluator.ReasonNoMatch},
	} {
		t.Run(name, func(t *testing.T) {
			r := request("other", "", "set") // other.set has no parameter brightness
			r.Resource.EntityID = tt.entity
			r.Parameters = map[string]evaluator.Value{"brightness": tt.value}
			if got := evaluator.Evaluate(m, r); got.Reason != tt.reason {
				t.Errorf("got (%s, %s), want reason %s", got.Decision, got.Reason, tt.reason)
			}
		})
	}
}

func TestParseRejectsConstraintsThatDoNotFitTheParameter(t *testing.T) {
	for name, rules := range map[string]string{
		"min on a string":              `[{"id":"r","resource":{"category":"climate"},"actions":["set_mode"],"decision":"allow","constraints":{"mode":{"min":1}}}]`,
		"integer for a string":         `[{"id":"r","resource":{"category":"climate"},"actions":["set_mode"],"decision":"allow","constraints":{"mode":{"one_of":[4]}}}]`,
		"string for an integer":        `[{"id":"r","resource":{"category":"light"},"actions":["set"],"decision":"allow","constraints":{"brightness":{"one_of":["50"]}}}]`,
		"not a permitted value":        `[{"id":"r","resource":{"category":"climate"},"actions":["set_mode"],"decision":"allow","constraints":{"mode":{"one_of":["heat","eco"]}}}]`,
		"no category, wrong type":      `[{"id":"r","resource":{"entity_id":"t-1"},"actions":["set_mode"],"decision":"allow","constraints":{"mode":{"one_of":[1]}}}]`,
		"no category, not permitted":   `[{"id":"r","resource":{"entity_id":"t-1"},"actions":["set_mode"],"decision":"allow","constraints":{"mode":{"one_of":["Heat"]}}}]`,
		"no parameters on other.set":   `[{"id":"r","resource":{"category":"other"},"actions":["set"],"decision":"allow","constraints":{"value":{"one_of":["on"]}}}]`,
		"one_of together with min":     `[{"id":"r","resource":{"category":"light"},"actions":["set"],"decision":"allow","constraints":{"brightness":{"one_of":[1],"min":0}}}]`,
		"mixed types for an extension": `[{"id":"r","resource":{"category":"vendor:x"},"actions":["set"],"decision":"allow","constraints":{"level":{"one_of":[1,"high"]}}}]`,
	} {
		t.Run(name, func(t *testing.T) {
			if m, err := evaluator.Parse(mandateReplacing(baseRules, rules)); err == nil {
				t.Errorf("Parse accepted %s: %v", rules, m.Digest())
			}
		})
	}
	for name, rules := range map[string]string{
		"string list":                 `[{"id":"r","resource":{"category":"climate"},"actions":["set_mode"],"decision":"allow","constraints":{"mode":{"one_of":["off"]}}}]`,
		"integer list":                `[{"id":"r","resource":{"category":"light"},"actions":["set"],"decision":"allow","constraints":{"brightness":{"one_of":[-1,1e2]}}}]`,
		"no category":                 `[{"id":"r","resource":{"entity_id":"t-1"},"actions":["set_mode"],"decision":"allow","constraints":{"mode":{"one_of":["heat"]}}}]`,
		"extension strings unchecked": `[{"id":"r","resource":{"category":"vendor:x"},"actions":["set"],"decision":"allow","constraints":{"level":{"one_of":["High"]}}}]`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := evaluator.Parse(mandateReplacing(baseRules, rules)); err != nil {
				t.Errorf("Parse rejected %s: %v", rules, err)
			}
		})
	}
}

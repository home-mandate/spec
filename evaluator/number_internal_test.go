// SPDX-License-Identifier: Apache-2.0

package evaluator

import (
	"encoding/json"
	"errors"
	"math/big"
	"strconv"
	"strings"
	"testing"
)

// exactInteger is reached through encoding/json, which already rejects malformed
// numbers; this test checks that it rejects them on its own as well, with the reason.
func TestExactIntegerOnItsOwn(t *testing.T) {
	for input, want := range map[string]int64{
		"0": 0, "-12": -12, "1e+2": 100, "1E2": 100, "12.30e1": 123, "0.0e+99999999999": 0,
		"9007199254740991": 1<<53 - 1, "-9007199254740991": -(1<<53 - 1),
	} {
		if got, err := exactInteger(input); err != nil || got != want {
			t.Errorf("exactInteger(%q) = %d, %v; want %d", input, got, err, want)
		}
	}
	for want, inputs := range map[error][]string{
		errNoNumberOrString: {"", "-", "a", "1a", "01", "1.", ".1", "1.a", "1e", "1e+", "1e-", "1ea", "--1", "+1"},
		errNoInteger:        {"1.5", "1e-1", "1e-99999999999", "50.00000000000000000001"},
		errOutOfRange:       {"9007199254740992", "-9007199254740992", "99999999999999999", "1e16", "1e99999999999"},
	} {
		for _, input := range inputs {
			if got, err := exactInteger(input); !errors.Is(err, want) {
				t.Errorf("exactInteger(%q) = %d, %v; want %v", input, got, err, want)
			}
		}
	}
}

func TestValueUnmarshalJSONNamesTheReason(t *testing.T) {
	for input, want := range map[string]error{
		`true`: errNoNumberOrString, `null`: errNoNumberOrString, `[1]`: errNoNumberOrString,
		`50.5`: errNoInteger, `1e-400`: errNoInteger,
		`9007199254740992`: errOutOfRange, `1e99`: errOutOfRange,
	} {
		var v Value
		if err := v.UnmarshalJSON([]byte(input)); !errors.Is(err, want) {
			t.Errorf("UnmarshalJSON(%s) = %v, want %v", input, err, want)
		}
	}
}

// buildConstraint checks a list itself, although the schema already does: a caller that
// skips the schema must not get a list that fails open or contradicts Section 4.5.
func TestBuildConstraintChecksTheListItself(t *testing.T) {
	list := func(values ...string) rawConstraint {
		raw := rawConstraint{OneOf: []json.RawMessage{}}
		for _, v := range values {
			raw.OneOf = append(raw.OneOf, json.RawMessage(v))
		}
		return raw
	}
	many := make([]string, 33)
	for i := range many {
		many[i] = strconv.Itoa(i)
	}
	limit := json.Number("1")
	for name, raw := range map[string]rawConstraint{
		"empty":          list(),
		"33 values":      list(many...),
		"duplicate":      list(`1`, `1.0`),
		"mixed types":    list(`1`, `"a"`),
		"invalid string": list(`"a b"`),
		"empty string":   list(`""`),
		"with min":       {OneOf: list(`1`).OneOf, Min: &limit},
		"not an integer": list(`1.5`),
		"not a value":    list(`true`),
	} {
		if _, err := buildConstraint("r", "p", raw); err == nil {
			t.Errorf("%s: accepted", name)
		} else if name != "not an integer" && name != "not a value" && !errors.Is(err, ErrSemantic) {
			t.Errorf("%s: error %v is not semantic", name, err)
		}
	}
	if c, err := buildConstraint("r", "p", list(many[:32]...)); err != nil || len(c.oneOf) != 32 {
		t.Errorf("32 values: %v", err)
	}
}

// FuzzValue: a valid value survives JSON unchanged, and exactInteger agrees with exact
// rational arithmetic on every JSON number that math/big can read.
func FuzzValue(f *testing.F) {
	for _, seed := range []string{`50`, `-0`, `5e1`, `2150.00e0`, `1e-400`, `9007199254740991`, `9007199254740992`,
		`50.00000000000000000001`, `"heat"`, `"fan only"`, `""`, `"heat"`, `true`, `null`, `1e99999`} {
		f.Add([]byte(seed))
	}
	maxExact := big.NewRat(maxParameter, 1)
	f.Fuzz(func(t *testing.T, data []byte) {
		var v Value
		if err := v.UnmarshalJSON(data); err == nil && v.valid() {
			out, err := v.MarshalJSON()
			if err != nil {
				t.Fatalf("Marshal(%+v): %v", v, err)
			}
			var again Value
			if err := again.UnmarshalJSON(out); err != nil || again != v {
				t.Fatalf("round trip %s -> %s -> %+v, %v; want %+v", data, out, again, err, v)
			}
		}
		var n json.Number
		if json.Unmarshal(data, &n) != nil || n == "" || strings.ContainsAny(string(data), `"`) {
			return // not a JSON number
		}
		text := n.String()
		if _, exponent, ok := strings.Cut(strings.ToLower(text), "e"); ok && len(strings.TrimLeft(strings.TrimLeft(exponent, "+-"), "0")) > 4 {
			return // out of scope: math/big would materialize 10^exponent
		}
		r, ok := new(big.Rat).SetString(text)
		if !ok {
			return // out of scope
		}
		want := r.IsInt() && new(big.Rat).Abs(r).Cmp(maxExact) <= 0
		got, err := exactInteger(text)
		if (err == nil) != want || (want && big.NewRat(got, 1).Cmp(r) != 0) {
			t.Fatalf("exactInteger(%s) = %d, %v; math/big says %s (integer within range: %v)", text, got, err, r.RatString(), want)
		}
	})
}

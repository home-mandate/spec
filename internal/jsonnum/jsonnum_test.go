// SPDX-License-Identifier: Apache-2.0

package jsonnum

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestZeroNumbers(t *testing.T) {
	in := map[string]any{
		"zero": json.Number("0e99999999999999999999"), "negative": json.Number("-0.0E-99999999999999999999"),
		"list": []any{json.Number("0e5"), json.Number("10"), "0e5", true, nil},
		"keep": json.Number("1e99999999999999999999"), "fraction": json.Number("0.5e1"), "plain": json.Number("10.0"),
	}
	got, ok := ZeroNumbers(in).(map[string]any)
	if !ok {
		t.Fatalf("result is %T", got)
	}
	for name, want := range map[string]json.Number{
		"zero": "0", "negative": "0", "keep": "1e99999999999999999999", "fraction": "0.5e1", "plain": "10.0",
	} {
		if got[name] != want {
			t.Errorf("%s = %v, want %v", name, got[name], want)
		}
	}
	list, ok := got["list"].([]any)
	if !ok || list[0] != json.Number("0") || list[1] != json.Number("10") || list[2] != "0e5" || list[3] != true || list[4] != nil {
		t.Errorf("list = %v", got["list"])
	}
	if in["zero"] != json.Number("0e99999999999999999999") {
		t.Error("the input was changed")
	}
}

// ExactInteger reads by the exact value: a fraction that floating point rounds to an integer
// is no integer (SPEC-v0 sections 4.5 and 9.4), and a huge exponent costs no more than its text.
func TestExactInteger(t *testing.T) {
	for in, want := range map[string]int64{
		"0": 0, "-0": 0, "20": 20, "20.0": 20, "2e1": 20, "2E+1": 20, "200e-1": 20, "-9007199254740991": -9007199254740991,
		"0e999999999999": 0, "9.007199254740991e15": 9007199254740991,
	} {
		if got, err := ExactInteger(in); err != nil || got != want {
			t.Errorf("ExactInteger(%s) = %d, %v; want %d", in, got, err, want)
		}
	}
	for in, want := range map[string]error{
		"1.00000000000000000001": ErrNoInteger, "120.5": ErrNoInteger, "1e-400": ErrNoInteger,
		"9007199254740992": ErrOutOfRange, "1e999999999999": ErrOutOfRange, "-9007199254740992": ErrOutOfRange,
		"01": ErrNoNumber, "1.": ErrNoNumber, ".5": ErrNoNumber, "+1": ErrNoNumber, "1e": ErrNoNumber, "": ErrNoNumber, "0x10": ErrNoNumber,
	} {
		if _, err := ExactInteger(in); !errors.Is(err, want) {
			t.Errorf("ExactInteger(%s) error %v, want %v", in, err, want)
		}
	}
}

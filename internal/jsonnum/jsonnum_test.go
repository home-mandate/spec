// SPDX-License-Identifier: Apache-2.0

package jsonnum

import (
	"encoding/json"
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

// SPDX-License-Identifier: Apache-2.0

package ijson

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestCheckSurrogatesEdgeCases(t *testing.T) {
	u := `\` + "u" // assembled so that no escape sequence appears in the source
	tests := []struct {
		name    string
		data    string
		wantErr bool
	}{
		{"valid pair", `"` + u + "d83d" + u + `de00"`, false},
		{"escaped backslash before u is no escape", `"\\` + "ud800" + `"`, false},
		{"escaped quote keeps string open", `"\"` + u + `dc00"`, true},
		{"truncated escape left to decoder", `"` + u + "d8", false},
		{"backslash at end left to decoder", `"abc\`, false},
		{"non-hex escape left to decoder", `"` + u + `zzzz"`, false},
		{"high surrogate at end of input", `"` + u + "d800", true},
		{"high surrogate followed by non-surrogate escape", `"` + u + "d800" + u + `0041"`, true},
		{"high surrogate followed by other escape", `"` + u + `d800\n"`, true},
		{"surrogate outside string is ignored", `{"a":1}`, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkSurrogates([]byte(tt.data))
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil && !errors.Is(err, ErrMalformed) {
				t.Errorf("err = %v, want ErrMalformed", err)
			}
		})
	}
}

func TestCheckSurrogatesBoundaries(t *testing.T) {
	u := `\` + "u"
	tests := []struct {
		name    string
		data    string
		wantErr bool
	}{
		{"lowest pair", `"` + u + "d800" + u + `dc00"`, false},
		{"highest pair", `"` + u + "dbff" + u + `dfff"`, false},
		{"lone highest high surrogate", `"` + u + `dbff"`, true},
		{"lone highest low surrogate", `"` + u + `dfff"`, true},
		{"just below surrogates", `"` + u + `d7ff"`, false},
		{"just above surrogates", `"` + u + `e000"`, false},
		{"high followed by just below low range", `"` + u + "d800" + u + `dbff"`, true},
		{"high followed by just above low range", `"` + u + "d800" + u + `e000"`, true},
		{"high followed by lone backslash at end", `"` + u + `d800\`, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := checkSurrogates([]byte(tt.data)); (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCheckTokensRejectsSecondValue(t *testing.T) {
	for _, data := range []string{`{} {}`, `1 2`, `[] "x"`, `null null`} {
		if err := checkTokens([]byte(data)); !errors.Is(err, ErrMalformed) {
			t.Errorf("checkTokens(%q) = %v, want ErrMalformed", data, err)
		}
	}
}

func TestCheckTokensDepthLimit(t *testing.T) {
	nested := func(depth int) []byte {
		return []byte(strings.Repeat("[", depth) + strings.Repeat("]", depth))
	}
	if err := checkTokens(nested(maxNestingDepth)); err != nil {
		t.Errorf("depth %d rejected: %v", maxNestingDepth, err)
	}
	if err := checkTokens(nested(maxNestingDepth + 1)); !errors.Is(err, ErrMalformed) {
		t.Errorf("depth %d: err = %v, want ErrMalformed", maxNestingDepth+1, err)
	}
}

func TestCheckTokensRejectsUnterminatedInput(t *testing.T) {
	for _, data := range []string{`{"a":`, `[1,2`, `{"a":{"b":1}`, `"abc`} {
		if err := checkTokens([]byte(data)); !errors.Is(err, ErrMalformed) {
			t.Errorf("checkTokens(%q) = %v, want ErrMalformed", data, err)
		}
	}
}

func TestCheck(t *testing.T) {
	tests := []struct {
		name string
		in   string
		ok   bool
	}{
		{"object", `{"a":[1,{"b":null}],"c":"😀"}`, true},
		{"invalid UTF-8", "{\"a\":\"\xff\"}", false},
		{"duplicate key", `{"a":1,"a":2}`, false},
		{"duplicate key nested", `{"x":{"a":1,"a":2}}`, false},
		{"same key in sibling objects", `[{"a":1},{"a":2}]`, true},
		{"lone high surrogate", `{"a":"\ud800"}`, false},
		{"two values", `{} {}`, false},
		{"empty", ``, false},
		{"invalid token", `{"a":tru}`, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Check([]byte(tt.in))
			if (err == nil) != tt.ok {
				t.Fatalf("Check(%q) = %v, want ok=%v", tt.in, err, tt.ok)
			}
			if err != nil && !errors.Is(err, ErrMalformed) {
				t.Errorf("err = %v, want ErrMalformed", err)
			}
		})
	}
}

func TestCheckRejectsNoncharacters(t *testing.T) {
	u := `\` + "u"
	for name, data := range map[string]string{
		"first of the block":     `"` + u + `fdd0"`,
		"last of the block":      `"` + u + `fdef"`,
		"end of plane 0":         `"` + u + `fffe"`,
		"last of plane 0":        `"` + u + `ffff"`,
		"end of plane 1, a pair": `"` + u + "d83f" + u + `dffe"`,
		"end of plane 16":        `"` + u + "dbff" + u + `dfff"`,
		"raw UTF-8":              "\"a￿b\"",
		"raw in plane 1":         "\"\U0001ffff\"",
		"in a member name":       `{"` + u + `ffff":1}`,
		"raw in a member name":   "{\"﷐\":1}",
		"nested":                 `{"a":[{"b":"` + u + `ffff"}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			if err := Check([]byte(data)); !errors.Is(err, ErrMalformed) {
				t.Errorf("Check = %v, want ErrMalformed", err)
			}
			if err := CheckRecorded([]byte(data)); err != nil {
				t.Errorf("CheckRecorded = %v, want nil", err)
			}
		})
	}
}

func TestCheckAcceptsNeighboursOfNoncharacters(t *testing.T) {
	u := `\` + "u"
	for _, data := range []string{
		`"` + u + `fdcf"`, `"` + u + `fdf0"`, `"` + u + `fffd"`,
		`"` + u + "d83f" + u + `dffd"`, `"` + u + "d840" + u + `dc00"`,
		"\"﷏ﷰ�\U0001fffd\U00020000\"", `{"a":"` + u + `0041","b":1,"c":null}`,
	} {
		if err := Check([]byte(data)); err != nil {
			t.Errorf("Check(%s) = %v", data, err)
		}
	}
}

func TestCheckRecordedKeepsEveryOtherRule(t *testing.T) {
	u := `\` + "u"
	for _, data := range []string{
		`"` + u + `d800"`, `{"a":1,"a":2}`, `{} {}`, `{"a":1`, ``, "\"\xff\"", strings.Repeat("[", 33) + strings.Repeat("]", 33),
	} {
		if err := CheckRecorded([]byte(data)); !errors.Is(err, ErrMalformed) {
			t.Errorf("CheckRecorded(%q) = %v, want ErrMalformed", data, err)
		}
	}
}

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

// TestDuplicateKeyIsQuotedCut: the error of a duplicate key quotes at most
// errquote.MaxBytes of the key, however long it is (spec#143).
func TestDuplicateKeyIsQuotedCut(t *testing.T) {
	long := strings.Repeat("k", 5000)
	err := Check([]byte(`{"` + long + `":1,"` + long + `":2}`))
	if !errors.Is(err, ErrMalformed) || !strings.Contains(err.Error(), "duplicate key") {
		t.Fatalf("err = %.200v, want a duplicate key", err)
	}
	if len(err.Error()) > 200 || !strings.Contains(err.Error(), `"...`) {
		t.Errorf("err of %d bytes does not quote the key cut: %.200s", len(err.Error()), err)
	}
}

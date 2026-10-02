// SPDX-License-Identifier: Apache-2.0

package ijson

import (
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

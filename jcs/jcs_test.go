// SPDX-License-Identifier: Apache-2.0

package jcs

import (
	"encoding/json"
	"strings"
	"testing"
)

// r builds a string from code points so that no escapes appear in the source.
func r(codepoints ...rune) string { return string(codepoints) }

// esc returns the JSON escape sequence for u (e.g. esc("000f")), assembled from parts.
func esc(hex string) string { return `\` + "u" + hex }

func TestCanonicalizeSortsKeysByUTF16CodeUnits(t *testing.T) {
	// RFC 8785 section 3.2.3: the emoji (UTF-16 D83D DE00) sorts before U+FB33,
	// although it would sort after it by code point.
	in := map[string]any{
		r(0x20ac): "Euro Sign", r(0x0d): "Carriage Return", r(0xfb33): "Hebrew Letter Dalet With Dagesh",
		"1": "One", r(0x1f600): "Emoji: Grinning Face", r(0x80): "Control", r(0xf6): "Latin Small Letter O With Diaeresis",
	}
	got, err := Canonicalize(in)
	if err != nil {
		t.Fatal(err)
	}
	wantOrder := []string{`\r`, "1", r(0x80), r(0xf6), r(0x20ac), r(0x1f600), r(0xfb33)}
	pos := -1
	for _, k := range wantOrder {
		i := strings.Index(string(got), `"`+k+`":`)
		if i <= pos {
			t.Fatalf("key %q out of order in %s", k, got)
		}
		pos = i
	}
}

func TestCanonicalizeEscapesStringsLikeRFC8785(t *testing.T) {
	// RFC 8785 section 3.2.2.2.
	in := map[string]any{"a": r(0x20ac) + "$" + r(0x0f) + r(0x0a) + "A'B" + r(0x22) + r(0x5c) + r(0x5c) + r(0x22) + "/"}
	want := `{"a":"` + r(0x20ac) + `$` + esc("000f") + `\nA'B\"\\\\\"/"}`
	got, err := Canonicalize(in)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
}

func TestCanonicalizeControlCharacters(t *testing.T) {
	tests := map[rune]string{
		0x08: `\b`, 0x09: `\t`, 0x0a: `\n`, 0x0c: `\f`, 0x0d: `\r`,
		0x00: esc("0000"), 0x1f: esc("001f"), 0x7f: r(0x7f), 0x2028: r(0x2028),
	}
	for in, want := range tests {
		got, err := Canonicalize(r(in))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != `"`+want+`"` {
			t.Errorf("U+%04X: got %s, want %q", in, got, want)
		}
	}
}

func TestCanonicalizeLiterals(t *testing.T) {
	tests := []struct {
		name string
		in   any
		want string
	}{
		{"null", nil, "null"},
		{"true", true, "true"},
		{"false", false, "false"},
		{"empty object", map[string]any{}, "{}"},
		{"empty array", []any{}, "[]"},
		{"nested", map[string]any{"b": []any{json.Number("1"), "x"}, "a": map[string]any{"z": nil, "y": true}},
			`{"a":{"y":true,"z":null},"b":[1,"x"]}`},
		{"integer", json.Number("1000"), "1000"},
		{"integer written as decimal", json.Number("10.0"), "10"},
		{"integer in exponent form", json.Number("1e3"), "1000"},
		{"negative zero", json.Number("-0"), "0"},
		{"negative integer", json.Number("-42"), "-42"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Canonicalize(tt.in)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tt.want {
				t.Errorf("got %s, want %s", got, tt.want)
			}
		})
	}
}

func TestCanonicalizeRejectsUnsupportedValues(t *testing.T) {
	tests := map[string]any{
		"fraction":           json.Number("10.5"),
		"beyond exact range": json.Number("9007199254740993"),
		"not a number":       json.Number("abc"),
		"go float":           1.5,
		"unsupported type":   struct{}{},
		"nested unsupported": []any{json.Number("0.1")},
		"nested in object":   map[string]any{"a": json.Number("0.1")},
	}
	for name, in := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := Canonicalize(in); err == nil {
				t.Error("expected error")
			}
		})
	}
}

func TestDigestFormat(t *testing.T) {
	d, err := Digest(map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	// SHA-256 of "{}".
	const want = "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
	if d != want {
		t.Errorf("got %s, want %s", d, want)
	}
	if _, err := Digest(json.Number("0.5")); err == nil {
		t.Error("expected error for unsupported value")
	}
}

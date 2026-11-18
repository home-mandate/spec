// SPDX-License-Identifier: Apache-2.0

package origin_test

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/home-mandate/spec/internal/origin"
)

type originCase struct {
	ID       string          `json:"id"`
	Value    *string         `json:"value"`
	HTU      *string         `json:"htu"`
	URL      *string         `json:"url"`
	Proof    json.RawMessage `json:"proof"`
	Expected string          `json:"expected"`
}

func loadCases(t *testing.T) []originCase {
	t.Helper()
	data, err := os.ReadFile("../../conformance/origin-v0.json")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Cases []originCase `json:"cases"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	return file.Cases
}

func TestConformanceCases(t *testing.T) {
	cases := loadCases(t)
	if len(cases) == 0 {
		t.Fatal("no cases")
	}
	for _, c := range cases {
		t.Run(c.ID, func(t *testing.T) {
			switch {
			case c.Value != nil:
				err := origin.Valid(*c.Value)
				if got := map[bool]string{true: "valid", false: "invalid"}[err == nil]; got != c.Expected {
					t.Errorf("Valid(%q) = %v, want %s", *c.Value, err, c.Expected)
				}
			case c.Proof != nil:
				t.Skip("a DPoP proof: package internal/dpop checks it")
			case c.HTU != nil && c.URL != nil:
				got := map[bool]string{true: "match", false: "mismatch"}[origin.HTUMatches(*c.HTU, *c.URL)]
				if got != c.Expected {
					t.Errorf("HTUMatches(%q, %q) = %s, want %s", *c.HTU, *c.URL, got, c.Expected)
				}
			default:
				t.Fatal("a case needs value, or htu and url")
			}
		})
	}
}

func TestValidNamesTheRuleBroken(t *testing.T) {
	tests := []struct {
		value string
		want  error
	}{
		{"http://home.example.net", origin.ErrScheme},
		{"https://home.example.net/", origin.ErrExtra},
		{"https://a@home.example.net", origin.ErrExtra},
		{"https://home.example.net:443", origin.ErrPort},
		{"https://home.example.net:x", origin.ErrPort},
		{"https://home.example.net:99999999999999999999", origin.ErrPort},
		{"https://Home.example.net", origin.ErrHost},
		{"https://home.example.net:8443:1", origin.ErrPort},
		{"https://:8443", origin.ErrHost},
	}
	for _, tc := range tests {
		if err := origin.Valid(tc.value); err != tc.want {
			t.Errorf("Valid(%q) = %v, want %v", tc.value, err, tc.want)
		}
	}
}

// The paths of the examples of RFC 3986 Section 5.4 (base http://a/b/c/d;p?q) exercise the
// removal of dot segments through HTUMatches.
func TestDotSegmentsOfRFC3986(t *testing.T) {
	tests := []struct{ raw, want string }{
		{"http://a/b/c/./../../g", "http://a/g"},
		{"http://a/b/c/../../../g", "http://a/g"},
		{"http://a/b/c/../../../../g", "http://a/g"},
		{"http://a/./g", "http://a/g"},
		{"http://a/../g", "http://a/g"},
		{"http://a/b/c/g.", "http://a/b/c/g."},
		{"http://a/b/c/.g", "http://a/b/c/.g"},
		{"http://a/b/c/g..", "http://a/b/c/g.."},
		{"http://a/b/c/..g", "http://a/b/c/..g"},
		{"http://a/b/c/./g/.", "http://a/b/c/g/"},
		{"http://a/b/c/g/./h", "http://a/b/c/g/h"},
		{"http://a/b/c/g/../h", "http://a/b/c/h"},
		{"http://a/b/c/..", "http://a/b/"},
		{"http://a/b/c/.", "http://a/b/c/"},
	}
	for _, tc := range tests {
		if !origin.HTUMatches(tc.raw, tc.want) {
			t.Errorf("HTUMatches(%q, %q) = false", tc.raw, tc.want)
		}
	}
}

func TestHTUMismatchesForUnparsableInput(t *testing.T) {
	for _, raw := range []string{"", "mcp", "https://", "https://home.example.net/a b", "mailto:a@example.net", "https://[::1/mcp", "https://home.example.net/%zz"} {
		if origin.HTUMatches(raw, raw) {
			t.Errorf("HTUMatches(%q, itself) = true", raw)
		}
	}
}

func FuzzValid(f *testing.F) {
	for _, c := range []string{"https://home.example.net", "https://hm.example.org:8443", "https://xn--bcher-kva.example", "https://home.example.net:443", "https://192.0.2.1"} {
		f.Add(c)
	}
	f.Fuzz(func(t *testing.T, value string) {
		if origin.Valid(value) != nil {
			return
		}
		// A public origin has one form: it is ASCII, in lower case, and a URL built from it
		// matches itself and its own form with an explicit path.
		if strings.ToLower(value) != value {
			t.Fatalf("valid but not in lower case: %q", value)
		}
		for _, r := range value {
			if r > 0x7e || r < 0x21 {
				t.Fatalf("valid but not printable ASCII: %q", value)
			}
		}
		if !origin.HTUMatches(value, value+"/") || !origin.HTUMatches(value+"/mcp", value+"/mcp") {
			t.Fatalf("a URL built from %q does not match itself", value)
		}
	})
}

func FuzzHTUMatches(f *testing.F) {
	f.Add("https://home.example.net/mcp", "HTTPS://Home.example.net:443/x/../mcp?q")
	f.Add("https://home.example.net/%7e", "https://home.example.net/~")
	f.Fuzz(func(t *testing.T, a, b string) {
		ab, ba := origin.HTUMatches(a, b), origin.HTUMatches(b, a)
		if ab != ba {
			t.Fatalf("not symmetric: %q %q", a, b)
		}
		if ab && !origin.HTUMatches(a, a) {
			t.Fatalf("matches another but not itself: %q", a)
		}
	})
}

// The bounds of the character classes and lengths of Section 11.7 item 1, one value at each
// edge.
func TestValidAtTheEdges(t *testing.T) {
	label63 := strings.Repeat("a", 63)
	host253 := strings.Repeat(label63+".", 3) + strings.Repeat("b", 61)
	for value, want := range map[string]bool{
		"https://home.a":             true,
		"https://home.z":             true,
		"https://a9.z0":              true,
		"https://09.example":         true,
		"https://home.0xa":           false,
		"https://home.0xf":           false,
		"https://home.0x0":           false,
		"https://home.example:1":     true,
		"https://home.example:9":     true,
		"https://home.example:65535": true,
		"https://home.example:65536": false,
		"https://home.example:1a":    false,
		"https://home.example:/":     false,
		"https://" + label63 + ".z":  true,
		"https://" + label63 + "a.z": false,
		"https://" + host253:         true,
		"https://" + host253 + "b":   false,
		"https://xn--a.example":      true, // decodes to U+0080, outside ASCII
		"https://h`.example":         false,
		"https://h{.example":         false,
		"https://h/.example":         false,
		"https://h:.example":         false,
	} {
		if got := origin.Valid(value) == nil; got != want {
			t.Errorf("Valid(%q) = %v, want %v", value, origin.Valid(value), want)
		}
	}
}

// The edges of percent-decoding, hexadecimal digits, ports and userinfo in the comparison of
// htu (RFC 3986 Section 6.2.2).
func TestHTUAtTheEdges(t *testing.T) {
	const base = "https://home.example"
	for _, tc := range []struct {
		htu, url string
		want     bool
	}{
		{base + "/%30%39%41%5A%61%7A%2D%2E%5F%7E", base + "/09AZaz-._~", true},
		{base + "/%2F", base + "//", false},
		{base + "/%3A", base + "/:", false},
		{base + "/%40", base + "/%40", true},
		{base + "/%5B", base + "/%5B", true},
		{base + "/%60", base + "/%60", true},
		{base + "/%7B", base + "/%7B", true},
		{base + "/a%2f", base + "/a%2F", true},
		{base + "/a%2F", base + "/a%2F", true},
		{base + "/a%af", base + "/a%AF", true},
		{base + "/a%g0", base + "/a%g0", false},
		{base + "/a%G0", base + "/a%G0", false},
		{base + "/a%/0", base + "/a%/0", false},
		{base + "/a%:0", base + "/a%:0", false},
		{base + "/a%@0", base + "/a%@0", false},
		{base + "/a%`0", base + "/a%`0", false},
		{base + "/a%2", base + "/a%2", false},
		{base + ":8443/mcp", base + ":8443/mcp", true},
		{base + ":8443/mcp", base + "/mcp", false},
		{"https://u@home.example/mcp", base + "/mcp", false},
	} {
		if got := origin.HTUMatches(tc.htu, tc.url); got != tc.want {
			t.Errorf("HTUMatches(%q, %q) = %v, want %v", tc.htu, tc.url, got, tc.want)
		}
	}
	if origin.Valid("https://home.example:10") != nil {
		t.Error("port 10 refused")
	}
}

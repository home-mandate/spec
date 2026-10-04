// SPDX-License-Identifier: Apache-2.0

package schema_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/mandate-spec/mandate-spec/schema"
)

func TestSchemasDeclareTheirIDs(t *testing.T) {
	for name, tt := range map[string]struct {
		data func() []byte
		id   string
	}{
		"mandate":    {schema.Mandate, schema.MandateID},
		"audit":      {schema.Audit, schema.AuditID},
		"vocabulary": {schema.Vocabulary, schema.VocabularyID},
	} {
		var doc struct {
			ID string `json:"$id"`
		}
		if err := json.Unmarshal(tt.data(), &doc); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if doc.ID != tt.id {
			t.Errorf("%s: $id = %q, want %q", name, doc.ID, tt.id)
		}
	}
}

func TestSchemasAreCopies(t *testing.T) {
	first := schema.Mandate()
	first[0] = 'X'
	if schema.Mandate()[0] == 'X' {
		t.Error("Mandate() returned shared bytes")
	}
	audit := schema.Audit()
	audit[0] = 'X'
	if schema.Audit()[0] == 'X' {
		t.Error("Audit() returned shared bytes")
	}
}

// portableEscapes are the escapes a pattern may use. Classes such as \s, \d and \w and
// the boundary \b differ between regular expression dialects (ECMA-262, RE2, PCRE,
// Python), so the schemas spell every class out (SPEC-v0 section 3).
const portableEscapes = `.*+?()[]{}|^$\/-`

func TestPatternsUseOnlyThePortableSubset(t *testing.T) {
	for name, data := range map[string][]byte{"mandate": schema.Mandate(), "audit": schema.Audit(), "vocabulary": schema.Vocabulary()} {
		var doc any
		if err := json.Unmarshal(data, &doc); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		patterns := collectPatterns(doc, nil)
		if len(patterns) < 3 {
			t.Fatalf("%s: found only %d patterns", name, len(patterns))
		}
		for _, p := range patterns {
			if problem := portabilityProblem(p); problem != "" {
				t.Errorf("%s: pattern %q: %s", name, p, problem)
			}
		}
	}
}

func TestPortabilityProblemDetectsDialectDependentPatterns(t *testing.T) {
	for pattern, portable := range map[string]bool{
		`^[a-z0-9_]{1,64}$`:      true,
		`^a[.]b\.c$`:             true,
		`^https://[^\s]+$`:       false, // \s differs between dialects
		`^\d+$`:                  false,
		`^\w+$`:                  false,
		`^a\b$`:                  false,
		`[a-z]+`:                 false, // not anchored
		`^(?=a)a$`:               false, // lookahead
		`^(?i)a$`:                false, // inline flag
		`^é$`:                    false, // not ASCII
		`^a.b$`:                  false, // bare dot: matches line terminators in some dialects only
		`^a$|^b$`:                false, // anchors inside
		"^a\n$":                  false,
		`^a\`:                    false,
		`^[.]$`:                  true,
		`/[.][.]?(/|$)`:          false,
		`^(\*|[a-z][a-z0-9_]*)$`: true,
	} {
		if got := portabilityProblem(pattern) == ""; got != portable {
			t.Errorf("portable(%q) = %v, want %v (%s)", pattern, got, portable, portabilityProblem(pattern))
		}
	}
}

func collectPatterns(node any, out []string) []string {
	switch n := node.(type) {
	case map[string]any:
		for key, value := range n {
			if s, ok := value.(string); ok && key == "pattern" {
				out = append(out, s)
				continue
			}
			out = collectPatterns(value, out)
		}
	case []any:
		for _, value := range n {
			out = collectPatterns(value, out)
		}
	}
	return out
}

// portabilityProblem returns why a pattern is outside the portable subset, or "".
func portabilityProblem(p string) string {
	if len(p) < 2 || p[0] != '^' || p[len(p)-1] != '$' {
		return "must start with ^ and end with $"
	}
	inClass := false
	for i := 1; i < len(p)-1; i++ {
		c := p[i]
		switch {
		case c < 0x20 || c > 0x7e:
			return "only printable ASCII is allowed"
		case c == '\\':
			i++
			if i >= len(p)-1 || !strings.ContainsRune(portableEscapes, rune(p[i])) {
				return "escape outside the portable subset"
			}
		case inClass:
			inClass = c != ']'
		case c == '[':
			inClass = true
		case c == '.':
			return "bare dot; write an explicit class"
		case c == '^' || c == '$':
			return "anchor inside the pattern"
		case c == '(' && p[i+1] == '?':
			return "group modifiers and lookarounds are not portable"
		}
	}
	return ""
}

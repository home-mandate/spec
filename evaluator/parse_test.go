// SPDX-License-Identifier: Apache-2.0

package evaluator_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"testing"

	mandatespec "github.com/mandate-spec/mandate-spec"
	"github.com/mandate-spec/mandate-spec/evaluator"
)

// baseMandate ist ein minimales gültiges Mandat; %s ist der Rohwert von display_name.
const baseMandate = `{"type":"https://mandate-spec.org/mandate/v0","id":"m-test","principal":"household:t",` +
	`"agent":{"client_id":"hm-client:test-0001","display_name":"%s"},` +
	`"rules":[{"id":"r-1","resource":{"category":"light"},"actions":["turn_on"],"decision":"allow"}],` +
	`"default":"deny","approval":{"timeout":"PT2M","approvers":["a-1"]},"limits":{"max_actions_per_hour":10},` +
	`"valid_from":"2026-01-01T00:00:00+01:00","created_by":"a-1","created_at":"2025-12-31T12:00:00+01:00"}`

func mandateNamed(displayName string) []byte {
	return []byte(fmt.Sprintf(baseMandate, displayName))
}

func mandateReplacing(old, replacement string) []byte {
	base := fmt.Sprintf(baseMandate, "Test")
	if !strings.Contains(base, old) {
		panic("baseMandate does not contain " + old)
	}
	return []byte(strings.Replace(base, old, replacement, 1))
}

func TestParseAcceptsAllShippedMandates(t *testing.T) {
	var paths []string
	for _, pattern := range []string{"examples/*.json", "conformance/mandates/*.json"} {
		found, err := fs.Glob(mandatespec.FS(), pattern)
		if err != nil {
			t.Fatal(err)
		}
		paths = append(paths, found...)
	}
	if len(paths) < 5 {
		t.Fatalf("expected at least 5 shipped mandates, found %d", len(paths))
	}
	for _, p := range paths {
		t.Run(p, func(t *testing.T) {
			data, err := fs.ReadFile(mandatespec.FS(), p)
			if err != nil {
				t.Fatal(err)
			}
			var head struct {
				ID string `json:"id"`
			}
			if err := json.Unmarshal(data, &head); err != nil {
				t.Fatal(err)
			}
			m, err := evaluator.Parse(data)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if m.ID() != head.ID {
				t.Errorf("ID = %q, want %q", m.ID(), head.ID)
			}
			if !strings.HasPrefix(m.Digest(), "sha256:") || len(m.Digest()) != len("sha256:")+64 {
				t.Errorf("malformed digest %q", m.Digest())
			}
		})
	}
}

func TestParseAcceptsMinimalMandate(t *testing.T) {
	if _, err := evaluator.Parse(mandateNamed("Test")); err != nil {
		t.Fatalf("Parse: %v", err)
	}
}

func TestParseAcceptsSurrogatePairWithSameDigestAsLiteral(t *testing.T) {
	// Escape zusammengesetzt, damit es im Quelltext garantiert als Escape steht: 😀.
	pair := `\` + "ud83d" + `\` + "ude00"
	escaped, err := evaluator.Parse(mandateNamed("Smile " + pair))
	if err != nil {
		t.Fatalf("escaped: %v", err)
	}
	literal, err := evaluator.Parse(mandateNamed("Smile \U0001F600"))
	if err != nil {
		t.Fatalf("literal: %v", err)
	}
	if escaped.Digest() != literal.Digest() {
		t.Errorf("digest differs: %s vs %s", escaped.Digest(), literal.Digest())
	}
}

func TestParseAcceptsIntegerWrittenAsDecimal(t *testing.T) {
	// JSON Schema zählt 10.0 als integer; der Fingerabdruck muss dem von 10 entsprechen (RFC 8785).
	decimal, err := evaluator.Parse(mandateReplacing(`"max_actions_per_hour":10`, `"max_actions_per_hour":10.0`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	plain, err := evaluator.Parse(mandateNamed("Test"))
	if err != nil {
		t.Fatal(err)
	}
	if decimal.Digest() != plain.Digest() {
		t.Errorf("digest differs: %s vs %s", decimal.Digest(), plain.Digest())
	}
}

func TestParseRejects(t *testing.T) {
	valid := fmt.Sprintf(baseMandate, "Test")
	tests := []struct {
		name string
		data []byte
		want error
	}{
		{"empty input", []byte(""), evaluator.ErrMalformed},
		{"whitespace only", []byte("  \n"), evaluator.ErrMalformed},
		{"null", []byte("null"), evaluator.ErrSchema},
		{"array", []byte("[]"), evaluator.ErrSchema},
		{"syntax error", []byte(valid[:len(valid)-1]), evaluator.ErrMalformed},
		{"trailing value", []byte(valid + "{}"), evaluator.ErrMalformed},
		{"trailing garbage", []byte(valid + "x"), evaluator.ErrMalformed},
		{"invalid utf-8", mandateNamed("Test \xff"), evaluator.ErrMalformed},
		{"lone high surrogate", mandateNamed(`Test \ud800`), evaluator.ErrMalformed},
		{"lone low surrogate", mandateNamed(`Test \udc00`), evaluator.ErrMalformed},
		{"high surrogate followed by text", mandateNamed(`\ud83dx`), evaluator.ErrMalformed},
		{"reversed surrogate pair", mandateNamed(`\ude00\ud83d`), evaluator.ErrMalformed},
		{"duplicate top-level key", mandateReplacing(`"id":"m-test"`, `"id":"m-test","id":"m-other"`), evaluator.ErrMalformed},
		{"duplicate nested key", mandateReplacing(`"timeout":"PT2M"`, `"timeout":"PT2M","timeout":"PT9M"`), evaluator.ErrMalformed},
		{"too large", []byte(valid + strings.Repeat(" ", evaluator.MaxMandateBytes)), evaluator.ErrTooLarge},
		{"too deep", mandateReplacing(`"created_by":"a-1"`, `"created_by":"a-1","x":`+strings.Repeat("[", 64)+strings.Repeat("]", 64)), evaluator.ErrMalformed},
		{"default allow", mandateReplacing(`"default":"deny"`, `"default":"allow"`), evaluator.ErrSchema},
		{"date without time", mandateReplacing(`"valid_from":"2026-01-01T00:00:00+01:00"`, `"valid_from":"2026-01-01"`), evaluator.ErrSchema},
		{"impossible date", mandateReplacing(`"valid_from":"2026-01-01T00:00:00+01:00"`, `"valid_from":"2026-02-30T00:00:00+01:00"`), evaluator.ErrSchema},
		{"impossible hour", mandateReplacing(`"valid_from":"2026-01-01T00:00:00+01:00"`, `"valid_from":"2026-01-01T25:00:00+01:00"`), evaluator.ErrSchema},
		{"non-integer limit", mandateReplacing(`"max_actions_per_hour":10`, `"max_actions_per_hour":10.5`), evaluator.ErrSchema},
		{"action outside category", mandateReplacing(`"actions":["turn_on"]`, `"actions":["unlock"]`), evaluator.ErrSemantic},
		{"time window start equals end", mandateReplacing(`"decision":"allow"`, `"decision":"allow","conditions":{"time_window":"00:00-00:00"}`), evaluator.ErrSemantic},
		{"duplicate rule id", mandateReplacing(`"decision":"allow"}]`, `"decision":"allow"},{"id":"r-1","resource":{"any":true},"actions":["read"],"decision":"deny"}]`), evaluator.ErrSemantic},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := evaluator.Parse(tt.data)
			if !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
			if m != nil {
				t.Error("mandate returned together with error")
			}
		})
	}
}

func TestParseSizeLimitBoundary(t *testing.T) {
	valid := mandateNamed("Test")
	padded := append(valid, []byte(strings.Repeat(" ", evaluator.MaxMandateBytes-len(valid)))...)
	if _, err := evaluator.Parse(padded); err != nil {
		t.Fatalf("exactly MaxMandateBytes rejected: %v", err)
	}
	if _, err := evaluator.Parse(append(padded, ' ')); !errors.Is(err, evaluator.ErrTooLarge) {
		t.Fatalf("MaxMandateBytes+1: err = %v, want ErrTooLarge", err)
	}
}

func TestParseAllowsUnknownExtensionCategoryWithAnyAction(t *testing.T) {
	// SPEC-v0 3.1 Nr. 4: Vokabular unbekannter Erweiterungen wird nicht geprüft.
	data := mandateReplacing(`"resource":{"category":"light"},"actions":["turn_on"]`,
		`"resource":{"category":"paperless:document"},"actions":["tag"]`)
	if _, err := evaluator.Parse(data); err != nil {
		t.Fatalf("Parse: %v", err)
	}
}

func TestParseAllowsWildcardActionOnKnownCategory(t *testing.T) {
	if _, err := evaluator.Parse(mandateReplacing(`"actions":["turn_on"]`, `"actions":["*"]`)); err != nil {
		t.Fatalf("Parse: %v", err)
	}
}

func TestParseDigestIgnoresKeyOrderAndWhitespace(t *testing.T) {
	a, err := evaluator.Parse(mandateNamed("Test"))
	if err != nil {
		t.Fatal(err)
	}
	var generic map[string]any
	if err := json.Unmarshal(mandateNamed("Test"), &generic); err != nil {
		t.Fatal(err)
	}
	indented, err := json.MarshalIndent(generic, "", "   ")
	if err != nil {
		t.Fatal(err)
	}
	b, err := evaluator.Parse(indented)
	if err != nil {
		t.Fatal(err)
	}
	if a.Digest() != b.Digest() {
		t.Errorf("digest differs: %s vs %s", a.Digest(), b.Digest())
	}
	c, err := evaluator.Parse(mandateNamed("Test2"))
	if err != nil {
		t.Fatal(err)
	}
	if a.Digest() == c.Digest() {
		t.Error("different content produced the same digest")
	}
}

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

// baseMandate is a minimal valid mandate; %s is the raw value of display_name.
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
	// The escape is assembled so that it is guaranteed to appear as an escape in the source: 😀.
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
	// JSON Schema counts 10.0 as an integer; the digest must equal that of 10 (RFC 8785).
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
		{"leap second", mandateReplacing(`"valid_from":"2026-01-01T00:00:00+01:00"`, `"valid_from":"2026-06-30T23:59:60Z"`), evaluator.ErrSchema},
		{"expires before valid_from", mandateReplacing(`"created_by"`, `"expires":"2025-12-31T23:59:59+01:00","created_by"`), evaluator.ErrSemantic},
		{"expires equals valid_from", mandateReplacing(`"created_by"`, `"expires":"2025-12-31T23:00:00Z","created_by"`), evaluator.ErrSemantic},
		{"timeout below 10s", mandateReplacing(`"timeout":"PT2M"`, `"timeout":"PT9S"`), evaluator.ErrSemantic},
		{"timeout zero", mandateReplacing(`"timeout":"PT2M"`, `"timeout":"PT0S"`), evaluator.ErrSemantic},
		{"timeout above 1h", mandateReplacing(`"timeout":"PT2M"`, `"timeout":"PT60M1S"`), evaluator.ErrSemantic},
		{"control character in display_name", mandateNamed(`Test\u0007`), evaluator.ErrSemantic},
		{"bidi override in display_name", mandateNamed("Test " + string(rune(0x202e))), evaluator.ErrSemantic},
		{"zero width space in display_name", mandateNamed("Te" + string(rune(0x200b)) + "st"), evaluator.ErrSemantic},
		{"line separator in created_by", mandateReplacing(`"created_by":"a-1"`, `"created_by":"a-1`+string(rune(0x2028))+`"`), evaluator.ErrSemantic},
		{"control character in approver", mandateReplacing(`"approvers":["a-1"]`, `"approvers":["a-1\n"]`), evaluator.ErrSemantic},
		{"control character in rule approver", mandateReplacing(`"decision":"allow"`, `"decision":"ask","approval":{"timeout":"PT1M","approvers":["a\t2"]}`), evaluator.ErrSemantic},
		{"unknown client_id scheme", mandateReplacing(`"client_id":"hm-client:test-0001"`, `"client_id":"ftp://agent.example"`), evaluator.ErrSchema},
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

func TestParseAcceptsTimeoutBoundariesAndNamespacedClientID(t *testing.T) {
	for _, data := range [][]byte{
		mandateReplacing(`"timeout":"PT2M"`, `"timeout":"PT10S"`),
		mandateReplacing(`"timeout":"PT2M"`, `"timeout":"PT60M"`),
		mandateReplacing(`"timeout":"PT2M"`, `"timeout":"PT59M60S"`),
		mandateReplacing(`"client_id":"hm-client:test-0001"`, `"client_id":"pairing:Ab9._~-x"`),
		mandateReplacing(`"client_id":"hm-client:test-0001"`, `"client_id":"https://agent.example/client.json"`),
		mandateNamed("Familie 👪 Müller"),
	} {
		if _, err := evaluator.Parse(data); err != nil {
			t.Errorf("Parse(%s): %v", data[100:180], err)
		}
	}
}

func TestParseKeepsNoReferenceToInput(t *testing.T) {
	data := mandateNamed("Test")
	m, err := evaluator.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	before := evaluator.Evaluate(m, request("light", "flur", "turn_on"))
	for i := range data {
		data[i] = ' '
	}
	after := evaluator.Evaluate(m, request("light", "flur", "turn_on"))
	if before.Decision != after.Decision || before.MandateDigest != after.MandateDigest || m.ID() != "m-test" {
		t.Errorf("mandate changed after input was overwritten: %+v vs %+v", before, after)
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
	// SPEC-v0 3.1 item 4: the vocabulary of unknown extensions is not checked.
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

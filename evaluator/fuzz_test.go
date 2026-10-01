// SPDX-License-Identifier: Apache-2.0

package evaluator_test

import (
	"encoding/json"
	"errors"
	"io/fs"
	"reflect"
	"testing"
	"time"
	"unicode/utf8"

	mandatespec "github.com/mandate-spec/mandate-spec"
	"github.com/mandate-spec/mandate-spec/evaluator"
)

// shippedMandates liefert alle mitgelieferten gültigen Mandate als Ausgangsmaterial.
func shippedMandates(f *testing.F) [][]byte {
	f.Helper()
	var out [][]byte
	for _, pattern := range []string{"examples/*.json", "conformance/mandates/*.json"} {
		paths, err := fs.Glob(mandatespec.FS(), pattern)
		if err != nil {
			f.Fatal(err)
		}
		for _, p := range paths {
			data, err := fs.ReadFile(mandatespec.FS(), p)
			if err != nil {
				f.Fatal(err)
			}
			out = append(out, data)
		}
	}
	return out
}

func FuzzParse(f *testing.F) {
	for _, data := range shippedMandates(f) {
		f.Add(data)
	}
	f.Add(mandateNamed("Test"))
	f.Add([]byte(`{"a":1,"a":2}`))
	f.Add([]byte(`"\ud800"`))
	f.Add([]byte(`[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]`))
	f.Fuzz(func(t *testing.T, data []byte) {
		m, err := evaluator.Parse(data)
		if (m == nil) == (err == nil) {
			t.Fatalf("Parse must return either a mandate or an error, got %v, %v", m, err)
		}
		if err != nil {
			if !errors.Is(err, evaluator.ErrTooLarge) && !errors.Is(err, evaluator.ErrMalformed) &&
				!errors.Is(err, evaluator.ErrSchema) && !errors.Is(err, evaluator.ErrSemantic) {
				t.Fatalf("unclassified error: %v", err)
			}
			return
		}
		if !utf8.Valid(data) || !json.Valid(data) {
			t.Fatal("accepted input that is not valid UTF-8 JSON")
		}
		again, err := evaluator.Parse(data)
		if err != nil || again.Digest() != m.Digest() {
			t.Fatalf("Parse is not deterministic: %v", err)
		}
	})
}

// vocabulary spiegelt SPEC-v0 Abschnitt 5, unabhängig von der Implementierung.
var vocabulary = map[string][]string{
	"light": {"read", "turn_on", "turn_off", "set"}, "switch": {"read", "turn_on", "turn_off"},
	"climate": {"read", "set_temperature", "set_mode"}, "cover": {"read", "open", "close", "stop", "set_position"},
	"gate": {"read", "open", "close"}, "lock": {"read", "lock", "unlock", "open"}, "alarm": {"read", "arm", "disarm"},
	"camera": {"read", "snapshot"}, "media": {"read", "turn_on", "turn_off", "play", "pause", "set_volume"},
	"sensor": {"read"}, "scene": {"read", "activate"}, "script": {"read", "run"}, "other": {"read", "set"},
}

func inVocabulary(category, action string) (categoryKnown, actionKnown bool) {
	actions, ok := vocabulary[category]
	if !ok {
		return false, false
	}
	for _, a := range actions {
		if a == action {
			return true, true
		}
	}
	return true, false
}

func FuzzEvaluate(f *testing.F) {
	mandates := shippedMandates(f)
	parsed := make([]*evaluator.Mandate, 0, len(mandates)+1)
	for _, data := range mandates {
		m, err := evaluator.Parse(data)
		if err != nil {
			f.Fatal(err)
		}
		parsed = append(parsed, m)
	}
	parsed = append(parsed, nil) // ungültiges Mandat
	f.Add(uint8(0), "lock.haustuer", "lock", "flur", "unlock", int64(1791824400), int16(120), "Europe/Berlin", false)
	f.Add(uint8(4), "light.flur", "light", "flur", "turn_on", int64(1791824400), int16(0), "", true)
	f.Add(uint8(3), "cover.terrasse", "cover", "terrasse", "open", int64(1792895400), int16(0), "Europe/Berlin", false)
	f.Add(uint8(4), "x", "paperless:document", "", "*", int64(0), int16(-720), "Local", false)
	f.Fuzz(func(t *testing.T, idx uint8, entity, category, area, action string, unix int64, offsetMin int16, zone string, revoked bool) {
		m := parsed[int(idx)%len(parsed)]
		req := evaluator.Request{
			Resource: evaluator.Resource{EntityID: entity, Category: category, Area: area},
			Action:   action,
			Time:     time.Unix(unix, 0).In(time.FixedZone("fuzz", int(offsetMin)*60)),
			TimeZone: zone,
			Revoked:  revoked,
		}
		got := evaluator.Evaluate(m, req)
		checkResultInvariants(t, m, req, got)
		if again := evaluator.Evaluate(m, req); !reflect.DeepEqual(got, again) {
			t.Fatalf("Evaluate is not deterministic: %+v vs %+v", got, again)
		}
	})
}

func checkResultInvariants(t *testing.T, m *evaluator.Mandate, req evaluator.Request, got evaluator.Result) {
	t.Helper()
	switch got.Decision {
	case evaluator.Allow, evaluator.Ask, evaluator.Deny:
	default:
		t.Fatalf("unknown decision %q", got.Decision)
	}
	byRule := got.Reason == evaluator.ReasonRule || got.Reason == evaluator.ReasonCriticalDemotion
	if !byRule && got.Decision != evaluator.Deny {
		t.Fatalf("reason %q with decision %q", got.Reason, got.Decision)
	}
	if got.Reason == evaluator.ReasonCriticalDemotion && got.Decision != evaluator.Ask {
		t.Fatalf("critical demotion with decision %q", got.Decision)
	}
	if byRule != (got.RuleID != "") {
		t.Fatalf("rule id %q with reason %q", got.RuleID, got.Reason)
	}
	if (got.Decision == evaluator.Ask) != (got.Approval != nil) {
		t.Fatalf("approval %+v with decision %q", got.Approval, got.Decision)
	}
	categoryKnown, actionKnown := inVocabulary(req.Resource.Category, req.Action)
	unknown := m == nil || req.Revoked || !categoryKnown || !actionKnown
	if unknown && got.Decision != evaluator.Deny {
		t.Fatalf("unknown or revoked input was not denied: %+v -> %+v", req, got)
	}
	if m == nil && got.Reason != evaluator.ReasonInvalidMandate {
		t.Fatalf("nil mandate gave reason %q", got.Reason)
	}
	if m != nil && got.MandateDigest != m.Digest() {
		t.Fatalf("digest %q, want %q", got.MandateDigest, m.Digest())
	}
}

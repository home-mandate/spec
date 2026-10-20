// SPDX-License-Identifier: Apache-2.0

package evaluator_test

import (
	"encoding/json"
	"errors"
	"io/fs"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/home-mandate/spec"
	"github.com/home-mandate/spec/evaluator"
)

// shippedMandates returns all shipped valid mandates as seed material.
func shippedMandates(f *testing.F) [][]byte {
	f.Helper()
	var out [][]byte
	for _, pattern := range []string{"examples/*.json", "conformance/mandates/*.json"} {
		paths, err := fs.Glob(spec.FS(), pattern)
		if err != nil {
			f.Fatal(err)
		}
		for _, p := range paths {
			data, err := fs.ReadFile(spec.FS(), p)
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

// vocabulary mirrors SPEC-v0 section 5, independently of the implementation.
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
	parsed = append(parsed, nil) // invalid mandate
	f.Add(uint8(0), "lock.haustuer", "lock", "flur\nerdgeschoss\nhome", "unlock", int64(1791824400), int16(120), "Europe/Berlin", "active", "")
	f.Add(uint8(4), "light.flur", "light", "flur", "turn_on", int64(1791824400), int16(0), "", "revoked", "50")
	f.Add(uint8(3), "cover.terrasse", "cover", "terrasse", "open", int64(1792895400), int16(0), "Europe/Berlin", "active", `"heat"`)
	f.Add(uint8(4), "x", "paperless:document", "", "*", int64(0), int16(-720), "Local", "", `"fan only"`)
	f.Add(uint8(0), "lock.haustuer", "lock", "flur\nflur", "unlock", int64(1791824400), int16(60), "", "active", "21.5")
	f.Add(uint8(0), "lock.haustuer", "lock", "a\nb\nc\nd\ne\nf\ng\nh\ni\nj\nk\nl\nm\nn\no\np\nq", "unlock", int64(1791824400), int16(60), "", "active", "")
	f.Add(uint8(9), "thermostat-1", "climate", "", "set_mode", int64(1791824400), int16(120), "Europe/Berlin", "active", `"auto"`)
	// areas holds the set of areas separated by line feeds, a character no area may contain.
	// parameter is the JSON text of a value given as mode and as brightness; "" means none.
	f.Fuzz(func(t *testing.T, idx uint8, entity, category, areas, action string, unix int64, offsetMin int16, zone, status, parameter string) {
		m := parsed[int(idx)%len(parsed)]
		req := evaluator.Request{
			Resource: evaluator.Resource{EntityID: entity, Category: category, Areas: splitAreas(areas)},
			Action:   action,
			Time:     time.Unix(unix, 0).In(time.FixedZone("fuzz", int(offsetMin)*60)),
			TimeZone: zone,
			Status:   evaluator.MandateStatus(status),
		}
		var value evaluator.Value
		if parameter != "" && json.Unmarshal([]byte(parameter), &value) == nil {
			req.Parameters = map[string]evaluator.Value{"mode": value, "brightness": value}
		}
		got := evaluator.Evaluate(m, req)
		checkResultInvariants(t, m, req, got)
		if again := evaluator.Evaluate(m, req); !reflect.DeepEqual(got, again) {
			t.Fatalf("Evaluate is not deterministic: %+v vs %+v", got, again)
		}
	})
}

// splitAreas reads the set of areas of a fuzz input: empty means no area.
func splitAreas(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
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
	unknown := m == nil || req.Status != evaluator.StatusActive || !categoryKnown || !actionKnown
	if unknown && got.Decision != evaluator.Deny {
		t.Fatalf("unknown or revoked input was not denied: %+v -> %+v", req, got)
	}
	for _, value := range req.Parameters {
		if text, ok := value.AsString(); ok && !identifier(text) && got.Reason != evaluator.ReasonInvalidMandate && got.Reason != evaluator.ReasonInvalidRequest {
			t.Fatalf("string parameter %q that is no identifier gave reason %q", text, got.Reason)
		}
	}
	byTheRules := got.Reason == evaluator.ReasonNoMatch || got.Reason == evaluator.ReasonRule
	if got.NotEnforced && (got.Decision != evaluator.Deny || !byTheRules || m.Enforce() || req.Resource.Critical && req.Action != "read") {
		t.Fatalf("not enforced: %+v for %+v", got, req)
	}
	if m == nil && got.Reason != evaluator.ReasonInvalidMandate {
		t.Fatalf("nil mandate gave reason %q", got.Reason)
	}
	if m != nil && got.MandateDigest != m.Digest() {
		t.Fatalf("digest %q, want %q", got.MandateDigest, m.Digest())
	}
}

// identifier reports whether s has 1 to 64 printable ASCII characters without space.
func identifier(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '!' || s[i] > '~' {
			return false
		}
	}
	return true
}

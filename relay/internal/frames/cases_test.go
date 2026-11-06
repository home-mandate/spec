// SPDX-License-Identifier: Apache-2.0

package frames_test

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/home-mandate/spec/relay/internal/frames"
)

type framesCase struct {
	ID     string `json:"id"`
	Frames []struct {
		From string `json:"from"`
		Hex  string `json:"hex"`
	} `json:"frames"`
	Expected string          `json:"expected"`
	At       *int            `json:"at"`
	Messages json.RawMessage `json:"messages"`
	Why      string          `json:"why"`
}

type bindingCase struct {
	ID     string `json:"id"`
	Tokens []struct {
		Token        string `json:"token"`
		Installation string `json:"installation"`
		State        string `json:"state"`
	} `json:"tokens"`
	ControlNotBefore string `json:"control_not_before"`
	LimitReached     bool   `json:"limit_reached"`
	Connection       struct {
		Installation string `json:"installation"`
		NotBefore    string `json:"not_before"`
	} `json:"connection"`
	FirstBytes string    `json:"first_bytes"`
	Expected   string    `json:"expected"`
	Consumed   *[]string `json:"consumed"`
	Why        string    `json:"why"`
}

func mustHex(t *testing.T, id, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("%s: hex: %v", id, err)
	}
	return b
}

// sameJSON compares two values by their JSON form.
func sameJSON(t *testing.T, a any, b json.RawMessage) bool {
	t.Helper()
	data, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	var x, y any
	if err := json.Unmarshal(data, &x); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &y); err != nil {
		t.Fatal(err)
	}
	return reflect.DeepEqual(x, y)
}

func TestFramesCasesMatchTheReference(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range loadCases[framesCase](t, "../../conformance/frames-v0.json") {
		in := make([]frames.Frame, 0, len(c.Frames))
		for _, f := range c.Frames {
			in = append(in, frames.Frame{From: f.From, Data: mustHex(t, c.ID, f.Hex)})
		}
		msgs, at, err := frames.Control(in)
		if errors.Is(err, frames.ErrCase) {
			t.Fatalf("%s: not a valid case: %v", c.ID, err)
		}
		seen[c.Expected] = true
		switch c.Expected {
		case "valid":
			if err != nil {
				t.Errorf("%s (%s): frame %d is an error: %v", c.ID, c.Why, at, err)
			} else if !sameJSON(t, msgs, c.Messages) {
				t.Errorf("%s (%s): messages differ from the reference", c.ID, c.Why)
			}
		case "error":
			if err == nil || c.At == nil || at != *c.At {
				t.Errorf("%s (%s): error at frame %d (%v), want at %v", c.ID, c.Why, at, err, c.At)
			}
		default:
			t.Errorf("%s: expected %q", c.ID, c.Expected)
		}
	}
	if !seen["valid"] || !seen["error"] {
		t.Error("the cases do not cover both results")
	}
}

func TestBindingCasesMatchTheReference(t *testing.T) {
	at := func(id, s string) time.Time {
		v, err := time.Parse(time.RFC3339, s)
		if err != nil {
			t.Fatalf("%s: time: %v", id, err)
		}
		return v
	}
	seen := map[string]bool{}
	for _, c := range loadCases[bindingCase](t, "../../conformance/binding-v0.json") {
		state := frames.RelayState{ControlNotBefore: at(c.ID, c.ControlNotBefore), LimitReached: c.LimitReached}
		for _, tok := range c.Tokens {
			state.Tokens = append(state.Tokens, frames.Token{Token: mustHex(t, c.ID, tok.Token), Installation: tok.Installation, State: tok.State})
		}
		conn := frames.Connection{Installation: c.Connection.Installation, NotBefore: at(c.ID, c.Connection.NotBefore)}
		got := frames.Bind(state, conn, mustHex(t, c.ID, c.FirstBytes))
		seen[c.Expected] = true
		if result := map[bool]string{true: "bound", false: "closed"}[got.Bound]; result != c.Expected {
			t.Errorf("%s (%s): %s, want %s", c.ID, c.Why, result, c.Expected)
		}
		if got.Determined != (c.Consumed != nil) {
			t.Errorf("%s (%s): consumed determined %v, case says %v", c.ID, c.Why, got.Determined, c.Consumed != nil)
			continue
		}
		if c.Consumed == nil {
			continue
		}
		consumed := []string{}
		for _, tok := range got.Consumed {
			consumed = append(consumed, hex.EncodeToString(tok))
		}
		if !reflect.DeepEqual(consumed, *c.Consumed) {
			t.Errorf("%s (%s): consumed %v, want %v", c.ID, c.Why, consumed, *c.Consumed)
		}
	}
	if !seen["bound"] || !seen["closed"] {
		t.Error("the cases do not cover both results")
	}
}

func loadCases[T any](t *testing.T, path string) []T {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Cases []T `json:"cases"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return file.Cases
}

// SPDX-License-Identifier: Apache-2.0

package refgateway_test

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"slices"
	"testing"

	"github.com/home-mandate/spec/relay/internal/refgateway"
)

// verdict is the outcome of one case against the reference with some faults: "" if the case
// passes, else what differs.
type verdict func(fault uint64) string

// caseFamily is one case file with a function that runs each of its cases.
type caseFamily struct {
	name string
	// cases maps the id of each case to its check.
	ids   []string
	check map[string]verdict
	// optional lists the cases that no defect can fail.
	optional map[string]bool
}

func loadFile[T any](t *testing.T, name string) []T {
	t.Helper()
	data, err := os.ReadFile("../../conformance/" + name + "-v0.json")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Cases []T `json:"cases"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return file.Cases
}

func build[T any](t *testing.T, name string, id func(T) string, check func(T) verdict) caseFamily {
	fam := caseFamily{name: name, check: map[string]verdict{}, optional: map[string]bool{}}
	for _, c := range loadFile[T](t, name) {
		fam.ids = append(fam.ids, id(c))
		fam.check[id(c)] = check(c)
	}
	return fam
}

func families(t *testing.T) []caseFamily {
	ct := ctFamily(t)
	// A case without certificates has no result that a defect could change.
	ct.optional["t35"] = true
	return []caseFamily{pairingFamily(t), pinsFamily(t), proxyFamily(t), destinationFamily(t), caaFamily(t), levelFamily(t), ct}
}

type pairingCase struct {
	ID       string          `json:"id"`
	Input    string          `json:"input"`
	Expected json.RawMessage `json:"expected"`
}

func pairingFamily(t *testing.T) caseFamily {
	return build(t, "pairing", func(c pairingCase) string { return c.ID }, func(c pairingCase) verdict {
		return func(bits uint64) string {
			domain, code, ok := refgateway.ParsePairing(c.Input, refgateway.PairingFault(bits))
			got, _ := json.Marshal(map[string]string{"operator_domain": domain, "code": code})
			if !ok {
				got = []byte(`"invalid"`)
			}
			return jsonDiff(got, c.Expected)
		}
	})
}

func jsonDiff(got, want []byte) string {
	var a, b any
	if json.Unmarshal(got, &a) != nil || json.Unmarshal(want, &b) != nil || !reflect.DeepEqual(a, b) {
		return "got " + string(got) + ", want " + string(want)
	}
	return ""
}

type pinsCase struct {
	ID string `json:"id"`
	refgateway.PinsInput
}

func pinsFamily(t *testing.T) caseFamily {
	return build(t, "pins", func(c pinsCase) string { return c.ID }, func(c pinsCase) verdict {
		return func(bits uint64) string {
			out, err := refgateway.RunPins(c.PinsInput, refgateway.PinFault(bits))
			if err != nil {
				return "not a valid case: " + err.Error()
			}
			for i, step := range c.Steps {
				if i > 0 && c.Steps[i-1].Connection == "closed" {
					return "not a valid case: a step follows the close"
				}
				if step.ArrivedOn == "other" && step.Expected != "stored" {
					return "not a valid case: a set stored through another connection is stored"
				}
				o := out[i]
				closed := map[bool]string{true: "closed", false: "open"}[o.Closed]
				if o.Answer != step.Expected || closed != step.Connection || !sameStored(o.Stored, step.StoredAfter) {
					return "step " + string(rune('1'+i)) + ": " + o.Answer + " " + closed
				}
			}
			return ""
		}
	})
}

func sameStored(a, b refgateway.Pins) bool {
	sorted := func(x []string) []string { y := slices.Clone(x); slices.Sort(y); return y }
	return slices.Equal(sorted(a.Active), sorted(b.Active)) && slices.Equal(sorted(a.Backup), sorted(b.Backup))
}

type proxyCase struct {
	ID       string `json:"id"`
	Hex      string `json:"hex"`
	Expected string `json:"expected"`
	Source   *struct {
		Address string `json:"address"`
		Port    int    `json:"port"`
	} `json:"source"`
	Consumed *int `json:"consumed"`
}

func proxyFamily(t *testing.T) caseFamily {
	fam := build(t, "proxy", func(c proxyCase) string { return c.ID }, func(c proxyCase) verdict {
		data, err := hex.DecodeString(c.Hex)
		if err != nil {
			t.Fatalf("%s: %v", c.ID, err)
		}
		return func(bits uint64) string {
			got := refgateway.ParseProxy(data, refgateway.ProxyFault(bits))
			if !got.Accepted {
				if c.Expected == "accepted" {
					return "refused"
				}
				return ""
			}
			if c.Expected == "refused" {
				return "accepted " + got.Address
			}
			if got.Address != c.Source.Address || got.Port != c.Source.Port || got.Consumed != *c.Consumed {
				return "read the wrong source or consumed the wrong number of bytes"
			}
			return ""
		}
	})
	for _, c := range loadFile[proxyCase](t, "proxy") {
		fam.optional[c.ID] = c.Expected == "either"
	}
	return fam
}

type destinationCase struct {
	ID       string `json:"id"`
	Address  string `json:"address"`
	Expected string `json:"expected"`
}

func destinationFamily(t *testing.T) caseFamily {
	return build(t, "destination", func(c destinationCase) string { return c.ID }, func(c destinationCase) verdict {
		return func(bits uint64) string {
			if got := map[bool]string{true: "allow", false: "refuse"}[refgateway.Allowed(c.Address, refgateway.DestFault(bits))]; got != c.Expected {
				return got
			}
			return ""
		}
	})
}

type caaCase struct {
	ID string `json:"id"`
	refgateway.CAAInput
	Expected string `json:"expected"`
	// Round is the successful_round of the case, if it has one.
	Round *bool `json:"successful_round"`
}

func caaFamily(t *testing.T) caseFamily {
	return build(t, "caa", func(c caaCase) string { return c.ID }, func(c caaCase) verdict {
		return func(bits uint64) string {
			f := refgateway.CAAFault(bits)
			if got := refgateway.CAAEvaluate(c.CAAInput, f); got != c.Expected {
				return got
			}
			if c.Round != nil && refgateway.CAASuccessfulRound(c.CAAInput, f) != *c.Round {
				return "the round is not as the case says"
			}
			return ""
		}
	})
}

type levelCase struct {
	ID string `json:"id"`
	refgateway.LevelInput
	Expected refgateway.LevelResult `json:"expected"`
}

func levelFamily(t *testing.T) caseFamily {
	return build(t, "protection-level", func(c levelCase) string { return c.ID }, func(c levelCase) verdict {
		return func(bits uint64) string {
			if got := refgateway.Level(c.LevelInput, refgateway.LevelFault(bits)); got != c.Expected {
				return got.Level
			}
			return ""
		}
	})
}

type ctCase struct {
	ID string `json:"id"`
	refgateway.CTInput
	Expected []refgateway.CTResult `json:"expected"`
}

func ctFamily(t *testing.T) caseFamily {
	return build(t, "ct", func(c ctCase) string { return c.ID }, func(c ctCase) verdict {
		return func(bits uint64) string {
			got, err := refgateway.CTAlarms(c.CTInput, refgateway.CTFault(bits))
			if err != nil {
				return "not a valid case: " + err.Error()
			}
			if !slices.Equal(got, c.Expected) && !(len(got) == 0 && len(c.Expected) == 0) {
				return "results differ"
			}
			return ""
		}
	})
}

func TestEveryCasePassesTheReference(t *testing.T) {
	for _, fam := range families(t) {
		if len(fam.ids) == 0 {
			t.Errorf("%s: no cases", fam.name)
		}
		for _, id := range fam.ids {
			if msg := fam.check[id](0); msg != "" {
				t.Errorf("%s %s: %q", fam.name, id, msg)
			}
		}
	}
}

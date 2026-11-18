// SPDX-License-Identifier: Apache-2.0

package dpop_test

import (
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/home-mandate/spec/internal/dpop"
)

type proofCase struct {
	ID       string        `json:"id"`
	Proof    *dpop.Proof   `json:"proof"`
	Request  *dpop.Request `json:"request"`
	Seen     []string      `json:"seen"`
	Started  *int64        `json:"started"`
	Expected string        `json:"expected"`
}

func loadCases(t *testing.T) []proofCase {
	t.Helper()
	data, err := os.ReadFile("../../conformance/origin-v0.json")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Cases []proofCase `json:"cases"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	var out []proofCase
	for _, c := range file.Cases {
		if c.Proof != nil {
			out = append(out, c)
		}
	}
	if len(out) < 20 {
		t.Fatalf("%d proof cases, want at least 20", len(out))
	}
	return out
}

func memoryOf(c proofCase) dpop.Memory {
	seen := map[string]bool{}
	for _, j := range c.Seen {
		seen[j] = true
	}
	return dpop.Memory{Seen: func(jti string) bool { return seen[jti] }, Started: c.Started}
}

func TestConformanceCases(t *testing.T) {
	for _, c := range loadCases(t) {
		t.Run(c.ID, func(t *testing.T) {
			err := dpop.Check(*c.Proof, *c.Request, memoryOf(c))
			got := map[bool]string{true: "valid", false: "invalid"}[err == nil]
			if got != c.Expected {
				t.Errorf("Check = %v, want %s", err, c.Expected)
			}
			if err != nil && !errors.Is(err, dpop.ErrInvalid) {
				t.Errorf("error %v is not ErrInvalid", err)
			}
		})
	}
}

// Every rule of the check is needed: a check that skips one accepts a case that expects
// invalid.
func TestEachRuleHasACase(t *testing.T) {
	cases := loadCases(t)
	for _, rule := range dpop.Rules() {
		t.Run(rule, func(t *testing.T) {
			caught := false
			for _, c := range cases {
				if c.Expected != "invalid" {
					continue
				}
				if dpop.CheckWithout(rule, *c.Proof, *c.Request, memoryOf(c)) == nil {
					caught = true
				}
			}
			if !caught {
				t.Errorf("no invalid case depends on the rule %s", rule)
			}
		})
	}
}

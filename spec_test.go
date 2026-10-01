// SPDX-License-Identifier: Apache-2.0

package mandatespec_test

import (
	"encoding/json"
	"io/fs"
	"testing"

	mandatespec "github.com/mandate-spec/mandate-spec"
)

func TestFSContainsSpecFiles(t *testing.T) {
	paths := []string{
		mandatespec.MandateSchemaPath,
		mandatespec.AuditSchemaPath,
		mandatespec.CasesPath,
		mandatespec.InvalidCasesPath,
		mandatespec.DigestCasesPath,
		mandatespec.AuditCasesPath,
		"examples/voice-assistant.json",
		"conformance/mandates/time.json",
	}
	for _, p := range paths {
		t.Run(p, func(t *testing.T) {
			data, err := fs.ReadFile(mandatespec.FS(), p)
			if err != nil {
				t.Fatalf("read %s: %v", p, err)
			}
			if !json.Valid(data) {
				t.Fatalf("%s is not valid JSON", p)
			}
		})
	}
}

func TestFSResolvesAllMandatePathsInCases(t *testing.T) {
	data, err := fs.ReadFile(mandatespec.FS(), mandatespec.CasesPath)
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Cases []struct {
			ID      string `json:"id"`
			Mandate string `json:"mandate"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	if len(file.Cases) == 0 {
		t.Fatal("no cases found")
	}
	for _, c := range file.Cases {
		if c.Mandate == "" {
			continue
		}
		if _, err := fs.Stat(mandatespec.FS(), c.Mandate); err != nil {
			t.Errorf("case %s: mandate %s not embedded: %v", c.ID, c.Mandate, err)
		}
	}
}

func TestFSExcludesNonSpecFiles(t *testing.T) {
	for _, p := range []string{"go.mod", "spec.go", "SPEC-v0.md", "README.md"} {
		if _, err := fs.Stat(mandatespec.FS(), p); err == nil {
			t.Errorf("%s must not be embedded", p)
		}
	}
}

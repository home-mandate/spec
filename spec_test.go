// SPDX-License-Identifier: Apache-2.0

package spec_test

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/home-mandate/spec"
	"github.com/home-mandate/spec/internal/manifest"
)

func TestFSContainsSpecFiles(t *testing.T) {
	paths := []string{
		spec.MandateSchemaPath,
		spec.AuditSchemaPath,
		spec.CasesPath,
		spec.InvalidCasesPath,
		spec.DigestCasesPath,
		spec.AuditCasesPath,
		"examples/voice-assistant.json",
		"conformance/mandates/time.json",
	}
	for _, p := range paths {
		t.Run(p, func(t *testing.T) {
			data, err := fs.ReadFile(spec.FS(), p)
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
	data, err := fs.ReadFile(spec.FS(), spec.CasesPath)
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
		if _, err := fs.Stat(spec.FS(), c.Mandate); err != nil {
			t.Errorf("case %s: mandate %s not embedded: %v", c.ID, c.Mandate, err)
		}
	}
}

func TestFSExcludesNonSpecFiles(t *testing.T) {
	for _, p := range []string{"go.mod", "spec.go", "SPEC-v0.md", "README.md"} {
		if _, err := fs.Stat(spec.FS(), p); err == nil {
			t.Errorf("%s must not be embedded", p)
		}
	}
}

func TestManifestMatchesEmbeddedFiles(t *testing.T) {
	data, err := fs.ReadFile(spec.FS(), spec.ManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := manifest.Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	built, err := manifest.Build(spec.FS())
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range manifest.Diff(built, stored) {
		t.Errorf("%s is out of date (%s); run: go run ./tools/vectors manifest", spec.ManifestPath, line)
	}
}

func TestConformanceFilesMatchTheirSchemas(t *testing.T) {
	for file, schemaPath := range map[string]string{
		spec.CasesPath:           "conformance/schema/cases-v0.schema.json",
		spec.InvalidCasesPath:    "conformance/schema/invalid-v0.schema.json",
		spec.DigestCasesPath:     "conformance/schema/digest-v0.schema.json",
		spec.AuditCasesPath:      "conformance/schema/audit-v0.schema.json",
		spec.SelectionCasesPath:  "conformance/schema/selection-v0.schema.json",
		spec.SignedCasesPath:     "conformance/schema/signed-v0.schema.json",
		spec.SuccessionCasesPath: "conformance/schema/succession-v0.schema.json",
		spec.ManifestPath:        "conformance/schema/manifest.schema.json",
	} {
		t.Run(file, func(t *testing.T) {
			compiled := compileSchema(t, schemaPath)
			if err := compiled.Validate(readJSON(t, file)); err != nil {
				t.Errorf("%s violates %s: %v", file, schemaPath, err)
			}
		})
	}
}

func TestConformanceSchemasRejectUnknownFields(t *testing.T) {
	compiled := compileSchema(t, "conformance/schema/cases-v0.schema.json")
	doc := map[string]any{"description": "d", "cases": []any{map[string]any{
		"id": "x", "mandate": "examples/a.json", "resource": map[string]any{"entity_id": "a.b", "category": "light"},
		"action": "read", "time": "2026-10-12T19:00:00+02:00", "expected": "deny", "reason": "no_match", "typo": true,
	}}}
	if err := compiled.Validate(doc); err == nil {
		t.Error("cases schema accepted an unknown field")
	}
}

func TestConformanceCaseIDsAreUnique(t *testing.T) {
	for file, key := range map[string]string{
		spec.CasesPath: "cases", spec.InvalidCasesPath: "cases",
		spec.DigestCasesPath: "cases", spec.AuditCasesPath: "logs",
		spec.SelectionCasesPath: "cases", spec.SignedCasesPath: "cases", spec.SuccessionCasesPath: "cases",
	} {
		doc, _ := readJSON(t, file).(map[string]any)
		cases, _ := doc[key].([]any)
		seen := map[string]bool{}
		for _, c := range cases {
			id, _ := c.(map[string]any)["id"].(string)
			if id == "" || seen[id] {
				t.Errorf("%s: missing or duplicate id %q", file, id)
			}
			seen[id] = true
		}
	}
}

func readJSON(t *testing.T, path string) any {
	t.Helper()
	data, err := fs.ReadFile(spec.FS(), path)
	if err != nil {
		t.Fatal(err)
	}
	v, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return v
}

func compileSchema(t *testing.T, path string) *jsonschema.Schema {
	t.Helper()
	c := jsonschema.NewCompiler()
	c.AssertFormat()
	if err := c.AddResource(path, readJSON(t, path)); err != nil {
		t.Fatal(err)
	}
	compiled, err := c.Compile(path)
	if err != nil {
		t.Fatalf("compile %s: %v", path, err)
	}
	return compiled
}

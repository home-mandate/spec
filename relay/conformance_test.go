// SPDX-License-Identifier: Apache-2.0

package relay_test

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/home-mandate/spec/internal/manifest"
)

// conformanceSchemas maps every conformance file of the Relay Specification to its schema.
var conformanceSchemas = map[string]string{
	"conformance/binding-v0.json":     "conformance/schema/binding-v0.schema.json",
	"conformance/certificate-v0.json": "conformance/schema/certificate-v0.schema.json",
	"conformance/csr-v0.json":         "conformance/schema/csr-v0.schema.json",
	"conformance/enrollment-v0.json":  "conformance/schema/enrollment-v0.schema.json",
	"conformance/frames-v0.json":      "conformance/schema/frames-v0.schema.json",
	"conformance/jws-v0.json":         "conformance/schema/jws-v0.schema.json",
	"conformance/metadata-v0.json":    "conformance/schema/metadata-v0.schema.json",
	"conformance/tls-v0.json":         "conformance/schema/tls-v0.schema.json",
	"conformance/manifest.json":       "conformance/schema/manifest.schema.json",
}

func TestRelayManifestIsUpToDate(t *testing.T) {
	data, err := os.ReadFile(manifest.RelayPath[len("relay/"):])
	if err != nil {
		t.Fatal(err)
	}
	stored, err := manifest.Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	built, err := manifest.Relay.Build(os.DirFS(".."))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range manifest.Diff(built, stored) {
		t.Errorf("%s is out of date (%s); run: make manifest", manifest.RelayPath, line)
	}
}

func TestRelayConformanceFilesMatchTheirSchemas(t *testing.T) {
	for file, schema := range conformanceSchemas {
		c := jsonschema.NewCompiler()
		c.AssertFormat()
		if err := c.AddResource(schema, loadJSON(t, schema)); err != nil {
			t.Fatal(err)
		}
		s, err := c.Compile(schema)
		if err != nil {
			t.Fatalf("compile %s: %v", schema, err)
		}
		if err := s.Validate(loadJSON(t, file)); err != nil {
			t.Errorf("%s violates %s: %v", file, schema, err)
		}
	}
}

func TestRelayConformanceCaseIDsAreUnique(t *testing.T) {
	for file := range conformanceSchemas {
		if file == "conformance/manifest.json" {
			continue
		}
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		var doc struct {
			Cases []struct {
				ID string `json:"id"`
			} `json:"cases"`
		}
		if err := json.Unmarshal(data, &doc); err != nil {
			t.Fatal(err)
		}
		seen := map[string]bool{}
		for _, c := range doc.Cases {
			if c.ID == "" || seen[c.ID] {
				t.Errorf("%s: missing or duplicate id %q", file, c.ID)
			}
			seen[c.ID] = true
		}
	}
}

func TestEveryRelayConformanceFileHasASchema(t *testing.T) {
	entries, err := os.ReadDir("conformance")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if path := "conformance/" + e.Name(); !e.IsDir() {
			if _, ok := conformanceSchemas[path]; !ok {
				t.Errorf("%s has no schema", path)
			}
		}
	}
}

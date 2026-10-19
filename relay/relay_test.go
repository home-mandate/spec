// SPDX-License-Identifier: Apache-2.0

package relay_test

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

const (
	metadataSchemaPath  = "schema/metadata-v0.schema.json"
	metadataExamplePath = "examples/metadata.json"
	metadataSchemaID    = "https://home-mandate.org/relay-metadata/v0/metadata.schema.json"
)

func compileMetadataSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	f, err := os.Open(metadataSchemaPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	doc, err := jsonschema.UnmarshalJSON(f)
	if err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource(metadataSchemaID, doc); err != nil {
		t.Fatal(err)
	}
	s, err := c.Compile(metadataSchemaID)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func loadExample(t *testing.T) map[string]any {
	t.Helper()
	data, err := os.ReadFile(metadataExamplePath)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

func TestMetadataSchemaDeclaresItsID(t *testing.T) {
	data, err := os.ReadFile(metadataSchemaPath)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		ID string `json:"$id"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.ID != metadataSchemaID {
		t.Errorf("$id = %q, want %q", doc.ID, metadataSchemaID)
	}
}

func TestMetadataExampleIsValid(t *testing.T) {
	if err := compileMetadataSchema(t).Validate(loadExample(t)); err != nil {
		t.Fatal(err)
	}
}

func TestMaxOfflineDaysBoundsAreAccepted(t *testing.T) {
	s := compileMetadataSchema(t)
	for _, days := range []float64{7, 30, 90} {
		doc := loadExample(t)
		doc["max_offline_days"] = days
		if err := s.Validate(doc); err != nil {
			t.Errorf("max_offline_days %v rejected: %v", days, err)
		}
	}
}

func TestInvalidMetadataIsRejected(t *testing.T) {
	s := compileMetadataSchema(t)
	for name, mutate := range map[string]func(map[string]any){
		"max_offline_days below 7":    func(d map[string]any) { d["max_offline_days"] = 6.0 },
		"max_offline_days above 90":   func(d map[string]any) { d["max_offline_days"] = 91.0 },
		"max_offline_days fractional": func(d map[string]any) { d["max_offline_days"] = 30.5 },
		"max_offline_days missing":    func(d map[string]any) { delete(d, "max_offline_days") },
		"wrong type":                  func(d map[string]any) { d["type"] = "https://home-mandate.org/relay-metadata/v1" },
		"unknown member":              func(d map[string]any) { d["extra"] = true },
		"only one relay pin":          func(d map[string]any) { d["relay_pins"] = []any{"47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"} },
		"duplicate relay pins": func(d map[string]any) {
			p := "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"
			d["relay_pins"] = []any{p, p}
		},
		"pin not base64url sha-256":    func(d map[string]any) { d["relay_pins"] = []any{"abc", "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"} },
		"protection level missing":     func(d map[string]any) { d["protection_levels"] = []any{"standard"} },
		"unknown protection level":     func(d map[string]any) { d["protection_levels"] = []any{"standard", "own-domain", "none"} },
		"enrollment over http":         func(d map[string]any) { d["enrollment"] = "http://example.org/enroll" },
		"enrollment with fragment":     func(d map[string]any) { d["enrollment"] = "https://example.org/enroll#x" },
		"portal over http":             func(d map[string]any) { d["portal"] = "http://example.org/" },
		"privacy policy missing":       func(d map[string]any) { delete(d, "privacy_policy") },
		"upper-case name domain":       func(d map[string]any) { d["name_domain"] = "Homes.Example.net" },
		"name domain with dot at end":  func(d map[string]any) { d["name_domain"] = "homes.example.net." },
		"single-label operator domain": func(d map[string]any) { d["operator_domain"] = "localhost" },
		"trust domain with port":       func(d map[string]any) { d["trust_domain"] = "example.org:443" },
		"relay port zero":              func(d map[string]any) { d["relay"].(map[string]any)["port"] = 0.0 },
		"relay port too high":          func(d map[string]any) { d["relay"].(map[string]any)["port"] = 65536.0 },
		"relay unknown member":         func(d map[string]any) { d["relay"].(map[string]any)["ip"] = "192.0.2.1" },
		"only own-domain":              func(d map[string]any) { d["protection_levels"] = []any{"own-domain"} },
		"nine relay pins":              func(d map[string]any) { d["relay_pins"] = ninePins() },
		"enrollment with query":        func(d map[string]any) { d["enrollment"] = "https://example.org/enroll?x=1" },
		"enrollment with user info":    func(d map[string]any) { d["enrollment"] = "https://user@example.org/enroll" },
		"enrollment with IP address":   func(d map[string]any) { d["enrollment"] = "https://192.0.2.1/enroll" },
		"enrollment with port zero":    func(d map[string]any) { d["enrollment"] = "https://example.org:0/enroll" },
		"enrollment with dots only":    func(d map[string]any) { d["enrollment"] = "https://../enroll" },
	} {
		doc := loadExample(t)
		mutate(doc)
		if err := s.Validate(doc); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func ninePins() []any {
	pins := make([]any, 9)
	for i := range pins {
		pins[i] = fmt.Sprintf("%042d%c", i, 'A')
	}
	return pins
}

func TestEveryRequiredMemberIsRequired(t *testing.T) {
	s := compileMetadataSchema(t)
	for name := range loadExample(t) {
		doc := loadExample(t)
		delete(doc, name)
		if err := s.Validate(doc); err == nil {
			t.Errorf("document without %q accepted", name)
		}
	}
}

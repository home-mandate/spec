// SPDX-License-Identifier: Apache-2.0

package metadata

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

const (
	casesPath  = "../../conformance/metadata-v0.json"
	schemaPath = "../../schema/metadata-v0.schema.json"
	schemaID   = "https://home-mandate.org/relay-metadata/v0/metadata.schema.json"
)

type metadataCase struct {
	ID          string          `json:"id"`
	Host        string          `json:"host"`
	Document    json.RawMessage `json:"document"`
	DocumentRaw *string         `json:"document_raw"`
	Expected    string          `json:"expected"`
	Why         string          `json:"why"`
}

func compileSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	data, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource(schemaID, doc); err != nil {
		t.Fatal(err)
	}
	s, err := c.Compile(schemaID)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// verdict is the reference: size and I-JSON and the rules (Check), then the schema.
func verdict(s *jsonschema.Schema, host string, data []byte) error {
	if err := Check(host, data); err != nil {
		return err
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		return err
	}
	return s.Validate(doc)
}

func TestMetadataCases(t *testing.T) {
	data, err := os.ReadFile(casesPath)
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Cases []metadataCase `json:"cases"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	if len(file.Cases) == 0 {
		t.Fatal("no cases")
	}
	s := compileSchema(t)
	for _, c := range file.Cases {
		doc := []byte(c.Document)
		if c.DocumentRaw != nil {
			doc = []byte(*c.DocumentRaw)
		}
		err := verdict(s, c.Host, doc)
		if got := map[bool]string{true: "valid", false: "invalid"}[err == nil]; got != c.Expected {
			t.Errorf("%s (%s): %s (%v), want %s", c.ID, c.Why, got, err, c.Expected)
		}
	}
}

// TestCheckRejectsWithErrInvalid: what Check refuses beyond the cases, also input that the
// schema would refuse anyway.
func TestCheckRejectsWithErrInvalid(t *testing.T) {
	for name, tt := range map[string]struct {
		host string
		doc  string
	}{
		"not JSON":       {"a.example", `{`},
		"not an object":  {"a.example", `"x"`},
		"no host in URL": {"a.example", `{"operator_domain":"a.example","enrollment":"https:"}`},
		"no portal host": {"a.example", `{"operator_domain":"a.example","enrollment":"https://a.example/","portal":"%"}`},
		"too large":      {"a.example", string(make([]byte, MaxBytes+1))},
	} {
		if err := Check(tt.host, []byte(tt.doc)); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: Check = %v, want ErrInvalid", name, err)
		}
	}
}

func TestAtOrBelow(t *testing.T) {
	for _, c := range []struct {
		host, domain string
		want         bool
	}{
		{"homes.example.net", "homes.example.net", true},
		{"a.homes.example.net", "homes.example.net", true},
		{"xhomes.example.net", "homes.example.net", false},
		{"example.net", "homes.example.net", false},
	} {
		if got := AtOrBelow(c.host, c.domain); got != c.want {
			t.Errorf("AtOrBelow(%q, %q) = %v, want %v", c.host, c.domain, got, c.want)
		}
	}
}

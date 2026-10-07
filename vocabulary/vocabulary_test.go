// SPDX-License-Identifier: Apache-2.0

package vocabulary_test

import (
	"bytes"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/home-mandate/spec/schema"
	"github.com/home-mandate/spec/vocabulary"
)

func decode(t *testing.T, data []byte) any {
	t.Helper()
	v, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func compile(t *testing.T) *jsonschema.Schema {
	t.Helper()
	c := jsonschema.NewCompiler()
	if err := c.AddResource(schema.VocabularyID, decode(t, schema.Vocabulary())); err != nil {
		t.Fatal(err)
	}
	compiled, err := c.Compile(schema.VocabularyID)
	if err != nil {
		t.Fatal(err)
	}
	return compiled
}

func TestV0MatchesTheVocabularySchema(t *testing.T) {
	if err := compile(t).Validate(decode(t, vocabulary.V0())); err != nil {
		t.Fatal(err)
	}
}

func TestVocabularySchemaAcceptsAnExtensionAndRejectsMistakes(t *testing.T) {
	compiled := compile(t)
	extension := `{"id":"https://paperless.example/vocabulary","version":"1",
		"categories":{"paperless:document":{"actions":{"read":{},"tag":{},"delete":{"critical":true}}}}}`
	if err := compiled.Validate(decode(t, []byte(extension))); err != nil {
		t.Errorf("extension vocabulary rejected: %v", err)
	}
	for name, doc := range map[string]string{
		"critical false":       `{"id":"x:y","version":"1","categories":{"a":{"actions":{"read":{"critical":false}}}}}`,
		"upper-case category":  `{"id":"x:y","version":"1","categories":{"Light":{"actions":{"read":{}}}}}`,
		"upper-case action":    `{"id":"x:y","version":"1","categories":{"light":{"actions":{"Read":{}}}}}`,
		"no actions":           `{"id":"x:y","version":"1","categories":{"light":{"actions":{}}}}`,
		"no categories":        `{"id":"x:y","version":"1","categories":{}}`,
		"missing version":      `{"id":"x:y","categories":{"light":{"actions":{"read":{}}}}}`,
		"unknown action field": `{"id":"x:y","version":"1","categories":{"light":{"actions":{"read":{"danger":1}}}}}`,
		"wildcard as action":   `{"id":"x:y","version":"1","categories":{"light":{"actions":{"*":{}}}}}`,
	} {
		if err := compiled.Validate(decode(t, []byte(doc))); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestV0IsACopy(t *testing.T) {
	first := vocabulary.V0()
	first[0] = 'X'
	if vocabulary.V0()[0] == 'X' {
		t.Error("V0() returned shared bytes")
	}
}

var tableRow = regexp.MustCompile("^\\| `([a-z]+)` \\| ([a-z_, ]+) \\| ([a-z_, ]+|–) \\|$")

// TestSpecTableMatchesV0 keeps the table in SPEC-v0.md section 5 and vocabulary/v0.json
// in agreement; the file is normative, the table is its rendering for humans.
func TestSpecTableMatchesV0(t *testing.T) {
	spec, err := os.ReadFile("../SPEC-v0.md")
	if err != nil {
		t.Fatal(err)
	}
	type entry struct{ actions, critical []string }
	table := map[string]entry{}
	_, section, found := strings.Cut(string(spec), "\n## 5. Vocabulary v0\n")
	section, _, end := strings.Cut(section, "\n### 5.1 ")
	if !found || !end {
		t.Fatal("section 5 not found in SPEC-v0.md")
	}
	for _, line := range strings.Split(section, "\n") {
		m := tableRow.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		e := entry{actions: strings.Split(m[2], ", ")}
		if m[3] != "–" {
			e.critical = strings.Split(m[3], ", ")
		}
		table[m[1]] = e
	}
	doc, _ := decode(t, vocabulary.V0()).(map[string]any)
	categories, _ := doc["categories"].(map[string]any)
	if len(table) != len(categories) || len(table) == 0 {
		t.Fatalf("table has %d categories, file has %d", len(table), len(categories))
	}
	for name, raw := range categories {
		actions, _ := raw.(map[string]any)["actions"].(map[string]any)
		var names, critical []string
		for action, properties := range actions {
			names = append(names, action)
			if properties.(map[string]any)["critical"] == true {
				critical = append(critical, action)
			}
		}
		row := table[name]
		slices.Sort(names)
		slices.Sort(critical)
		slices.Sort(row.actions)
		slices.Sort(row.critical)
		if !slices.Equal(names, row.actions) || !slices.Equal(critical, row.critical) {
			t.Errorf("%s: file has actions %v critical %v, table has %v and %v", name, names, critical, row.actions, row.critical)
		}
	}
}

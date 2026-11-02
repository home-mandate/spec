// SPDX-License-Identifier: Apache-2.0

package vocabulary_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
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
	thirtyTwo := `{"id":"x:y","version":"1","categories":{"a":{"actions":{"set":{"parameters":{"p":{"type":"string","values":[` + values(32) + `]}}}}}}}`
	if err := compiled.Validate(decode(t, []byte(thirtyTwo))); err != nil {
		t.Errorf("32 permitted values rejected: %v", err)
	}
	wallbox := `{"id":"https://wallbox.example/vocabulary","version":"1","categories":{"wallbox:charger":{"actions":{
		"set_charge_mode":{"parameters":{"charge_mode":{"type":"string","values":["PV","BOOST"]}}},
		"set_preset":{"parameters":{"preset":{"type":"string","description":"any preset name"}}},
		"set_current":{"parameters":{"current":{"type":"integer","unit":"0.1 ampere","minimum":60,"maximum":320}}}}}}}`
	if err := compiled.Validate(decode(t, []byte(wallbox))); err != nil {
		t.Errorf("extension vocabulary with integer and string parameters rejected: %v", err)
	}
	for name, doc := range map[string]string{
		"critical false":         `{"id":"x:y","version":"1","categories":{"a":{"actions":{"read":{"critical":false}}}}}`,
		"upper-case category":    `{"id":"x:y","version":"1","categories":{"Light":{"actions":{"read":{}}}}}`,
		"upper-case action":      `{"id":"x:y","version":"1","categories":{"light":{"actions":{"Read":{}}}}}`,
		"no actions":             `{"id":"x:y","version":"1","categories":{"light":{"actions":{}}}}`,
		"no categories":          `{"id":"x:y","version":"1","categories":{}}`,
		"missing version":        `{"id":"x:y","categories":{"light":{"actions":{"read":{}}}}}`,
		"unknown action field":   `{"id":"x:y","version":"1","categories":{"light":{"actions":{"read":{"danger":1}}}}}`,
		"wildcard as action":     `{"id":"x:y","version":"1","categories":{"light":{"actions":{"*":{}}}}}`,
		"parameter without type": `{"id":"x:y","version":"1","categories":{"a":{"actions":{"set":{"parameters":{"p":{"unit":"percent"}}}}}}}`,
		"integer without unit":   `{"id":"x:y","version":"1","categories":{"a":{"actions":{"set":{"parameters":{"p":{"type":"integer"}}}}}}}`,
		"integer with values":    `{"id":"x:y","version":"1","categories":{"a":{"actions":{"set":{"parameters":{"p":{"type":"integer","unit":"percent","values":["1"]}}}}}}}`,
		"string with unit":       `{"id":"x:y","version":"1","categories":{"a":{"actions":{"set":{"parameters":{"p":{"type":"string","unit":"percent"}}}}}}}`,
		"string with minimum":    `{"id":"x:y","version":"1","categories":{"a":{"actions":{"set":{"parameters":{"p":{"type":"string","minimum":0}}}}}}}`,
		"unknown type":           `{"id":"x:y","version":"1","categories":{"a":{"actions":{"set":{"parameters":{"p":{"type":"number","unit":"percent"}}}}}}}`,
		"no values":              `{"id":"x:y","version":"1","categories":{"a":{"actions":{"set":{"parameters":{"p":{"type":"string","values":[]}}}}}}}`,
		"duplicate value":        `{"id":"x:y","version":"1","categories":{"a":{"actions":{"set":{"parameters":{"p":{"type":"string","values":["on","on"]}}}}}}}`,
		"value with a space":     `{"id":"x:y","version":"1","categories":{"a":{"actions":{"set":{"parameters":{"p":{"type":"string","values":["fan only"]}}}}}}}`,
		"value of 65 characters": `{"id":"x:y","version":"1","categories":{"a":{"actions":{"set":{"parameters":{"p":{"type":"string","values":["` + strings.Repeat("a", 65) + `"]}}}}}}}`,
		"33 values":              `{"id":"x:y","version":"1","categories":{"a":{"actions":{"set":{"parameters":{"p":{"type":"string","values":[` + values(33) + `]}}}}}}}`,
		"integer value":          `{"id":"x:y","version":"1","categories":{"a":{"actions":{"set":{"parameters":{"p":{"type":"string","values":[1]}}}}}}}`,
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

var parameterRow = regexp.MustCompile("^\\| `([a-z_]+)[.]([a-z_]+)` \\| `([a-z_]+)` \\| (integer|string) \\| ([^|]+) \\| ([^|]+) \\| ([^|]+) \\|$")

// TestSpecParameterTableMatchesV0 keeps the parameter table in SPEC-v0.md section 5 and
// vocabulary/v0.json in agreement: type, unit, range and permitted values.
func TestSpecParameterTableMatchesV0(t *testing.T) {
	spec, err := os.ReadFile("../SPEC-v0.md")
	if err != nil {
		t.Fatal(err)
	}
	_, section, _ := strings.Cut(string(spec), "\n## 5. Vocabulary v0\n")
	section, _, _ = strings.Cut(section, "\n### 5.1 ")
	table := map[string]string{}
	for _, line := range strings.Split(section, "\n") {
		if m := parameterRow.FindStringSubmatch(line); m != nil {
			table[m[1]+"."+m[2]+" "+m[3]] = m[4] + " | " + strings.TrimSpace(m[5]) + " | " + strings.TrimSpace(m[6]) + " | " + strings.TrimSpace(m[7])
		}
	}
	var doc struct {
		Categories map[string]struct {
			Actions map[string]struct {
				Parameters map[string]struct {
					Type     string   `json:"type"`
					Unit     string   `json:"unit"`
					Minimum  *int     `json:"minimum"`
					Maximum  *int     `json:"maximum"`
					Values   []string `json:"values"`
					Required bool     `json:"required"`
				} `json:"parameters"`
				RequiredOneOf [][]string `json:"required_one_of"`
			} `json:"actions"`
		} `json:"categories"`
	}
	if err := json.Unmarshal(vocabulary.V0(), &doc); err != nil {
		t.Fatal(err)
	}
	file := map[string]string{}
	for category, c := range doc.Categories {
		for action, a := range c.Actions {
			for name, p := range a.Parameters {
				unit, rest := p.Unit, "–"
				if p.Type == "string" {
					unit = "–"
					quoted := make([]string, len(p.Values))
					for i, v := range p.Values {
						quoted[i] = "`" + v + "`"
					}
					rest = strings.Join(quoted, ", ")
				} else if p.Minimum != nil && p.Maximum != nil {
					rest = fmt.Sprintf("%d to %d", *p.Minimum, *p.Maximum)
				}
				required := "–"
				switch {
				case p.Required:
					required = "yes"
				case inAlternative(a.RequiredOneOf, name):
					required = "one alternative"
				}
				file[category+"."+action+" "+name] = p.Type + " | " + unit + " | " + rest + " | " + required
			}
		}
	}
	if len(file) == 0 || !maps.Equal(table, file) {
		t.Errorf("table %v\nfile  %v", table, file)
	}
}

// Every name of required_one_of is a declared parameter of the action without required, and
// the alternatives share no name: otherwise an alternative could never be satisfied, or
// "no name of another alternative" would contradict itself (SPEC-v0 sections 4.5 and 5).
func TestRequiredOneOfNamesDeclaredOptionalDisjointParameters(t *testing.T) {
	var doc struct {
		Categories map[string]struct {
			Actions map[string]struct {
				Parameters    map[string]struct{ Required bool } `json:"parameters"`
				RequiredOneOf [][]string                         `json:"required_one_of"`
			} `json:"actions"`
		} `json:"categories"`
	}
	if err := json.Unmarshal(vocabulary.V0(), &doc); err != nil {
		t.Fatal(err)
	}
	found := 0
	for category, c := range doc.Categories {
		for action, a := range c.Actions {
			seen := map[string]bool{}
			for _, alternative := range a.RequiredOneOf {
				found++
				for _, name := range alternative {
					p, declared := a.Parameters[name]
					if !declared || p.Required || seen[name] {
						t.Errorf("%s.%s: required_one_of names %q: declared %t, required %t, in another alternative %t", category, action, name, declared, p.Required, seen[name])
					}
					seen[name] = true
				}
			}
		}
	}
	if found == 0 {
		t.Error("no required_one_of in the vocabulary; the test checks nothing")
	}
}

// inAlternative reports whether name is part of one of the alternatives of required_one_of.
func inAlternative(alternatives [][]string, name string) bool {
	for _, alternative := range alternatives {
		if slices.Contains(alternative, name) {
			return true
		}
	}
	return false
}

// values returns n distinct JSON strings, separated by commas.
func values(n int) string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("%q", fmt.Sprintf("v%d", i))
	}
	return strings.Join(out, ",")
}

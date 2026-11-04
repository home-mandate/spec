// SPDX-License-Identifier: Apache-2.0

package data_test

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/home-mandate/spec/data"
)

func TestForbiddenCodepointsIsSortedAndDisjoint(t *testing.T) {
	var doc struct {
		UnicodeVersion string   `json:"unicode_version"`
		Forbidden      [][2]int `json:"forbidden"`
		Joiners        []int    `json:"joiners"`
		NotFirst       [][2]int `json:"not_first"`
	}
	if err := json.Unmarshal(data.ForbiddenCodepoints(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.UnicodeVersion == "" || len(doc.Joiners) != 2 {
		t.Errorf("version %q, joiners %v", doc.UnicodeVersion, doc.Joiners)
	}
	for name, list := range map[string][][2]int{"forbidden": doc.Forbidden, "not_first": doc.NotFirst} {
		if len(list) == 0 {
			t.Errorf("%s is empty", name)
		}
		for i, r := range list {
			if r[0] > r[1] || (i > 0 && r[0] <= list[i-1][1]+1) {
				t.Errorf("%s: range %d (%x) is not sorted, disjoint and merged", name, i, r)
			}
		}
	}
	for _, r := range doc.Forbidden {
		for _, j := range doc.Joiners {
			if j >= r[0] && j <= r[1] {
				t.Errorf("joiner %x is in the forbidden list", j)
			}
		}
	}
}

func TestForbiddenCodepointsIsACopy(t *testing.T) {
	first := data.ForbiddenCodepoints()
	first[0] = 'X'
	if data.ForbiddenCodepoints()[0] == 'X' {
		t.Error("ForbiddenCodepoints() returned shared bytes")
	}
}

func TestCorrectionsNameACaseThatExists(t *testing.T) {
	var doc struct {
		Corrections []struct {
			ID        string   `json:"id"`
			Since     string   `json:"since"`
			Rule      string   `json:"rule"`
			Tolerated string   `json:"tolerated"`
			Formats   []string `json:"formats"`
			Cases     []string `json:"cases"`
		} `json:"corrections"`
	}
	if err := json.Unmarshal(data.Corrections(), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Corrections) == 0 {
		t.Fatal("no corrections")
	}
	raw, err := os.ReadFile("../conformance/audit-v0.json")
	if err != nil {
		t.Fatal(err)
	}
	var audit struct {
		Logs []struct {
			ID       string `json:"id"`
			Expected string `json:"expected"`
		} `json:"logs"`
	}
	if err := json.Unmarshal(raw, &audit); err != nil {
		t.Fatal(err)
	}
	valid := map[string]bool{}
	for _, l := range audit.Logs {
		valid[l.ID] = l.Expected == "valid"
	}
	seen := map[string]bool{}
	for _, c := range doc.Corrections {
		if c.ID == "" || seen[c.ID] || c.Since == "" || c.Rule == "" || c.Tolerated == "" || len(c.Formats) == 0 || len(c.Cases) == 0 {
			t.Errorf("incomplete or repeated correction: %+v", c)
		}
		seen[c.ID] = true
		for _, id := range c.Cases {
			if !valid[id] {
				t.Errorf("correction %s: case %s is not a valid log in conformance/audit-v0.json", c.ID, id)
			}
		}
	}
}

func TestCorrectionsIsACopy(t *testing.T) {
	first := data.Corrections()
	first[0] = 'X'
	if data.Corrections()[0] == 'X' {
		t.Error("Corrections() returned shared bytes")
	}
}

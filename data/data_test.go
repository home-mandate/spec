// SPDX-License-Identifier: Apache-2.0

package data_test

import (
	"encoding/json"
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

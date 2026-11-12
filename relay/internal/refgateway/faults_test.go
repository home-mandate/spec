// SPDX-License-Identifier: Apache-2.0

package refgateway_test

import (
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"sort"
	"strings"
	"testing"
)

// faultSets is the fixed table: for each defect, the ids of exactly the cases that fail with it.
const faultSetsFile = "testdata/fault-sets.json"

type faultEntry struct {
	name string
	bits uint64
}

func faultList(family string) []faultEntry {
	var out []faultEntry
	add := func(name string, bits uint64) { out = append(out, faultEntry{name, bits}) }
	switch family {
	case "pairing":
		for _, f := range pairingFaults {
			add(f.name, uint64(f.fault))
		}
	case "pins":
		for _, f := range pinFaults {
			add(f.name, uint64(f.fault))
		}
	case "proxy":
		for _, f := range proxyFaults {
			add(f.name, uint64(f.fault))
		}
	case "destination":
		for _, f := range destFaults {
			add(f.name, uint64(f.fault))
		}
	case "caa":
		for _, f := range caaFaults {
			add(f.name, uint64(f.fault))
		}
	case "protection-level":
		for _, f := range levelFaults {
			add(f.name, uint64(f.fault))
		}
	case "ct":
		for _, f := range ctFaults {
			add(f.name, uint64(f.fault))
		}
	}
	return out
}

// failing returns the ids of the cases that fail with the defect, in file order.
func failing(fam caseFamily, bits uint64) []string {
	var ids []string
	for _, id := range fam.ids {
		if fam.check[id](bits) != "" {
			ids = append(ids, id)
		}
	}
	return ids
}

func actualSets(t *testing.T) map[string][]string {
	sets := map[string][]string{}
	for _, fam := range families(t) {
		for _, f := range faultList(fam.name) {
			sets[fam.name+"/"+f.name] = failing(fam, f.bits)
		}
	}
	return sets
}

func TestEachFaultFailsExactlyItsCases(t *testing.T) {
	data, err := os.ReadFile(faultSetsFile)
	if err != nil {
		t.Fatal(err)
	}
	var want map[string][]string
	if err := json.Unmarshal(data, &want); err != nil {
		t.Fatal(err)
	}
	got := actualSets(t)
	for key, ids := range got {
		w, ok := want[key]
		if !ok {
			t.Errorf("%s is not in the table", key)
		} else if !slices.Equal(ids, w) {
			t.Errorf("%s fails %v, the table says %v", key, ids, w)
		}
		if len(ids) == 0 {
			t.Errorf("%s fails no case: it is not a defect the cases can see", key)
		}
	}
	for key := range want {
		if _, ok := got[key]; !ok {
			t.Errorf("the table lists %s, which is not a defect", key)
		}
	}
}

// TestEveryCaseIsCaught: every case, the valid ones as well as the refusals and the
// boundaries, fails with at least one defect.
func TestEveryCaseIsCaught(t *testing.T) {
	for _, fam := range families(t) {
		caught := map[string]bool{}
		for _, f := range faultList(fam.name) {
			for _, id := range failing(fam, f.bits) {
				caught[id] = true
			}
		}
		for _, id := range fam.ids {
			if !caught[id] && !fam.optional[id] {
				t.Errorf("%s %s is caught by no defect", fam.name, id)
			}
		}
	}
}

// TestWriteFaultSets rewrites the table when FAULT_SETS=write; the result is to be read, not
// trusted.
func TestWriteFaultSets(t *testing.T) {
	if os.Getenv("FAULT_SETS") != "write" {
		t.Skip("set FAULT_SETS=write to rewrite " + faultSetsFile)
	}
	sets := actualSets(t)
	keys := make([]string, 0, len(sets))
	for k := range sets {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString("{\n")
	for i, k := range keys {
		line, _ := json.Marshal(sets[k])
		fmt.Fprintf(&b, "  %q: %s", k, line)
		if i < len(keys)-1 {
			b.WriteString(",")
		}
		b.WriteString("\n")
	}
	b.WriteString("}\n")
	if err := os.MkdirAll("testdata", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(faultSetsFile, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
}

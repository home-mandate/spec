// SPDX-License-Identifier: Apache-2.0

package spec_test

import (
	"encoding/json"
	"os"
	"regexp"
	"testing"
	"time"
	_ "time/tzdata" // the names are checked against the database Go ships, not the system's
)

// timeZoneName is the form of a time zone name in SPEC-v0 section 4.2.
var timeZoneName = regexp.MustCompile(`^(UTC|[A-Z][A-Za-z0-9_+-]*(/[A-Z][A-Za-z0-9_+-]*)+)$`)

func TestTheInformativeListOfTimeZoneNames(t *testing.T) {
	data, err := os.ReadFile("timezone-names.json")
	if err != nil {
		t.Fatal(err)
	}
	var list struct {
		Release string   `json:"release"`
		Names   []string `json:"names"`
	}
	if err := json.Unmarshal(data, &list); err != nil {
		t.Fatal(err)
	}
	if list.Release == "" || len(list.Names) < 400 {
		t.Fatalf("release %q with %d names", list.Release, len(list.Names))
	}
	seen := map[string]bool{}
	for i, name := range list.Names {
		if !timeZoneName.MatchString(name) || len(name) > 64 {
			t.Errorf("%q does not have the form of section 4.2", name)
		}
		if seen[name] || i > 0 && list.Names[i-1] >= name {
			t.Errorf("%q is not in ascending order without repeats", name)
		}
		seen[name] = true
		if _, err := time.LoadLocation(name); err != nil {
			t.Errorf("%q: %v", name, err)
		}
	}
	for _, name := range []string{"UTC", "Europe/Berlin", "US/Eastern", "Etc/GMT+9"} {
		if !seen[name] {
			t.Errorf("%q is missing", name)
		}
	}
	for _, name := range []string{"Europe/BERLIN", "EST5EDT", "GMT", "Local"} {
		if seen[name] {
			t.Errorf("%q is listed", name)
		}
	}
}

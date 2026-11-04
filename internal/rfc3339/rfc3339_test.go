// SPDX-License-Identifier: Apache-2.0

package rfc3339

import (
	"testing"
	"time"
)

func TestParseAccepts(t *testing.T) {
	want := time.Date(2026, 10, 12, 4, 30, 0, 500_000_000, time.UTC)
	for _, s := range []string{
		"2026-10-12T04:30:00.5Z", "2026-10-12T06:30:00.5+02:00", "2026-10-12T02:30:00.500-02:00",
		"2026-10-13T04:29:00.5+23:59", "2026-10-11T04:31:00.5-23:59",
	} {
		got, err := Parse(s)
		if err != nil || !got.Equal(want) {
			t.Errorf("Parse(%s) = %v, %v", s, got, err)
		}
	}
}

func TestParseRejects(t *testing.T) {
	for _, s := range []string{
		"", "not-a-time", "2026-10-12", "2026-10-12T04:30:00", "2026-10-12 04:30:00Z",
		"2026-10-12t04:30:00Z", "2026-10-12T04:30:00z", "2026-10-12T4:30:00Z", "2026-10-12T04:30:00,5Z",
		"2026-10-12T04:30:00.Z", "2026-10-12T04:30:00+24:00", "2026-10-12T04:30:00-24:00",
		"2026-10-12T04:30:00+23:60", "2026-10-12T04:30:00+00:60", "2026-10-12T04:30:00+0200",
		"2026-02-30T12:00:00Z", "2026-13-01T12:00:00Z", "2026-10-12T24:00:00Z", "2026-10-12T12:60:00Z",
		"2016-12-31T23:59:60Z", "2026-10-12T04:30:00Z\n",
	} {
		if got, err := Parse(s); err == nil {
			t.Errorf("Parse(%q) = %v, want an error", s, got)
		}
	}
}

func TestParseLeavesTheNarrowerRulesToTheSchema(t *testing.T) {
	// They fit the grammar of RFC 3339. Whether they count for the time of a request is
	// open (home-mandate/spec#112); this pins that nothing changes by accident.
	for _, s := range []string{"0000-01-01T00:00:00Z", "2026-10-12T04:30:00-00:00", "2026-10-12T04:30:00.1234567891Z"} {
		if _, err := Parse(s); err != nil {
			t.Errorf("Parse(%s) = %v", s, err)
		}
	}
}

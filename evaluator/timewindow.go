// SPDX-License-Identifier: Apache-2.0

package evaluator

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	// Embedded time zone data: without it, every request with a time zone would be denied
	// in containers without zoneinfo. It is used only if the system provides no data.
	_ "time/tzdata"
)

// maxZoneNameLength matches the limit for timezone in the audit log schema.
const maxZoneNameLength = 64

// locations caches successfully loaded time zones. The upper bound prevents spelling
// variants on case-insensitive file systems from filling memory; zones beyond the
// limit are still loaded, just not cached.
var (
	locations      sync.Map // string → *time.Location
	cachedZones    atomic.Int64
	maxCachedZones = 256 // a variable so that tests can check the limit
)

func cachedZoneCount() int { return int(cachedZones.Load()) }

// localTime converts at to household local time (SPEC-v0 section 4.2).
// If zone is empty, the offset of at applies. ok is false for the zero time or an unknown zone.
func localTime(at time.Time, zone string) (time.Time, bool) {
	if at.IsZero() {
		return time.Time{}, false
	}
	if zone == "" {
		return at, true
	}
	if cached, ok := locations.Load(zone); ok {
		return at.In(cached.(*time.Location)), true
	}
	if !validZoneName(zone) {
		return time.Time{}, false
	}
	loc, err := time.LoadLocation(zone)
	if err != nil {
		return time.Time{}, false
	}
	if cachedZones.Load() < int64(maxCachedZones) {
		if _, loaded := locations.LoadOrStore(zone, loc); !loaded {
			cachedZones.Add(1)
		}
	}
	return at.In(loc), true
}

// validZoneName implements SPEC-v0 section 4.2: "UTC" or "Area/Location", each part starting
// with an upper-case letter. This excludes host-dependent names such as "Local", "localtime"
// or "posixrules", abbreviations such as "CET", as well as paths and control characters.
func validZoneName(zone string) bool {
	if zone == "UTC" {
		return true
	}
	parts := strings.Split(zone, "/")
	if len(zone) > maxZoneNameLength || len(parts) < 2 {
		return false
	}
	for _, part := range parts {
		if part == "" || part[0] < 'A' || part[0] > 'Z' {
			return false
		}
		for _, c := range part {
			ok := c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '+'
			if !ok {
				return false
			}
		}
	}
	return true
}

// contains checks a minute since midnight: start inclusive, end exclusive; if the start
// is greater than the end, the window spans midnight.
func (w timeWindow) contains(minute int) bool {
	if w.start < w.end {
		return minute >= w.start && minute < w.end
	}
	return minute >= w.start || minute < w.end
}

func (s weekdaySet) contains(d time.Weekday) bool {
	return s&(1<<d) != 0
}

// conditionsMet checks a rule's conditions for a point in time in household local time.
func (r rule) conditionsMet(local time.Time) bool {
	if r.window.set && !r.window.contains(local.Hour()*60+local.Minute()) {
		return false
	}
	if r.weekdays != 0 && !r.weekdays.contains(local.Weekday()) {
		return false
	}
	return true
}

// timeWindow is a time window in minutes since midnight (SPEC-v0 section 4.2).
// set is false if the rule has no time window.
type timeWindow struct {
	start int
	end   int
	set   bool
}

func parseTimeWindow(s string) (timeWindow, error) {
	startText, endText, ok := strings.Cut(s, "-")
	if !ok {
		return timeWindow{}, fmt.Errorf("%w: time window %q", ErrSchema, s)
	}
	start, err := parseClock(startText)
	if err != nil {
		return timeWindow{}, err
	}
	end, err := parseClock(endText)
	if err != nil {
		return timeWindow{}, err
	}
	if start == end {
		return timeWindow{}, fmt.Errorf("%w: time window %q has equal start and end", ErrSemantic, s)
	}
	return timeWindow{start: start, end: end, set: true}, nil
}

func parseClock(s string) (int, error) {
	t, err := time.Parse("15:04", s)
	if err != nil {
		return 0, fmt.Errorf("%w: clock time %q: %v", ErrSchema, s, err)
	}
	return t.Hour()*60 + t.Minute(), nil
}

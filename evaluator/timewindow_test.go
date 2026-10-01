// SPDX-License-Identifier: Apache-2.0

package evaluator

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func mustWindow(t *testing.T, s string) timeWindow {
	t.Helper()
	w, err := parseTimeWindow(s)
	if err != nil {
		t.Fatalf("parseTimeWindow(%q): %v", s, err)
	}
	return w
}

func clock(h, m int) int { return h*60 + m }

func TestTimeWindowContains(t *testing.T) {
	tests := []struct {
		window string
		minute int
		want   bool
	}{
		{"06:00-22:00", clock(5, 59), false},
		{"06:00-22:00", clock(6, 0), true},
		{"06:00-22:00", clock(21, 59), true},
		{"06:00-22:00", clock(22, 0), false},
		{"22:00-06:00", clock(21, 59), false},
		{"22:00-06:00", clock(22, 0), true},
		{"22:00-06:00", clock(23, 59), true},
		{"22:00-06:00", clock(0, 0), true},
		{"22:00-06:00", clock(5, 59), true},
		{"22:00-06:00", clock(6, 0), false},
		{"00:00-23:59", clock(0, 0), true},
		{"00:00-23:59", clock(23, 58), true},
		{"00:00-23:59", clock(23, 59), false},
		{"23:59-00:00", clock(23, 59), true},
		{"23:59-00:00", clock(0, 0), false},
		{"23:59-00:00", clock(23, 58), false},
		{"00:00-00:01", clock(0, 0), true},
		{"00:00-00:01", clock(0, 1), false},
	}
	for _, tt := range tests {
		if got := mustWindow(t, tt.window).contains(tt.minute); got != tt.want {
			t.Errorf("%s contains %02d:%02d = %v, want %v", tt.window, tt.minute/60, tt.minute%60, got, tt.want)
		}
	}
}

func TestParseTimeWindowRejects(t *testing.T) {
	tests := map[string]error{
		"12:00-12:00": ErrSemantic,
		"00:00-00:00": ErrSemantic,
		"24:00-01:00": ErrSchema,
		"12:60-13:00": ErrSchema,
		"1200-1300":   ErrSchema,
		"12:00":       ErrSchema,
		"12:00-13:0x": ErrSchema,
	}
	for in, want := range tests {
		if _, err := parseTimeWindow(in); !errors.Is(err, want) {
			t.Errorf("parseTimeWindow(%q) = %v, want %v", in, err, want)
		}
	}
}

func TestWeekdaySetContains(t *testing.T) {
	set := weekdaySet(1<<time.Friday | 1<<time.Sunday)
	for d := time.Sunday; d <= time.Saturday; d++ {
		want := d == time.Friday || d == time.Sunday
		if got := set.contains(d); got != want {
			t.Errorf("contains(%v) = %v, want %v", d, got, want)
		}
	}
}

func mustTime(t *testing.T, s string) time.Time {
	t.Helper()
	at, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatal(err)
	}
	return at
}

func TestLocalTime(t *testing.T) {
	tests := []struct {
		name, at, zone, want string
	}{
		{"no zone keeps offset", "2026-10-25T00:30:00Z", "", "2026-10-25 00:30 Sun"},
		{"no zone keeps positive offset", "2026-10-12T23:30:00+02:00", "", "2026-10-12 23:30 Mon"},
		{"Berlin summer time", "2026-10-25T00:30:00Z", "Europe/Berlin", "2026-10-25 02:30 Sun"},
		{"Berlin repeated hour in winter time", "2026-10-25T01:30:00Z", "Europe/Berlin", "2026-10-25 02:30 Sun"},
		{"Berlin after fall back", "2026-10-25T02:00:00Z", "Europe/Berlin", "2026-10-25 03:00 Sun"},
		{"Berlin before spring forward", "2026-03-29T00:59:00Z", "Europe/Berlin", "2026-03-29 01:59 Sun"},
		{"Berlin skips 02:xx in spring", "2026-03-29T01:00:00Z", "Europe/Berlin", "2026-03-29 03:00 Sun"},
		{"weekday changes with zone", "2026-10-16T23:30:00Z", "Europe/Berlin", "2026-10-17 01:30 Sat"},
		{"New York", "2026-10-12T06:30:00Z", "America/New_York", "2026-10-12 02:30 Mon"},
		{"quarter-hour offset", "2026-10-12T00:00:00Z", "Asia/Kathmandu", "2026-10-12 05:45 Mon"},
		{"UTC", "2026-10-12T21:00:00+02:00", "UTC", "2026-10-12 19:00 Mon"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			local, ok := localTime(mustTime(t, tt.at), tt.zone)
			if !ok {
				t.Fatalf("localTime rejected zone %q", tt.zone)
			}
			if got := local.Format("2006-01-02 15:04 Mon"); got != tt.want {
				t.Errorf("got %s, want %s", got, tt.want)
			}
		})
	}
}

func TestLocalTimeRejects(t *testing.T) {
	at := mustTime(t, "2026-10-12T12:00:00Z")
	for _, zone := range []string{
		"Mars/Olympus_Mons", "Local", "../../etc/passwd", "/etc/localtime", "Europe/Berlin\x00",
		"Europe/../Europe/Berlin", " Europe/Berlin", strings.Repeat("A", 300),
	} {
		if _, ok := localTime(at, zone); ok {
			t.Errorf("localTime accepted zone %q", zone)
		}
	}
	if _, ok := localTime(time.Time{}, ""); ok {
		t.Error("localTime accepted the zero time")
	}
}

func TestRuleConditionsMet(t *testing.T) {
	friLate := rule{window: mustWindow(t, "22:00-02:00"), weekdays: weekdaySet(1 << time.Friday)}
	onlyWeekday := rule{weekdays: weekdaySet(1 << time.Monday)}
	onlyWindow := rule{window: mustWindow(t, "06:00-22:00")}
	none := rule{}
	berlin, err := time.LoadLocation("Europe/Berlin")
	if err != nil {
		t.Fatal(err)
	}
	at := func(s string) time.Time { return mustTime(t, s).In(berlin) }
	tests := []struct {
		name string
		r    rule
		at   time.Time
		want bool
	}{
		{"friday 23:00 in window", friLate, at("2026-10-16T23:00:00+02:00"), true},
		{"saturday 01:00 wrong weekday", friLate, at("2026-10-17T01:00:00+02:00"), false},
		{"friday 01:00 in window", friLate, at("2026-10-16T01:00:00+02:00"), true},
		{"friday 21:59 outside window", friLate, at("2026-10-16T21:59:00+02:00"), false},
		{"monday weekday only", onlyWeekday, at("2026-10-12T03:00:00+02:00"), true},
		{"sunday weekday only", onlyWeekday, at("2026-10-11T03:00:00+02:00"), false},
		{"window only inside", onlyWindow, at("2026-10-11T06:00:00+02:00"), true},
		{"window only outside", onlyWindow, at("2026-10-11T22:00:00+02:00"), false},
		{"no conditions", none, at("2026-10-11T03:00:00+02:00"), true},
	}
	for _, tt := range tests {
		if got := tt.r.conditionsMet(tt.at); got != tt.want {
			t.Errorf("%s: got %v, want %v", tt.name, got, tt.want)
		}
	}
}

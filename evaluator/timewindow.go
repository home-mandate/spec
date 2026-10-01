// SPDX-License-Identifier: Apache-2.0

package evaluator

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	// Zeitzonendaten eingebettet: Ohne sie wäre in Containern ohne Zoneinfo jede Anfrage
	// mit Zeitzone deny. Genutzt wird sie nur, wenn das System keine Daten liefert.
	_ "time/tzdata"
)

// maxZoneNameLength entspricht der Grenze für timezone im Protokollschema.
const maxZoneNameLength = 64

// locations speichert erfolgreich geladene Zeitzonen. Die Obergrenze verhindert, dass
// Schreibvarianten auf Dateisystemen ohne Groß-/Kleinschreibung den Speicher füllen;
// Zonen jenseits der Grenze werden weiter geladen, nur nicht gespeichert.
var (
	locations      sync.Map // string → *time.Location
	cachedZones    atomic.Int64
	maxCachedZones = 256 // Variable, damit Tests die Grenze prüfen können
)

func cachedZoneCount() int { return int(cachedZones.Load()) }

// localTime rechnet at in die Ortszeit des Haushalts um (SPEC-v0 Abschnitt 4.2).
// Leere zone: es gilt der Offset von at. ok ist false bei Nullzeit oder unbekannter Zone.
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

// validZoneName setzt SPEC-v0 Abschnitt 4.2 um: "UTC" oder "Gebiet/Ort", jeder Teil beginnt
// mit einem Großbuchstaben. Das schließt rechnerabhängige Namen wie "Local", "localtime"
// oder "posixrules", Kürzel wie "CET" sowie Pfade und Steuerzeichen aus.
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

// contains prüft eine Minute seit Mitternacht: Beginn einschließlich, Ende ausschließlich;
// ist der Beginn größer als das Ende, geht das Fenster über Mitternacht.
func (w timeWindow) contains(minute int) bool {
	if w.start < w.end {
		return minute >= w.start && minute < w.end
	}
	return minute >= w.start || minute < w.end
}

func (s weekdaySet) contains(d time.Weekday) bool {
	return s&(1<<d) != 0
}

// conditionsMet prüft die Bedingungen einer Regel für einen Zeitpunkt in Ortszeit.
func (r rule) conditionsMet(local time.Time) bool {
	if r.window.set && !r.window.contains(local.Hour()*60+local.Minute()) {
		return false
	}
	if r.weekdays != 0 && !r.weekdays.contains(local.Weekday()) {
		return false
	}
	return true
}

// timeWindow ist ein Zeitfenster in Minuten seit Mitternacht (SPEC-v0 Abschnitt 4.2).
// set ist false, wenn die Regel kein Zeitfenster hat.
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

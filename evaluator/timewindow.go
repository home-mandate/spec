// SPDX-License-Identifier: Apache-2.0

package evaluator

import (
	"fmt"
	"strings"
	"time"
)

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

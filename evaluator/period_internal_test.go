// SPDX-License-Identifier: Apache-2.0

package evaluator

import (
	"encoding/json"
	"errors"
	"strconv"
	"testing"
	"time"
)

// A rule's period (SPEC-v0 section 4, step 2): valid_from inclusive, expires exclusive, a
// bound that is not set does not restrict, points in time are compared.
func TestPeriodContains(t *testing.T) {
	from := time.Date(2026, 10, 16, 14, 0, 0, 0, time.FixedZone("CEST", 2*60*60))
	until := from.Add(52 * time.Hour)
	tests := []struct {
		name string
		p    period
		t    time.Time
		want bool
	}{
		{"no bounds", period{}, from, true},
		{"at valid_from", period{from: from, hasFrom: true}, from, true},
		{"before valid_from", period{from: from, hasFrom: true}, from.Add(-time.Nanosecond), false},
		{"at valid_from in UTC", period{from: from, hasFrom: true}, from.UTC(), true},
		{"before expires", period{until: until, hasUntil: true}, until.Add(-time.Nanosecond), true},
		{"at expires", period{until: until, hasUntil: true}, until, false},
		{"after expires", period{until: until, hasUntil: true}, until.Add(time.Hour), false},
		{"inside both", period{from: from, until: until, hasFrom: true, hasUntil: true}, from.Add(time.Hour), true},
		{"a bound that is not set does not restrict", period{from: until, until: from}, from, true},
	}
	for _, tt := range tests {
		if got := tt.p.contains(tt.t); got != tt.want {
			t.Errorf("%s: contains = %v, want %v", tt.name, got, tt.want)
		}
	}
}

// setPeriod checks the order of the bounds itself (SPEC-v0 section 3.1 item 6).
func TestSetPeriod(t *testing.T) {
	const from, later = "2026-10-16T14:00:00+02:00", "2026-10-16T14:00:01+02:00"
	for name, tc := range map[string]struct {
		validFrom, expires string
		wantErr            error
	}{
		"both":                       {from, later, nil},
		"valid_from only":            {from, "", nil},
		"expires only":               {"", from, nil},
		"none":                       {"", "", nil},
		"equal":                      {from, from, ErrSemantic},
		"equal with another offset":  {from, "2026-10-16T12:00:00Z", ErrSemantic},
		"expires before valid_from":  {later, from, ErrSemantic},
		"valid_from not a timestamp": {"tomorrow", "", ErrSchema},
		"expires not a timestamp":    {"", "tomorrow", ErrSchema},
	} {
		var r rule
		err := r.setPeriod(rawRule{ID: "r", ValidFrom: tc.validFrom, Expires: tc.expires})
		if tc.wantErr == nil && err != nil || tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
			t.Errorf("%s: error %v, want %v", name, err, tc.wantErr)
			continue
		}
		if err == nil && (r.period.hasFrom != (tc.validFrom != "") || r.period.hasUntil != (tc.expires != "")) {
			t.Errorf("%s: period %+v", name, r.period)
		}
	}
}

// checkDates repeats the checks of the schema, so that no caller gets a range that
// contradicts SPEC-v0 sections 3.1 items 0 and 3.
func TestCheckDates(t *testing.T) {
	for name, tc := range map[string]struct {
		from, to string
		wantErr  error
	}{
		"a range":             {"2026-12-24", "2027-01-06", nil},
		"one day":             {"2026-12-24", "2026-12-24", nil},
		"a leap day":          {"2028-02-29", "2028-02-29", nil},
		"from after to":       {"2026-12-25", "2026-12-24", ErrSemantic},
		"no leap day":         {"2026-02-29", "2026-03-01", ErrSchema},
		"the year 0000":       {"0000-01-01", "0000-01-02", ErrSchema},
		"to in the year 0000": {"2026-01-01", "0000-01-02", ErrSchema},
		"no leading zero":     {"2026-1-05", "2026-01-06", ErrSchema},
		"a time":              {"2026-12-24T00:00:00Z", "2026-12-25", ErrSchema},
		"another form of to":  {"2026-12-24", "20261225", ErrSchema},
	} {
		err := checkDates(tc.from, tc.to)
		if tc.wantErr == nil && err != nil || tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
			t.Errorf("%s: error %v, want %v", name, err, tc.wantErr)
		}
	}
}

// conditions.dates compares the date of household local time; both ends are inclusive and
// one range of the list suffices (SPEC-v0 section 4.2).
func TestConditionsMetDates(t *testing.T) {
	r := rule{dates: []dateRange{{20261224, 20270106}, {20270701, 20270701}}}
	berlin := time.FixedZone("CET", 60*60)
	for _, tc := range []struct {
		local time.Time
		want  bool
	}{
		{time.Date(2026, 12, 23, 23, 59, 0, 0, berlin), false},
		{time.Date(2026, 12, 24, 0, 0, 0, 0, berlin), true},
		{time.Date(2027, 1, 6, 23, 59, 0, 0, berlin), true},
		{time.Date(2027, 1, 7, 0, 0, 0, 0, berlin), false},
		{time.Date(2027, 7, 1, 12, 0, 0, 0, berlin), true},
		{time.Date(2027, 7, 2, 0, 0, 0, 0, berlin), false},
	} {
		if got := r.conditionsMet(tc.local); got != tc.want {
			t.Errorf("%v: conditionsMet = %v, want %v", tc.local, got, tc.want)
		}
	}
	if !(rule{}).conditionsMet(time.Date(2026, 1, 1, 0, 0, 0, 0, berlin)) {
		t.Error("a rule without conditions is not met")
	}
}

// none_of permits only values of its own type that it does not list (SPEC-v0 section 4.5):
// a list that does not fit the parameter permits nothing, never everything.
func TestNoneOfPermits(t *testing.T) {
	strings := constraint{parameter: "mode", noneOf: []Value{StringValue("off"), StringValue("dry")}}
	integers := constraint{parameter: "brightness", noneOf: []Value{IntegerValue(100)}}
	for _, tc := range []struct {
		c    constraint
		v    Value
		want bool
	}{
		{strings, StringValue("heat"), true},
		{strings, StringValue("off"), false},
		{strings, StringValue("dry"), false},
		{strings, StringValue("Off"), true},
		{strings, IntegerValue(0), false},
		{integers, IntegerValue(50), true},
		{integers, IntegerValue(100), false},
		{integers, StringValue("50"), false},
	} {
		if got := tc.c.permits(tc.v); got != tc.want {
			t.Errorf("%v permits %v = %v, want %v", tc.c.noneOf, tc.v, got, tc.want)
		}
	}
	mode := parameterInfo{Type: typeString, Values: []string{"off", "heat", "dry"}}
	if !strings.fits(mode) {
		t.Error("none_of of permitted values does not fit mode")
	}
	if (constraint{noneOf: []Value{StringValue("of")}}).fits(mode) {
		t.Error("none_of with a value mode does not permit fits mode")
	}
	if integers.fits(mode) {
		t.Error("none_of of integers fits a string parameter")
	}
}

// buildConstraint checks a none_of itself, as it does a one_of.
func TestBuildConstraintChecksNoneOfItself(t *testing.T) {
	list := func(values ...string) []json.RawMessage {
		out := []json.RawMessage{}
		for _, v := range values {
			out = append(out, json.RawMessage(v))
		}
		return out
	}
	many := make([]string, 33)
	for i := range many {
		many[i] = strconv.Itoa(i)
	}
	limit := json.Number("1")
	for name, raw := range map[string]rawConstraint{
		"empty":       {NoneOf: list()},
		"33 values":   {NoneOf: list(many...)},
		"duplicate":   {NoneOf: list(`1`, `1.0`)},
		"mixed types": {NoneOf: list(`1`, `"a"`)},
		"with min":    {NoneOf: list(`1`), Min: &limit},
		"with max":    {NoneOf: list(`1`), Max: &limit},
		"with one_of": {NoneOf: list(`1`), OneOf: list(`2`)},
	} {
		if _, err := buildConstraint("r", "p", raw); !errors.Is(err, ErrSemantic) {
			t.Errorf("%s: error %v, want a semantic one", name, err)
		}
	}
	c, err := buildConstraint("r", "p", rawConstraint{NoneOf: list(many[:32]...)})
	if err != nil || len(c.noneOf) != 32 || c.oneOf != nil {
		t.Errorf("32 values: %v, %+v", err, c)
	}
	if c, err := buildConstraint("r", "p", rawConstraint{OneOf: list(`1`)}); err != nil || c.noneOf != nil || len(c.oneOf) != 1 {
		t.Errorf("one_of: %v, %+v", err, c)
	}
}

// setLimits repeats the checks of the schema (SPEC-v0 section 3.1 item 12): only on an allow
// rule, at least one member, counts of at least 1, min_interval from 1 second to 24 hours.
func TestSetLimits(t *testing.T) {
	type raw = struct {
		MaxActionsPerHour json.Number `json:"max_actions_per_hour"`
		MaxActionsPerDay  json.Number `json:"max_actions_per_day"`
		MinInterval       string      `json:"min_interval"`
	}
	for name, tc := range map[string]struct {
		decision Decision
		limits   raw
		want     RuleLimits
		wantErr  error
	}{
		"per hour":               {Allow, raw{MaxActionsPerHour: "3"}, RuleLimits{PerHour: 3}, nil},
		"per day as 2.0":         {Allow, raw{MaxActionsPerDay: "2.0"}, RuleLimits{PerDay: 2}, nil},
		"one second":             {Allow, raw{MinInterval: "PT1S"}, RuleLimits{MinInterval: time.Second}, nil},
		"24 hours":               {Allow, raw{MinInterval: "PT23H59M60S"}, RuleLimits{MinInterval: 24 * time.Hour}, nil},
		"all three":              {Allow, raw{"1", "2", "PT10M"}, RuleLimits{1, 2, 10 * time.Minute}, nil},
		"none":                   {Allow, raw{}, RuleLimits{}, ErrSemantic},
		"on a deny rule":         {Deny, raw{MaxActionsPerHour: "3"}, RuleLimits{}, ErrSemantic},
		"on an ask rule":         {Ask, raw{MaxActionsPerHour: "3"}, RuleLimits{}, ErrSemantic},
		"zero per hour":          {Allow, raw{MaxActionsPerHour: "0"}, RuleLimits{}, ErrSchema},
		"a fraction per day":     {Allow, raw{MaxActionsPerDay: "1.5"}, RuleLimits{}, ErrSchema},
		"zero seconds":           {Allow, raw{MinInterval: "PT0S"}, RuleLimits{}, ErrSemantic},
		"a nanosecond above 24h": {Allow, raw{MinInterval: "PT24H1S"}, RuleLimits{}, ErrSemantic},
		"not a duration":         {Allow, raw{MinInterval: "P1D"}, RuleLimits{}, ErrSchema},
	} {
		limits := tc.limits
		r := rule{decision: tc.decision}
		err := r.setLimits(rawRule{ID: "r", Limits: &limits})
		if tc.wantErr == nil && err != nil || tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
			t.Errorf("%s: error %v, want %v", name, err, tc.wantErr)
			continue
		}
		if err == nil && (r.limits == nil || *r.limits != tc.want) {
			t.Errorf("%s: limits %+v, want %+v", name, r.limits, tc.want)
		}
	}
	var r rule
	if err := r.setLimits(rawRule{ID: "r"}); err != nil || r.limits != nil {
		t.Errorf("a rule without limits: %v, %+v", err, r.limits)
	}
}

// A local date beyond the years 1 to 9999 lies in no range: as text, 10000-01-01 would come
// before 1999-12-31 (SPEC-v0 section 4.2).
func TestConditionsMetDatesBeyondTheYears(t *testing.T) {
	r := rule{dates: []dateRange{{10101, 19991231}}}
	kiritimati := time.FixedZone("LINT", 14*60*60)
	for _, local := range []time.Time{
		time.Date(9999, 12, 31, 10, 0, 1, 0, time.UTC).In(kiritimati),                // 10000-01-01
		time.Date(1, 1, 1, 0, 0, 0, 0, time.UTC).In(time.FixedZone("EST", -5*60*60)), // the year 0
	} {
		if r.conditionsMet(local) {
			t.Errorf("%v: in the range 0001-01-01 to 1999-12-31", local)
		}
	}
	if !r.conditionsMet(time.Date(1999, 12, 31, 23, 0, 0, 0, time.UTC)) {
		t.Error("the last day of the range is not in it")
	}
}

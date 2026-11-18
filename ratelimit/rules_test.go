// SPDX-License-Identifier: Apache-2.0

package ratelimit_test

import (
	"testing"
	"time"

	"github.com/home-mandate/spec/ratelimit"
)

func perHour(key string, n int) ratelimit.Rule { return ratelimit.Rule{Key: key, PerHour: n} }
func perDay(key string, n int) ratelimit.Rule  { return ratelimit.Rule{Key: key, PerDay: n} }
func interval(key string, d time.Duration) ratelimit.Rule {
	return ratelimit.Rule{Key: key, MinInterval: d}
}

// "At most three unlocks a day" (SPEC-v0 section 11.2): every period of 86 400 seconds.
func TestRulePerDay(t *testing.T) {
	c := newClock()
	l := ratelimit.NewRuleLimiter(c.Now)
	unlock := perDay("m-1/r-unlock", 3)
	for i := range 3 {
		if !l.AllowN([]ratelimit.Rule{unlock}, 1) {
			t.Fatalf("unlock %d denied", i+1)
		}
		c.advance(4 * time.Hour)
	}
	if l.AllowN([]ratelimit.Rule{unlock}, 1) {
		t.Fatal("fourth unlock within a day allowed")
	}
	c.advance(12*time.Hour - time.Nanosecond) // 24 h after the first, less a nanosecond
	if l.AllowN([]ratelimit.Rule{unlock}, 1) {
		t.Error("unlock allowed a nanosecond before the first leaves the day")
	}
	c.advance(time.Nanosecond)
	if !l.AllowN([]ratelimit.Rule{unlock}, 1) {
		t.Error("unlock denied once the first has left the day")
	}
}

func TestRulePerHour(t *testing.T) {
	c := newClock()
	l := ratelimit.NewRuleLimiter(c.Now)
	garage := perHour("m-1/r-garage", 2)
	if !l.AllowN([]ratelimit.Rule{garage}, 2) {
		t.Fatal("two at once denied")
	}
	if l.AllowN([]ratelimit.Rule{garage}, 1) {
		t.Fatal("third within the hour allowed")
	}
	c.advance(time.Hour)
	if !l.AllowN([]ratelimit.Rule{garage}, 2) {
		t.Error("denied after the hour")
	}
}

// Both counts of a rule hold: an hour with room does not lift a full day.
func TestRulePerHourAndPerDay(t *testing.T) {
	c := newClock()
	l := ratelimit.NewRuleLimiter(c.Now)
	hall := ratelimit.Rule{Key: "m-1/r-hall", PerHour: 4, PerDay: 5}
	for i := range 4 {
		if !l.AllowN([]ratelimit.Rule{hall}, 1) {
			t.Fatalf("request %d denied", i+1)
		}
	}
	if l.AllowN([]ratelimit.Rule{hall}, 1) {
		t.Fatal("fifth within the hour allowed")
	}
	c.advance(time.Hour)
	if !l.AllowN([]ratelimit.Rule{hall}, 1) {
		t.Fatal("fifth of the day denied")
	}
	if l.AllowN([]ratelimit.Rule{hall}, 1) {
		t.Error("sixth of the day allowed")
	}
}

// min_interval is the time between two requests, inclusive at its end; a request for several
// resources counts as one request for it.
func TestRuleMinInterval(t *testing.T) {
	c := newClock()
	l := ratelimit.NewRuleLimiter(c.Now)
	heating := interval("m-1/r-heating", 10*time.Minute)
	if !l.AllowN([]ratelimit.Rule{heating}, 3) {
		t.Fatal("a request for three thermostats denied")
	}
	c.advance(10*time.Minute - time.Nanosecond)
	if l.AllowN([]ratelimit.Rule{heating}, 1) {
		t.Error("allowed within the interval")
	}
	c.advance(time.Nanosecond)
	if !l.AllowN([]ratelimit.Rule{heating}, 1) {
		t.Error("denied once the interval has passed")
	}
	c.advance(-time.Minute) // the clock is set back: the later request still counts
	if l.AllowN([]ratelimit.Rule{heating}, 1) {
		t.Error("allowed after the clock was set back")
	}
}

// A rule with a count and a longer interval keeps its times for the interval: an hour does not
// end a min_interval of two hours.
func TestRuleIntervalLongerThanTheHour(t *testing.T) {
	c := newClock()
	l := ratelimit.NewRuleLimiter(c.Now)
	siren := ratelimit.Rule{Key: "m-1/r-siren", PerHour: 5, MinInterval: 2 * time.Hour}
	if !l.AllowN([]ratelimit.Rule{siren}, 1) {
		t.Fatal("first denied")
	}
	c.advance(90 * time.Minute)
	if l.AllowN([]ratelimit.Rule{siren}, 1) {
		t.Error("allowed 90 minutes after the first with an interval of two hours")
	}
	c.advance(30 * time.Minute)
	if !l.AllowN([]ratelimit.Rule{siren}, 1) {
		t.Error("denied after two hours")
	}
}

// All or nothing over the rules and the resources (SPEC-v0 section 11.2): a rule without
// room denies the request, and no rule counts it.
func TestRuleAllOrNothing(t *testing.T) {
	c := newClock()
	l := ratelimit.NewRuleLimiter(c.Now)
	broad, narrow := perHour("m-1/r-heating", 10), perHour("m-1/r-hall", 2)
	if !l.AllowN([]ratelimit.Rule{broad, narrow}, 2) {
		t.Fatal("first request denied")
	}
	if l.AllowN([]ratelimit.Rule{broad, narrow}, 1) {
		t.Fatal("allowed although the narrow rule is full")
	}
	// The broad rule did not count the denied request: 8 more fit, not 7.
	if !l.AllowN([]ratelimit.Rule{broad}, 8) {
		t.Error("the denied request was counted for the broad rule")
	}
	if l.AllowN([]ratelimit.Rule{broad}, 1) {
		t.Error("the broad rule allows more than 10")
	}
	if l.AllowN([]ratelimit.Rule{narrow}, 3) {
		t.Error("three at once fit into a limit of two")
	}
}

func TestRuleEdges(t *testing.T) {
	c := newClock()
	l := ratelimit.NewRuleLimiter(c.Now)
	if l.AllowN([]ratelimit.Rule{perHour("k", 5)}, 0) || l.AllowN([]ratelimit.Rule{perHour("k", 5)}, -1) {
		t.Error("n below 1 allowed")
	}
	if !l.AllowN(nil, 1) {
		t.Error("a request without limited rules denied")
	}
	if !l.AllowN([]ratelimit.Rule{{Key: "unlimited"}}, 1000) || l.Keys() != 0 {
		t.Errorf("a rule without limits was limited or kept (%d keys)", l.Keys())
	}
	// The same rule twice counts once.
	twice := perHour("k-twice", 2)
	if !l.AllowN([]ratelimit.Rule{twice, twice}, 2) {
		t.Error("the same rule twice was counted twice")
	}
}

// The count survives a restart (SPEC-v0 section 11.2): Restore counts the earlier requests.
func TestRuleRestore(t *testing.T) {
	c := newClock()
	l := ratelimit.NewRuleLimiter(c.Now)
	unlock := perDay("m-1/r-unlock", 3)
	l.Restore(unlock, []time.Time{c.now.Add(-25 * time.Hour), c.now.Add(-2 * time.Hour), c.now.Add(-time.Hour)})
	if !l.AllowN([]ratelimit.Rule{unlock}, 1) {
		t.Fatal("third of the day denied: a time older than a day was restored")
	}
	if l.AllowN([]ratelimit.Rule{unlock}, 1) {
		t.Error("fourth of the day allowed after a restore")
	}
	// A stored time after now counts as now: it blocks no longer than the interval.
	heating := interval("m-1/r-heating", 10*time.Minute)
	l.Restore(heating, []time.Time{c.now.Add(48 * time.Hour)})
	if l.AllowN([]ratelimit.Rule{heating}, 1) {
		t.Error("a restored time does not count")
	}
	c.advance(10 * time.Minute)
	if !l.AllowN([]ratelimit.Rule{heating}, 1) {
		t.Error("a time in the future blocks beyond the interval")
	}
	// Restore keeps no more times than the limit can use: two of 500 within the hour.
	many := make([]time.Time, 500)
	for i := range many {
		many[i] = c.now.Add(-time.Duration(i) * time.Second)
	}
	small := perHour("m-1/r-many", 2)
	l.Restore(small, many)
	if l.AllowN([]ratelimit.Rule{small}, 1) {
		t.Error("allowed although two restored times fill the hour")
	}
	l.Forget(unlock.Key)
	if !l.AllowN([]ratelimit.Rule{unlock}, 3) {
		t.Error("Forget kept the count")
	}
}

// Keys that have not been used for a day are dropped, so that rules no longer used do not
// accumulate.
func TestRuleSweep(t *testing.T) {
	c := newClock()
	l := ratelimit.NewRuleLimiter(c.Now)
	for _, key := range []string{"a", "b", "c"} {
		l.AllowN([]ratelimit.Rule{perDay(key, 1)}, 1)
	}
	if got := l.Keys(); got != 3 {
		t.Fatalf("keys = %d, want 3", got)
	}
	c.advance(24 * time.Hour)
	l.AllowN([]ratelimit.Rule{perDay("d", 1)}, 1)
	if got := l.Keys(); got != 1 {
		t.Errorf("keys after a day = %d, want 1", got)
	}
}

func TestRuleKey(t *testing.T) {
	seen := map[string]bool{}
	for _, k := range []string{ratelimit.RuleKey("m-1", "r-a"), ratelimit.RuleKey("m-1", "r-b"), ratelimit.RuleKey("m-2", "r-a"),
		ratelimit.RuleKey("m-1r", "-a")} {
		if seen[k] {
			t.Errorf("key %q repeats", k)
		}
		seen[k] = true
	}
}

// With a count as well, a time exactly min_interval ago is still held, and the interval has
// passed at that point: the end is inclusive.
func TestRuleIntervalEndWithACount(t *testing.T) {
	c := newClock()
	l := ratelimit.NewRuleLimiter(c.Now)
	heating := ratelimit.Rule{Key: "m-1/r-heating", PerHour: 5, MinInterval: 10 * time.Minute}
	l.AllowN([]ratelimit.Rule{heating}, 1)
	c.advance(10 * time.Minute)
	if !l.AllowN([]ratelimit.Rule{heating}, 1) {
		t.Error("denied exactly min_interval after the last request")
	}
}

// A rule without min_interval is not limited by a clock that was set back, only by its counts.
func TestRuleWithoutIntervalAfterTheClockWasSetBack(t *testing.T) {
	c := newClock()
	l := ratelimit.NewRuleLimiter(c.Now)
	garage := perHour("m-1/r-garage", 5)
	l.AllowN([]ratelimit.Rule{garage}, 1)
	c.advance(-time.Minute)
	if !l.AllowN([]ratelimit.Rule{garage}, 1) {
		t.Error("denied by a time after now, although the rule has no min_interval")
	}
}

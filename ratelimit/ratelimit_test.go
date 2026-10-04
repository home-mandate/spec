// SPDX-License-Identifier: Apache-2.0

package ratelimit_test

import (
	"math/rand"
	"slices"
	"testing"
	"time"

	"github.com/mandate-spec/mandate-spec/ratelimit"
)

type clock struct{ now time.Time }

func (c *clock) Now() time.Time          { return c.now }
func (c *clock) advance(d time.Duration) { c.now = c.now.Add(d) }

func newClock() *clock {
	return &clock{now: time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)}
}

func TestAllowsUpToTheLimitWithinAnHour(t *testing.T) {
	c := newClock()
	l := ratelimit.New(c.Now)
	for i := range 3 {
		if !l.Allow("m-1", 3) {
			t.Fatalf("request %d denied", i+1)
		}
		c.advance(time.Minute)
	}
	if l.Allow("m-1", 3) {
		t.Fatal("fourth request within the hour allowed")
	}
}

func TestWindowBoundaryIsExact(t *testing.T) {
	c := newClock()
	l := ratelimit.New(c.Now)
	if !l.Allow("m-1", 1) {
		t.Fatal("first request denied")
	}
	c.advance(time.Hour - time.Nanosecond)
	if l.Allow("m-1", 1) {
		t.Error("request allowed one nanosecond before the hour has passed")
	}
	c.advance(time.Nanosecond)
	if !l.Allow("m-1", 1) {
		t.Error("request denied exactly one hour after the first")
	}
}

func TestDeniedRequestsDoNotCount(t *testing.T) {
	c := newClock()
	l := ratelimit.New(c.Now)
	l.Allow("m-1", 1)
	for range 100 {
		c.advance(time.Minute / 2)
		l.Allow("m-1", 1) // denied until the hour has passed
	}
	c.advance(10 * time.Minute)
	if !l.Allow("m-1", 1) {
		t.Error("denied requests extended the limit")
	}
}

func TestNoBurstAfterAnIdlePeriod(t *testing.T) {
	// A token bucket would allow 2N within an hour here; the bound does not.
	c := newClock()
	l := ratelimit.New(c.Now)
	const n = 10
	allowed := 0
	for range n {
		if l.Allow("m-1", n) {
			allowed++
		}
	}
	c.advance(59 * time.Minute)
	for range n {
		if l.Allow("m-1", n) {
			allowed++
		}
	}
	if allowed != n {
		t.Errorf("%d requests allowed within 59 minutes, want %d", allowed, n)
	}
}

func TestKeysAreIndependent(t *testing.T) {
	l := ratelimit.New(newClock().Now)
	if !l.Allow("m-1", 1) || !l.Allow("m-2", 1) {
		t.Error("the limit of one mandate affected another")
	}
}

func TestNonPositiveLimitDenies(t *testing.T) {
	l := ratelimit.New(newClock().Now)
	if l.Allow("m-1", 0) || l.Allow("m-1", -1) {
		t.Error("request allowed with a limit of zero or less")
	}
}

func TestLoweredLimitAppliesAtOnce(t *testing.T) {
	c := newClock()
	l := ratelimit.New(c.Now)
	for range 5 {
		l.Allow("m-1", 10)
	}
	if l.Allow("m-1", 5) {
		t.Error("request allowed although the lowered limit is already used up")
	}
	if !l.Allow("m-1", 6) {
		t.Error("request denied below the limit")
	}
}

func TestClockJumpBackwardsDoesNotFreeTheLimit(t *testing.T) {
	c := newClock()
	l := ratelimit.New(c.Now)
	l.Allow("m-1", 1)
	c.advance(-2 * time.Hour)
	if l.Allow("m-1", 1) {
		t.Error("a clock set back freed the limit")
	}
}

func TestForgetDropsTheState(t *testing.T) {
	l := ratelimit.New(newClock().Now)
	l.Allow("m-1", 1)
	l.Forget("m-1")
	if !l.Allow("m-1", 1) {
		t.Error("state survived Forget")
	}
}

func TestNewDefaultsToTheSystemClock(t *testing.T) {
	if !ratelimit.New(nil).Allow("m-1", 1) {
		t.Error("first request denied")
	}
}

func TestRestoreCountsEarlierRequests(t *testing.T) {
	c := newClock()
	l := ratelimit.New(c.Now)
	// After a restart, an implementation restores the requests of the last hour, for
	// example from its audit log; older ones are ignored.
	l.Restore("m-1", []time.Time{c.now.Add(-2 * time.Hour), c.now.Add(-30 * time.Minute), c.now.Add(-time.Minute)})
	if !l.Allow("m-1", 3) {
		t.Error("third request within the hour denied")
	}
	if l.Allow("m-1", 3) {
		t.Error("fourth request within the hour allowed")
	}
}

// TestBoundHoldsForRandomTraffic is the property SPEC-v0 section 11.2 requires: in every
// period of 3600 seconds at most N requests are allowed.
func TestBoundHoldsForRandomTraffic(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for round := range 50 {
		c := newClock()
		l := ratelimit.New(c.Now)
		n := 1 + rng.Intn(20)
		var allowed []time.Time
		for range 2000 {
			c.advance(time.Duration(rng.Int63n(int64(10 * time.Minute / time.Duration(n)))))
			if l.Allow("m", n) {
				allowed = append(allowed, c.now)
			}
		}
		if len(allowed) < n {
			t.Fatalf("round %d: only %d requests allowed", round, len(allowed))
		}
		for i, start := range allowed {
			end := start.Add(time.Hour)
			j, _ := slices.BinarySearchFunc(allowed, end, func(a, b time.Time) int { return a.Compare(b) })
			if j-i > n {
				t.Fatalf("round %d: %d requests allowed in the hour from %s, limit %d", round, j-i, start, n)
			}
		}
	}
}

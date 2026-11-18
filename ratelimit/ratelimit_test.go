// SPDX-License-Identifier: Apache-2.0

package ratelimit_test

import (
	"math/rand"
	"slices"
	"testing"
	"time"

	"github.com/home-mandate/spec/ratelimit"
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
	l.Restore("m-1", []time.Time{c.now.Add(-2 * time.Hour), c.now.Add(-30 * time.Minute), c.now.Add(-time.Minute)}, 3)
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

func TestIdleKeysAreDropped(t *testing.T) {
	c := newClock()
	l := ratelimit.New(c.Now)
	for _, key := range []string{"m-1", "m-2", "m-3"} {
		l.Allow(key, 5)
	}
	if got := l.Keys(); got != 3 {
		t.Fatalf("Keys() = %d, want 3", got)
	}
	c.advance(2 * time.Hour)
	l.Allow("m-1", 5) // any call sweeps what has expired
	if got := l.Keys(); got != 1 {
		t.Errorf("Keys() after the window = %d, want 1", got)
	}
}

// A request for several resources counts once for each, all or nothing (SPEC-v0 section 11.2):
// if the limit leaves no room for all of them, the whole request is denied and counts nothing.
func TestAllowNCountsAllOrNothing(t *testing.T) {
	c := newClock()
	l := ratelimit.New(c.Now)
	if !l.AllowN("m-1", 3, 5) {
		t.Fatal("three of five denied")
	}
	if l.AllowN("m-1", 3, 5) {
		t.Fatal("three more allowed, with room for two")
	}
	if !l.AllowN("m-1", 2, 5) {
		t.Fatal("the denied request counted: two more denied")
	}
	if l.Allow("m-1", 5) {
		t.Error("a sixth request allowed")
	}
}

func TestAllowNOfNothingDenies(t *testing.T) {
	l := ratelimit.New(newClock().Now)
	for _, n := range []int{0, -1} {
		if l.AllowN("m-1", n, 5) {
			t.Errorf("AllowN(%d) allowed", n)
		}
	}
	if !l.AllowN("m-1", 5, 5) || l.Keys() != 1 {
		t.Error("the full limit at once denied, or a denied request kept a key")
	}
}

// Restore keeps at most perHour times, the latest ones: they are the ones that still count
// longest, and a long list from outside cannot grow the state.
func TestRestoreKeepsAtMostTheLimit(t *testing.T) {
	c := newClock()
	l := ratelimit.New(c.Now)
	var earlier []time.Time
	for i := range 1000 {
		earlier = append(earlier, c.now.Add(-time.Duration(1000-i)*time.Second))
	}
	l.Restore("m-1", earlier, 2)
	if l.Allow("m-1", 2) {
		t.Fatal("a request allowed after the limit was restored")
	}
	// The two latest restored requests lie 1 and 2 seconds back; the earlier ones are gone.
	c.advance(time.Hour - 3*time.Second)
	if l.Allow("m-1", 2) {
		t.Fatal("allowed while both kept requests are less than an hour old")
	}
	c.advance(time.Second)
	if !l.Allow("m-1", 2) {
		t.Error("denied after the older kept request expired")
	}
}

func TestRestoreIgnoresANonPositiveLimit(t *testing.T) {
	c := newClock()
	l := ratelimit.New(c.Now)
	l.Restore("m-1", []time.Time{c.now.Add(-time.Minute)}, 0)
	if l.Keys() != 0 {
		t.Error("a restore with limit 0 kept times")
	}
}

// The idle keys are dropped as soon as a full window has passed since the last sweep.
func TestIdleKeysAreDroppedAfterExactlyAWindow(t *testing.T) {
	c := newClock()
	l := ratelimit.New(c.Now)
	l.Allow("m-1", 5)
	l.Allow("m-2", 5)
	c.advance(time.Hour)
	l.Allow("m-1", 5)
	if got := l.Keys(); got != 1 {
		t.Errorf("Keys() = %d, want 1", got)
	}
}

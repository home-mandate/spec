// SPDX-License-Identifier: Apache-2.0

// Package ratelimit is a reference for the bound of SPEC-v0 section 11.2: in every
// period of 3600 seconds, at most limits.max_actions_per_hour requests of an agent
// under a mandate reach the evaluation. The specification fixes the bound, not the
// algorithm; this one keeps the times of the allowed requests of the last hour.
package ratelimit

import (
	"slices"
	"sync"
	"time"
)

// Window is the period the bound refers to.
const Window = time.Hour

// Limiter holds the allowed requests of the last hour per key. The key identifies what
// the limit applies to, for example the ID of the mandate.
type Limiter struct {
	now func() time.Time

	mu      sync.Mutex
	allowed map[string][]time.Time // ascending
}

// New returns a Limiter using now as its clock (time.Now if nil).
func New(now func() time.Time) *Limiter {
	if now == nil {
		now = time.Now
	}
	return &Limiter{now: now, allowed: map[string][]time.Time{}}
}

// Allow reports whether one more request may reach the evaluation and, if so, counts
// it. A denied request is not counted. A non-positive limit denies. If the clock was
// set back, requests recorded with a later time still count.
func (l *Limiter) Allow(key string, perHour int) bool {
	if perHour <= 0 {
		return false
	}
	now := l.now()

	l.mu.Lock()
	defer l.mu.Unlock()
	times := current(l.allowed[key], now)
	if len(times) >= perHour {
		l.allowed[key] = times
		return false
	}
	l.allowed[key] = insert(times, now)
	return true
}

// Restore counts requests that were allowed earlier, for example before a restart.
// Without it a restart would give every agent a fresh limit.
func (l *Limiter) Restore(key string, earlier []time.Time) {
	now := l.now()

	l.mu.Lock()
	defer l.mu.Unlock()
	times := l.allowed[key]
	for _, t := range earlier {
		times = insert(times, t)
	}
	l.allowed[key] = current(times, now)
}

// Forget drops the state of a key, for example when its mandate is deleted.
func (l *Limiter) Forget(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.allowed, key)
}

// current drops the times that lie a full window or more before now.
func current(times []time.Time, now time.Time) []time.Time {
	cutoff := now.Add(-Window)
	return slices.DeleteFunc(times, func(t time.Time) bool { return !t.After(cutoff) })
}

func insert(times []time.Time, t time.Time) []time.Time {
	i, _ := slices.BinarySearchFunc(times, t, func(a, b time.Time) int { return a.Compare(b) })
	return slices.Insert(times, i, t)
}

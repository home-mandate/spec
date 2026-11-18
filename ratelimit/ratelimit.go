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
// the limit applies to, for example the ID of the mandate. The caller bounds the number of
// keys: a key it derives from what an agent sends (a client ID, a principal) would let the
// agent grow the state. Keys without a request in the last hour are dropped within the next
// hour.
type Limiter struct {
	now func() time.Time

	mu        sync.Mutex
	allowed   map[string][]time.Time // ascending
	lastSweep time.Time
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
	return l.AllowN(key, 1, perHour)
}

// AllowN reports whether a request that counts n times, one for each resource it
// evaluates, may reach the evaluation, and if so counts all n. It is all or nothing
// (SPEC-v0 section 11.2): if the limit leaves no room for all n, the request is denied and
// counts nothing. n below 1 denies.
func (l *Limiter) AllowN(key string, n, perHour int) bool {
	if n < 1 {
		return false
	}
	now := l.now()

	l.mu.Lock()
	defer l.mu.Unlock()
	l.sweep(now)
	times := current(l.allowed[key], now)
	if n > perHour-len(times) {
		l.keep(key, times)
		return false
	}
	i, _ := slices.BinarySearchFunc(times, now, func(a, b time.Time) int { return a.Compare(b) })
	l.allowed[key] = slices.Insert(times, i, slices.Repeat([]time.Time{now}, n)...)
	return true
}

// sweep drops the expired times of every key once a window has passed since the last
// sweep, so that keys which are no longer used do not accumulate, at a cost that does not
// grow with every call.
func (l *Limiter) sweep(now time.Time) {
	if !l.lastSweep.IsZero() && now.Sub(l.lastSweep) < Window && !now.Before(l.lastSweep) {
		return
	}
	l.lastSweep = now
	for key, times := range l.allowed {
		l.keep(key, current(times, now))
	}
}

func (l *Limiter) keep(key string, times []time.Time) {
	if len(times) == 0 {
		delete(l.allowed, key)
		return
	}
	l.allowed[key] = times
}

// Keys returns the number of keys the limiter currently holds times for.
func (l *Limiter) Keys() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.allowed)
}

// Restore counts requests that were allowed earlier, for example before a restart, as
// SPEC-v0 section 11.2 requires: without it a restart would give every agent a fresh limit.
// It is meant for a fresh Limiter: the times are added to those the key already holds. A
// time after now counts as now, so that a wrong stored time cannot block the key beyond an
// hour. It keeps at most perHour times for the key, the latest, so that a long list cannot
// grow the state.
func (l *Limiter) Restore(key string, earlier []time.Time, perHour int) {
	now := l.now()

	l.mu.Lock()
	defer l.mu.Unlock()
	restored := current(slices.Clone(earlier), now)
	for i, t := range restored {
		if t.After(now) {
			restored[i] = now
		}
	}
	times := append(slices.Clone(l.allowed[key]), restored...)
	slices.SortFunc(times, func(a, b time.Time) int { return a.Compare(b) })
	times = times[max(len(times)-max(perHour, 0), 0):]
	l.keep(key, times)
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

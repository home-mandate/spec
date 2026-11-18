// SPDX-License-Identifier: Apache-2.0

package ratelimit

import (
	"slices"
	"sync"
	"time"
)

// Day is the period of max_actions_per_day (SPEC-v0 section 11.2).
const Day = 24 * time.Hour

// Rule is the state key and the limits of one rule (SPEC-v0 section 11.2). A zero field does
// not limit. The key identifies the rule within its mandate, as RuleKey forms it: the count
// belongs to the mandate id and the rule id, not to a version of the mandate.
type Rule struct {
	Key         string
	PerHour     int
	PerDay      int
	MinInterval time.Duration
}

// limited reports whether the rule sets any limit.
func (r Rule) limited() bool { return r.PerHour > 0 || r.PerDay > 0 || r.MinInterval > 0 }

// retention is how long a time of the rule is needed: the longest of its periods.
func (r Rule) retention() time.Duration {
	d := r.MinInterval
	if r.PerHour > 0 {
		d = max(d, Window)
	}
	if r.PerDay > 0 {
		d = max(d, Day)
	}
	return d
}

// keep is the largest number of times the rule needs: no more than its counts can use.
func (r Rule) keep() int { return max(r.PerHour, r.PerDay, 1) }

// RuleKey forms the key of a rule: the mandate id and the rule id, which contain no slash.
func RuleKey(mandateID, ruleID string) string { return mandateID + "/" + ruleID }

// RuleLimiter holds, per rule, the times of the requests the rule let through within its
// longest period, at most a day. A PEP that evaluates itself, or a PDP apart from its PEP,
// asks it after an evaluation that allowed, for the rules the evaluation names (SPEC-v0
// sections 6 and 11.2).
type RuleLimiter struct {
	now func() time.Time

	mu        sync.Mutex
	allowed   map[string][]time.Time // ascending
	lastSweep time.Time
}

// NewRuleLimiter returns a RuleLimiter using now as its clock (time.Now if nil).
func NewRuleLimiter(now func() time.Time) *RuleLimiter {
	if now == nil {
		now = time.Now
	}
	return &RuleLimiter{now: now, allowed: map[string][]time.Time{}}
}

// AllowN reports whether a request that counts n times, once for each resource it evaluates,
// may pass the limits of every rule in rules, and if so counts it for each of them. It is all
// or nothing: if one rule leaves no room, the request is denied and no rule counts it.
// min_interval is the time between two requests, so the n resources of one request do not
// count against each other. A rule that appears twice counts once, a rule without limits is
// not counted, and n below 1 denies. If the clock was set back, requests recorded with a later
// time still count.
func (l *RuleLimiter) AllowN(rules []Rule, n int) bool {
	if n < 1 {
		return false
	}
	now := l.now()

	l.mu.Lock()
	defer l.mu.Unlock()
	l.sweep(now)
	var counted []Rule
	for _, r := range rules {
		if !r.limited() || slices.ContainsFunc(counted, func(c Rule) bool { return c.Key == r.Key }) {
			continue
		}
		if !l.room(r, n, now) {
			return false
		}
		counted = append(counted, r)
	}
	for _, r := range counted {
		times := l.allowed[r.Key]
		i, _ := slices.BinarySearchFunc(times, now, func(a, b time.Time) int { return a.Compare(b) })
		l.allowed[r.Key] = slices.Insert(times, i, slices.Repeat([]time.Time{now}, n)...)
	}
	return true
}

// room reports whether rule r leaves room for n more requests at now, and drops the times it
// no longer needs.
func (l *RuleLimiter) room(r Rule, n int, now time.Time) bool {
	times := within(l.allowed[r.Key], now, r.retention())
	l.keep(r.Key, times)
	if r.PerHour > 0 && n > r.PerHour-len(within(slices.Clone(times), now, Window)) {
		return false
	}
	if r.PerDay > 0 && n > r.PerDay-len(within(slices.Clone(times), now, Day)) {
		return false
	}
	return r.MinInterval <= 0 || len(times) == 0 || now.Sub(times[len(times)-1]) >= r.MinInterval
}

// sweep drops the expired times of every key once a day has passed since the last sweep.
func (l *RuleLimiter) sweep(now time.Time) {
	if !l.lastSweep.IsZero() && now.Sub(l.lastSweep) < Day && !now.Before(l.lastSweep) {
		return
	}
	l.lastSweep = now
	for key, times := range l.allowed {
		l.keep(key, within(times, now, Day))
	}
}

func (l *RuleLimiter) keep(key string, times []time.Time) {
	if len(times) == 0 {
		delete(l.allowed, key)
		return
	}
	l.allowed[key] = times
}

// Keys returns the number of rules the limiter currently holds times for.
func (l *RuleLimiter) Keys() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.allowed)
}

// Restore counts requests that rule r let through earlier, for example before a restart, as
// SPEC-v0 section 11.2 requires. It is meant for a fresh RuleLimiter: the times are added to
// those the key already holds. A time after now counts as now, so that a wrong stored time
// cannot block the rule beyond its longest period, and it keeps no more times than the limits
// of r can use, the latest.
func (l *RuleLimiter) Restore(r Rule, earlier []time.Time) {
	now := l.now()

	l.mu.Lock()
	defer l.mu.Unlock()
	restored := slices.Clone(earlier)
	for i, t := range restored {
		if t.After(now) {
			restored[i] = now
		}
	}
	times := append(slices.Clone(l.allowed[r.Key]), restored...)
	slices.SortFunc(times, func(a, b time.Time) int { return a.Compare(b) })
	times = within(times, now, r.retention())
	l.keep(r.Key, times[max(len(times)-r.keep(), 0):])
}

// Forget drops the state of a rule, for example when its mandate is deleted.
func (l *RuleLimiter) Forget(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.allowed, key)
}

// within drops the times that lie period or more before now. It reuses the array of times.
func within(times []time.Time, now time.Time, period time.Duration) []time.Time {
	cutoff := now.Add(-period)
	return slices.DeleteFunc(times, func(t time.Time) bool { return !t.After(cutoff) })
}

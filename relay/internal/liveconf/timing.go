// SPDX-License-Identifier: Apache-2.0

package liveconf

import "time"

// Timing holds the time values of a run. Everything waits in real time; tests make the values
// small instead of replacing the clock.
type Timing struct {
	// Request is the total limit of one request, from connecting to the last byte.
	Request time.Duration
	// Slow is the limit of a request that waits for DNS: a gateway allows at least 150 seconds
	// for such a response (RELAY-v0 section 5.1).
	Slow time.Duration
	// Hook is the limit of one call of the DNS hook.
	Hook time.Duration
	// Visible is how long the tool waits for a record of the tester to show on the name
	// servers of the tester's zone; Poll is the pause between two questions.
	Visible, Poll time.Duration
	// Cleanup is the limit of the clean-up at the end, which runs after the run's own limit
	// and also after an abort.
	Cleanup time.Duration
	// RetryBudget is the sum of all Retry-After waits a run accepts (RELAY-v0 section 8.3).
	RetryBudget time.Duration
	// RetryUnit is the length of the second of a Retry-After value.
	RetryUnit time.Duration
	// Gap is the least time between two connections: at most ten connections a second.
	Gap time.Duration
	// Tunnel is how long the tool waits for the relay's answer to a frame or a stream-open.
	Tunnel time.Duration
	// Close is how long a relay may take to close a connection it has to close (RELAY-v0
	// sections 4.4 and 4.5).
	Close time.Duration
	// Slack is the margin after a token's validity, and how long the tool waits for something
	// that must not happen.
	Slack time.Duration
	// ControlWindow is the period in which at most MaxControlPerWindow control connections are
	// opened: the operator is spared (the limit of RELAY-v0 section 4.8 is 6 a minute).
	ControlWindow time.Duration
	// Deny is how long after unpairing the tool waits for the relay to close the connections of
	// the installation: the relay has 60 seconds (section 4.1).
	Deny time.Duration
	// Jitter is the most that a random wait adds to Gap, so that the pace and the order of
	// the requests do not give the test away (RELAY-v0 section 8.4).
	Jitter time.Duration
}

// MaxControlPerWindow is how many control connections a run opens in one ControlWindow.
const MaxControlPerWindow = 5

// DefaultTiming is what the command uses.
var DefaultTiming = Timing{
	Request:       30 * time.Second,
	Slow:          180 * time.Second,
	Hook:          60 * time.Second,
	Visible:       10 * time.Minute,
	Poll:          5 * time.Second,
	Cleanup:       5 * time.Minute,
	RetryBudget:   5 * time.Minute,
	RetryUnit:     time.Second,
	Gap:           100 * time.Millisecond,
	Jitter:        400 * time.Millisecond,
	Tunnel:        5 * time.Second,
	Close:         5 * time.Second,
	Slack:         time.Second,
	ControlWindow: time.Minute,
	Deny:          65 * time.Second,
}

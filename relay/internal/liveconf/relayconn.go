// SPDX-License-Identifier: Apache-2.0

package liveconf

import (
	"context"
	"crypto/tls"
	"errors"
	"math/rand/v2"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/home-mandate/spec/relay/internal/netguard"
	"github.com/home-mandate/spec/relay/internal/tunnelclient"
)

// pollInterval is how often the tool looks at connections it waits for.
const pollInterval = 10 * time.Millisecond

// tun reaches the relay: every connection goes through the address filter, a connection is
// paced like a request of the enrollment client, and the control connections of the run stay
// within MaxControlPerWindow in one ControlWindow (RELAY-v0 section 8.3).
type tun struct {
	d      *netguard.Dialer
	timing Timing
	host   string
	addr   string
	agent  string
	pins   []tunnelclient.Pin

	mu      sync.Mutex
	last    time.Time
	control []time.Time
}

// newTun returns the way to the relay of the metadata: relay.host and relay.port, and the first
// of relay_addresses on port 443 for agents.
func newTun(env Env, host string, port int, addresses []string, pins []tunnelclient.Pin) (*tun, error) {
	if host == "" || port <= 0 || len(addresses) == 0 {
		return nil, errors.New("the metadata names no relay")
	}
	return &tun{
		d: netguard.New(env.Net), timing: env.Timing, host: host, pins: pins,
		addr:  net.JoinHostPort(host, strconv.Itoa(port)),
		agent: net.JoinHostPort(addresses[0], "443"),
	}, nil
}

// pace waits until at least Gap has passed since the last connection, plus a random time up to Jitter.
func (t *tun) pace(ctx context.Context) error {
	t.mu.Lock()
	now := time.Now()
	start := now
	if next := t.last.Add(t.timing.Gap); next.After(start) {
		start = next
	}
	if t.timing.Jitter > 0 {
		start = start.Add(rand.N(t.timing.Jitter))
	}
	t.last = start
	t.mu.Unlock()
	return sleep(ctx, start.Sub(now))
}

// beforeControl waits until another control connection is within the limit of the run, and counts it.
func (t *tun) beforeControl(ctx context.Context) error {
	for {
		t.mu.Lock()
		now := time.Now()
		for len(t.control) > 0 && now.Sub(t.control[0]) >= t.timing.ControlWindow {
			t.control = t.control[1:]
		}
		if len(t.control) < MaxControlPerWindow {
			t.control = append(t.control, now)
			t.mu.Unlock()
			return nil
		}
		wait := t.control[0].Add(t.timing.ControlWindow).Sub(now)
		t.mu.Unlock()
		if err := sleep(ctx, wait); err != nil {
			return err
		}
	}
}

// params are the parameters of a gateway with the certificate, or without one if cert is nil.
func (t *tun) params(cert *tls.Certificate) tunnelclient.Params {
	return tunnelclient.Params{ServerName: t.host, Pins: t.pins, Cert: cert}
}

// dialControl opens the TLS connection of a control connection.
func (t *tun) dialControl(ctx context.Context, p tunnelclient.Params) (*tunnelclient.Control, error) {
	if err := t.pace(ctx); err != nil {
		return nil, err
	}
	return tunnelclient.OpenControl(ctx, t.d, t.addr, p)
}

// hello sends the hello of a control connection, after the limit of control connections.
func (t *tun) hello(ctx context.Context, c *tunnelclient.Control) error {
	if err := t.beforeControl(ctx); err != nil {
		return err
	}
	return c.Hello()
}

// dialData opens a data connection and sends first.
func (t *tun) dialData(ctx context.Context, cert *tls.Certificate, first []byte) (*tunnelclient.Conn, error) {
	if err := t.pace(ctx); err != nil {
		return nil, err
	}
	return tunnelclient.DialData(ctx, t.d, t.addr, t.params(cert), first)
}

// dialAgent connects as an agent and sends the parts.
func (t *tun) dialAgent(ctx context.Context, parts ...[]byte) (net.Conn, error) {
	if err := t.pace(ctx); err != nil {
		return nil, err
	}
	return tunnelclient.DialAgent(ctx, t.d, t.agent, parts...)
}

// netProblem turns an error of dialing into the error of a run: the relay cannot be reached, or
// the run ended. A failed handshake is the relay's answer and not an error of the network.
func netProblem(err error) error {
	if err == nil || errors.Is(err, tunnelclient.ErrHandshake) {
		return nil
	}
	return incompleteFor(err)
}

// routed is how an agent connection ended up.
type routed struct {
	open   tunnelclient.Open
	opened bool
	closed bool
	bytes  []byte
}

// opener gives the stream-open frames that came on a control connection.
type opener interface {
	TryOpen() (tunnelclient.Open, bool)
}

// await waits until the relay sends a stream-open for the agent connection, or closes the
// connection, or the time is over.
func await(ctx context.Context, ctl opener, agent net.Conn, wait time.Duration) routed {
	deadline := time.Now().Add(wait)
	var got []byte
	for {
		if open, ok := ctl.TryOpen(); ok {
			return routed{open: open, opened: true, bytes: got}
		}
		seen := tunnelclient.Observe(agent, pollInterval, 8-len(got))
		got = append(got, seen.Bytes...)
		if seen.Closed || len(got) == 8 || time.Now().After(deadline) || ctx.Err() != nil {
			// A stream-open can be on its way; look once more.
			open, ok := ctl.TryOpen()
			return routed{open: open, opened: ok, closed: seen.Closed, bytes: got}
		}
	}
}

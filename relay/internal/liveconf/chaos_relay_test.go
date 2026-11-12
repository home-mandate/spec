// SPDX-License-Identifier: Apache-2.0

package liveconf

import (
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/home-mandate/spec/relay/internal/refop"
)

// isRelayDial reports whether a connection goes to the relay: its host for tunnel connections, or
// one of its addresses on port 443 for agents.
func isRelayDial(hostport string) bool {
	host, port, err := net.SplitHostPort(hostport)
	return err == nil && (host == "tunnel."+refop.DefaultOperator || port == "443" && (host == "127.0.0.1" || host == "::1"))
}

// runWithBrokenDial runs the class relay against the reference; the k-th connection to the relay
// (counted from 1) goes to a port nobody listens on. It returns the result and the number of
// connections to the relay that were made.
func runWithBrokenDial(t *testing.T, k int32, own bool) (Result, int32) {
	t.Helper()
	r, env := serveRelay(t, refop.Config{}, 0)
	var dials atomic.Int32
	real := env.Net.Remap
	env.Net.Remap = func(hostport string) string {
		if isRelayDial(hostport) && dials.Add(1) == k {
			return closedPort(t)
		}
		return real(hostport)
	}
	set := enrollSettings(t, r, ClassRelay)
	if !own {
		set.OwnDomain, set.DNSHook = "", ""
	}
	return RunWith(ctx(t), set, env), dials.Load()
}

// TestAnyConnectionToTheRelayMayBreak: wherever a connection to the relay fails, the run is
// incomplete, not failed, and every installation is unpaired. Every third connection of a run is
// broken in turn (about a hundred are made), so each kind of step meets a failure.
func TestAnyConnectionToTheRelayMayBreak(t *testing.T) {
	for k := int32(1); k <= 91; k += 3 {
		t.Run(strconv.Itoa(int(k)), func(t *testing.T) {
			t.Parallel()
			res, dials := runWithBrokenDial(t, k, false)
			if dials < k {
				t.Fatalf("only %d connections to the relay, the %dth was not made", dials, k)
			}
			if res.Exit != ExitIncomplete || len(res.Report.Failures) != 0 {
				t.Errorf("exit %d, failures %+v", res.Exit, res.Report.Failures)
			}
			if res.Report.Installations.Created != res.Report.Installations.Unpaired {
				t.Errorf("installations %+v", res.Report.Installations)
			}
		})
	}
}

// TestAnyLateConnectionToTheRelayMayBreak: the connections the own-domain name and the
// unpairing bring about, which come after the first hundred, break too.
func TestAnyLateConnectionToTheRelayMayBreak(t *testing.T) {
	_, total := runWithBrokenDial(t, 0, true)
	for k := total - 4; k <= total; k++ {
		t.Run(strconv.Itoa(int(k)), func(t *testing.T) {
			t.Parallel()
			res, dials := runWithBrokenDial(t, k, true)
			if dials < k {
				t.Fatalf("only %d connections to the relay, the %dth was not made", dials, k)
			}
			if res.Exit != ExitIncomplete || len(res.Report.Failures) != 0 || res.Report.Installations.Created != res.Report.Installations.Unpaired {
				t.Errorf("exit %d, failures %+v, installations %+v", res.Exit, res.Report.Failures, res.Report.Installations)
			}
		})
	}
}

// TestTheRunMayEndAtAnyTime: wherever the limit of the run falls, the run is incomplete, not
// failed, and every installation is unpaired.
func TestTheRunMayEndAtAnyTime(t *testing.T) {
	for i := range 12 {
		limit := 1300*time.Millisecond + time.Duration(i)*220*time.Millisecond
		t.Run(limit.String(), func(t *testing.T) {
			t.Parallel()
			r, env := serveRelay(t, refop.Config{}, 0)
			set := enrollSettings(t, r, ClassRelay)
			set.OwnDomain, set.DNSHook, set.Timeout = "", "", limit
			res := RunWith(ctx(t), set, env)
			if res.Exit != ExitIncomplete || len(res.Report.Failures) != 0 || res.Report.Installations.Created != res.Report.Installations.Unpaired {
				t.Errorf("exit %d, failures %+v, installations %+v", res.Exit, res.Report.Failures, res.Report.Installations)
			}
		})
	}
}

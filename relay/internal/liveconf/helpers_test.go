// SPDX-License-Identifier: Apache-2.0

package liveconf

import (
	"context"
	"crypto/x509"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/home-mandate/spec/relay/internal/netguard"
	"github.com/home-mandate/spec/relay/internal/refop"
)

// testTiming is DefaultTiming made small; everything still waits in real time.
func testTiming() Timing {
	return Timing{
		Request: 5 * time.Second, Slow: 10 * time.Second, Hook: 5 * time.Second, Visible: 2 * time.Second, Poll: 20 * time.Millisecond, Cleanup: 5 * time.Second, RetryBudget: 300 * time.Millisecond,
		RetryUnit: 10 * time.Millisecond, Gap: time.Millisecond, Jitter: 2 * time.Millisecond,
		Tunnel: 3 * time.Second, Close: 2 * time.Second, Slack: 150 * time.Millisecond, ControlWindow: 120 * time.Millisecond, Deny: 600 * time.Millisecond,
	}
}

// loopbackPolicy allows what the production policy allows and loopback, where the reference
// operator listens.
func loopbackPolicy(a netip.Addr) bool { return netguard.Allowed(a) || a.IsLoopback() }

// envFor is the environment for a reference operator.
func envFor(r *refop.Running) Env {
	return Env{
		Net:    netguard.Options{Policy: loopbackPolicy, Remap: r.Remap, Lookup: r.Lookup},
		NS:     r.NS,
		Roots:  r.Roots,
		Timing: testTiming(),
		Unpair: func(context.Context, *Web, string, StateInstallation, []StateKey) error { return nil },
	}
}

func serve(t *testing.T, cfg refop.Config) (*refop.Running, Env) {
	t.Helper()
	r := refop.Serve(cfg)
	t.Cleanup(func() { _ = r.Close() })
	return r, envFor(r)
}

// webFor returns a Web that reaches an HTTPS test server under the host example.com, and the
// URL to fetch.
func webFor(t *testing.T, h http.Handler, timing Timing) (*Web, string) {
	t.Helper()
	srv := httptest.NewUnstartedServer(h)
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	env := Env{
		Net:   netguard.Options{Policy: loopbackPolicy, Remap: func(string) string { return srv.Listener.Addr().String() }},
		Roots: roots, Timing: timing,
	}
	return newWeb(env), "https://example.com/x"
}

// closedPort returns a loopback port nothing listens on.
func closedPort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

// ctx returns a context that ends with the test.
func ctx(t *testing.T) context.Context {
	t.Helper()
	c, cancel := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)
	return c
}

// failureIDs returns the IDs of the failures of a result.
func failureIDs(res Result) []string {
	ids := []string{}
	for _, f := range res.Report.Failures {
		ids = append(ids, f.ID)
	}
	return ids
}

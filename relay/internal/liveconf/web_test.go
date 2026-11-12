// SPDX-License-Identifier: Apache-2.0

package liveconf

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/home-mandate/spec/relay/internal/netguard"
	"github.com/home-mandate/spec/relay/internal/refop"
)

func okHandler(body string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(body)) })
}

func kindOf(t *testing.T, err error) string {
	t.Helper()
	var nf *netFailure
	if !errors.As(err, &nf) {
		t.Fatalf("not a network failure: %v", err)
	}
	return nf.kind
}

func TestGetReturnsStatusAndBody(t *testing.T) {
	w, url := webFor(t, okHandler("hello"), testTiming())
	res, err := w.get(ctx(t), url, 100)
	if err != nil || res.Status != 200 || string(res.Body) != "hello" || res.Over {
		t.Fatalf("%+v, %v", res, err)
	}
}

func TestGetCutsTheBodyAtTheLimit(t *testing.T) {
	w, url := webFor(t, okHandler(strings.Repeat("x", 50)), testTiming())
	res, err := w.get(ctx(t), url, 10)
	if err != nil || !res.Over || len(res.Body) != 10 {
		t.Fatalf("%+v, %v", res, err)
	}
	res, err = w.get(ctx(t), url, 50)
	if err != nil || res.Over || len(res.Body) != 50 {
		t.Fatalf("at the limit: %+v, %v", res, err)
	}
}

func TestGetDoesNotFollowRedirectsOrOfferCompression(t *testing.T) {
	var accept atomic.Value
	h := http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		accept.Store(r.Header.Get("Accept-Encoding"))
		if r.URL.Path == "/x" {
			http.Redirect(rw, r, "/elsewhere", http.StatusFound)
			return
		}
		t.Error("the redirect was followed")
	})
	w, url := webFor(t, h, testTiming())
	res, err := w.get(ctx(t), url, 100)
	if err != nil || res.Status != http.StatusFound {
		t.Fatalf("%+v, %v", res, err)
	}
	if got := accept.Load(); got != "" {
		t.Errorf("Accept-Encoding %q sent", got)
	}
}

func TestGetRefusesNonHTTPSAndBadURLs(t *testing.T) {
	w, _ := webFor(t, okHandler(""), testTiming())
	for _, u := range []string{"http://example.com/x", "ftp://example.com", "%", "example.com/x", ""} {
		if _, err := w.get(ctx(t), u, 10); !errors.Is(err, errNotHTTPS) {
			t.Errorf("get(%q) = %v", u, err)
		}
	}
}

func TestGetHonoursRetryAfterWithinTheBudget(t *testing.T) {
	var calls atomic.Int32
	h := http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) < 3 {
			rw.Header().Set("Retry-After", "2") // 2 units of 10 ms
			rw.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = rw.Write([]byte("done"))
	})
	w, url := webFor(t, h, testTiming())
	start := time.Now()
	res, err := w.get(ctx(t), url, 10)
	if err != nil || string(res.Body) != "done" || calls.Load() != 3 {
		t.Fatalf("%+v, %v, %d calls", res, err, calls.Load())
	}
	if time.Since(start) < 40*time.Millisecond {
		t.Errorf("did not wait for the two Retry-After values: %v", time.Since(start))
	}
}

func TestGetRateLimited(t *testing.T) {
	for name, tt := range map[string]struct {
		status int
		header string
	}{
		"429 without Retry-After": {http.StatusTooManyRequests, ""},
		"429 over the budget":     {http.StatusTooManyRequests, "1000"},
		"503 over the budget":     {http.StatusServiceUnavailable, "3600"},
		"429 forever":             {http.StatusTooManyRequests, "0"},
	} {
		h := http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
			if tt.header != "" {
				rw.Header().Set("Retry-After", tt.header)
			}
			rw.WriteHeader(tt.status)
		})
		w, url := webFor(t, h, testTiming())
		if _, err := w.get(ctx(t), url, 10); !errors.Is(err, errRateLimited) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestA503WithoutRetryAfterIsJustAStatus(t *testing.T) {
	w, url := webFor(t, http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusServiceUnavailable)
	}), testTiming())
	if res, err := w.get(ctx(t), url, 10); err != nil || res.Status != 503 {
		t.Errorf("%+v, %v", res, err)
	}
}

func TestRetryWait(t *testing.T) {
	w := &Web{timing: Timing{RetryUnit: time.Second}}
	date := time.Now().Add(30 * time.Second).UTC().Format(http.TimeFormat)
	past := time.Now().Add(-time.Hour).UTC().Format(http.TimeFormat)
	for _, tt := range []struct {
		value    string
		min, max time.Duration
	}{
		{"5", 5 * time.Second, 5 * time.Second},
		{"0", 0, 0},
		{"-3", time.Second, time.Second},
		{"soon", time.Second, time.Second},
		{"", time.Second, time.Second},
		{date, 28 * time.Second, 31 * time.Second},
		{past, 0, 0},
		{"99999999999999", maxRetryAfter * time.Second, maxRetryAfter * time.Second},
	} {
		if got := w.retryWait(tt.value); got < tt.min || got > tt.max {
			t.Errorf("retryWait(%q) = %v, want %v..%v", tt.value, got, tt.min, tt.max)
		}
	}
}

func TestSpendStopsAtTheBudget(t *testing.T) {
	w := &Web{timing: Timing{RetryBudget: 10 * time.Millisecond}}
	if !w.spend(6*time.Millisecond) || w.spend(6*time.Millisecond) || !w.spend(4*time.Millisecond) {
		t.Error("the budget is not kept")
	}
}

func TestGetFailureKinds(t *testing.T) {
	srv := httptest.NewUnstartedServer(okHandler("x"))
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	defer srv.Close()
	to := func(addr string) func(string) string { return func(string) string { return addr } }
	const url = "https://example.com/x"
	// Certificate not trusted: no roots given.
	untrusted := newWeb(Env{Net: netguard.Options{Policy: loopbackPolicy, Remap: to(srv.Listener.Addr().String())}, Timing: testTiming()})
	if _, err := untrusted.get(ctx(t), url, 10); kindOf(t, err) != kindCertificate {
		t.Errorf("untrusted certificate: %v", err)
	}
	// Address not allowed: the production policy refuses loopback.
	strict := newWeb(Env{Net: netguard.Options{Remap: to(srv.Listener.Addr().String())}, Timing: testTiming()})
	if _, err := strict.get(ctx(t), url, 10); kindOf(t, err) != kindBlocked {
		t.Errorf("blocked: %v", err)
	}
	// Nothing listens.
	gone := newWeb(Env{Net: netguard.Options{Policy: loopbackPolicy, Remap: to(closedPort(t))}, Timing: testTiming()})
	if _, err := gone.get(ctx(t), url, 10); kindOf(t, err) != kindOther {
		t.Errorf("refused: %v", err)
	}
}

func TestGetTimesOut(t *testing.T) {
	slow := http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(2 * time.Second):
		case <-r.Context().Done():
		}
	})
	timing := testTiming()
	timing.Request = 100 * time.Millisecond
	w, url := webFor(t, slow, timing)
	if _, err := w.get(ctx(t), url, 10); kindOf(t, err) != kindTimeout {
		t.Errorf("timeout: %v", err)
	}
}

func TestGetStopsWhenTheRunIsCancelled(t *testing.T) {
	w, url := webFor(t, okHandler("x"), testTiming())
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := w.get(cancelled, url, 10); err == nil {
		t.Error("get on a cancelled context succeeded")
	}
	// A cancel while waiting for Retry-After.
	h := http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.Header().Set("Retry-After", "20") // 200 ms
		rw.WriteHeader(http.StatusTooManyRequests)
	})
	w, url = webFor(t, h, testTiming())
	waiting, stop := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer stop()
	if _, err := w.get(waiting, url, 10); kindOf(t, err) != kindTimeout {
		t.Errorf("cancel during the wait: %v", err)
	}
}

func TestPaceSpacesConnections(t *testing.T) {
	timing := testTiming()
	timing.Gap, timing.Jitter = 40*time.Millisecond, 0
	w, url := webFor(t, okHandler("x"), timing)
	start := time.Now()
	for range 3 {
		if _, err := w.get(ctx(t), url, 10); err != nil {
			t.Fatal(err)
		}
	}
	if got := time.Since(start); got < 80*time.Millisecond {
		t.Errorf("three requests in %v with a gap of 40 ms", got)
	}
}

func TestWebUsesNoProxyAndNoHTTP2(t *testing.T) {
	var hit atomic.Bool
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		if c, err := l.Accept(); err == nil {
			hit.Store(true)
			_ = c.Close()
		}
	}()
	t.Setenv("HTTPS_PROXY", "http://"+l.Addr().String())
	t.Setenv("https_proxy", "http://"+l.Addr().String())
	r, env := serve(t, refop.Config{})
	w := newWeb(env)
	res, err := w.get(ctx(t), "https://"+refop.DefaultOperator+refop.MetadataPath, 1<<16)
	if err != nil || res.Status != 200 {
		t.Fatalf("%+v, %v", res, err)
	}
	_ = r
	if hit.Load() {
		t.Error("the proxy of the environment was used")
	}
}

func TestProductionEnvBuildsTheFilteringDialer(t *testing.T) {
	env := productionEnv()
	if env.Net.Policy != nil || env.Net.Lookup != nil || env.Net.Remap != nil || env.Roots != nil || env.Timing != DefaultTiming {
		t.Fatalf("productionEnv changes the defaults: %+v", env)
	}
	// A real listener on loopback, reached with the production environment through the way
	// every run builds its client: no connection may arrive.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	var accepted atomic.Int32
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			_ = c.Close()
		}
	}()
	w := newWeb(env)
	for _, target := range []string{"https://" + l.Addr().String() + "/x", "https://[::1]:1/x", "https://10.0.0.1/x", "https://169.254.169.254/x"} {
		_, err := w.get(ctx(t), target, 10)
		if kindOf(t, err) != kindBlocked {
			t.Errorf("get(%s) = %v", target, err)
		}
	}
	if n := accepted.Load(); n != 0 {
		t.Errorf("the production client made %d connections to loopback", n)
	}
	if w.policy(netip.MustParseAddr("127.0.0.1")) || !w.policy(netip.MustParseAddr("8.8.8.8")) {
		t.Error("the policy of the production client is not netguard.Allowed")
	}
}

func TestClassifyAndErrors(t *testing.T) {
	if (&netFailure{kindTimeout}).Error() != "network failure: timeout" {
		t.Error("netFailure text")
	}
	if got := classify(context.DeadlineExceeded).kind; got != kindTimeout {
		t.Errorf("deadline: %s", got)
	}
	if got := classify(errors.New("x")).kind; got != kindOther {
		t.Errorf("other: %s", got)
	}
	if got := scrub(errors.New("plain")); got.Error() != "plain" {
		t.Errorf("scrub: %v", got)
	}
}

func TestGetFailsOnATruncatedBody(t *testing.T) {
	h := http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.Header().Set("Content-Length", "100")
		_, _ = rw.Write([]byte("short"))
		panic(http.ErrAbortHandler)
	})
	w, url := webFor(t, h, testTiming())
	if _, err := w.get(ctx(t), url, 1000); kindOf(t, err) != kindOther {
		t.Errorf("truncated body: %v", err)
	}
}

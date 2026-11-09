// SPDX-License-Identifier: Apache-2.0

package liveconf

import (
	"fmt"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/home-mandate/spec/relay/internal/refop"
)

// breaker wraps the handler of the reference operator and breaks the request with number n
// (counting from 1, over all requests of the operator): it drops the connection, answers with
// an error of the operator, or with a rate limit that never ends.
type breaker struct {
	n, seen atomic.Int64
	mode    string
}

func (b *breaker) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if b.seen.Add(1) != b.n.Load() {
			next.ServeHTTP(w, r)
			return
		}
		switch b.mode {
		case "drop":
			conn, _, _ := w.(http.Hijacker).Hijack()
			_ = conn.Close()
		case "500":
			w.Header().Set("Content-Type", "application/problem+json")
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"type":"https://home-mandate.org/relay/errors/server-internal"}`))
		case "garbage":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{`))
		}
	})
}

func chaosRun(t *testing.T, n int64, mode string) Result {
	b := &breaker{mode: mode}
	b.n.Store(n)
	r, env := serve(t, refop.Config{Wrap: b.wrap})
	env.Timing.Gap, env.Timing.Jitter = 0, 0
	s := enrollSettings(t, r, ClassEnrollment, ClassDNS)
	s.OwnDomain, s.DNSHook = "", ""
	return RunWith(ctx(t), s, env)
}

func countRequests(t *testing.T) int64 {
	b := &breaker{mode: "none"}
	r, env := serve(t, refop.Config{Wrap: b.wrap})
	s := enrollSettings(t, r, ClassEnrollment, ClassDNS)
	s.OwnDomain, s.DNSHook = "", ""
	if res := RunWith(ctx(t), s, env); res.Exit == ExitCleanup {
		t.Fatal("clean run failed")
	}
	return b.seen.Load()
}

// TestAnyRequestMayBreak: whatever request breaks, the run ends without a panic, is never
// conformant, and unpairs what it paired (or says how to clean up).
func TestAnyRequestMayBreak(t *testing.T) {
	total := countRequests(t)
	for _, mode := range []string{"drop", "500"} {
		for n := int64(2); n <= total; n++ {
			t.Run(fmt.Sprintf("%s-%d", mode, n), func(t *testing.T) {
				t.Parallel()
				res := chaosRun(t, n, mode)
				if res.Report.Conforms || (res.Exit != ExitIncomplete && res.Exit != ExitFails && res.Exit != ExitCleanup) {
					t.Fatalf("exit %d, conforms %v", res.Exit, res.Report.Conforms)
				}
				if res.Exit != ExitCleanup && res.Report.Installations.Created != res.Report.Installations.Unpaired {
					t.Fatalf("installations %+v", res.Report.Installations)
				}
			})
		}
	}
}

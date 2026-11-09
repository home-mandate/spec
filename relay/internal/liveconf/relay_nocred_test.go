// SPDX-License-Identifier: Apache-2.0

package liveconf

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/home-mandate/spec/relay/internal/refop"
	"github.com/home-mandate/spec/relay/internal/refrelay"
)

// chainReplaced wraps the operator so that the chain of every pairing response is the given one.
func chainReplaced(chain []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !strings.HasSuffix(r.URL.Path, "/enroll/pair") {
				next.ServeHTTP(w, r)
				return
			}
			rec := httptest.NewRecorder()
			next.ServeHTTP(rec, r)
			out := rec.Body.Bytes()
			var body map[string]any
			if rec.Code == http.StatusCreated && json.Unmarshal(out, &body) == nil {
				cert, _ := body["tunnel_certificate"].(map[string]any)
				cert["chain"] = chain
				out, _ = json.Marshal(body)
			}
			for k, v := range rec.Header() {
				w.Header()[k] = v
			}
			w.Header().Del("Content-Length")
			w.WriteHeader(rec.Code)
			_, _ = w.Write(out)
		})
	}
}

// TestAPairingWithoutAUsableCertificateEndsTheRelayClassIncomplete: no credential for the relay
// is no panic; the failure shows in the certificate rules and the relay class is incomplete.
func TestAPairingWithoutAUsableCertificateEndsTheRelayClassIncomplete(t *testing.T) {
	for name, chain := range map[string][]string{"empty chain": {}, "unparseable leaf": {"AAAA"}} {
		t.Run(name, func(t *testing.T) {
			res := runAll(t, refop.Config{Wrap: chainReplaced(chain)}, refrelay.Fault(0), ClassEnrollment, ClassRelay)
			if got := failures(res); !slices.Contains(got, "live:"+CheckEnrollCertRules) {
				t.Errorf("failures %v %+v incomplete %v", got, res.Report.Failures, res.Report.Incomplete)
			}
			if c := res.Report.Classes[ClassRelay]; !c.NotRun || !strings.Contains(c.Reason, "tunnel certificate") {
				t.Errorf("relay class %+v", c)
			}
			if res.Exit != ExitFails {
				t.Errorf("exit %d", res.Exit)
			}
		})
	}
}

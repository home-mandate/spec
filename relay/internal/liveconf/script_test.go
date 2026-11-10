// SPDX-License-Identifier: Apache-2.0

package liveconf

import (
	"context"
	"encoding/json"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/home-mandate/spec/relay/internal/netguard"
	"github.com/home-mandate/spec/relay/internal/refdns"
	"github.com/home-mandate/spec/relay/internal/refop"
)

func runEnroll(t *testing.T, cfg refop.Config, edit func(*Settings, *Env)) Result {
	t.Helper()
	r, env := serve(t, cfg)
	env.Timing.Gap, env.Timing.Jitter = 0, 0
	s := enrollSettings(t, r, ClassEnrollment, ClassDNS)
	if edit != nil {
		edit(&s, &env)
	}
	return RunWith(ctx(t), s, env)
}

func notRunReason(res Result, class string) string {
	if c := res.Report.Classes[class]; c.NotRun {
		return c.Reason
	}
	return ""
}

func TestARefusedPairingCodeMakesTheRunIncomplete(t *testing.T) {
	res := runEnroll(t, refop.Config{Codes: []string{"AAAAAAAAAAAAAAAA"}}, nil)
	if res.Exit != ExitIncomplete || !strings.Contains(notRunReason(res, ClassEnrollment), "refused a pairing code") {
		t.Errorf("exit %d, reason %q", res.Exit, notRunReason(res, ClassEnrollment))
	}
	if res.Report.Installations.Created != 0 {
		t.Errorf("installations %+v", res.Report.Installations)
	}
}

func TestMetadataThatIsNotUsableMakesTheClassesIncomplete(t *testing.T) {
	for name, doc := range map[string]string{"empty": `{}`, "not JSON": `x`, "foreign operator": `{"operator_domain":"other.example"}`} {
		res := runEnroll(t, refop.Config{Document: []byte(doc)}, nil)
		if !strings.Contains(notRunReason(res, ClassEnrollment), "metadata") || !strings.Contains(notRunReason(res, ClassDNS), "metadata") {
			t.Errorf("%s: %q", name, notRunReason(res, ClassEnrollment))
		}
	}
	// An operator that cannot be reached.
	res := runEnroll(t, refop.Config{}, func(_ *Settings, env *Env) {
		env.Net.Remap = func(string) string { return closedPort(t) }
	})
	if !strings.Contains(notRunReason(res, ClassEnrollment), "cannot be reached") || res.Exit != ExitIncomplete {
		t.Errorf("unreachable: %q", notRunReason(res, ClassEnrollment))
	}
}

func TestACMEChecksAreSkippedWithoutAKnownCA(t *testing.T) {
	base := refop.New(refop.Config{})
	var doc map[string]any
	_ = json.Unmarshal(base.Metadata(), &doc)
	base.Close()
	doc["acme_cas"] = []string{"unknown-ca.example"}
	data, _ := json.Marshal(doc)
	res := runEnroll(t, refop.Config{Document: data}, nil)
	c := res.Report.Classes[ClassEnrollment]
	if !slices.Contains(res.Report.Incomplete, "acme_cas lists no CA of relay/cas.md, so the ACME checks were not made") ||
		c.Conforms || c.Failed != 0 || c.Skipped == 0 || res.Exit != ExitIncomplete || res.Report.Conforms {
		t.Errorf("incomplete %v, class %+v, exit %d", res.Report.Incomplete, c, res.Exit)
	}
}

func TestADNSHookThatFailsMakesTheRunIncomplete(t *testing.T) {
	for name, tt := range map[string]struct {
		hook string
		want string
	}{
		"exit status": {"/bin/false", "DNS hook failed"},
		"not visible": {"/bin/true", "does not show"},
	} {
		res := runEnroll(t, refop.Config{}, func(s *Settings, env *Env) {
			s.DNSHook = tt.hook
			env.Timing.Visible = 150 * time.Millisecond
		})
		if !strings.Contains(notRunReason(res, ClassEnrollment), tt.want) || res.Report.Installations.Created != res.Report.Installations.Unpaired {
			t.Errorf("%s: %q %+v", name, notRunReason(res, ClassEnrollment), res.Report.Installations)
		}
	}
}

func TestATokenTheHookCannotTakeMakesTheRunIncomplete(t *testing.T) {
	res := runEnroll(t, refop.Config{Faults: refop.DashToken}, nil)
	if !strings.Contains(notRunReason(res, ClassEnrollment), "cannot be given to a DNS hook") {
		t.Errorf("reason %q", notRunReason(res, ClassEnrollment))
	}
}

// syncBuffer is a writer that a test reads while the tool writes.
type syncBuffer struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) lines() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	// Only complete lines: the last element is what follows the final line break.
	all := strings.Split(b.buf.String(), "\n")
	return all[:len(all)-1]
}

// TestManualDNSPromptsAndWaitsForTheRecord: the tester reads what the tool asks for and sets and
// removes the record by hand (here: in the reference DNS), and the run waits for it.
func TestManualDNSPromptsAndWaitsForTheRecord(t *testing.T) {
	r, env := serve(t, refop.Config{})
	env.Timing.Gap, env.Timing.Jitter = 0, 0
	prompt := &syncBuffer{}
	env.Prompt = prompt
	s := enrollSettings(t, r, ClassEnrollment)
	s.DNSHook, s.DNSManual = "", true
	done := make(chan struct{})
	defer close(done)
	go func() {
		handled := 0
		for {
			select {
			case <-done:
				return
			case <-time.After(5 * time.Millisecond):
			}
			lines := prompt.lines()
			for ; handled < len(lines); handled++ {
				if name, value, ok := parseSet(lines[handled]); ok {
					r.Operator.DNS().Replace(name, refdns.TypeTXT, refdns.TXT(name, 60, value))
				} else if name, ok := strings.CutPrefix(lines[handled], "relay-conformance: remove the TXT record "); ok {
					r.Operator.DNS().Replace(name, refdns.TypeTXT)
				}
			}
		}
	}()
	res := RunWith(ctx(t), s, env)
	if c := res.Report.Classes[ClassEnrollment]; !c.Conforms || len(res.Report.Failures) > 0 {
		t.Errorf("class %+v, failures %+v, reason %q", c, res.Report.Failures, c.Reason)
	}
}

// parseSet reads the line of a "set" prompt: name and value.
func parseSet(line string) (name, value string, ok bool) {
	rest, ok := strings.CutPrefix(line, "relay-conformance: set the TXT record ")
	if !ok {
		return "", "", false
	}
	name, rest, _ = strings.Cut(rest, " to ")
	value, _, _ = strings.Cut(strings.TrimPrefix(rest, `"`), `"`)
	return name, value, true
}

func TestARateLimitThatNeverEndsMakesTheRunIncomplete(t *testing.T) {
	limit := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				next.ServeHTTP(w, r)
				return
			}
			w.Header().Set("Retry-After", "1")
			w.Header().Set("Content-Type", "application/problem+json")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"type":"https://home-mandate.org/relay/errors/rate-limited"}`))
		})
	}
	res := runEnroll(t, refop.Config{Wrap: limit}, nil)
	if res.Exit != ExitIncomplete || !strings.Contains(notRunReason(res, ClassEnrollment), "limits the rate") {
		t.Errorf("exit %d, reason %q", res.Exit, notRunReason(res, ClassEnrollment))
	}
}

func TestNameServersThatCannotBeFoundFailOneCheckAndSkipTheRest(t *testing.T) {
	res := runEnroll(t, refop.Config{}, func(s *Settings, env *Env) {
		s.Classes = []string{ClassDNS}
		env.NS = func(context.Context, string) ([]string, error) { return nil, os.ErrNotExist }
	})
	c := res.Report.Classes[ClassDNS]
	if len(res.Report.Failures) != 1 || res.Report.Failures[0].ID != CheckDNSServers || c.Skipped != 8 {
		t.Errorf("failures %+v, class %+v", res.Report.Failures, c)
	}
}

func TestNameServersThatDoNotAnswerFailTheirChecks(t *testing.T) {
	res := runEnroll(t, refop.Config{}, func(s *Settings, env *Env) {
		s.Classes = []string{ClassDNS}
		env.Net.Policy = func(a netip.Addr) bool { return netguard.Allowed(a) || a.IsLoopback() }
		real := env.Net.Remap
		env.Net.Remap = func(hp string) string {
			out := real(hp)
			if strings.HasSuffix(hp, ":53") {
				return closedPort(t)
			}
			return out
		}
	})
	ids := failureIDs(res)
	if len(ids) == 0 || ids[0] != CheckDNSServers {
		t.Errorf("failures %v", ids)
	}
}

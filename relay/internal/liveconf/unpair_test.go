// SPDX-License-Identifier: Apache-2.0

package liveconf

import (
	"bytes"
	"context"
	"encoding/base64"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/home-mandate/spec/relay/internal/enroll"
	"github.com/home-mandate/spec/relay/internal/refdns"
	"github.com/home-mandate/spec/relay/internal/refop"
)

const enrollURL = "https://" + refop.DefaultOperator + "/enroll/directory"

func stateKey(t *testing.T, id, alg string) (StateKey, *enroll.Signer) {
	t.Helper()
	s, err := enroll.Generate(alg)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := s.PKCS8()
	return StateKey{ID: id, Alg: alg, Private: base64.RawURLEncoding.EncodeToString(der)}, s
}

// pairedInstallation pairs one installation with a key and returns it as the state file holds it.
func pairedInstallation(t *testing.T, w *Web, code string, signer *enroll.Signer, keyID string) StateInstallation {
	t.Helper()
	c := &enroll.Client{T: w, Host: refop.DefaultOperator}
	if _, err := c.Load(ctx(t), enrollURL); err != nil {
		t.Fatal(err)
	}
	tunnel, csr := newTunnel(enroll.AlgEdDSA)
	_ = tunnel
	p, _, err := c.Pair(ctx(t), signer, code, csr)
	if err != nil {
		t.Fatal(err)
	}
	return StateInstallation{URL: p.Location, Key: keyID}
}

func TestUnpairInstallationWithTheRightKeyAndWithAFallback(t *testing.T) {
	_, env := serve(t, refop.Config{})
	w := newWeb(env)
	k1, s1 := stateKey(t, "k1", enroll.AlgEdDSA)
	k3, _ := stateKey(t, "k3", enroll.AlgEdDSA)
	keys := []StateKey{k3, k1}
	inst := pairedInstallation(t, w, refop.DefaultCodes[0], s1, "k1")
	if err := unpairInstallation(ctx(t), w, enrollURL, inst, keys); err != nil {
		t.Fatal(err)
	}
	// An installation that is unpaired already counts as done.
	if err := unpairInstallation(ctx(t), w, enrollURL, inst, keys); err != nil {
		t.Errorf("second unpair: %v", err)
	}
}

func TestUnpairInstallationFallsBackToAnotherKey(t *testing.T) {
	_, env := serve(t, refop.Config{})
	w := newWeb(env)
	k1, s1 := stateKey(t, "k1", enroll.AlgEdDSA)
	k3, _ := stateKey(t, "k3", enroll.AlgEdDSA)
	inst := pairedInstallation(t, w, refop.DefaultCodes[0], s1, "k1")
	inst.Key = "k3" // the state file names the wrong key first
	if err := unpairInstallation(ctx(t), w, enrollURL, inst, []StateKey{k3, k1}); err != nil {
		t.Errorf("fallback: %v", err)
	}
}

func TestUnpairInstallationFailures(t *testing.T) {
	r, env := serve(t, refop.Config{})
	w := newWeb(env)
	k1, s1 := stateKey(t, "k1", enroll.AlgEdDSA)
	k3, _ := stateKey(t, "k3", enroll.AlgEdDSA)
	inst := pairedInstallation(t, w, refop.DefaultCodes[0], s1, "k1")
	if err := unpairInstallation(ctx(t), w, enrollURL, inst, []StateKey{k3}); err != errNoKey {
		t.Errorf("no key fits: %v", err)
	}
	if err := unpairInstallation(ctx(t), w, enrollURL, inst, []StateKey{{ID: "k1", Private: "***"}}); err == nil {
		t.Error("unreadable key")
	}
	if err := unpairInstallation(ctx(t), w, enrollURL, inst, []StateKey{{ID: "k1", Private: "AAAA"}}); err == nil {
		t.Error("key that is no key")
	}
	if err := unpairInstallation(ctx(t), w, "%", inst, []StateKey{k1}); err == nil {
		t.Error("unusable enrollment URL")
	}
	if err := unpairInstallation(ctx(t), w, "https://"+refop.DefaultOperator+"/nowhere", inst, []StateKey{k1}); err == nil {
		t.Error("no directory")
	}
	r.Operator.SetOffline(inst.URL, true)
	err := unpairInstallation(ctx(t), w, enrollURL, inst, []StateKey{k1})
	if err == nil || strings.Contains(err.Error(), "installation/") {
		t.Errorf("offline-too-long: %v", err)
	}
	// An unknown key ID in the order is skipped.
	inst.Key = "nope"
	r.Operator.SetOffline(inst.URL, false)
	if err := unpairInstallation(ctx(t), w, enrollURL, inst, []StateKey{k1}); err != nil {
		t.Errorf("unknown key ID first: %v", err)
	}
}

func TestCleanupRemovesTheTXTRecordWithTheHookGivenAgain(t *testing.T) {
	r, env := serve(t, refop.Config{})
	record := proofLabel + testOwnDomain
	for name, tt := range map[string]struct {
		settings func(Settings) Settings
		exit     int
		wantGone bool
		message  string
	}{
		"hook":     {func(s Settings) Settings { s.DNSHook = hookFor(t, r); return s }, ExitConforms, true, "done"},
		"manual":   {func(s Settings) Settings { s.DNSManual = true; return s }, ExitConforms, false, "done"},
		"no hook":  {func(s Settings) Settings { return s }, ExitCleanup, false, "-dns-hook"},
		"bad hook": {func(s Settings) Settings { s.DNSHook = "/nonexistent/hook"; return s }, ExitCleanup, false, "-cleanup"},
	} {
		r.Operator.DNS().Replace(record, refdns.TypeTXT, refdns.TXT(record, 60, "leftover"))
		path := newStatePath(t)
		st := newState(refop.DefaultOperator, nil).WithOwnName(testOwnDomain)
		f, err := CreateState(path, st)
		if err != nil {
			t.Fatal(err)
		}
		_ = f.Close()
		var prompt bytes.Buffer
		env.Prompt = &prompt
		if name == "manual" {
			// The tester removes the record by hand while the tool waits.
			time.AfterFunc(100*time.Millisecond, func() { r.Operator.DNS().Replace(record, refdns.TypeTXT) })
		}
		res := CleanupWith(ctx(t), tt.settings(Settings{CleanupPath: path}), env)
		if res.Exit != tt.exit || !strings.Contains(res.Message, tt.message) {
			t.Errorf("%s: exit %d, message %q", name, res.Exit, res.Message)
		}
		left := len(r.Operator.DNS().Lookup(0, record, refdns.TypeTXT)) > 0
		if tt.wantGone && left {
			t.Errorf("%s: the TXT record is still there", name)
		}
		if name == "manual" {
			// The tester removes the record by hand; the tool waited for that only if it was gone.
			if !strings.Contains(prompt.String(), "remove the TXT record") {
				t.Errorf("manual: prompt %q", prompt.String())
			}
		}
		if _, err := os.Stat(path); (err == nil) == (tt.exit == ExitConforms) {
			t.Errorf("%s: state file present: %v", name, err == nil)
		}
		if tt.exit == ExitConforms {
			continue
		}
		_ = os.Remove(path)
		_ = os.Remove(path + ".lock")
	}
}

func TestPromptDefaultsToStandardError(t *testing.T) {
	if (Env{}).prompt() != os.Stderr {
		t.Error("the default prompt is not standard error")
	}
}

func TestWebDoAndBackoff(t *testing.T) {
	w, url := webFor(t, nil, testTiming())
	_ = url
	if err := w.Backoff(ctx(t), enroll.Response{Header: map[string][]string{"Retry-After": {"1"}}}); err != nil {
		t.Errorf("Backoff: %v", err)
	}
	w.spent = w.timing.RetryBudget
	if err := w.Backoff(ctx(t), enroll.Response{Header: map[string][]string{"Retry-After": {"1"}}}); err != errRateLimited {
		t.Errorf("Backoff over budget: %v", err)
	}
	cancelled, cancel := context.WithCancel(ctx(t))
	cancel()
	if _, err := w.Do(cancelled, "GET", "https://example.com/x", nil, "", false); err == nil {
		t.Error("cancelled Do")
	}
	if _, err := w.Do(ctx(t), "GET", "http://example.com/x", nil, "", true); err == nil {
		t.Error("an http URL was fetched")
	}
}

func TestUnpairInstallationRefusesAnAnswerThatLeavesItActive(t *testing.T) {
	_, env := serve(t, refop.Config{Faults: refop.UnpairIgnored})
	w := newWeb(env)
	k1, s1 := stateKey(t, "k1", enroll.AlgEdDSA)
	inst := pairedInstallation(t, w, refop.DefaultCodes[0], s1, "k1")
	err := unpairInstallation(ctx(t), w, enrollURL, inst, []StateKey{k1})
	if err == nil || err == errNoKey {
		t.Errorf("a 200 that leaves the installation active counted as unpaired: %v", err)
	}
}

func TestRunKeepsStateAndExitsCleanupWhenUnpairingChangesNothing(t *testing.T) {
	failing := func(context.Context, *Web, string, StateInstallation, []StateKey) error { return errNoKey }
	for name, tt := range map[string]struct {
		faults refop.Fault
		unpair Unpairer
	}{
		// The clean-up uses the real unpairing, which must not take the 200 for success.
		"cleanup of the installations": {refop.UnpairIgnored, unpairInstallation},
		// The clean-up fails, so only the unpairing of the stray installation could mark it.
		"stray installation": {refop.UnpairIgnored | refop.CodeWithOtherKey, failing},
	} {
		t.Run(name, func(t *testing.T) {
			r, env := serve(t, refop.Config{Faults: tt.faults})
			env.Unpair = tt.unpair
			s := enrollSettings(t, r, ClassEnrollment)
			s.OwnDomain, s.DNSHook = "", ""
			res := RunWith(ctx(t), s, env)
			if res.Exit != ExitCleanup {
				t.Errorf("exit %d (%s)", res.Exit, res.Message)
			}
			if _, err := os.Stat(s.StatePath); err != nil {
				t.Errorf("the state file is gone: %v", err)
			}
			if res.Report.Installations.Unpaired != 0 {
				t.Errorf("installations %+v", res.Report.Installations)
			}
		})
	}
}

// SPDX-License-Identifier: Apache-2.0

package liveconf

import (
	"context"
	"errors"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/home-mandate/spec/relay/internal/refop"
	"github.com/home-mandate/spec/relay/internal/refrelay"
)

// serveFull is a reference operator and relay with the real unpairing.
func serveFull(t *testing.T, faults refrelay.Fault) (*refop.Running, Env) {
	t.Helper()
	r, env := serveRelay(t, refop.Config{}, faults)
	env.Unpair = unpairInstallation
	return r, env
}

// noInstallationIsLeft says that the operator serves no installation and at least two tunnel
// certificates, one for each installation, are on the denylist.
func noInstallationIsLeft(t *testing.T, r *refop.Running) {
	t.Helper()
	if routes := r.Operator.Routes(); len(routes) != 0 {
		t.Errorf("the operator still serves %d names", len(routes))
	}
	if n := len(r.Operator.Denylist()); n < 2 {
		t.Errorf("%d certificates on the denylist, want at least 2", n)
	}
}

// TestReferenceConforms: the clean reference passes all four classes with two codes and an own
// domain, creates two installations and unpairs both.
func TestReferenceConforms(t *testing.T) {
	r, env := serveFull(t, 0)
	s := enrollSettings(t, r)
	res := RunWith(ctx(t), s, env)
	if res.Exit != ExitConforms || !res.Report.Conforms || len(res.Report.Failures) != 0 || len(res.Report.Incomplete) != 0 {
		t.Fatalf("exit %d (%s), failures %+v, incomplete %v", res.Exit, res.Message, res.Report.Failures, res.Report.Incomplete)
	}
	for _, class := range AllClasses {
		if c := res.Report.Classes[class]; !c.Conforms || c.Skipped != 0 || c.Failed != 0 || c.Cases == 0 {
			t.Errorf("%s: %+v", class, c)
		}
	}
	if res.Report.Installations != (Installations{Created: 2, Unpaired: 2}) {
		t.Errorf("installations %+v", res.Report.Installations)
	}
	if got := res.Report.Classes[ClassRelay].Cases; got != len(checksOf(ClassRelay)) {
		t.Errorf("%d checks of the class relay, the table has %d", got, len(checksOf(ClassRelay)))
	}
	noInstallationIsLeft(t, r)
	if n := len(r.Operator.Denylist()); n != 4 {
		t.Errorf("%d certificates on the denylist, want 4", n)
	}
	if _, err := os.Stat(s.StatePath); err == nil {
		t.Error("the state file is still there")
	}
}

// TestCleanupOnFailure: whatever ends a run, the installations are unpaired, or the state file
// stays and the clean-up of a later call finishes the job.
func TestCleanupOnFailure(t *testing.T) {
	t.Run("an abort at the limit of the run", func(t *testing.T) {
		t.Parallel()
		r, env := serveFull(t, 0)
		s := enrollSettings(t, r)
		s.Timeout = 1500 * time.Millisecond
		res := RunWith(ctx(t), s, env)
		if res.Exit != ExitIncomplete || res.Report.Installations.Created != res.Report.Installations.Unpaired {
			t.Errorf("exit %d (%s), installations %+v", res.Exit, res.Message, res.Report.Installations)
		}
		if routes := r.Operator.Routes(); len(routes) != 0 {
			t.Errorf("%d names are still served", len(routes))
		}
		if _, err := os.Stat(s.StatePath); err == nil {
			t.Error("the state file is still there")
		}
	})
	t.Run("an unpairing that fails once", func(t *testing.T) {
		t.Parallel()
		r, env := serveFull(t, 0)
		var calls atomic.Int32
		real := env.Unpair
		env.Unpair = func(ctx context.Context, w *Web, enrollment string, inst StateInstallation, keys []StateKey) error {
			if calls.Add(1) == 1 {
				return errors.New("refused")
			}
			return real(ctx, w, enrollment, inst, keys)
		}
		s := enrollSettings(t, r)
		res := RunWith(ctx(t), s, env)
		if res.Exit != ExitCleanup || res.Report.Installations.Unpaired >= res.Report.Installations.Created {
			t.Fatalf("exit %d (%s), installations %+v", res.Exit, res.Message, res.Report.Installations)
		}
		if _, err := os.Stat(s.StatePath); err != nil {
			t.Fatalf("the state file is gone: %v", err)
		}
		cleanup := Settings{CleanupPath: s.StatePath, DNSHook: s.DNSHook}
		if done := CleanupWith(ctx(t), cleanup, env); done.Exit != ExitConforms {
			t.Fatalf("clean-up: exit %d (%s)", done.Exit, done.Message)
		}
		noInstallationIsLeft(t, r)
		if _, err := os.Stat(s.StatePath); err == nil {
			t.Error("the state file is still there after the clean-up")
		}
	})
	t.Run("a clean-up after a kill", func(t *testing.T) {
		t.Parallel()
		r, env := serveFull(t, 0)
		s := enrollSettings(t, r)
		s.Timeout = 2 * time.Second
		// A killed tool has no time to clean up: here the clean-up has none.
		killed := env
		killed.Timing.Cleanup = time.Nanosecond
		res := RunWith(ctx(t), s, killed)
		if res.Exit != ExitCleanup {
			t.Fatalf("exit %d (%s)", res.Exit, res.Message)
		}
		if done := CleanupWith(ctx(t), Settings{CleanupPath: s.StatePath, DNSHook: s.DNSHook}, env); done.Exit != ExitConforms {
			t.Fatalf("clean-up: exit %d (%s)", done.Exit, done.Message)
		}
		noInstallationIsLeft(t, r)
	})
}

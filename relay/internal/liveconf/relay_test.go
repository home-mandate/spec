// SPDX-License-Identifier: Apache-2.0

package liveconf

import (
	"slices"
	"testing"
	"time"

	"github.com/home-mandate/spec/relay/internal/refop"
	"github.com/home-mandate/spec/relay/internal/refrelay"
)

// serveRelay starts a reference operator with a reference relay that shows the faults.
func serveRelay(t *testing.T, cfg refop.Config, faults refrelay.Fault) (*refop.Running, Env) {
	t.Helper()
	cfg.Relay = refrelay.New(refrelay.Config{
		Host: "tunnel." + refop.DefaultOperator, Faults: faults, AnnouncePins: true,
		TokenValidity: 400 * time.Millisecond, Heartbeat: 30 * time.Second,
	})
	r, env := serve(t, cfg)
	env.Timing.Gap, env.Timing.Jitter = 0, 0
	return r, env
}

// runRelayClass runs all four classes against the reference operator and relay.
func runAll(t *testing.T, cfg refop.Config, faults refrelay.Fault, classes ...string) Result {
	t.Helper()
	r, env := serveRelay(t, cfg, faults)
	set := enrollSettings(t, r, classes...)
	if faults != refrelay.PendingRouted && len(classes) == 1 {
		// Only this defect needs the own domain and its DNS hook.
		set.OwnDomain, set.DNSHook = "", ""
	}
	return RunWith(ctx(t), set, env)
}

func TestTheCleanReferenceConforms(t *testing.T) {
	res := runAll(t, refop.Config{}, 0)
	if res.Exit != ExitConforms || !res.Report.Conforms || len(res.Report.Failures) != 0 {
		t.Fatalf("exit %d, failures %+v, incomplete %v, classes %+v", res.Exit, res.Report.Failures, res.Report.Incomplete, res.Report.Classes)
	}
	for _, class := range AllClasses {
		if c := res.Report.Classes[class]; !c.Conforms || c.Skipped != 0 {
			t.Errorf("%s: %+v", class, c)
		}
	}
	if got := res.Report.Installations; got.Created != 2 || got.Unpaired != 2 {
		t.Errorf("installations %+v", got)
	}
}

// TestEachBrokenRelayVariantFailsExactlyItsCheck: every defect of the reference relay fails the
// check meant to catch it, and no other; a variant runs only the class relay.
func TestEachBrokenRelayVariantFailsExactlyItsCheck(t *testing.T) {
	for name, tt := range map[string]struct {
		fault refrelay.Fault
		want  string
	}{
		"R1 TLS 1.2":             {refrelay.TLS12, CheckRelayTLS},
		"R2 x25519":              {refrelay.GroupX25519, CheckRelayTLS},
		"R3 resumption":          {refrelay.Resumption, CheckRelayTLS},
		"R4 no denylist":         {refrelay.NoDenylist, CheckRelayDenylist},
		"R5 token twice":         {refrelay.TokenReuse, CheckRelayBinding},
		"R6 foreign token":       {refrelay.ForeignToken, CheckRelayBinding},
		"R7 byte before close":   {refrelay.ByteBeforeClose, CheckRelaySilent},
		"R8 mapped IPv4":         {refrelay.MappedIPv4, CheckRelayProxy},
		"R9 real destination":    {refrelay.RealDestination, CheckRelayProxy},
		"R10 agent PROXY header": {refrelay.AgentProxyHeader, CheckRelayProxy},
		"R11 pending routed":     {refrelay.PendingRouted, CheckRelayRouting},
		"R12 case sensitive SNI": {refrelay.CaseSensitiveSNI, CheckRelayRouting},
		"R13 pins from gateway":  {refrelay.PinsFromGateway, CheckRelayPins},
		"R14 heartbeat 3":        {refrelay.Heartbeat3, CheckRelayHello},
		"R15 no session-exists":  {refrelay.NoSessionExists, CheckRelaySession},
		"R16 key not pinned":     {refrelay.KeyNotPinned, CheckRelayKey},
		"R17 no close_notify":    {refrelay.NoCloseNotify, CheckRelayStream},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			res := runAll(t, refop.Config{}, tt.fault, ClassRelay)
			got := []string{}
			for _, f := range res.Report.Failures {
				got = append(got, f.File+":"+f.ID)
			}
			if want := []string{"live:" + tt.want}; !slices.Equal(got, want) {
				t.Errorf("failed %v, want %v (exit %d, %s)", got, want, res.Exit, res.Message)
			}
			if res.Exit != ExitFails || res.Report.Installations.Created != res.Report.Installations.Unpaired {
				t.Errorf("exit %d, installations %+v", res.Exit, res.Report.Installations)
			}
		})
	}
}

// TestRunsWithOneCodeOrOneCertificateSkipWhatTheyCannotPlay: with one code there is no second
// installation, no certificate with a P-256 key and no connection to unpair; where the operator
// accepts a request with the installation key, the first installation has one certificate only, so
// there is no older certificate for the cases with an earlier or a later notBefore.
func TestRunsWithOneCodeOrOneCertificateSkipWhatTheyCannotPlay(t *testing.T) {
	r, env := serveRelay(t, refop.Config{}, 0)
	set := enrollSettings(t, r, ClassRelay)
	set.OwnDomain, set.DNSHook, set.Codes = "", "", set.Codes[:1]
	res := RunWith(ctx(t), set, env)
	c := res.Report.Classes[ClassRelay]
	if len(res.Report.Failures) != 0 || res.Exit != ExitIncomplete || c.Skipped == 0 || c.Passed == 0 {
		t.Errorf("one code: exit %d, failures %v, class %+v", res.Exit, failureIDs(res), c)
	}
	r, env = serveRelay(t, refop.Config{Faults: refop.CSRWithInstallationKey}, 0)
	set = enrollSettings(t, r, ClassEnrollment, ClassRelay)
	set.OwnDomain, set.DNSHook = "", ""
	res = RunWith(ctx(t), set, env)
	if c := res.Report.Classes[ClassRelay]; c.Failed != 0 || c.Passed == 0 {
		t.Errorf("one certificate: class %+v, failures %v", c, failureIDs(res))
	}
}

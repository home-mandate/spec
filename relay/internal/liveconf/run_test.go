// SPDX-License-Identifier: Apache-2.0

package liveconf

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime/debug"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/home-mandate/spec/relay"
	"github.com/home-mandate/spec/relay/internal/refop"
)

const installURL = "https://op.example.net/enroll/installations/s3cret-token"

var twoCodes = []string{goodCode, "AAAA-BBBB-CCCC-DDDD"}

// passAll plugs in a class that passes one check; the classes of later steps will do more.
func passAll(class string) classRunner {
	return func(_ context.Context, r *run) error {
		r.pass(class)
		return nil
	}
}

func withRunners(m map[string]classRunner) func(*run) {
	return func(r *run) {
		for k, v := range m {
			r.runners[k] = v
		}
	}
}

func envWithoutNetwork() Env {
	return Env{Timing: testTiming(), Unpair: func(context.Context, *Web, string, StateInstallation, []StateKey) error { return nil }}
}

func TestRunWithRejectsBadSettings(t *testing.T) {
	for name, s := range map[string]Settings{
		"no operator": {},
		"cleanup":     {CleanupPath: "x.json"},
	} {
		if res := RunWith(ctx(t), s, envWithoutNetwork()); res.Exit != ExitUsage || res.Message == "" {
			t.Errorf("%s: exit %d, message %q", name, res.Exit, res.Message)
		}
	}
	if res := Execute(ctx(t), Settings{}); res.Exit != ExitUsage {
		t.Errorf("Execute: exit %d", res.Exit)
	}
	if res := ExecuteCleanup(ctx(t), Settings{}); res.Exit != ExitUsage {
		t.Errorf("ExecuteCleanup: exit %d", res.Exit)
	}
	if res := CleanupWith(ctx(t), Settings{Operator: "op.example.net"}, envWithoutNetwork()); res.Exit != ExitUsage {
		t.Errorf("CleanupWith with a run's settings: exit %d", res.Exit)
	}
}

func TestClassesOfLaterStepsReportAsNotRun(t *testing.T) {
	res := runWith(ctx(t), Settings{Operator: "op.example.net"}, envWithoutNetwork(),
		func(r *run) {
			r.runners = map[string]classRunner{ClassMetadata: passAll(ClassMetadata)}
		})
	for _, class := range []string{ClassEnrollment, ClassDNS, ClassRelay} {
		c := res.Report.Classes[class]
		if !c.NotRun || c.Conforms || c.Reason != notImplemented || c.Cases != 0 {
			t.Errorf("%s: %+v", class, c)
		}
	}
	if res.Exit != ExitIncomplete || res.Report.Conforms || !res.Report.Classes[ClassMetadata].Conforms {
		t.Errorf("exit %d, conforms %v", res.Exit, res.Report.Conforms)
	}
	for _, want := range []string{"class enrollment was not run", "needs 2 pairing codes, 0 given", "needs an own domain"} {
		if !slices.ContainsFunc(res.Report.Incomplete, func(s string) bool { return strings.Contains(s, want) }) {
			t.Errorf("no incomplete reason %q in %v", want, res.Report.Incomplete)
		}
	}
}

func TestUnselectedClassesAreNotRun(t *testing.T) {
	res := runWith(ctx(t), metadataOnly, envWithoutNetwork(), withRunners(map[string]classRunner{ClassMetadata: passAll(ClassMetadata)}))
	if c := res.Report.Classes[ClassRelay]; !c.NotRun || c.Reason != notSelected {
		t.Errorf("relay: %+v", c)
	}
}

// TestConformsOnlyWithAllClassesTwoCodesAndAnOwnDomain: the only way to exit 0.
func TestConformsOnlyWithAllClassesTwoCodesAndAnOwnDomain(t *testing.T) {
	all := map[string]classRunner{}
	for _, c := range AllClasses {
		all[c] = passAll(c)
	}
	full := Settings{Operator: "op.example.net", Codes: twoCodes, OwnDomain: "x.test.example", DNSManual: true, StatePath: filepath.Join(t.TempDir(), "s.json")}
	res := runWith(ctx(t), full, envWithoutNetwork(), withRunners(all))
	if res.Exit != ExitConforms || !res.Report.Conforms || len(res.Report.Incomplete) != 0 {
		t.Fatalf("exit %d: %+v", res.Exit, res.Report)
	}
	for name, mod := range map[string]func(*Settings){
		"one code":      func(s *Settings) { s.Codes = s.Codes[:1] },
		"no code":       func(s *Settings) { s.Codes = nil },
		"no own domain": func(s *Settings) { s.OwnDomain, s.DNSManual = "", false },
		"one class":     func(s *Settings) { s.Classes = []string{ClassMetadata} },
	} {
		s := full
		s.Codes = slices.Clone(full.Codes)
		s.StatePath = filepath.Join(t.TempDir(), "s.json")
		mod(&s)
		if res := runWith(ctx(t), s, envWithoutNetwork(), withRunners(all)); res.Exit != ExitIncomplete || res.Report.Conforms {
			t.Errorf("%s: exit %d, conforms %v", name, res.Exit, res.Report.Conforms)
		}
	}
	// A failure of any check keeps the result from conforming, however complete the run.
	all[ClassDNS] = func(_ context.Context, r *run) error { r.fail(ClassDNS, "dns.x", "a", "b"); return nil }
	full.StatePath = filepath.Join(t.TempDir(), "s.json")
	if res := runWith(ctx(t), full, envWithoutNetwork(), withRunners(all)); res.Exit != ExitFails || res.Report.Conforms {
		t.Errorf("with a failure: exit %d", res.Exit)
	}
}

func TestStateFileExistsBeforeTheFirstClassAndIsGoneAfterwards(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.json")
	var during State
	probe := func(_ context.Context, r *run) error {
		f, err := OpenState(path) // the run holds the lock: this must fail
		if err == nil {
			_ = f.Close()
			t.Error("the state file is not locked during the run")
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(data, &during); err != nil {
			t.Fatal(err)
		}
		return nil
	}
	res := runWith(ctx(t), Settings{Operator: "op.example.net", Codes: twoCodes, StatePath: path}, envWithoutNetwork(),
		withRunners(map[string]classRunner{ClassMetadata: probe}))
	if len(during.Keys) != 4 || during.Operator != "op.example.net" || during.Keys[0].Alg != "EdDSA" || during.Keys[1].Alg != "ES256" || during.Keys[0].Private == "" {
		t.Errorf("state during the run: %+v", during)
	}
	for _, p := range []string{path, path + ".lock"} {
		if _, err := os.Stat(p); err == nil {
			t.Errorf("%s was not deleted", p)
		}
	}
	if res.Report.Installations != (Installations{}) {
		t.Errorf("installations %+v", res.Report.Installations)
	}
	if bytes.Contains([]byte(fmt.Sprint(during)), []byte("ABCDEFGHIJKLMNOP")) {
		t.Error("a pairing code is in the state file")
	}
}

func TestDefaultStatePathIsANewFileInTheWorkingDirectory(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	var seen []string
	probe := func(context.Context, *run) error {
		entries, _ := os.ReadDir(dir)
		for _, e := range entries {
			seen = append(seen, e.Name())
		}
		return nil
	}
	runWith(ctx(t), Settings{Operator: "op.example.net", Codes: twoCodes}, envWithoutNetwork(), withRunners(map[string]classRunner{ClassMetadata: probe}))
	if len(seen) == 0 || !strings.HasPrefix(seen[0], "relay-conformance-") {
		t.Errorf("files during the run: %v", seen)
	}
	if left, _ := os.ReadDir(dir); len(left) != 0 {
		t.Errorf("files left: %v", left)
	}
}

func TestAnExistingStateFileIsNeverOverwritten(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.json")
	if err := os.WriteFile(path, []byte("mine"), 0o600); err != nil {
		t.Fatal(err)
	}
	called := false
	res := runWith(ctx(t), Settings{Operator: "op.example.net", Codes: twoCodes, StatePath: path}, envWithoutNetwork(),
		withRunners(map[string]classRunner{ClassMetadata: func(context.Context, *run) error { called = true; return nil }}))
	if res.Exit != ExitUsage || called || res.Message == "" || res.Report.Conforms {
		t.Errorf("exit %d, called %v", res.Exit, called)
	}
	if data, _ := os.ReadFile(path); string(data) != "mine" {
		t.Errorf("the file was changed: %q", data)
	}
}

func TestAPanicEndsTheRunButNotTheCleanUp(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.json")
	unpaired := 0
	env := envWithoutNetwork()
	env.Unpair = func(context.Context, *Web, string, StateInstallation, []StateKey) error { unpaired++; return nil }
	boom := func(_ context.Context, r *run) error {
		r.enrollURL = "https://op.example.net/enroll/directory"
		_ = r.state.Save(r.state.State().WithInstallation(StateInstallation{URL: installURL, Key: "k1"}))
		panic("secret " + installURL)
	}
	res := runWith(ctx(t), Settings{Operator: "op.example.net", Codes: twoCodes, StatePath: path}, env,
		withRunners(map[string]classRunner{ClassMetadata: boom}))
	if unpaired != 1 || res.Report.Installations != (Installations{Created: 1, Unpaired: 1}) {
		t.Errorf("unpaired %d, %+v", unpaired, res.Report.Installations)
	}
	if res.Exit != ExitIncomplete || !slices.Contains(res.Report.Incomplete, internalFailure) {
		t.Errorf("exit %d, incomplete %v", res.Exit, res.Report.Incomplete)
	}
	var out bytes.Buffer
	Summarize(&out, res.Report)
	if strings.Contains(out.String(), "s3cret") || strings.Contains(res.Message, "s3cret") {
		t.Error("the panic value reached the output")
	}
	if _, err := os.Stat(path); err == nil {
		t.Error("the state file is still there after a successful clean-up")
	}
}

func TestFailedUnpairingIsExit4AndKeepsTheStateFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.json")
	env := envWithoutNetwork()
	attempts := 0
	env.Unpair = func(context.Context, *Web, string, StateInstallation, []StateKey) error {
		attempts++
		return errors.New("refused: " + installURL)
	}
	add := func(_ context.Context, r *run) error {
		r.enrollURL = "https://op.example.net/enroll/directory"
		st := r.state.State().WithInstallation(StateInstallation{URL: installURL, Key: "k1"})
		return r.state.Save(st)
	}
	res := runWith(ctx(t), Settings{Operator: "op.example.net", Codes: twoCodes, StatePath: path}, env,
		withRunners(map[string]classRunner{ClassMetadata: add}))
	if res.Exit != ExitCleanup || attempts != 1 {
		t.Fatalf("exit %d, attempts %d", res.Exit, attempts)
	}
	if !strings.Contains(res.Message, "-cleanup") || !strings.Contains(res.Message, path) {
		t.Errorf("message %q does not name the clean-up", res.Message)
	}
	var out bytes.Buffer
	Summarize(&out, res.Report)
	_ = res.Report.Write(&out)
	if strings.Contains(out.String()+res.Message, "s3cret") {
		t.Error("the installation URL reached the output")
	}
	if res.Report.Installations != (Installations{Created: 1, Unpaired: 0}) || res.Report.Conforms {
		t.Errorf("report %+v", res.Report)
	}
	// The lock is released and the file is intact: -cleanup can take over.
	f, err := OpenState(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if f.State().Pending() != 1 {
		t.Errorf("state %+v", f.State())
	}
}

func TestARunnerErrorMakesTheClassNotRun(t *testing.T) {
	res := runWith(ctx(t), metadataOnly, envWithoutNetwork(), withRunners(map[string]classRunner{
		ClassMetadata: func(_ context.Context, r *run) error {
			r.pass(ClassMetadata)
			return errors.New("bad\nstuff")
		},
	}))
	c := res.Report.Classes[ClassMetadata]
	if !c.NotRun || c.Cases != 0 || c.Reason != `bad\u000astuff` {
		t.Errorf("class %+v", c)
	}
}

func TestTheRunEndsAtItsTimeout(t *testing.T) {
	start := time.Now()
	res := runWith(ctx(t), Settings{Operator: "op.example.net", Timeout: 50 * time.Millisecond}, envWithoutNetwork(),
		withRunners(map[string]classRunner{ClassMetadata: func(ctx context.Context, _ *run) error {
			<-ctx.Done()
			return ctx.Err()
		}}))
	if time.Since(start) > 5*time.Second || res.Exit != ExitIncomplete {
		t.Errorf("exit %d after %v", res.Exit, time.Since(start))
	}
}

func TestFailuresAreCapped(t *testing.T) {
	r := newRun(Settings{Operator: "op.example.net", Classes: []string{ClassMetadata}}, envWithoutNetwork())
	r.rep.Classes[ClassMetadata].NotRun = false
	for i := range maxFailures + 5 {
		r.fail(ClassMetadata, "id", strings.Repeat("g", 500), fmt.Sprint(i))
	}
	res := r.result()
	if len(res.Report.Failures) != maxFailures || res.Report.FailuresOmitted != 5 || res.Report.Classes[ClassMetadata].Failed != maxFailures+5 {
		t.Errorf("%d failures, %d omitted", len(res.Report.Failures), res.Report.FailuresOmitted)
	}
	if n := len(res.Report.Failures[0].Got); n != maxText {
		t.Errorf("a text has %d characters", n)
	}
	var out bytes.Buffer
	Summarize(&out, res.Report)
	if !strings.Contains(out.String(), "5 more failures not shown") {
		t.Errorf("summary:\n%s", out.String())
	}
}

func TestReportNamesAndManifest(t *testing.T) {
	res := runWith(ctx(t), metadataOnly, envWithoutNetwork(), withRunners(map[string]classRunner{ClassMetadata: passAll(ClassMetadata)}))
	var buf bytes.Buffer
	if err := res.Report.Write(&buf); err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"spec", "version", "manifest", "operator", "date", "classes", "failures", "installations", "notes", "incomplete", "conforms"} {
		if _, ok := doc[key]; !ok {
			t.Errorf("report has no member %s", key)
		}
	}
	data, err := fs.ReadFile(relay.FS(), relay.ManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	if doc["manifest"] != hex.EncodeToString(sum[:]) || doc["spec"] != "relay-v0" {
		t.Errorf("manifest %v, spec %v", doc["manifest"], doc["spec"])
	}
	if _, err := time.Parse("2006-01-02", doc["date"].(string)); err != nil {
		t.Errorf("date: %v", err)
	}
	class := doc["classes"].(map[string]any)["enrollment"].(map[string]any)
	for _, key := range []string{"cases", "passed", "failed", "skipped", "conforms", "not_run"} {
		if _, ok := class[key]; !ok {
			t.Errorf("class result has no member %s", key)
		}
	}
}

func TestSummarize(t *testing.T) {
	r := newRun(metadataOnly, envWithoutNetwork())
	r.rep.Classes[ClassMetadata].NotRun = false
	r.pass(ClassMetadata)
	r.fail(ClassMetadata, CheckMetadataSize, "big", "small")
	r.note("hint")
	res := r.result()
	delete(res.Report.Classes, ClassDNS)
	var out bytes.Buffer
	Summarize(&out, res.Report)
	for _, want := range []string{"class metadata: 2 checks, 1 passed, 1 failed", "class enrollment: not run", "FAIL metadata metadata.size: got big, want small",
		"incomplete: ", "note: hint", "installations: 0 created", "conforms: false"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("summary lacks %q:\n%s", want, out.String())
		}
	}
	if strings.Contains(out.String(), "class dns:") {
		t.Error("a class without a result was printed")
	}
}

func TestChecksTable(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range Checks() {
		if c.ID == "" || c.Title == "" || c.Section == "" || seen[c.ID] || !slices.Contains(AllClasses, c.Class) || !strings.HasPrefix(c.ID, c.Class+".") {
			t.Errorf("bad check %+v", c)
		}
		seen[c.ID] = true
	}
	if len(checksOf(ClassMetadata)) != 9 || len(checksOf(ClassEnrollment)) != 29 || len(checksOf(ClassDNS)) != 9 || len(checksOf(ClassRelay)) != 12 {
		t.Error("checksOf")
	}
	got := Checks()
	got[0].ID = "changed"
	if Checks()[0].ID == "changed" {
		t.Error("Checks hands out its table")
	}
}

func TestDependencyVersion(t *testing.T) {
	info := &debug.BuildInfo{Deps: []*debug.Module{{Path: "other", Version: "v1"}, {Path: publicSuffixModule, Version: "v0.62.0"}}}
	if got := dependencyVersion(info, true); got != "v0.62.0" {
		t.Errorf("got %q", got)
	}
	if got := dependencyVersion(info, false); got != "unknown" {
		t.Errorf("got %q", got)
	}
	if got := dependencyVersion(&debug.BuildInfo{}, true); got != "unknown" {
		t.Errorf("got %q", got)
	}
}

func TestMetadataRunAgainstTheReferenceNeverTouchesTheState(t *testing.T) {
	_, env := serve(t, refop.Config{})
	res := RunWith(ctx(t), Settings{Operator: refop.DefaultOperator, Classes: []string{ClassMetadata}, StatePath: "unused.json"}, env)
	if _, err := os.Stat("unused.json"); err == nil || res.Exit != ExitIncomplete {
		t.Errorf("exit %d, %v", res.Exit, err)
	}
}

func TestUnpairUnavailable(t *testing.T) {
	if got := Execute(ctx(t), Settings{Operator: "op.example.net", Classes: []string{"nope"}}); got.Exit != ExitUsage {
		t.Errorf("exit %d", got.Exit)
	}
}

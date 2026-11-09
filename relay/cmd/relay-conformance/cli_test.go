// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"
	"time"

	"github.com/home-mandate/spec/relay/internal/liveconf"
)

const code1 = "ABCD-EFGH-IJKL-MNOP"

// fake records what the command asked for and answers with a prepared result.
type fake struct {
	settings liveconf.Settings
	cleaned  bool
	called   bool
	result   liveconf.Result
}

func (f *fake) executor() executor {
	return executor{
		run: func(_ context.Context, s liveconf.Settings) liveconf.Result {
			f.settings, f.called = s, true
			return f.result
		},
		cleanup: func(_ context.Context, s liveconf.Settings) liveconf.Result {
			f.settings, f.called, f.cleaned = s, true, true
			return f.result
		},
	}
}

func call(t *testing.T, f *fake, env map[string]string, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := run(context.Background(), args, func(k string) string { return env[k] }, &out, &errOut, f.executor())
	return code, out.String(), errOut.String()
}

func sampleResult(exit int) liveconf.Result {
	return liveconf.Result{Exit: exit, Report: liveconf.Report{
		Spec: liveconf.SpecName, Operator: "op.example.net", Date: "2026-11-09", Version: "devel",
		Classes:  map[string]*liveconf.ClassResult{liveconf.ClassMetadata: {Cases: 1, Passed: 1, Conforms: true}},
		Failures: []liveconf.Failure{}, Notes: []string{}, Incomplete: []string{},
	}}
}

func TestExitCodesAreThoseOfTheResult(t *testing.T) {
	for _, exit := range []int{0, 1, 3, 4} {
		f := &fake{result: sampleResult(exit)}
		if code, out, _ := call(t, f, nil, "-operator", "op.example.net"); code != exit || !strings.Contains(out, "class metadata") {
			t.Errorf("exit %d: got %d, output %q", exit, code, out)
		}
	}
}

func TestUsageErrorsExitWith2AndRunNothing(t *testing.T) {
	for name, args := range map[string][]string{
		"unknown flag":    {"-nope"},
		"positional":      {"-operator", "op.example.net", "extra"},
		"no operator":     {},
		"bad operator":    {"-operator", "OP.example.net"},
		"bad class":       {"-operator", "op.example.net", "-classes", "x"},
		"timeout too big": {"-operator", "op.example.net", "-timeout", "61m"},
		"three codes":     {"-operator", "op.example.net", "-code", code1, "-code", "AAAA-BBBB-CCCC-DDDD", "-code", "EEEE-FFFF-GGGG-HHHH"},
		"bad code":        {"-operator", "op.example.net", "-code", "x"},
		"missing file":    {"-operator", "op.example.net", "-code-file", filepath.Join(t.TempDir(), "none")},
		"hook alone":      {"-operator", "op.example.net", "-dns-hook", "./h"},
		"cleanup + run":   {"-cleanup", "s.json", "-operator", "op.example.net"},
	} {
		f := &fake{result: sampleResult(0)}
		code, _, errOut := call(t, f, nil, args...)
		if code != liveconf.ExitUsage || f.called || errOut == "" {
			t.Errorf("%s: exit %d, called %v, stderr %q", name, code, f.called, errOut)
		}
	}
}

func TestCodesComeFromFilesFlagsOrTheEnvironment(t *testing.T) {
	dir := t.TempDir()
	file1, file2 := filepath.Join(dir, "1"), filepath.Join(dir, "2")
	_ = os.WriteFile(file1, []byte(" abcd-efgh-ijkl-mnop \n"), 0o600)
	_ = os.WriteFile(file2, []byte("AAAA-BBBB-CCCC-DDDD"), 0o600)
	for name, tt := range map[string]struct {
		args []string
		env  string
		want int
	}{
		"two files":                  {[]string{"-code-file", file1, "-code-file", file2}, "", 2},
		"file and flag":              {[]string{"-code-file", file1, "-code", "AAAA-BBBB-CCCC-DDDD"}, "", 2},
		"one flag":                   {[]string{"-code", code1}, "", 1},
		"environment":                {nil, "ABCD-EFGH-IJKL-MNOP, AAAA-BBBB-CCCC-DDDD\n", 2},
		"flags beat the environment": {[]string{"-code", code1}, "AAAA-BBBB-CCCC-DDDD", 1},
		"none":                       {nil, "", 0},
	} {
		f := &fake{result: sampleResult(3)}
		call(t, f, map[string]string{codesEnv: tt.env}, append([]string{"-operator", "op.example.net"}, tt.args...)...)
		if len(f.settings.Codes) != tt.want {
			t.Errorf("%s: %d codes %v, want %d", name, len(f.settings.Codes), f.settings.Codes, tt.want)
		}
	}
}

func TestCodesNeverAppearInTheOutput(t *testing.T) {
	f := &fake{result: sampleResult(3)}
	code, out, errOut := call(t, f, nil, "-operator", "op.example.net", "-code", code1, "-code", "nonsense-secret")
	if code != liveconf.ExitUsage || strings.Contains(out+errOut, "nonsense") {
		t.Errorf("exit %d, output %q", code, out+errOut)
	}
	big := filepath.Join(t.TempDir(), "big")
	_ = os.WriteFile(big, bytes.Repeat([]byte("SECRETSECRET"), 200), 0o600)
	_, _, errOut = call(t, f, nil, "-operator", "op.example.net", "-code-file", big)
	if strings.Contains(errOut, "SECRET") || errOut == "" {
		t.Errorf("stderr %q", errOut)
	}
}

func TestFlagsReachTheSettings(t *testing.T) {
	f := &fake{result: sampleResult(3)}
	call(t, f, nil, "-operator", "op.example.net", "-classes", "metadata,relay", "-own-domain", "x.test.example", "-dns-manual",
		"-state", "s.json", "-timeout", "10m")
	s := f.settings
	if s.Operator != "op.example.net" || len(s.Classes) != 2 || s.OwnDomain != "x.test.example" || !s.DNSManual ||
		s.StatePath != "s.json" || s.Timeout != 10*time.Minute || s.Version == "" {
		t.Errorf("settings %+v", s)
	}
	call(t, f, nil, "-operator", "op.example.net", "-own-domain", "x.test.example", "-dns-hook", "./hook")
	if f.settings.DNSHook != "./hook" {
		t.Errorf("settings %+v", f.settings)
	}
}

func TestCleanupMode(t *testing.T) {
	f := &fake{result: liveconf.Result{Exit: liveconf.ExitConforms, Message: "clean-up done"}}
	code, out, _ := call(t, f, nil, "-cleanup", "s.json", "-dns-hook", "./hook")
	if code != 0 || !f.cleaned || f.settings.CleanupPath != "s.json" || f.settings.DNSHook != "./hook" || !strings.Contains(out, "clean-up done") {
		t.Errorf("exit %d, settings %+v, output %q", code, f.settings, out)
	}
	f = &fake{result: liveconf.Result{Exit: liveconf.ExitCleanup, Message: "clean-up failed: run relay-conformance -cleanup s.json"}}
	code, out, errOut := call(t, f, nil, "-cleanup", "s.json", "-report", filepath.Join(t.TempDir(), "r.json"))
	if code != liveconf.ExitCleanup || out != "" || !strings.Contains(errOut, "-cleanup") {
		t.Errorf("exit %d, stdout %q, stderr %q", code, out, errOut)
	}
}

func TestReportFileIsWrittenAndHoldsTheResult(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.json")
	f := &fake{result: sampleResult(1)}
	f.result.Report.Failures = []liveconf.Failure{{Class: "metadata", File: "live", ID: "metadata.size", Got: "big", Want: "small"}}
	code, _, _ := call(t, f, nil, "-operator", "op.example.net", "-report", path)
	if code != liveconf.ExitFails {
		t.Errorf("exit %d", code)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var got liveconf.Report
	if err := json.Unmarshal(data, &got); err != nil || got.Operator != "op.example.net" || len(got.Failures) != 1 || got.Failures[0].ID != "metadata.size" {
		t.Errorf("report %s, %v", data, err)
	}
}

func TestAReportThatCannotBeWrittenNeverImprovesTheExitCode(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "no", "such", "dir", "r.json")
	for exit, want := range map[int]int{0: 3, 1: 1, 3: 3, 4: 4} {
		f := &fake{result: sampleResult(exit)}
		code, _, errOut := call(t, f, nil, "-operator", "op.example.net", "-report", bad)
		if code != want || !strings.Contains(errOut, "report could not be written") {
			t.Errorf("exit %d: got %d, stderr %q", exit, code, errOut)
		}
	}
}

func TestList(t *testing.T) {
	f := &fake{}
	code, out, _ := call(t, f, nil, "-list")
	if code != 0 || f.called {
		t.Fatalf("exit %d, called %v", code, f.called)
	}
	for _, c := range liveconf.Checks() {
		if !strings.Contains(out, c.ID+"\t"+c.Class+"\t"+c.Section+"\t") {
			t.Errorf("list lacks %s:\n%s", c.ID, out)
		}
	}
}

func TestAPanicIsCaught(t *testing.T) {
	f := &fake{}
	f.result = sampleResult(0)
	var errOut bytes.Buffer
	code := run(context.Background(), []string{"-operator", "op.example.net"}, func(string) string { return "" }, panicWriter{}, &errOut, f.executor())
	if code != liveconf.ExitIncomplete || !strings.Contains(errOut.String(), "internal error") {
		t.Errorf("exit %d, stderr %q", code, errOut.String())
	}
}

type panicWriter struct{}

func (panicWriter) Write([]byte) (int, error) { panic("boom") }

func TestUsageTextWithoutExecution(t *testing.T) {
	_, _, errOut := call(t, &fake{}, nil, "-h")
	if !strings.Contains(errOut, "relay-conformance -cleanup") || !strings.Contains(errOut, "RELAY_CONFORMANCE_CODES") {
		t.Errorf("usage: %q", errOut)
	}
}

func TestBuildVersion(t *testing.T) {
	read := func(v string, ok bool) func() (*debug.BuildInfo, bool) {
		return func() (*debug.BuildInfo, bool) { return &debug.BuildInfo{Main: debug.Module{Version: v}}, ok }
	}
	for name, tt := range map[string]struct {
		ldflags string
		read    func() (*debug.BuildInfo, bool)
		want    string
	}{
		"ldflags win":    {"v1.2.3", read("v9", true), "v1.2.3"},
		"module version": {"", read("v0.1.0", true), "v0.1.0"},
		"devel build":    {"", read("(devel)", true), "devel"},
		"empty version":  {"", read("", true), "devel"},
		"no build info":  {"", read("v0.1.0", false), "devel"},
	} {
		if got := buildVersion(tt.ldflags, tt.read); got != tt.want {
			t.Errorf("%s: %q, want %q", name, got, tt.want)
		}
	}
}

func TestProductionExecutorIsTheOneOfLiveconf(t *testing.T) {
	// A cleanup of a file that is no state file exercises the real executor without a network.
	path := filepath.Join(t.TempDir(), "state.json")
	_ = os.WriteFile(path, []byte("nope"), 0o600)
	var out, errOut bytes.Buffer
	code := run(context.Background(), []string{"-cleanup", path}, func(string) string { return "" }, &out, &errOut, production)
	if code != liveconf.ExitCleanup || !strings.Contains(errOut.String(), "-cleanup") {
		t.Errorf("exit %d, stderr %q", code, errOut.String())
	}
	// And a real run that is refused before any network use.
	code = run(context.Background(), []string{"-operator", "op.example.net", "-code", code1}, func(string) string { return "" }, &out, &errOut,
		executor{run: func(ctx context.Context, s liveconf.Settings) liveconf.Result {
			s.StatePath = path // exists: the real executor must refuse to overwrite it
			return liveconf.Execute(ctx, s)
		}, cleanup: liveconf.ExecuteCleanup})
	if code != liveconf.ExitUsage {
		t.Errorf("exit %d: %s", code, errOut.String())
	}
	if data, _ := os.ReadFile(path); string(data) != "nope" {
		t.Errorf("the state file was overwritten: %q", data)
	}
}

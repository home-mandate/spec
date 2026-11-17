// SPDX-License-Identifier: Apache-2.0

package harness_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/home-mandate/spec"
	"github.com/home-mandate/spec/evaluator"
	"github.com/home-mandate/spec/internal/harness"
)

const harnessMode = "MANDATE_HARNESS_MODE"

// TestMain lets the test binary act as an implementation under test: with the
// environment variable set it speaks the process binding instead of running tests.
func TestMain(m *testing.M) {
	switch os.Getenv(harnessMode) {
	case "reference":
		if err := harness.Serve(os.Stdin, os.Stdout); err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	case "garbage":
		fmt.Println("this is not JSON")
		os.Exit(0)
	case "silent":
		os.Exit(0)
	case "failing":
		_ = harness.Serve(os.Stdin, os.Stdout)
		os.Exit(3)
	}
	os.Exit(m.Run())
}

func self(t *testing.T, mode string) []string {
	t.Helper()
	t.Setenv(harnessMode, mode)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return []string{exe}
}

func runMain(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := harness.Main(context.Background(), spec.FS(), args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func TestProcessBindingEndToEnd(t *testing.T) {
	report := filepath.Join(t.TempDir(), "report.json")
	args := append([]string{"-report", report, "-classes", "evaluator,selection,signatures,audit,audit-anchored", "-exec"}, self(t, "reference")...)
	code, stdout, stderr := runMain(t, args...)
	if code != harness.ExitConforms {
		t.Fatalf("exit %d\n%s\n%s", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "evaluator") || !strings.Contains(stdout, "conforms") {
		t.Errorf("summary:\n%s", stdout)
	}
	data, err := os.ReadFile(report)
	if err != nil {
		t.Fatal(err)
	}
	var written harness.Report
	if err := json.Unmarshal(data, &written); err != nil || !written.Conforms(harness.ClassEvaluator) || written.Binding != "process" {
		t.Errorf("report = %+v, %v", written, err)
	}
}

func TestProcessBindingFailures(t *testing.T) {
	for _, mode := range []string{"garbage", "silent", "failing"} {
		code, _, stderr := runMain(t, append([]string{"-exec"}, self(t, mode)...)...)
		if code != harness.ExitFails || stderr == "" {
			t.Errorf("%s: exit %d, stderr %q", mode, code, stderr)
		}
	}
	if code, _, _ := runMain(t, "-exec", filepath.Join(t.TempDir(), "does-not-exist")); code != harness.ExitFails {
		t.Errorf("missing command: exit %d", code)
	}
	if _, err := harness.StartProcess(context.Background(), nil); err == nil {
		t.Error("StartProcess without a command succeeded")
	}
	// A class the implementation was not tested for is not conformed to.
	if code, _, _ := runMain(t, append([]string{"-classes", "pdp", "-exec"}, self(t, "reference")...)...); code != harness.ExitFails {
		t.Errorf("required class pdp over the process binding: exit %d", code)
	}
	bad := filepath.Join(t.TempDir(), "no-such-dir", "report.json")
	if code, _, _ := runMain(t, append([]string{"-report", bad, "-exec"}, self(t, "reference")...)...); code != harness.ExitFails {
		t.Errorf("report that cannot be written: exit %d", code)
	}
}

func TestUsageErrors(t *testing.T) {
	for name, args := range map[string][]string{
		"nothing":                 nil,
		"exec without command":    {"-exec"},
		"authzen without control": {"-authzen", "http://x"},
		"both bindings":           {"-authzen", "http://x", "-control", "http://x", "-exec", "x"},
		"unknown flag":            {"-nope"},
		"bad header":              {"-header", "no colon", "-authzen", "http://x", "-control", "http://x"},
		"stray argument":          {"-authzen", "http://x", "-control", "http://x", "extra"},
		// The process binding's implementation names itself (capabilities).
		"name with exec":    {"-name", "x", "-exec", "x"},
		"version with exec": {"-version", "1", "-exec", "x"},
	} {
		if code, _, stderr := runMain(t, args...); code != harness.ExitUsage || !strings.Contains(stderr, "usage") {
			t.Errorf("%s: exit %d, stderr %q", name, code, stderr)
		}
	}
}

func TestHTTPBindingAgainstAReferencePDP(t *testing.T) {
	pdp := &harness.ReferencePDP{Token: "secret"}
	server := httptest.NewServer(pdp.Handler())
	defer server.Close()
	code, stdout, stderr := runMain(t, "-header", "Authorization: Bearer secret", "-authzen", server.URL, "-control", server.URL+"/test/state")
	if code != harness.ExitConforms {
		t.Fatalf("exit %d\n%s\n%s", code, stdout, stderr)
	}
	report, err := harness.RunPDP(context.Background(), spec.FS(), harness.PDP{AuthZEN: server.URL + "/", Control: server.URL + "/test/state",
		Header: http.Header{"Authorization": {"Bearer secret"}}})
	if err != nil {
		t.Fatal(err)
	}
	c := report.Classes[harness.ClassPDP]
	if !c.Conforms || c.Cases < 100 || report.Binding != "http" {
		t.Errorf("pdp = %+v", c)
	}
	// The HTTP binding has no capabilities: -name and -version name the implementation.
	path := filepath.Join(t.TempDir(), "report.json")
	code, stdout, stderr = runMain(t, "-header", "Authorization: Bearer secret", "-name", "Example PDP", "-version", "1.2.0",
		"-report", path, "-authzen", server.URL, "-control", server.URL+"/test/state")
	if code != harness.ExitConforms || !strings.Contains(stdout, `implementation: "Example PDP" "1.2.0"`) {
		t.Fatalf("with -name and -version: exit %d\n%s\n%s", code, stdout, stderr)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var written harness.Report
	if err := json.Unmarshal(data, &written); err != nil || written.Implementation != (harness.Described{Name: "Example PDP", Version: "1.2.0"}) {
		t.Errorf("implementation = %+v, %v", written.Implementation, err)
	}
	// Without the header the control resource refuses, and nothing conforms.
	code, _, _ = runMain(t, "-authzen", server.URL, "-control", server.URL+"/test/state")
	if code != harness.ExitFails {
		t.Errorf("without authorization: exit %d", code)
	}
}

func TestHTTPBindingDetectsDeviations(t *testing.T) {
	for name, mutate := range map[string]func(*evaluator.Result){
		"allows everything": func(r *evaluator.Result) { r.Decision, r.Reason = evaluator.Allow, evaluator.ReasonRule },
		"wrong reason": func(r *evaluator.Result) {
			if r.Reason == evaluator.ReasonNoMandate {
				r.Reason = evaluator.ReasonInvalidMandate
			}
		},
		"no rule":             func(r *evaluator.Result) { r.RuleID = "" },
		"enforces every deny": func(r *evaluator.Result) { r.NotEnforced = false },
		"enforces no deny":    func(r *evaluator.Result) { r.NotEnforced = r.Decision == evaluator.Deny },
		"never confirms":      func(r *evaluator.Result) { r.Confirm = false },
	} {
		pdp := &harness.ReferencePDP{Mutate: mutate}
		server := httptest.NewServer(pdp.Handler())
		report, err := harness.RunPDP(context.Background(), spec.FS(), harness.PDP{AuthZEN: server.URL, Control: server.URL + "/test/state"})
		server.Close()
		if err != nil {
			t.Fatal(err)
		}
		if c := report.Classes[harness.ClassPDP]; c.Conforms || c.Failed == 0 {
			t.Errorf("%s: pdp = %+v, want failures", name, c)
		}
	}
}

func TestHTTPBindingReportsAnUnreachablePDP(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	report, err := harness.RunPDP(ctx, spec.FS(), harness.PDP{AuthZEN: server.URL, Control: server.URL, Client: &http.Client{Timeout: time.Second}})
	if err != nil {
		t.Fatal(err)
	}
	if c := report.Classes[harness.ClassPDP]; c.Conforms || c.Passed != 0 {
		t.Errorf("pdp = %+v, want no passed case", c)
	}
	garbage := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "nope") }))
	defer garbage.Close()
	report, _ = harness.RunPDP(ctx, spec.FS(), harness.PDP{AuthZEN: garbage.URL, Control: garbage.URL})
	if c := report.Classes[harness.ClassPDP]; c.Passed != 0 {
		t.Errorf("garbage answers: pdp = %+v", c)
	}
}

// The reference PDP of mandate-harness -serve-authzen: on loopback only, and the class pdp
// conforms against it (SPEC-v0 section 10.3).
func TestServeAuthZEN(t *testing.T) {
	for _, addr := range []string{"0.0.0.0:0", "192.0.2.1:0", "localhost:0", "no port"} {
		if err := harness.ServeAuthZEN(context.Background(), addr, "", io.Discard); err == nil {
			t.Errorf("%s: served", addr)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	ready, write := io.Pipe()
	done := make(chan error, 1)
	go func() { done <- harness.ServeAuthZEN(ctx, "127.0.0.1:0", "secret", write) }()
	line, err := bufio.NewReader(ready).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	var authzen, control string
	if _, err := fmt.Sscanf(line, "-authzen %s -control %s", &authzen, &control); err != nil {
		t.Fatalf("ready line %q: %v", line, err)
	}
	report, err := harness.RunPDP(ctx, spec.FS(), harness.PDP{AuthZEN: authzen, Control: control, Header: http.Header{"Authorization": {"Bearer secret"}}})
	if err != nil {
		t.Fatal(err)
	}
	if !report.Conforms(harness.ClassPDP) {
		t.Errorf("pdp = %+v", report.Classes[harness.ClassPDP])
	}
	cancel()
	if err := <-done; err != nil {
		t.Errorf("ServeAuthZEN after cancel: %v", err)
	}
	if err := harness.ServeAuthZEN(context.Background(), "127.0.0.1:0", "", errorWriter{}); err == nil {
		t.Error("served although the ready line could not be written")
	}
}

type errorWriter struct{}

func (errorWriter) Write([]byte) (int, error) { return 0, errors.New("closed") }

func TestHarnessMain(t *testing.T) {
	for _, args := range [][]string{{"extra"}, {"-token", "t"}, {"-unknown"}} {
		var stderr bytes.Buffer
		if code := harness.HarnessMain(context.Background(), args, strings.NewReader(""), io.Discard, &stderr); code != harness.ExitUsage || !strings.Contains(stderr.String(), "usage") {
			t.Errorf("%v: exit %d, stderr %q", args, code, stderr.String())
		}
	}
	var stdout, stderr bytes.Buffer
	if code := harness.HarnessMain(context.Background(), nil, strings.NewReader(`{"op":"capabilities"}`+"\n"), &stdout, &stderr); code != harness.ExitConforms || !strings.Contains(stdout.String(), "reference") {
		t.Errorf("process binding: exit %d, stdout %q, stderr %q", code, stdout.String(), stderr.String())
	}
	if code := harness.HarnessMain(context.Background(), []string{"-serve-authzen", "0.0.0.0:0"}, nil, io.Discard, &stderr); code != harness.ExitFails {
		t.Errorf("serve on a public address: exit %d", code)
	}
}

// The reference PDP answers only requests to a loopback host, with a token if it has one, and
// reads at most a few MiB of a body.
func TestReferencePDPRefusesRebindingLargeBodiesAndWrongTokens(t *testing.T) {
	handler := (&harness.ReferencePDP{Token: "secret"}).Handler()
	for name, tt := range map[string]struct {
		host, auth string
		body       string
		want       int
	}{
		"rebound name": {"evil.example:8080", "Bearer secret", `{}`, http.StatusMisdirectedRequest},
		"no host port": {"localhost", "Bearer secret", `{}`, http.StatusMisdirectedRequest},
		"wrong token":  {"127.0.0.1:8080", "Bearer secreT", `{}`, http.StatusUnauthorized},
		"large body":   {"[::1]:8080", "Bearer secret", `{"time":"` + strings.Repeat("x", 5<<20) + `"}`, http.StatusBadRequest},
		"good":         {"127.0.0.1:8080", "Bearer secret", `{"mandates":[],"directory":[],"time":"2026-10-12T19:00:00+02:00"}`, http.StatusNoContent},
	} {
		req := httptest.NewRequest(http.MethodPut, "/test/state", strings.NewReader(tt.body))
		req.Host = tt.host
		req.Header.Set("Authorization", tt.auth)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != tt.want {
			t.Errorf("%s: status %d, want %d", name, rec.Code, tt.want)
		}
	}
}

// SPDX-License-Identifier: Apache-2.0

package harness_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	mandatespec "github.com/mandate-spec/mandate-spec"
	"github.com/mandate-spec/mandate-spec/evaluator"
	"github.com/mandate-spec/mandate-spec/internal/harness"
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
	code := harness.Main(context.Background(), mandatespec.FS(), args, &stdout, &stderr)
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
	} {
		if code, _, stderr := runMain(t, args...); code != harness.ExitUsage || !strings.Contains(stderr, "usage") {
			t.Errorf("%s: exit %d, stderr %q", name, code, stderr)
		}
	}
}

// referencePDP is a PDP with the HTTP binding of the test interface, built on the
// reference evaluator. mutate lets a test make it deviate.
type referencePDP struct {
	mu     sync.Mutex
	state  harness.State
	mutate func(*evaluator.Result)
	token  string
}

func (p *referencePDP) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("PUT /test/state", func(w http.ResponseWriter, r *http.Request) {
		if p.token != "" && r.Header.Get("Authorization") != "Bearer "+p.token {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var state harness.State
		if err := json.NewDecoder(r.Body).Decode(&state); err != nil {
			http.Error(w, "bad state", http.StatusBadRequest)
			return
		}
		p.mu.Lock()
		p.state = state
		p.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /access/v1/evaluation", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Subject struct {
				Type       string            `json:"type"`
				ID         string            `json:"id"`
				Properties map[string]string `json:"properties"`
			} `json:"subject"`
			Action struct {
				Name       string                 `json:"name"`
				Properties map[string]json.Number `json:"properties"`
			} `json:"action"`
			Resource struct {
				ID string `json:"id"`
			} `json:"resource"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		p.mu.Lock()
		state := p.state
		p.mu.Unlock()
		// The PDP takes category, area and the critical marking from its directory.
		resource := harness.Resource{EntityID: req.Resource.ID}
		for _, known := range state.Directory {
			if known.EntityID == req.Resource.ID {
				resource = known
			}
		}
		answer := harness.Answer(harness.Request{Op: harness.OpSelect, Mandates: state.Mandates,
			Subject: &harness.Subject{ClientID: req.Subject.ID, Principal: req.Subject.Properties["principal"]},
			Request: &harness.Evaluation{Resource: resource, Action: req.Action.Name, Parameters: req.Action.Properties,
				Time: state.Time, Timezone: state.Timezone}})
		result := evaluator.Result{Decision: evaluator.Decision(answer.Decision), Reason: evaluator.Reason(answer.Reason)}
		if answer.RuleID != nil {
			result.RuleID = *answer.RuleID
		}
		if p.mutate != nil {
			p.mutate(&result)
		}
		context := map[string]any{"outcome": result.Decision, "reason": result.Reason}
		if result.RuleID != "" {
			context["rule_id"] = result.RuleID
		}
		if answer.ApprovalTimeout != "" {
			context["approval_timeout"], context["approvers"] = answer.ApprovalTimeout, answer.Approvers
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"decision": result.Decision == evaluator.Allow, "context": context})
	})
	return mux
}

func TestHTTPBindingAgainstAReferencePDP(t *testing.T) {
	pdp := &referencePDP{token: "secret"}
	server := httptest.NewServer(pdp.handler())
	defer server.Close()
	code, stdout, stderr := runMain(t, "-header", "Authorization: Bearer secret", "-authzen", server.URL, "-control", server.URL+"/test/state")
	if code != harness.ExitConforms {
		t.Fatalf("exit %d\n%s\n%s", code, stdout, stderr)
	}
	report, err := harness.RunPDP(context.Background(), mandatespec.FS(), harness.PDP{AuthZEN: server.URL + "/", Control: server.URL + "/test/state",
		Header: http.Header{"Authorization": {"Bearer secret"}}})
	if err != nil {
		t.Fatal(err)
	}
	c := report.Classes[harness.ClassPDP]
	if !c.Conforms || c.Cases < 100 || report.Binding != "http" {
		t.Errorf("pdp = %+v", c)
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
		"no rule": func(r *evaluator.Result) { r.RuleID = "" },
	} {
		pdp := &referencePDP{mutate: mutate}
		server := httptest.NewServer(pdp.handler())
		report, err := harness.RunPDP(context.Background(), mandatespec.FS(), harness.PDP{AuthZEN: server.URL, Control: server.URL + "/test/state"})
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
	report, err := harness.RunPDP(ctx, mandatespec.FS(), harness.PDP{AuthZEN: server.URL, Control: server.URL, Client: &http.Client{Timeout: time.Second}})
	if err != nil {
		t.Fatal(err)
	}
	if c := report.Classes[harness.ClassPDP]; c.Conforms || c.Passed != 0 {
		t.Errorf("pdp = %+v, want no passed case", c)
	}
	garbage := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "nope") }))
	defer garbage.Close()
	report, _ = harness.RunPDP(ctx, mandatespec.FS(), harness.PDP{AuthZEN: garbage.URL, Control: garbage.URL})
	if c := report.Classes[harness.ClassPDP]; c.Passed != 0 {
		t.Errorf("garbage answers: pdp = %+v", c)
	}
}

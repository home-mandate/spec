// SPDX-License-Identifier: Apache-2.0

package harness

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/home-mandate/spec/evaluator"
)

// Bounds of the reference PDP: a request's headers, its whole body and the answer, an idle
// connection, and the size of a body. A state with every mandate of a case is far smaller.
const (
	readHeaderTimeout = 10 * time.Second
	requestTimeouts   = 30 * time.Second
	idleTimeout       = time.Minute
	maxBodyBytes      = 4 << 20
)

// ServeAuthZEN offers the reference PDP over the HTTP binding on addr, an address on the
// loopback interface such as 127.0.0.1:8080, until ctx ends. The control resource lets its
// caller replace every mandate (SPEC-v0 section 10.3), so the reference listens on loopback
// only; token, if set, is required on the control resource as well. ready receives the
// arguments that mandate-conformance needs.
func ServeAuthZEN(ctx context.Context, addr, token string, ready io.Writer) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("harness: address %q: %w", addr, err)
	}
	if ip, err := netip.ParseAddr(host); err != nil || !ip.IsLoopback() {
		return fmt.Errorf("harness: %q is not a loopback address; the control resource replaces every mandate", host)
	}
	var config net.ListenConfig
	listener, err := config.Listen(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("harness: %w", err)
	}
	base := "http://" + listener.Addr().String()
	if _, err := fmt.Fprintf(ready, "-authzen %s -control %s/test/state\n", base, base); err != nil {
		_ = listener.Close()
		return fmt.Errorf("harness: %w", err)
	}
	server := &http.Server{Handler: (&ReferencePDP{Token: token}).Handler(), ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout: requestTimeouts, WriteTimeout: requestTimeouts, IdleTimeout: idleTimeout}
	serving, stop := context.WithCancel(ctx)
	defer stop()
	stopped := make(chan error, 1)
	go func() {
		<-serving.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), readHeaderTimeout)
		defer cancel()
		stopped <- server.Shutdown(shutdown)
	}()
	if err := server.Serve(listener); !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("harness: %w", err)
	}
	return <-stopped
}

// loopbackHost refuses a request whose Host is not an address on the loopback interface, so
// that a web page that rebinds a name to 127.0.0.1 cannot reach the control resource.
func loopbackHost(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.Host)
		if err != nil {
			host = r.Host
		}
		if ip, err := netip.ParseAddr(host); err != nil || !ip.IsLoopback() {
			http.Error(w, "host is not a loopback address", http.StatusMisdirectedRequest)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ReferencePDP is a PDP with the HTTP binding of the test interface (SPEC-v0 section 10.3),
// built on the reference evaluator: the control resource at /test/state and the AuthZEN API
// at /access/v1/evaluation.
type ReferencePDP struct {
	// Token, if set, is the bearer token the control resource requires.
	Token string
	// Mutate, if set, changes every result before it is sent, so that a test can make the
	// PDP deviate. It is read without a lock: set it before Handler is used, never while
	// requests are served.
	Mutate func(*evaluator.Result)

	mu     sync.Mutex
	state  State
	limits *pdpLimits
}

// Handler serves the control resource and the AuthZEN API.
func (p *ReferencePDP) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("PUT /test/state", func(w http.ResponseWriter, r *http.Request) {
		if p.Token != "" && subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+p.Token)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var state State
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes)).Decode(&state); err != nil {
			http.Error(w, "bad state", http.StatusBadRequest)
			return
		}
		p.mu.Lock()
		p.state, p.limits = state, newPDPLimits(state.Time)
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
				Name       string                     `json:"name"`
				Properties map[string]json.RawMessage `json:"properties"`
			} `json:"action"`
			Resource struct {
				Type string `json:"type"`
				ID   string `json:"id"`
			} `json:"resource"`
		}
		// AuthZEN requires resource.type (SPEC-v0 section 10.3); a strict PDP refuses without it.
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes)).Decode(&req); err != nil || req.Resource.Type == "" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		p.mu.Lock()
		state, limits := p.state, p.limits
		if limits == nil {
			limits = newPDPLimits(state.Time)
			p.limits = limits
		}
		p.mu.Unlock()
		// The PDP takes category, areas and the critical marking from its directory.
		resource := Resource{EntityID: req.Resource.ID}
		for _, known := range state.Directory {
			if known.EntityID == req.Resource.ID {
				resource = known
			}
		}
		subject := Subject{ClientID: req.Subject.ID, Principal: req.Subject.Properties["principal"]}
		answer := Answer(Request{Op: OpSelect, Mandates: state.Mandates, Subject: &subject,
			Request: &Evaluation{Resource: resource, Action: req.Action.Name, Parameters: req.Action.Properties,
				Time: state.Time, Timezone: state.Timezone}})
		result := evaluator.Result{Decision: evaluator.Decision(answer.Decision), Reason: evaluator.Reason(answer.Reason)}
		if answer.RuleID != nil {
			result.RuleID = *answer.RuleID
		}
		result.NotEnforced = answer.Enforced != nil && !*answer.Enforced
		result.Confirm = answer.Confirm
		if p.Mutate != nil {
			p.Mutate(&result)
		}
		context := map[string]any{"outcome": result.Decision, "reason": result.Reason}
		if result.RuleID != "" {
			context["rule_id"] = result.RuleID
		}
		if result.NotEnforced {
			context["enforced"] = false
		}
		if result.Confirm {
			context["confirm"] = true
		}
		if answer.ApprovalTimeout != "" {
			context["approval_timeout"], context["approvers"] = answer.ApprovalTimeout, answer.Approvers
		}
		if answer.MandateDigest != "" {
			context["mandate_digest"] = answer.MandateDigest
		}
		if answer.Selected != nil {
			context["mandate_id"] = *answer.Selected
		}
		decision := result.Decision == evaluator.Allow
		// A PDP apart from its PEP enforces the rate limits (SPEC-v0 sections 6 and 11.2).
		switch limits.check(state, subject, answer) {
		case deniedBeforeEvaluation:
			context = map[string]any{"denied_by": "rate_limit"}
			if answer.Selected != nil && ownLimit(state, answer) != nil {
				context["mandate_id"], context["mandate_digest"] = *answer.Selected, answer.MandateDigest
			}
			decision = false
		case deniedAfterEvaluation:
			context["denied_by"] = "rate_limit"
			decision = false
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"decision": decision, "context": context})
	})
	return loopbackHost(mux)
}

// HarnessMain is mandate-harness (cmd/mandate-harness): without arguments the process binding
// on stdin and stdout, with -serve-authzen the reference PDP until ctx ends. It returns the
// exit code.
func HarnessMain(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("mandate-harness", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	authzen := flags.String("serve-authzen", "", "offer the reference PDP over the HTTP binding on this loopback address")
	token := flags.String("token", "", "with -serve-authzen: bearer token the control resource requires")
	if err := flags.Parse(args); err != nil || flags.NArg() > 0 || *authzen == "" && *token != "" {
		fmt.Fprintln(stderr, "usage: mandate-harness [-serve-authzen address [-token token]]")
		return ExitUsage
	}
	var err error
	if *authzen != "" {
		err = ServeAuthZEN(ctx, *authzen, *token, stderr)
	} else {
		err = Serve(stdin, stdout)
	}
	if err != nil {
		fmt.Fprintln(stderr, "mandate-harness:", err)
		return ExitFails
	}
	return ExitConforms
}

// SPDX-License-Identifier: Apache-2.0

package liveconf

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"
)

// The DNS hook sets and removes the one TXT record, _home-mandate-relay.<own domain>, that the
// operator looks for (RELAY-v0 section 6.4). It is called without a shell:
//
//	<command> set <name> <value>
//	<command> delete <name>
//
// The command line is split at blanks, with no quoting. The arguments are not trustworthy
// text for a script: the tool checks them (a name is a DNS name, a value base64url that does
// not begin with "-"), but a hook MUST treat them as data and never as commands or options.
// The hook gets an empty input and a minimal environment (PATH and LC_ALL), runs in a
// process group of its own that the tool kills on a timeout, and its output is capped.
const (
	hookOutputMax = 4 << 10
	hookWaitDelay = 2 * time.Second
	hookPath      = "/usr/local/bin:/usr/bin:/bin"
	placeholder   = "home-mandate-conformance-placeholder"
	// proofLabel is the label before an own-domain name where the operator looks for the token.
	proofLabel = "_home-mandate-relay."
)

var (
	hookNamePattern  = regexp.MustCompile(`^[a-z0-9_][a-z0-9_.-]{0,252}$`)
	hookValuePattern = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_-]{0,127}$`)
	// tokenPattern is the token of an own-domain name (RELAY-v0 schema $defs/installation).
	tokenPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{22,128}$`)
)

// dnsHook sets and removes the TXT record of the tester.
type dnsHook interface {
	Set(ctx context.Context, name, value string) error
	Delete(ctx context.Context, name string) error
}

var errHookArgument = errors.New("the DNS hook was given a name or value it does not accept")

// validToken reports whether the token of an operator is one the hook can be given.
func validToken(token string) bool {
	return tokenPattern.MatchString(token) && hookValuePattern.MatchString(token)
}

// execHook runs a command.
type execHook struct {
	argv    []string
	timeout time.Duration
}

func newExecHook(commandLine string, timeout time.Duration) dnsHook {
	return &execHook{argv: strings.Fields(commandLine), timeout: timeout}
}

func (h *execHook) Set(ctx context.Context, name, value string) error {
	if !hookNamePattern.MatchString(name) || !hookValuePattern.MatchString(value) {
		return errHookArgument
	}
	return h.run(ctx, "set", name, value)
}

func (h *execHook) Delete(ctx context.Context, name string) error {
	if !hookNamePattern.MatchString(name) {
		return errHookArgument
	}
	return h.run(ctx, "delete", name)
}

// capBuffer keeps the first bytes that are written to it and drops the rest.
type capBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (c *capBuffer) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if room := hookOutputMax - c.buf.Len(); room > 0 {
		c.buf.Write(p[:min(len(p), room)])
	}
	return len(p), nil
}

func (c *capBuffer) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.String()
}

func (h *execHook) run(ctx context.Context, args ...string) error {
	ctx, cancel := context.WithTimeout(ctx, h.timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, h.argv[0], append(append([]string{}, h.argv[1:]...), args...)...)
	cmd.Env = []string{"PATH=" + hookPath, "LC_ALL=C"}
	out := &capBuffer{}
	var sink io.Writer = out
	cmd.Stdout, cmd.Stderr = sink, sink
	cmd.WaitDelay = hookWaitDelay
	isolate(cmd)
	err := cmd.Run()
	killGroup(cmd)
	switch {
	case err == nil:
		return nil
	case ctx.Err() != nil:
		return fmt.Errorf("the DNS hook did not finish in %s and was killed", h.timeout)
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return fmt.Errorf("the DNS hook failed (%s): %s", exit.ProcessState, esc(out.String()))
	}
	return errors.New("the DNS hook could not be started")
}

// manualHook asks the tester to set the record by hand and waits for it to show (the caller
// waits).
type manualHook struct{ out io.Writer }

func (h manualHook) Set(_ context.Context, name, value string) error {
	if !hookNamePattern.MatchString(name) || !hookValuePattern.MatchString(value) {
		return errHookArgument
	}
	_, err := fmt.Fprintf(h.out, "relay-conformance: set the TXT record %s to %q in the zone of the own domain (one record, replacing any other)\n", name, value)
	return err
}

func (h manualHook) Delete(_ context.Context, name string) error {
	if !hookNamePattern.MatchString(name) {
		return errHookArgument
	}
	_, err := fmt.Fprintf(h.out, "relay-conformance: remove the TXT record %s\n", name)
	return err
}

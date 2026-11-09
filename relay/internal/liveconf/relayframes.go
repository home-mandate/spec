// SPDX-License-Identifier: Apache-2.0

package liveconf

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/home-mandate/spec/relay/internal/frames"
	"github.com/home-mandate/spec/relay/internal/tunnelclient"
)

// framesCases plays the cases of frames-v0.json whose defect comes from the gateway and whose
// outcome does not depend on timing: each is sent on a control connection of its own, and the
// relay has to end it (RELAY-v0 section 4.9). Cases of pins belong to the check pins.
func (rl *relayRun) framesCases(ctx context.Context) error {
	plays := playableFrames()
	cred := newest(rl.s.insts[0])
	problems := map[string][]string{}
	for _, play := range plays {
		problem, err := rl.playFrames(ctx, play, &cred.cert)
		if err != nil {
			return err
		}
		rl.reached[play.kind] = true
		if problem != "" && len(problems[play.kind]) < maxProblems {
			problems[play.kind] = append(problems[play.kind], play.id+": "+problem)
		}
	}
	for _, kind := range []string{CheckRelayFrames, CheckRelayPins} {
		if rl.reached[kind] {
			rl.note(kind, strings.Join(problems[kind], ", "))
		}
	}
	return nil
}

// playFrames sends the frames of a case and says what is wrong with the relay's reaction to the
// last, "" if it ends the connection.
func (rl *relayRun) playFrames(ctx context.Context, play livePlay, cert *tls.Certificate) (string, error) {
	ctl, err := rl.t.dialControl(ctx, rl.t.params(cert))
	if err != nil {
		return "", netProblem(err)
	}
	defer ctl.Close()
	if err := rl.t.beforeControl(ctx); err != nil {
		return "", incompleteFor(err)
	}
	rest := play.frames
	if len(rest) > 1 {
		if err := ctl.Hello(); err != nil {
			return "", ctxProblem(ctx)
		}
		// A hello-ack that breaks the rules is the business of the check hello.
		if _, err := ctl.Recv(rl.t.timing.Tunnel); err != nil && !errors.Is(err, frames.ErrFrame) {
			return "no hello-ack before the frames of the case (" + ackProblem(err) + ")", nil
		}
		rest = rest[1:]
	}
	for _, raw := range rest {
		if err := ctl.Write(raw); err != nil {
			// The relay has closed the connection already.
			return "", nil
		}
	}
	if _, closed := ctl.Drain(rl.t.timing.Close); !closed {
		return "the relay did not end the connection", nil
	}
	return "", nil
}

// opened is the result of opening a control connection.
type opened struct {
	ctl *tunnelclient.Control
	// code is the code of an error frame the relay sent instead of hello-ack, 0 if none.
	code int
	// problem says what went wrong otherwise, "" if the connection is open and acknowledged.
	problem string
}

// openSession opens a control connection with the certificate and reads the answer to hello.
func (rl *relayRun) openSession(ctx context.Context, cert *tls.Certificate) (opened, error) {
	ctl, err := rl.t.dialControl(ctx, rl.t.params(cert))
	if err != nil {
		if fatal := netProblem(err); fatal != nil {
			return opened{}, fatal
		}
		return opened{problem: "the relay refused a TLS connection with a valid tunnel certificate"}, nil
	}
	return rl.greet(ctx, ctl)
}

// greet sends hello on an open control connection and reads the answer. A hello that cannot be
// written while the run is alive is a problem of the relay, not an empty result.
func (rl *relayRun) greet(ctx context.Context, ctl *tunnelclient.Control) (opened, error) {
	if err := rl.t.hello(ctx, ctl); err != nil {
		ctl.Close()
		if fatal := ctxProblem(ctx); fatal != nil {
			return opened{}, fatal
		}
		return opened{problem: "hello could not be sent on the control connection"}, nil
	}
	_, err := ctl.Recv(rl.t.timing.Tunnel)
	var relayErr *tunnelclient.RelayError
	switch {
	case errors.As(err, &relayErr):
		return opened{ctl: ctl, code: relayErr.Code}, nil
	case err != nil:
		ctl.Close()
		return opened{problem: ackProblem(err)}, nil
	}
	ctl.Run()
	return opened{ctl: ctl}, nil
}

// session checks the rules for several control connections of one installation (RELAY-v0 section
// 4.4): the same certificate again is session-exists, and a certificate with a later notBefore
// replaces the connection, whose gateway gets superseded.
func (rl *relayRun) session(ctx context.Context) error {
	a := rl.s.insts[0]
	older, newer := oldest(a), newest(a)
	first, err := rl.openSession(ctx, &older.cert)
	if err != nil {
		return err
	}
	if first.ctl == nil || first.code != 0 {
		rl.note(CheckRelayHello, first.problem)
		if first.ctl != nil {
			first.ctl.Close()
			rl.note(CheckRelaySession, fmt.Sprintf("the first control connection of an installation got error %d", first.code))
		}
		rl.stopped = true
		return nil
	}
	rl.sa, rl.saCred = first.ctl, older
	problem, err := rl.again(ctx, older)
	if err != nil {
		return err
	}
	if newer != older {
		more, err := rl.replace(ctx, newer)
		if err != nil {
			return err
		}
		problem += more
	}
	rl.note(CheckRelaySession, problem)
	return nil
}

// again opens a second control connection with the same certificate, which must be refused.
func (rl *relayRun) again(ctx context.Context, cred *tunnelCred) (string, error) {
	second, err := rl.openSession(ctx, &cred.cert)
	if err != nil {
		return "", err
	}
	defer func() {
		if second.ctl != nil {
			second.ctl.Close()
		}
	}()
	switch {
	case second.ctl == nil:
		return "a second control connection with the same certificate got no answer: " + second.problem, nil
	case second.code == frames.CodeSessionExists:
		return "", nil
	case second.code == 0:
		return "a second control connection with the same certificate was accepted instead of session-exists", nil
	}
	return fmt.Sprintf("a second control connection with the same certificate got error %d, want session-exists", second.code), nil
}

// replace opens a control connection with a newer certificate, which replaces the first.
func (rl *relayRun) replace(ctx context.Context, cred *tunnelCred) (string, error) {
	next, err := rl.openSession(ctx, &cred.cert)
	if err != nil {
		return "", err
	}
	if next.ctl == nil || next.code != 0 {
		if next.ctl != nil {
			next.ctl.Close()
		}
		return "; a control connection with a newer certificate was refused", nil
	}
	old := rl.sa
	defer old.Close() // whether it was superseded or not, the tool no longer holds it
	rl.sa, rl.olderCred, rl.saCred = next.ctl, rl.saCred, cred
	select {
	case <-old.Done():
	case <-time.After(rl.t.timing.Close):
		return "; the first control connection was not replaced by one with a newer certificate", nil
	}
	var relayErr *tunnelclient.RelayError
	if err := old.Err(); !errors.As(err, &relayErr) || relayErr.Code != frames.CodeSuperseded {
		return "; the replaced control connection did not get superseded", nil
	}
	return "", nil
}

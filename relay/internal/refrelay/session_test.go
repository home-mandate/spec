// SPDX-License-Identifier: Apache-2.0

package refrelay_test

import (
	"errors"
	"testing"
	"time"

	"github.com/home-mandate/spec/relay/internal/frames"
	"github.com/home-mandate/spec/relay/internal/refrelay"
	"github.com/home-mandate/spec/relay/internal/tunnelclient"
)

// errorOf reads what the relay sends on a control connection that has not started its reader.
func errorOf(t *testing.T, c *tunnelclient.Control) (tunnelclient.Event, bool) {
	t.Helper()
	events, closed := c.Drain(wait)
	for _, e := range events {
		if e.Type == "error" {
			return e, closed
		}
	}
	return tunnelclient.Event{}, closed
}

func TestASecondControlConnectionIsSessionExistsAndANewerCertificateReplacesTheFirst(t *testing.T) {
	w := newWorld(t, refrelay.Config{})
	first, newer := w.cert(homeA, 0), w.cert(homeA, time.Minute)
	old := w.session(&first)
	// The same certificate again, and an older one: the first stays.
	for name, c := range map[string]*struct{ offset time.Duration }{"same": {0}, "older": {-time.Minute}} {
		cert := w.cert(homeA, c.offset)
		_, msg, err := w.open(&cert)
		var relayErr *tunnelclient.RelayError
		if !asRelayError(err, &relayErr) || relayErr.Code != frames.CodeSessionExists || msg["type"] != "error" {
			t.Errorf("%s: %v, %v", name, msg, err)
		}
	}
	select {
	case <-old.Done():
		t.Fatal("the first connection ended")
	case <-time.After(100 * time.Millisecond):
	}
	// A newer certificate replaces it: the old connection gets superseded.
	second := w.session(&newer)
	select {
	case <-old.Done():
		var relayErr *tunnelclient.RelayError
		if !asRelayError(old.Err(), &relayErr) || relayErr.Code != frames.CodeSuperseded {
			t.Errorf("the old connection ended with %v", old.Err())
		}
	case <-time.After(wait):
		t.Fatal("the old connection was not replaced")
	}
	select {
	case <-second.Done():
		t.Error("the new connection ended")
	case <-time.After(50 * time.Millisecond):
	}
}

func TestADefectOfSessionExistsLetsBothConnectionsLive(t *testing.T) {
	w := newWorld(t, refrelay.Config{Faults: refrelay.NoSessionExists})
	cert := w.cert(homeA, 0)
	first := w.session(&cert)
	second := w.session(&cert)
	select {
	case <-first.Done():
		t.Error("the first connection ended")
	case <-second.Done():
		t.Error("the second connection ended")
	case <-time.After(150 * time.Millisecond):
	}
}

func TestAControlConnectionThatWasDrainedIsReplacedByAnyCertificate(t *testing.T) {
	w := newWorld(t, refrelay.Config{})
	cert := w.cert(homeA, time.Minute)
	first := w.session(&cert)
	drain, _ := frames.EncodeDrain(1, 5)
	if err := first.Write(drain); err != nil {
		t.Fatal(err)
	}
	// The drain has been read when a stream cannot be opened any more.
	deadline := time.Now().Add(wait)
	for time.Now().Before(deadline) {
		a := w.agent(nameA)
		if seen := tunnelclient.Observe(a, 100*time.Millisecond, 1); seen.Closed {
			break
		}
	}
	older := w.cert(homeA, 0)
	w.session(&older)
	select {
	case <-first.Done():
	case <-time.After(wait):
		t.Error("the drained connection was not replaced")
	}
}

func TestTheHeartbeatIsAnsweredAndAGatewayThatDoesNotAnswerIsClosed(t *testing.T) {
	w := newWorld(t, refrelay.Config{Heartbeat: 80 * time.Millisecond})
	cert := w.cert(homeA, 0)
	ctl, msg, err := w.open(&cert)
	if err != nil || msg["type"] != "hello-ack" {
		t.Fatal(msg, err)
	}
	// No reader runs: ping goes unanswered, and the relay ends the connection with timeout.
	e, closed := errorOf(t, ctl)
	if e.Code != frames.CodeTimeout || !closed {
		t.Errorf("%+v, closed %v", e, closed)
	}
}

func TestPingOfTheGatewayIsAnsweredWithAPong(t *testing.T) {
	w := newWorld(t, refrelay.Config{})
	cert := w.cert(homeA, 0)
	ctl, _, err := w.open(&cert)
	if err != nil {
		t.Fatal(err)
	}
	if err := ctl.Write(frames.EncodePing([8]byte{9, 8, 7, 6, 5, 4, 3, 2})); err != nil {
		t.Fatal(err)
	}
	events, closed := ctl.Drain(200 * time.Millisecond)
	if closed || len(events) != 1 || events[0].Type != "pong" {
		t.Errorf("%v, closed %v", events, closed)
	}
}

func TestAnErrorFrameOfTheGatewayEndsTheConnection(t *testing.T) {
	w := newWorld(t, refrelay.Config{})
	cert := w.cert(homeA, 0)
	ctl, _, _ := w.open(&cert)
	raw, _ := frames.EncodeError(frames.CodeInternal, "bye")
	if err := ctl.Write(raw); err != nil {
		t.Fatal(err)
	}
	if _, closed := ctl.Drain(wait); !closed {
		t.Error("the relay kept the connection after error")
	}
}

func TestAPinsFrameOfTheGatewayIsAnErrorExceptWithDefectR13(t *testing.T) {
	pins, _ := frames.EncodePins(1, [][frames.TokenSize]byte{{1}}, nil)
	for _, faulty := range []bool{false, true} {
		var faults refrelay.Fault
		if faulty {
			faults = refrelay.PinsFromGateway
		}
		w := newWorld(t, refrelay.Config{Faults: faults})
		cert := w.cert(homeA, 0)
		ctl, _, _ := w.open(&cert)
		if err := ctl.Write(pins); err != nil {
			t.Fatal(err)
		}
		events, closed := ctl.Drain(300 * time.Millisecond)
		if faulty == closed || (!faulty && len(events) != 1) || (faulty && len(events) != 0) {
			t.Errorf("faulty %v: %v, closed %v", faulty, events, closed)
		}
	}
}

func TestAnnouncedPinsAreAcknowledgedAndAWrongAckIsAnError(t *testing.T) {
	w := newWorld(t, refrelay.Config{AnnouncePins: true})
	cert := w.cert(homeA, 0)
	ctl, _, _ := w.open(&cert)
	events, _ := ctl.Drain(100 * time.Millisecond)
	if len(events) != 1 || events[0].Type != "pins" {
		t.Fatalf("events %v", events)
	}
	ack, _ := frames.EncodePinsAck(1, 1)
	if err := ctl.Write(ack); err != nil {
		t.Fatal(err)
	}
	if events, closed := ctl.Drain(100 * time.Millisecond); closed || len(events) != 0 {
		t.Errorf("after a right ack: %v, closed %v", events, closed)
	}
	wrong, _ := frames.EncodePinsAck(2, 1)
	if err := ctl.Write(wrong); err != nil {
		t.Fatal(err)
	}
	if _, closed := ctl.Drain(wait); !closed {
		t.Error("an ack for pins the relay did not send was accepted")
	}
}

func TestStreamCloseOfAnotherConnectionDoesNotVoidAToken(t *testing.T) {
	w := newWorld(t, refrelay.Config{})
	a, b := w.cert(homeA, 0), w.cert(homeB, 0)
	ca, cb := w.session(&a), w.session(&b)
	agentA, open := w.routed(ca, nameA)
	// B withdraws the token of A: nothing happens.
	if err := cb.StreamClose(open.Token, frames.ReasonRefused); err != nil {
		t.Fatal(err)
	}
	if seen := tunnelclient.Observe(agentA, 200*time.Millisecond, 1); seen.Closed {
		t.Error("another installation withdrew a token")
	}
	// An unknown token is ignored.
	if err := ca.StreamClose([32]byte{7}, frames.ReasonRefused); err != nil {
		t.Fatal(err)
	}
	// A withdraws its own: the agent connection is closed.
	if err := ca.StreamClose(open.Token, frames.ReasonRefused); err != nil {
		t.Fatal(err)
	}
	if seen := tunnelclient.Observe(agentA, wait, 1); !seen.Closed {
		t.Error("the agent connection of a withdrawn token stays open")
	}
}

func asRelayError(err error, target **tunnelclient.RelayError) bool {
	return errors.As(err, target)
}

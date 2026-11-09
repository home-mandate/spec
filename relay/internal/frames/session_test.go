// SPDX-License-Identifier: Apache-2.0

package frames

import (
	"errors"
	"testing"
)

func TestSessionFeedsFrameByFrameAndStaysFailed(t *testing.T) {
	s := NewSession()
	hello := ok(Hello{MinVersion: 1, MaxVersion: 1, Software: "g"}.Encode())
	ack := ok(HelloAck{Version: 1, Software: "r", Heartbeat: 30, MaxStreams: 1}.Encode())
	if s.Acked() {
		t.Error("acked before hello-ack")
	}
	for _, f := range []Frame{{Gateway, hello}, {Relay, ack}} {
		if _, err := s.Next(f); err != nil {
			t.Fatal(err)
		}
	}
	if !s.Acked() {
		t.Error("not acked after hello-ack")
	}
	_, first := s.Next(Frame{Gateway, hello})
	if !errors.Is(first, ErrFrame) {
		t.Fatalf("second hello: %v", first)
	}
	// Even a valid frame is refused after an error: there is no recovery from a framing error.
	if _, again := s.Next(Frame{Gateway, EncodePing([8]byte{1})}); again != first {
		t.Errorf("after an error: %v", again)
	}
}

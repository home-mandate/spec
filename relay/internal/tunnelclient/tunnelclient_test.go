// SPDX-License-Identifier: Apache-2.0

package tunnelclient_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/home-mandate/spec/relay/internal/frames"
	"github.com/home-mandate/spec/relay/internal/refrelay"
	"github.com/home-mandate/spec/relay/internal/tunnelclient"
)

func TestDialChecksThePinOfTheRelay(t *testing.T) {
	w := newWorld(t, refrelay.Config{})
	p := w.params(homeA, 0)
	c, err := tunnelclient.Dial(ctx(t), w.d, "relay.example:8443", p)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	p.Pins = []tunnelclient.Pin{{1}}
	if _, err := tunnelclient.Dial(ctx(t), w.d, "relay.example:8443", p); !errors.Is(err, tunnelclient.ErrPin) {
		t.Errorf("a wrong pin: %v", err)
	}
	p.Pins, p.AnyKey = nil, true
	c, err = tunnelclient.Dial(ctx(t), w.d, "relay.example:8443", p)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if c.Pin != w.pins()[0] {
		t.Error("the pin of the connection is not the pin of the relay's key")
	}
}

func TestDialFailsWhereTheDialerOrTheHandshakeFails(t *testing.T) {
	w := newWorld(t, refrelay.Config{})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	closedPort := tunnelclient.Params{ServerName: relayHost, AnyKey: true}
	d := w.d
	_ = d
	if _, err := tunnelclient.Dial(ctx(t), failingDialer{}, addr, closedPort); err == nil || errors.Is(err, tunnelclient.ErrHandshake) {
		t.Errorf("dialed through a dialer that fails: %v", err)
	}
	// A server that closes at once: the handshake fails.
	srv, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	go func() {
		for {
			c, err := srv.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	if _, err := tunnelclient.Dial(ctx(t), plainDialer{}, srv.Addr().String(), closedPort); !errors.Is(err, tunnelclient.ErrHandshake) {
		t.Errorf("handshake with a closing server: %v", err)
	}
	if _, err := tunnelclient.DialData(ctx(t), failingDialer{}, addr, closedPort, nil); err == nil {
		t.Error("DialData through a failing dialer")
	}
	if _, err := tunnelclient.OpenControl(ctx(t), failingDialer{}, addr, closedPort); err == nil {
		t.Error("OpenControl through a failing dialer")
	}
	if _, err := tunnelclient.DialAgent(ctx(t), failingDialer{}, addr); err == nil {
		t.Error("DialAgent through a failing dialer")
	}
}

type failingDialer struct{}

func (failingDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("no")
}

type plainDialer struct{}

func (plainDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, network, address)
}

func TestParsePin(t *testing.T) {
	w := newWorld(t, refrelay.Config{})
	if _, err := tunnelclient.ParsePin(w.relay.Pins()[0]); err != nil {
		t.Error(err)
	}
	for _, bad := range []string{"", "AAAA", "not base64!", w.relay.Pins()[0] + "="} {
		if _, err := tunnelclient.ParsePin(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestClosedTellsACloseFromATimeout(t *testing.T) {
	if tunnelclient.Closed(nil) || tunnelclient.Closed(context.DeadlineExceeded) {
		t.Error("nil or a deadline counts as a close")
	}
	if !tunnelclient.Closed(io.EOF) || !tunnelclient.Closed(io.ErrUnexpectedEOF) || !tunnelclient.Closed(errors.New("reset")) {
		t.Error("a close is not recognized")
	}
}

func TestControlConnectionAnswersTheHeartbeatAndSeesTheEnd(t *testing.T) {
	w := newWorld(t, refrelay.Config{Heartbeat: 100 * time.Millisecond})
	c := w.control(w.params(homeA, 0))
	c.Run()
	// Several intervals pass: a gateway that does not answer ping is closed after two.
	select {
	case <-c.Done():
		t.Fatalf("the connection ended: %v", c.Err())
	case <-time.After(600 * time.Millisecond):
	}
	if c.State().Version != tls.VersionTLS13 || c.State().CipherSuite == 0 || c.Pin() != w.pins()[0] {
		t.Error("state or pin of the connection")
	}
	w.relay.Close()
	select {
	case <-c.Done():
	case <-time.After(wait):
		t.Fatal("the end of the connection was not seen")
	}
	if !errors.Is(c.Err(), tunnelclient.ErrClosed) {
		t.Errorf("err %v", c.Err())
	}
	if _, err := c.WaitOpen(time.Second); !errors.Is(err, tunnelclient.ErrClosed) {
		t.Errorf("WaitOpen after the end: %v", err)
	}
}

func TestControlConnectionKeepsPinsAndAnswersThemAsIgnored(t *testing.T) {
	w := newWorld(t, refrelay.Config{AnnouncePins: true})
	c := w.control(w.params(homeA, 0))
	c.Run()
	deadline := time.Now().Add(wait)
	for len(c.Pins()) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	pins := c.Pins()
	if len(pins) != 1 || pins[0]["sequence"] != int64(1) {
		t.Fatalf("pins %v", pins)
	}
	// The relay accepted the answer: the connection is still open.
	select {
	case <-c.Done():
		t.Errorf("the relay ended the connection: %v", c.Err())
	case <-time.After(100 * time.Millisecond):
	}
}

func TestAnAgentConnectionIsBoundAndItsBytesAndEndsPassUnchanged(t *testing.T) {
	w := newWorld(t, refrelay.Config{})
	c := w.control(w.params(homeA, 0))
	c.Run()
	hello := tunnelclient.ClientHello(nameA)
	agent, err := tunnelclient.DialAgent(ctx(t), w.d, "relay.example:443", hello, []byte("request"))
	if err != nil {
		t.Fatal(err)
	}
	defer agent.Close()
	open, err := c.WaitOpen(wait)
	if err != nil || open.ValidityMS <= 0 {
		t.Fatalf("stream-open: %+v, %v", open, err)
	}
	data, err := tunnelclient.DialData(ctx(t), w.d, "relay.example:8443", w.params(homeA, 0), frames.EncodeDataBind(open.Token))
	if err != nil {
		t.Fatal(err)
	}
	defer data.Close()
	_ = data.SetReadDeadline(time.Now().Add(wait))
	proxy, err := tunnelclient.ReadPROXY(data)
	if err != nil || !proxy.Src.Addr().IsValid() {
		t.Fatalf("PROXY: %+v, %v", proxy, err)
	}
	got := make([]byte, len(hello)+len("request"))
	if _, err := io.ReadFull(data, got); err != nil || !bytes.Equal(got, append(append([]byte{}, hello...), "request"...)) {
		t.Fatalf("the agent's bytes: %v", err)
	}
	// The agent ends its direction; the gateway sees close_notify, then answers; the answer
	// arrives although the agent half-closed.
	if err := tunnelclient.CloseWrite(agent); err != nil {
		t.Fatal(err)
	}
	if n, err := data.Read(make([]byte, 1)); n != 0 || err != io.EOF || !data.ClosedWithNotify() {
		t.Fatalf("after the half close: %d, %v, close_notify %v", n, err, data.ClosedWithNotify())
	}
	if _, err := data.Write([]byte("response")); err != nil {
		t.Fatal(err)
	}
	if err := data.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	reply, err := io.ReadAll(agent)
	if err != nil || string(reply) != "response" {
		t.Fatalf("the reply: %q, %v", reply, err)
	}
}

func TestNegativeRoutingShowsAsAClosedAgentConnection(t *testing.T) {
	w := newWorld(t, refrelay.Config{})
	c := w.control(w.params(homeA, 0))
	c.Run()
	for name, sni := range map[string]string{"unknown": "unknown." + nameA, "no name": ""} {
		agent, err := tunnelclient.DialAgent(ctx(t), w.d, "relay.example:443", tunnelclient.ClientHello(sni))
		if err != nil {
			t.Fatal(err)
		}
		seen := tunnelclient.Observe(agent, wait, 8)
		_ = agent.Close()
		if !seen.Closed || len(seen.Bytes) != 0 {
			t.Errorf("%s: %+v", name, seen)
		}
	}
	if _, err := c.WaitOpen(100 * time.Millisecond); !errors.Is(err, tunnelclient.ErrTimeout) {
		t.Errorf("a stream-open for a name that is not served: %v", err)
	}
}

func TestStreamCloseWithdrawsATokenAndDrainSeesTheCloseAfterADefect(t *testing.T) {
	w := newWorld(t, refrelay.Config{})
	c := w.control(w.params(homeA, 0))
	c.Run()
	agent, err := tunnelclient.DialAgent(ctx(t), w.d, "relay.example:443", tunnelclient.ClientHello(nameA))
	if err != nil {
		t.Fatal(err)
	}
	defer agent.Close()
	open, err := c.WaitOpen(wait)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.StreamClose(open.Token, frames.ReasonRefused); err != nil {
		t.Fatal(err)
	}
	if seen := tunnelclient.Observe(agent, wait, 8); !seen.Closed {
		t.Errorf("the agent connection of a withdrawn token stays open: %+v", seen)
	}
	// A frame with a defect: a second connection of another certificate sends one, and the
	// relay closes.
	d := w.control(w.params(homeB, 0))
	bad, _ := frames.Raw(0x0000, nil)
	if err := d.Write(bad); err != nil {
		t.Fatal(err)
	}
	seen, closed := d.Drain(wait)
	if !closed || len(seen) != 1 || seen[0] != (tunnelclient.Event{Type: "error", Code: frames.CodeMalformed}) {
		t.Errorf("after a frame with a defect: saw %v, closed %v", seen, closed)
	}
}

func TestDrainGivesUpWhenNothingHappens(t *testing.T) {
	w := newWorld(t, refrelay.Config{})
	c := w.control(w.params(homeA, 0))
	if seen, closed := c.Drain(100 * time.Millisecond); closed || len(seen) != 0 {
		t.Errorf("seen %v, closed %v", seen, closed)
	}
	if _, err := c.Recv(50 * time.Millisecond); !errors.Is(err, tunnelclient.ErrTimeout) {
		t.Errorf("Recv: %v", err)
	}
}

func TestRecvReportsErrorFramesAndFramesTheGatewayRefuses(t *testing.T) {
	w := newWorld(t, refrelay.Config{})
	// A second control connection of the same certificate gets error session-exists.
	p := w.params(homeA, 0)
	w.control(p)
	c, err := tunnelclient.OpenControl(ctx(t), w.d, "relay.example:8443", p)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Hello(); err != nil {
		t.Fatal(err)
	}
	msg, err := c.Recv(wait)
	var relayErr *tunnelclient.RelayError
	if !errors.As(err, &relayErr) || relayErr.Code != frames.CodeSessionExists || msg["type"] != "error" || relayErr.Error() == "" {
		t.Errorf("%v, %v", msg, err)
	}
	// A relay that announces a heartbeat of 3 seconds sends a frame the gateway refuses.
	w2 := newWorld(t, refrelay.Config{Faults: refrelay.Heartbeat3})
	c2, err := tunnelclient.OpenControl(ctx(t), w2.d, "relay.example:8443", w2.params(homeA, 0))
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	if err := c2.Hello(); err != nil {
		t.Fatal(err)
	}
	if _, err := c2.Recv(wait); !errors.Is(err, frames.ErrFrame) {
		t.Errorf("hello-ack with a heartbeat of 3: %v", err)
	}
	// Run ends with that error too.
	w3 := newWorld(t, refrelay.Config{Faults: refrelay.Heartbeat3})
	c3, err := tunnelclient.OpenControl(ctx(t), w3.d, "relay.example:8443", w3.params(homeA, 0))
	if err != nil {
		t.Fatal(err)
	}
	defer c3.Close()
	if err := c3.Hello(); err != nil {
		t.Fatal(err)
	}
	c3.Run()
	select {
	case <-c3.Done():
	case <-time.After(wait):
		t.Fatal("no end")
	}
	if !errors.Is(c3.Err(), frames.ErrFrame) {
		t.Errorf("err %v", c3.Err())
	}
}

func TestHelloIsRefusedByItsOwnRulesOnlyIfBroken(t *testing.T) {
	w := newWorld(t, refrelay.Config{})
	c := w.control(w.params(homeA, 0))
	// A second hello breaks the rules of the connection: Hello refuses to send it.
	if err := c.Hello(); err == nil {
		t.Error("a second hello was sent")
	}
	// StreamClose is a frame of the gateway too; with an invalid reason it is refused.
	if err := c.StreamClose([32]byte{}, 300); err == nil {
		t.Error("an unencodable stream-close was sent")
	}
	c.Close()
	if err := c.Write([]byte{0, 0, 0, 0}); err == nil {
		// The first write after a close may still be accepted by the kernel.
		if err := c.Write(make([]byte, 1<<16)); err == nil {
			t.Error("writes to a closed connection succeed")
		}
	}
}

// closedConn is what a dialer returns for a connection that was closed at once.
type closedDialer struct{}

func (closedDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	a, b := net.Pipe()
	_ = a.Close()
	_ = b.Close()
	return a, nil
}

func TestWritesToAConnectionThatIsGoneFail(t *testing.T) {
	if _, err := tunnelclient.DialAgent(ctx(t), closedDialer{}, "x:1", []byte("a")); err == nil {
		t.Error("DialAgent wrote to a closed connection")
	}
	w := newWorld(t, refrelay.Config{})
	c := w.control(w.params(homeA, 0))
	c.Close()
	if err := c.StreamClose([32]byte{}, frames.ReasonRefused); err == nil {
		t.Error("StreamClose after Close")
	}
	if err := c.Write([]byte{0, 0, 0, 0}); err == nil {
		t.Error("Write after Close")
	}
	d, err := tunnelclient.OpenControl(ctx(t), w.d, "relay.example:8443", w.params(homeB, 0))
	if err != nil {
		t.Fatal(err)
	}
	d.Close()
	if err := d.Hello(); err == nil {
		t.Error("Hello after Close")
	}
}

func TestAGatewayWithoutACertificateIsRefusedAfterTheHandshake(t *testing.T) {
	w := newWorld(t, refrelay.Config{})
	p := w.params(homeA, 0)
	p.Cert = nil
	c, err := tunnelclient.OpenControl(ctx(t), w.d, "relay.example:8443", p)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.Hello()
	if _, err := c.Recv(wait); !errors.Is(err, tunnelclient.ErrClosed) {
		t.Errorf("without a certificate: %v", err)
	}
}

// stub is a TLS server that runs a function for each connection.
func stub(t *testing.T, serve func(*tls.Conn)) string {
	t.Helper()
	w := newWorld(t, refrelay.Config{})
	cert := w.reg.Issue(homeA, time.Now(), nil, nil)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				serve(c.(*tls.Conn))
			}()
		}
	}()
	return ln.Addr().String()
}

func TestAFrameOfMoreThan1024BytesFromTheRelayIsAnError(t *testing.T) {
	addr := stub(t, func(c *tls.Conn) {
		buf := make([]byte, 64)
		_, _ = c.Read(buf)
		_, _ = c.Write([]byte{0x00, 0x02, 0x04, 0x01})
		time.Sleep(200 * time.Millisecond)
	})
	c, err := tunnelclient.OpenControl(ctx(t), plainDialer{}, addr, tunnelclient.Params{ServerName: relayHost, AnyKey: true})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Hello(); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Recv(wait); !errors.Is(err, frames.ErrFrame) {
		t.Errorf("an oversized header: %v", err)
	}
}

func TestDrainReadsFramesWithoutTheRulesOfTheConnection(t *testing.T) {
	w := newWorld(t, refrelay.Config{Faults: refrelay.Heartbeat3})
	c, err := tunnelclient.OpenControl(ctx(t), w.d, "relay.example:8443", w.params(homeA, 0))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Hello(); err != nil {
		t.Fatal(err)
	}
	seen, closed := c.Drain(300 * time.Millisecond)
	if closed || len(seen) != 1 || seen[0].Type != "hello-ack" {
		t.Errorf("seen %v, closed %v", seen, closed)
	}
}

func TestDataConnectionThatCannotSendItsFirstFrameFails(t *testing.T) {
	addr := stub(t, func(c *tls.Conn) { _ = c.Close() })
	// The server closes after the handshake; a first frame that does not fit the buffers of the
	// connection ends in an error.
	_, err := tunnelclient.DialData(ctx(t), plainDialer{}, addr, tunnelclient.Params{ServerName: relayHost, AnyKey: true}, make([]byte, 16<<20))
	if err == nil {
		t.Error("a first frame of 16 MiB was sent to a closed connection")
	}
}

func TestTryOpenDoesNotWait(t *testing.T) {
	w := newWorld(t, refrelay.Config{})
	c := w.control(w.params(homeA, 0))
	c.Run()
	if _, ok := c.TryOpen(); ok {
		t.Error("a stream-open before an agent connection")
	}
	agent, err := tunnelclient.DialAgent(ctx(t), w.d, "relay.example:443", tunnelclient.ClientHello(nameA))
	if err != nil {
		t.Fatal(err)
	}
	defer agent.Close()
	deadline := time.Now().Add(wait)
	for time.Now().Before(deadline) {
		if _, ok := c.TryOpen(); ok {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Error("no stream-open")
}

// TestDialGivesUpOnARelayThatNeverAnswersTheHandshake: a connection that is accepted and then
// stays silent must not hold the run for as long as the run lasts.
func TestDialGivesUpOnARelayThatNeverAnswersTheHandshake(t *testing.T) {
	t.Parallel()
	srv, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	go func() {
		for {
			c, err := srv.Accept()
			if err != nil {
				return
			}
			defer c.Close()
		}
	}()
	start := time.Now()
	_, err = tunnelclient.Dial(ctx(t), plainDialer{}, srv.Addr().String(), tunnelclient.Params{ServerName: relayHost, AnyKey: true})
	if !errors.Is(err, tunnelclient.ErrHandshake) || time.Since(start) > 15*time.Second {
		t.Errorf("after %s: %v", time.Since(start), err)
	}
}

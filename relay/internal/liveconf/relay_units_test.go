// SPDX-License-Identifier: Apache-2.0

package liveconf

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/home-mandate/spec/relay/internal/frames"
	"github.com/home-mandate/spec/relay/internal/netguard"
	"github.com/home-mandate/spec/relay/internal/tunnelclient"
)

func TestTheCaseFilesOfTheClassRelayAreComplete(t *testing.T) {
	if n := len(loadCases[tlsProbe](tlsFile)); n != 14 {
		t.Errorf("%d probes, want 14", n)
	}
	if n := len(loadCases[bindingCase](bindingFile)); n != 16 {
		t.Errorf("%d binding cases, want 16", n)
	}
	plays := playableFrames()
	if len(plays) < 25 {
		t.Errorf("only %d cases of frames-v0.json are played", len(plays))
	}
	pins := 0
	for _, p := range plays {
		if p.kind == CheckRelayPins {
			pins++
		}
	}
	if pins != 1 {
		t.Errorf("%d cases of the check pins, want the one with pins from the gateway", pins)
	}
}

func TestPlayOfPlaysOnlyWhatDoesNotDependOnTiming(t *testing.T) {
	byID := map[string]framesCase{}
	for _, c := range loadCases[framesCase](framesFile) {
		byID[c.ID] = c
	}
	for id, want := range map[string]bool{
		"e07": true,  // hello with a trailing byte
		"e20": true,  // second hello
		"e68": true,  // data-bind on a control connection
		"e58": true,  // pins from the gateway
		"e69": true,  // hello with payload length 65535
		"f01": false, // a valid case
		"e19": false, // hello from the relay
		"e21": false, // hello-ack before hello
		"e35": false, // drain "before hello-ack": after the real hello-ack it is valid
		"e39": false, // a ping of the relay in the prefix
		"e64": false, // pins-ack: the relay may announce pins of its own
		"e72": true,
	} {
		_, err := playOf(byID[id])
		if (err == nil) != want {
			t.Errorf("%s: played %v, want %v", id, err == nil, want)
		}
	}
	if _, err := playOf(framesCase{}); !errors.Is(err, errNotPlayable) {
		t.Errorf("an empty case: %v", err)
	}
	bad := framesCase{Expected: "error", At: new(int), Frames: []struct {
		From string `json:"from"`
		Hex  string `json:"hex"`
	}{{From: frames.Gateway, Hex: "00"}}}
	if _, err := playOf(bad); err != nil {
		t.Errorf("a case with a short frame: %v", err)
	}
	*bad.At = 5
	if _, err := playOf(bad); !errors.Is(err, errNotPlayable) {
		t.Errorf("an index past the frames: %v", err)
	}
}

func TestSubstituteReplacesTheTokenAndKeepsTheDifferences(t *testing.T) {
	reference := bytes.Repeat([]byte{1}, 32)
	live := bytes.Repeat([]byte{0x40}, 32)
	same := append([]byte{0, 0x20, 0, 0x20}, reference...)
	if got := substitute(same, reference, live); !bytes.Equal(got[4:], live) || !bytes.Equal(got[:4], same[:4]) {
		t.Errorf("the same token: %x", got)
	}
	flipped := append([]byte{}, same...)
	flipped[len(flipped)-1] ^= 1
	if got := substitute(flipped, reference, live); got[35] != live[31]^1 || !bytes.Equal(got[4:35], live[:31]) {
		t.Errorf("the flipped token: %x", got)
	}
	longer := append(append([]byte{}, same...), 9)
	if got := substitute(longer, reference, live); got[36] != 9 {
		t.Error("a byte after the token was changed")
	}
	short := same[:10]
	if got := substitute(short, reference, live); len(got) != 10 {
		t.Error("a short frame changed its length")
	}
}

func TestOwnTokenFindsTheStateAndFallsBackToTheReference(t *testing.T) {
	cases := loadCases[bindingCase](bindingFile)
	byID := map[string]bindingCase{}
	for _, c := range cases {
		byID[c.ID] = c
	}
	for id, want := range map[string]string{"b01": "open", "b03": "used", "b04": "withdrawn", "b05": "expired", "b06": "open", "b08": "", "b13": ""} {
		c := byID[id]
		first := must(hexBytes(c.FirstBytes))
		state, _, ref := ownToken(c, first)
		if state != want || len(ref) != 32 {
			t.Errorf("%s: state %q, token of %d bytes", id, state, len(ref))
		}
	}
	// A case without any token of its own installation has the zero token as reference.
	if _, _, ref := ownToken(bindingCase{}, nil); !bytes.Equal(ref, make([]byte, 32)) {
		t.Error("no reference token")
	}
}

func hexBytes(s string) ([]byte, error) {
	var out []byte
	for i := 0; i+1 < len(s); i += 2 {
		var b byte
		if _, err := fmt.Sscanf(s[i:i+2], "%02x", &b); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, nil
}

func TestProblemTextsAreAsTheCheckMeansThem(t *testing.T) {
	for name, tt := range map[string]struct {
		got  string
		want string
	}{
		"closed":               {closedProblem(routed{closed: true}), ""},
		"closed with an alert": {closedProblem(routed{closed: true, bytes: []byte{0x15, 3, 3}}), ""},
		"stream-open":          {closedProblem(routed{opened: true}), "stream-open"},
		"TLS handshake":        {closedProblem(routed{closed: true, bytes: []byte{0x16, 3, 3}}), "TLS handshake"},
		"kept open":            {closedProblem(routed{}), "kept the connection open"},
		"valid ack":            {ackProblem(nil), ""},
		"no ack":               {ackProblem(tunnelclient.ErrTimeout), "no hello-ack"},
		"closed after hello":   {ackProblem(tunnelclient.ErrClosed), "closed the connection"},
		"error frame":          {ackProblem(&tunnelclient.RelayError{Code: 4}), "error 4"},
		"invalid ack":          {ackProblem(frames.ErrFrame), "breaks the rules"},
		"proxy fine":           {proxyProblem(nil), ""},
		"proxy content":        {proxyProblem(tunnelclient.ErrProxyContent), "addresses"},
		"proxy framing":        {proxyProblem(tunnelclient.ErrProxyFraming), "not of the form"},
		"no proxy":             {proxyProblem(io.EOF), "no PROXY header"},
	} {
		if !strings.Contains(tt.got, tt.want) || (tt.want == "" && tt.got != "") {
			t.Errorf("%s: %q, want %q", name, tt.got, tt.want)
		}
	}
	if got := mixedCase("ab.cd-9"); got != "Ab.cD-9" {
		t.Errorf("mixedCase = %q", got)
	}
}

func TestInstallationsWithoutCertificatesHaveNoNewestOrOldest(t *testing.T) {
	if newest(nil) != nil || oldest(nil) != nil || newest(&liveInst{}) != nil || oldest(&liveInst{}) != nil || credsOf(nil) != nil {
		t.Error("certificates out of nothing")
	}
	now := time.Now()
	inst := &liveInst{creds: []tunnelCred{{notBefore: now}, {notBefore: now.Add(time.Minute)}, {notBefore: now.Add(-time.Minute)}}}
	if !newest(inst).notBefore.Equal(now.Add(time.Minute)) || !oldest(inst).notBefore.Equal(now.Add(-time.Minute)) {
		t.Error("newest or oldest")
	}
}

func TestParsePinsLeavesOutWhatDoesNotParse(t *testing.T) {
	good := "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"
	if got := parsePins([]string{good, "short", "", good}); len(got) != 2 {
		t.Errorf("%d pins", len(got))
	}
}

func TestNewTunNeedsAHostAPortAndAnAddress(t *testing.T) {
	for name, tt := range map[string]struct {
		host      string
		port      int
		addresses []string
	}{"no host": {"", 8443, []string{"192.0.2.1"}}, "no port": {"h.example", 0, []string{"192.0.2.1"}}, "no address": {"h.example", 8443, nil}} {
		if _, err := newTun(Env{}, tt.host, tt.port, tt.addresses, nil); err == nil {
			t.Errorf("%s: a way to the relay was made", name)
		}
	}
	tn, err := newTun(Env{}, "h.example", 8443, []string{"2001:db8::1", "192.0.2.1"}, nil)
	if err != nil || tn.addr != "h.example:8443" || tn.agent != "[2001:db8::1]:443" {
		t.Errorf("%+v, %v", tn, err)
	}
}

func TestControlConnectionsStayWithinTheLimitOfTheRun(t *testing.T) {
	tn, _ := newTun(Env{Timing: Timing{ControlWindow: 150 * time.Millisecond}}, "h.example", 8443, []string{"192.0.2.1"}, nil)
	start := time.Now()
	for range MaxControlPerWindow {
		if err := tn.beforeControl(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if time.Since(start) > 100*time.Millisecond {
		t.Error("the first connections waited")
	}
	if err := tn.beforeControl(context.Background()); err != nil || time.Since(start) < 140*time.Millisecond {
		t.Errorf("the sixth connection did not wait for the window: %v after %s", err, time.Since(start))
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for range MaxControlPerWindow {
		_ = tn.beforeControl(ctx)
	}
	if err := tn.beforeControl(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("a waiting control connection ignores the end of the run: %v", err)
	}
	if err := tn.pace(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("pace: %v", err)
	}
}

func TestNetProblemKeepsTheHandshakeAsTheRelaysAnswer(t *testing.T) {
	if netProblem(nil) != nil || netProblem(fmt.Errorf("%w: x", tunnelclient.ErrHandshake)) != nil {
		t.Error("an answer of the relay is no problem of the network")
	}
	var inc *incompleteError
	if err := netProblem(netguard.ErrBlocked); !errors.As(err, &inc) || !strings.Contains(inc.reason, "cannot be reached (address)") {
		t.Errorf("a blocked address: %v", err)
	}
}

func TestAwaitReportsTheStateOfAnAgentConnection(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	// Nothing happens: the wait ends, nothing is closed, no stream-open came.
	ctl := &fakeOpener{}
	got := await(context.Background(), ctl, a, 50*time.Millisecond)
	if got.opened || got.closed || len(got.bytes) != 0 {
		t.Errorf("%+v", got)
	}
	go func() {
		_, _ = b.Write([]byte{0x15, 3, 3})
		_ = b.Close()
	}()
	got = await(context.Background(), ctl, a, time.Second)
	if got.opened || !got.closed || len(got.bytes) != 3 {
		t.Errorf("an alert and a close: %+v", got)
	}
	ctl.opens = []tunnelclient.Open{{ValidityMS: 7}}
	if got := await(context.Background(), ctl, a, time.Second); !got.opened || got.open.ValidityMS != 7 {
		t.Errorf("a stream-open: %+v", got)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c, d := net.Pipe()
	defer c.Close()
	defer d.Close()
	if got := await(ctx, ctl, c, time.Minute); got.closed || got.opened {
		t.Errorf("a cancelled wait: %+v", got)
	}
}

// fakeGateway is the gateway end of a stream as the check of the bytes reads it.
type fakeGateway struct {
	in       io.Reader
	out      bytes.Buffer
	writeErr error
	notified bool
	closed   bool
}

func (g *fakeGateway) Read(p []byte) (int, error) { return g.in.Read(p) }
func (g *fakeGateway) Write(p []byte) (int, error) {
	if g.writeErr != nil {
		return 0, g.writeErr
	}
	return g.out.Write(p)
}
func (g *fakeGateway) CloseWrite() error      { g.closed = true; return nil }
func (g *fakeGateway) ClosedWithNotify() bool { return g.notified }

// tcpPair returns the two ends of a TCP connection.
func tcpPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	done := make(chan net.Conn, 1)
	go func() {
		c, _ := l.Accept()
		done <- c
	}()
	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	s := <-done
	t.Cleanup(func() { _ = c.Close(); _ = s.Close() })
	return c.(*net.TCPConn), s.(*net.TCPConn)
}

func TestPassBytesNamesWhatIsWrongWithTheStream(t *testing.T) {
	rl := &relayRun{t: &tun{timing: Timing{Close: 300 * time.Millisecond}}}
	sent := []byte("hello and tail")
	for name, tt := range map[string]struct {
		gw    *fakeGateway
		agent func(*testing.T) (net.Conn, func())
		want  string
	}{
		"changed bytes":             {&fakeGateway{in: strings.NewReader("hello and TAIL")}, tcpAgent, "did not arrive unchanged"},
		"short bytes":               {&fakeGateway{in: strings.NewReader("hello")}, tcpAgent, "did not arrive unchanged"},
		"no half close":             {&fakeGateway{in: strings.NewReader("hello and tail")}, pipeAgent, "cannot half-close"},
		"data after the half close": {&fakeGateway{in: io.MultiReader(strings.NewReader("hello and tail"), strings.NewReader("more"))}, tcpAgent, "did not end the stream"},
		"no close_notify":           {&fakeGateway{in: strings.NewReader("hello and tail")}, tcpAgent, "not passed on as close_notify (the check assumes an unpadded record"},
		"cannot answer":             {&fakeGateway{in: strings.NewReader("hello and tail"), notified: true, writeErr: errors.New("gone")}, tcpAgent, "could not be sent"},
		"no answer back":            {&fakeGateway{in: strings.NewReader("hello and tail"), notified: true}, tcpAgent, "did not arrive unchanged after"},
	} {
		agent, cleanup := tt.agent(t)
		if got := rl.passBytes(agent, tt.gw, sent); !strings.Contains(got, tt.want) {
			t.Errorf("%s: %q, want %q", name, got, tt.want)
		}
		cleanup()
	}
}

func tcpAgent(t *testing.T) (net.Conn, func()) {
	a, _ := tcpPair(t)
	return a, func() {}
}

func pipeAgent(t *testing.T) (net.Conn, func()) {
	a, b := net.Pipe()
	return a, func() { _ = a.Close(); _ = b.Close() }
}

func TestSelfSignedTunnelCertificateHasTheNameOfATunnelCertificate(t *testing.T) {
	cert := selfSignedTunnel("op.example.net", "k7q2xwmpd4hj3n6rt5vbyc2ezu")
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil || leaf.CheckSignatureFrom(leaf) != nil && leaf.Issuer.String() != leaf.Subject.String() {
		t.Fatalf("%v", err)
	}
	if len(leaf.Extensions) == 0 || leaf.Issuer.String() != leaf.Subject.String() {
		t.Error("not self-signed with an extension")
	}
}

// fakeOpener has stream-opens only when a test puts them in.
type fakeOpener struct{ opens []tunnelclient.Open }

func (f *fakeOpener) TryOpen() (tunnelclient.Open, bool) {
	if len(f.opens) == 0 {
		return tunnelclient.Open{}, false
	}
	open := f.opens[0]
	f.opens = f.opens[1:]
	return open, true
}

func TestConnectionsToTheRelayArePacedAndStopWithTheRun(t *testing.T) {
	tn, _ := newTun(Env{Timing: Timing{Gap: 30 * time.Millisecond, Jitter: 5 * time.Millisecond, ControlWindow: time.Second}}, "h.example", 8443, []string{"192.0.2.1"}, nil)
	start := time.Now()
	for range 3 {
		if err := tn.pace(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if time.Since(start) < 55*time.Millisecond {
		t.Errorf("three connections in %s: no gap between them", time.Since(start))
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := tn.dialControl(ctx, tn.params(nil)); err == nil {
		t.Error("dialControl after the end of the run")
	}
	if _, err := tn.dialData(ctx, nil, nil); err == nil {
		t.Error("dialData after the end of the run")
	}
	if _, err := tn.dialAgent(ctx); err == nil {
		t.Error("dialAgent after the end of the run")
	}
}

// TestAHelloThatCannotBeWrittenIsAProblemAndNotAnEmptyResult: an empty result would make the check
// hello count as passed.
func TestAHelloThatCannotBeWrittenIsAProblemAndNotAnEmptyResult(t *testing.T) {
	addr, pin := serveStub(t, func(c *tls.Conn) { _, _ = io.Copy(io.Discard, c) })
	parsed, err := tunnelclient.ParsePin(pin)
	if err != nil {
		t.Fatal(err)
	}
	host, port, _ := net.SplitHostPort(addr)
	portNumber, _ := strconv.Atoi(port)
	env := Env{Net: netguard.Options{Policy: loopbackPolicy}, Timing: testTiming()}
	tn, err := newTun(env, host, portNumber, []string{host}, []tunnelclient.Pin{parsed})
	if err != nil {
		t.Fatal(err)
	}
	rl := &relayRun{t: tn}
	ctl, err := tn.dialControl(ctx(t), tn.params(nil))
	if err != nil {
		t.Fatal(err)
	}
	ctl.Close() // the connection is gone when hello is written
	got, err := rl.greet(ctx(t), ctl)
	if err != nil || got.ctl != nil || got.problem == "" {
		t.Errorf("result %+v, error %v", got, err)
	}
	// A run that has ended is no problem of the relay.
	ended, cancel := context.WithCancel(ctx(t))
	cancel()
	if _, err := rl.greet(ended, ctl); err == nil {
		t.Error("a hello after the end of the run")
	}
}

// TestTheSupersededControlConnectionIsClosedByTheTool: a relay that does not supersede leaves the
// first connection of the check session open; the tool must close it and not leave it behind.
func TestTheSupersededControlConnectionIsClosedByTheTool(t *testing.T) {
	t.Parallel()
	ack := must(frames.HelloAck{Version: 1, Software: "stub", Heartbeat: 30, MaxStreams: 8}.Encode())
	var open atomic.Int64
	runAgainstStub(t, func(c *tls.Conn) {
		open.Add(1)
		defer open.Add(-1)
		if readHello(c) {
			_, _ = c.Write(ack)
			_, _ = io.Copy(io.Discard, c)
		}
	})
	deadline := time.Now().Add(3 * time.Second)
	for open.Load() > 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if n := open.Load(); n != 0 {
		t.Errorf("%d connections are still open after the run", n)
	}
}

// endlessAgent is an agent connection that never stops sending and ignores deadlines.
type endlessAgent struct {
	net.Conn
	read atomic.Int64
}

func (e *endlessAgent) Read(p []byte) (int, error) {
	e.read.Add(int64(len(p)))
	return len(p), nil
}
func (e *endlessAgent) SetReadDeadline(time.Time) error { return nil }
func (e *endlessAgent) CloseWrite() error               { return nil }

func TestPassBytesReadsNoMoreThanTheReplyAndOneByte(t *testing.T) {
	a, _ := tcpPair(t)
	agent := &endlessAgent{Conn: a}
	rl := &relayRun{t: &tun{timing: Timing{Close: 300 * time.Millisecond}}}
	gw := &fakeGateway{in: strings.NewReader("hello and tail"), notified: true}
	done := make(chan string, 1)
	go func() { done <- rl.passBytes(agent, gw, []byte("hello and tail")) }()
	select {
	case got := <-done:
		if !strings.Contains(got, "did not arrive unchanged after") {
			t.Errorf("got %q", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("passBytes reads an endless answer without end")
	}
	if n := agent.read.Load(); n > replyBytes+1 {
		t.Errorf("read %d bytes, limit %d", n, replyBytes+1)
	}
}

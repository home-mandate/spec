// SPDX-License-Identifier: Apache-2.0

package refrelay_test

import (
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/home-mandate/spec/relay/internal/frames"
	"github.com/home-mandate/spec/relay/internal/refrelay"
	"github.com/home-mandate/spec/relay/internal/tunnelclient"
)

// bound binds the token with the certificate and reads the PROXY header.
func (w *world) bound(open tunnelclient.Open, cert *tls.Certificate) (*tunnelclient.Conn, tunnelclient.Proxy, error) {
	w.t.Helper()
	d := w.data(cert, frames.EncodeDataBind(open.Token))
	_ = d.SetReadDeadline(time.Now().Add(wait))
	p, err := tunnelclient.ReadPROXY(d)
	return d, p, err
}

func TestAnAgentConnectionIsRoutedByItsNameAndItsBytesPassUnchanged(t *testing.T) {
	w := newWorld(t, refrelay.Config{})
	cert := w.cert(homeA, 0)
	ctl := w.session(&cert)
	// The name is compared without regard to case.
	agent, open := w.routed(ctl, "K7Q2xwmpd4hj3n6rt5vbyc2ezu.Homes.Example.NET")
	if open.ValidityMS != 10000 {
		t.Errorf("validity %d", open.ValidityMS)
	}
	d, proxy, err := w.bound(open, &cert)
	if err != nil || proxy.Src.Addr() != netip.MustParseAddr("45.33.32.156") || proxy.Src.Port() == 0 {
		t.Fatalf("PROXY: %+v, %v", proxy, err)
	}
	got := make([]byte, 5)
	if _, err := io.ReadFull(d, got); err != nil || got[0] != 0x16 {
		t.Fatalf("the ClientHello does not come first: %x, %v", got, err)
	}
	// The rest of the ClientHello, then more bytes in both directions, and the ends.
	if _, err := agent.Write([]byte("payload")); err != nil {
		t.Fatal(err)
	}
	if err := tunnelclient.CloseWrite(agent); err != nil {
		t.Fatal(err)
	}
	rest, err := io.ReadAll(d)
	if err != nil || !bytes.HasSuffix(rest, []byte("payload")) || !d.ClosedWithNotify() {
		t.Fatalf("the agent's bytes and its end: %q, %v, close_notify %v", rest, err, d.ClosedWithNotify())
	}
	if _, err := d.Write([]byte("answer")); err != nil {
		t.Fatal(err)
	}
	if err := d.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	answer, err := io.ReadAll(agent)
	if err != nil || string(answer) != "answer" {
		t.Errorf("the answer: %q, %v", answer, err)
	}
}

func TestADefectOfCloseNotifyLeavesTheEndOfTheAgentUnmarked(t *testing.T) {
	w := newWorld(t, refrelay.Config{Faults: refrelay.NoCloseNotify})
	cert := w.cert(homeA, 0)
	ctl := w.session(&cert)
	agent, open := w.routed(ctl, nameA)
	d, _, err := w.bound(open, &cert)
	if err != nil {
		t.Fatal(err)
	}
	_ = tunnelclient.CloseWrite(agent)
	_ = d.SetReadDeadline(time.Now().Add(wait))
	if _, err := io.ReadAll(d); err != nil || d.ClosedWithNotify() {
		t.Errorf("the end of the agent without close_notify: %v, notified %v", err, d.ClosedWithNotify())
	}
}

func TestAnAbruptEndOfTheGatewayResetsTheAgent(t *testing.T) {
	w := newWorld(t, refrelay.Config{})
	cert := w.cert(homeA, 0)
	ctl := w.session(&cert)
	agent, open := w.routed(ctl, nameA)
	d, _, err := w.bound(open, &cert)
	if err != nil {
		t.Fatal(err)
	}
	_ = d.NetConn().Close()
	_ = agent.SetReadDeadline(time.Now().Add(wait))
	// A reset or an end: either way the agent sees the end of the stream.
	if seen := tunnelclient.Observe(agent, wait, 1); !seen.Closed {
		t.Error("the agent connection stays open")
	}
}

func TestAnAgentThatEndsFirstEndsTheStream(t *testing.T) {
	w := newWorld(t, refrelay.Config{})
	cert := w.cert(homeA, 0)
	ctl := w.session(&cert)
	agent, open := w.routed(ctl, nameA)
	d, _, _ := w.bound(open, &cert)
	_ = agent.Close()
	// The gateway sees the end of the stream, with close_notify: the relay passes on the end of
	// the agent, which was a close.
	_ = d.SetReadDeadline(time.Now().Add(wait))
	if _, err := io.ReadAll(d); err != nil || !d.ClosedWithNotify() {
		t.Errorf("the end of the agent: %v, close_notify %v", err, d.ClosedWithNotify())
	}
}

func TestNamesThatAreNotServedAreClosedWithoutAnAnswer(t *testing.T) {
	w := newWorld(t, refrelay.Config{})
	cert := w.cert(homeA, 0)
	ctl := w.session(&cert)
	w.reg.Name(ownA, homeA, false)
	w.reg.Name("home.paused.example.com", homeB, true)
	w.reg.Unpair(homeB)
	for name, sni := range map[string]string{
		"unknown name":   "nobody." + nameA,
		"no server name": "",
		"installation without a control connection": nameB,
		"pending own-domain name":                   ownA,
		"unpaired installation":                     "home.paused.example.com",
	} {
		a := w.agent(sni)
		seen := tunnelclient.Observe(a, wait, 8)
		if !seen.Closed || len(seen.Bytes) != 0 {
			t.Errorf("%s: %+v", name, seen)
		}
	}
	if _, err := ctl.WaitOpen(100 * time.Millisecond); !errors.Is(err, tunnelclient.ErrTimeout) {
		t.Errorf("a stream-open for a name that is not served: %v", err)
	}
	// Once verified, the own-domain name is routed.
	w.reg.Name(ownA, homeA, true)
	w.routed(ctl, ownA)
}

func TestDefectsOfRouting(t *testing.T) {
	// R11: a pending own-domain name is routed.
	w := newWorld(t, refrelay.Config{Faults: refrelay.PendingRouted})
	cert := w.cert(homeA, 0)
	ctl := w.session(&cert)
	w.reg.Name(ownA, homeA, false)
	w.routed(ctl, ownA)
	// R12: the name is compared with regard to case.
	w2 := newWorld(t, refrelay.Config{Faults: refrelay.CaseSensitiveSNI})
	cert2 := w2.cert(homeA, 0)
	ctl2 := w2.session(&cert2)
	w2.routed(ctl2, nameA)
	upper := w2.agent("K7q2xwmpd4hj3n6rt5vbyc2ezu.homes.example.net")
	if seen := tunnelclient.Observe(upper, wait, 1); !seen.Closed {
		t.Error("R12: an upper case name was routed")
	}
}

func TestTokensAreUsedOnceAndOnlyByTheirInstallation(t *testing.T) {
	w := newWorld(t, refrelay.Config{})
	a, b := w.cert(homeA, 0), w.cert(homeB, 0)
	ca, cb := w.session(&a), w.session(&b)
	_, open := w.routed(ca, nameA)
	_, openB := w.routed(cb, nameB)
	// The token of B on a connection of A: closed without a byte, and B cannot use it either.
	d := w.data(&a, frames.EncodeDataBind(openB.Token))
	if closed, n := closedWithoutAnAnswer(d); !closed || n != 0 {
		t.Errorf("a foreign token: closed %v, %d bytes", closed, n)
	}
	d = w.data(&b, frames.EncodeDataBind(openB.Token))
	if closed, n := closedWithoutAnAnswer(d); !closed || n != 0 {
		t.Errorf("the token of B after a foreign use: closed %v, %d bytes", closed, n)
	}
	// A token is bound once.
	if _, _, err := w.bound(open, &a); err != nil {
		t.Fatal(err)
	}
	d = w.data(&a, frames.EncodeDataBind(open.Token))
	if closed, n := closedWithoutAnAnswer(d); !closed || n != 0 {
		t.Errorf("a used token: closed %v, %d bytes", closed, n)
	}
}

func TestDataConnectionsWithDefectsAreClosedWithoutAnAnswer(t *testing.T) {
	w := newWorld(t, refrelay.Config{})
	a := w.cert(homeA, time.Minute)
	ctl := w.session(&a)
	_, open := w.routed(ctl, nameA)
	old := w.cert(homeA, 0)
	token := open.Token
	flipped := token
	flipped[31] ^= 1
	for name, first := range map[string][]byte{
		"unknown token":  frames.EncodeDataBind([32]byte{9}),
		"flipped token":  frames.EncodeDataBind(flipped),
		"hello":          mustHello(t, 1, 1),
		"31 bytes":       rawFrame(t, 0x0020, token[:31]),
		"33 bytes":       rawFrame(t, 0x0020, append(token[:], 0)),
		"type 0x0021":    rawFrame(t, 0x0021, token[:]),
		"1025 bytes":     {0x00, 0x20, 0x04, 0x01},
		"optional frame": rawFrame(t, 0x8000, token[:]),
		"nothing":        {},
	} {
		if name == "hello" {
			continue
		}
		d := w.data(&a, first)
		if closed, n := closedWithoutAnAnswer(d); !closed || n != 0 {
			t.Errorf("%s: closed %v, %d bytes", name, closed, n)
		}
	}
	// A certificate that starts before that of the control connection.
	d := w.data(&old, frames.EncodeDataBind(token))
	if closed, n := closedWithoutAnAnswer(d); !closed || n != 0 {
		t.Errorf("an older certificate: closed %v, %d bytes", closed, n)
	}
	// None of that consumed the token.
	if _, _, err := w.bound(open, &a); err != nil {
		t.Errorf("the token was consumed: %v", err)
	}
	// A data connection of an installation without a control connection.
	b := w.cert(homeB, 0)
	d = w.data(&b, frames.EncodeDataBind(token))
	if closed, n := closedWithoutAnAnswer(d); !closed || n != 0 {
		t.Errorf("no control connection: closed %v, %d bytes", closed, n)
	}
}

func TestDefectsOfTokens(t *testing.T) {
	// R5: a token binds twice. R6: a token of another installation binds. R7: a byte before the close.
	w := newWorld(t, refrelay.Config{Faults: refrelay.TokenReuse | refrelay.ForeignToken | refrelay.ByteBeforeClose})
	a, b := w.cert(homeA, 0), w.cert(homeB, 0)
	ca, cb := w.session(&a), w.session(&b)
	_, open := w.routed(ca, nameA)
	_, openB := w.routed(cb, nameB)
	if _, _, err := w.bound(open, &a); err != nil {
		t.Fatal(err)
	}
	if _, _, err := w.bound(open, &a); err != nil {
		t.Errorf("R5: the second binding: %v", err)
	}
	if _, _, err := w.bound(openB, &a); err != nil {
		t.Errorf("R6: a foreign token: %v", err)
	}
	d := w.data(&a, frames.EncodeDataBind([32]byte{5}))
	if seen := tunnelclient.Observe(d, wait, 12); !seen.Closed || len(seen.Bytes) == 0 {
		t.Errorf("R7: %+v", seen)
	}
}

func TestATokenExpiresAndTheAgentIsClosed(t *testing.T) {
	w := newWorld(t, refrelay.Config{TokenValidity: 150 * time.Millisecond})
	cert := w.cert(homeA, 0)
	ctl := w.session(&cert)
	agent, open := w.routed(ctl, nameA)
	if open.ValidityMS != 150 {
		t.Errorf("validity %d", open.ValidityMS)
	}
	if seen := tunnelclient.Observe(agent, wait, 1); !seen.Closed {
		t.Error("the agent connection of an expired token stays open")
	}
	d := w.data(&cert, frames.EncodeDataBind(open.Token))
	if closed, n := closedWithoutAnAnswer(d); !closed || n != 0 {
		t.Errorf("an expired token: closed %v, %d bytes", closed, n)
	}
}

func TestTheRelayLimitsTheStreamsOfAnInstallationAndFreesThemAgain(t *testing.T) {
	w := newWorld(t, refrelay.Config{MaxStreams: 1})
	cert := w.cert(homeA, 0)
	ctl := w.session(&cert)
	first, open := w.routed(ctl, nameA)
	second := w.agent(nameA)
	if seen := tunnelclient.Observe(second, wait, 1); !seen.Closed {
		t.Error("a second stream above max streams was routed")
	}
	// The stream ends: room again.
	d, _, err := w.bound(open, &cert)
	if err != nil {
		t.Fatal(err)
	}
	_ = first.Close()
	_ = d.Close()
	deadline := time.Now().Add(wait)
	for time.Now().Before(deadline) {
		a := w.agent(nameA)
		if _, err := ctl.WaitOpen(200 * time.Millisecond); err == nil {
			return
		}
		_ = a.Close()
	}
	t.Error("the stream was not freed")
}

func TestAnAgentThatSendsAProxyHeaderIsNotBelievedExceptWithDefectR10(t *testing.T) {
	claimed := netip.MustParseAddrPort("9.9.9.9:4545")
	header := tunnelclient.EncodeProxy(claimed, netip.MustParseAddrPort("192.0.2.1:443"))
	hello := tunnelclient.ClientHello(nameA)
	for _, faulty := range []bool{false, true} {
		var faults refrelay.Fault
		if faulty {
			faults = refrelay.AgentProxyHeader
		}
		w := newWorld(t, refrelay.Config{Faults: faults})
		cert := w.cert(homeA, 0)
		ctl := w.session(&cert)
		agent, err := tunnelclient.DialAgent(ctx(t), w.d, agentAddr, header, hello)
		if err != nil {
			t.Fatal(err)
		}
		defer agent.Close()
		open, err := ctl.WaitOpen(300 * time.Millisecond)
		if !faulty {
			if err == nil {
				t.Error("a ClientHello behind a PROXY header was routed")
			}
			continue
		}
		if err != nil {
			t.Fatalf("R10: %v", err)
		}
		_, proxy, err := w.bound(open, &cert)
		if err != nil || proxy.Src != claimed {
			t.Errorf("R10: the source is %v, %v", proxy.Src, err)
		}
	}
}

func TestOtherFirstBytesOfAnAgentAreNotAProxyHeaderEither(t *testing.T) {
	w := newWorld(t, refrelay.Config{Faults: refrelay.AgentProxyHeader})
	cert := w.cert(homeA, 0)
	ctl := w.session(&cert)
	// A ClientHello without a header is routed as usual; a header of IPv6, or cut short, is not
	// understood and the connection ends.
	w.routed(ctl, nameA)
	short := []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00}
	v6 := append(append([]byte{}, tunnelclient.EncodeProxy(netip.MustParseAddrPort("9.9.9.9:1"), netip.MustParseAddrPort("192.0.2.1:443"))[:12]...), 0x21, 0x21, 0, 36)
	cut := tunnelclient.EncodeProxy(netip.MustParseAddrPort("9.9.9.9:1"), netip.MustParseAddrPort("192.0.2.1:443"))[:20]
	for name, first := range map[string][]byte{"cut short": short, "IPv6": v6, "cut in the block": cut} {
		a := w.agent("", first)
		if seen := tunnelclient.Observe(a, wait, 1); !seen.Closed {
			t.Errorf("%s: the connection stays open", name)
		}
	}
}

// bigHello returns the first flight of a TLS client with so many ALPN protocols that the
// ClientHello is about size bytes long.
func bigHello(sni string, size int) []byte {
	var protocols []string
	for n := 0; n < size; n += 256 {
		protocols = append(protocols, strings.Repeat("p", 254)+string(rune('a'+n/256%26)))
	}
	local, remote := net.Pipe()
	_ = remote.Close()
	defer local.Close()
	rec := &recorder{Conn: local}
	_ = tls.Client(rec, &tls.Config{ServerName: sni, InsecureSkipVerify: true, NextProtos: protocols}).Handshake()
	return rec.written.Bytes()
}

// fragment writes the handshake record of a flight as three records.
func fragment(flight []byte) []byte {
	payload := flight[5 : 5+(int(flight[3])<<8|int(flight[4]))]
	var out []byte
	for _, part := range [][]byte{payload[:100], payload[100:9000], payload[9000:]} {
		out = append(out, flight[0], flight[1], flight[2], byte(len(part)>>8), byte(len(part)))
		out = append(out, part...)
	}
	return out
}

type recorder struct {
	net.Conn
	written bytes.Buffer
}

func (r *recorder) Write(p []byte) (int, error) { return r.written.Write(p) }
func (r *recorder) Read([]byte) (int, error)    { return 0, io.EOF }

func TestAClientHelloOfAlmost16384BytesIsRoutedAndAnEndlessOneIsRefused(t *testing.T) {
	w := newWorld(t, refrelay.Config{})
	cert := w.cert(homeA, 0)
	ctl := w.session(&cert)
	hello := bigHello(nameA, 14500)
	if len(hello) < 16000 || len(hello) > 16384 {
		t.Fatalf("the ClientHello has %d bytes", len(hello))
	}
	// In one record and across several.
	for name, flight := range map[string][]byte{"one record": hello, "three records": fragment(hello)} {
		a, err := tunnelclient.DialAgent(ctx(t), w.d, agentAddr, flight)
		if err != nil {
			t.Fatal(err)
		}
		defer a.Close()
		if _, err := ctl.WaitOpen(wait); err != nil {
			t.Errorf("%s: a ClientHello of %d bytes was not routed: %v", name, len(hello), err)
		}
	}
	// Garbage that begins like TLS and then goes on: the relay stops reading and closes.
	big := append([]byte{0x16, 0x03, 0x01, 0x3f, 0x00, 0x01, 0x00, 0xff, 0xff}, make([]byte, 0x3f00-5)...)
	for range 2 {
		big = append(big, append([]byte{0x16, 0x03, 0x03, 0x3f, 0x00}, make([]byte, 0x3f00)...)...)
	}
	endless := w.agent("", big)
	if seen := tunnelclient.Observe(endless, wait, 1); !seen.Closed {
		t.Error("an endless ClientHello was not refused")
	}
	// Not TLS at all.
	g := w.agent("", []byte("GET / HTTP/1.1\r\n\r\n"))
	if seen := tunnelclient.Observe(g, wait, 1); !seen.Closed {
		t.Error("HTTP was not refused")
	}
}

func TestThePROXYHeaderOfDefectsAndOfIPv6(t *testing.T) {
	for name, tt := range map[string]struct {
		cfg   refrelay.Config
		check func(*testing.T, tunnelclient.Proxy, error)
	}{
		"R8 mapped": {refrelay.Config{Faults: refrelay.MappedIPv4}, func(t *testing.T, p tunnelclient.Proxy, err error) {
			if !errors.Is(err, tunnelclient.ErrProxyContent) || !p.Src.Addr().Is4In6() {
				t.Errorf("%+v, %v", p, err)
			}
		}},
		"R9 real destination": {refrelay.Config{Faults: refrelay.RealDestination}, func(t *testing.T, p tunnelclient.Proxy, err error) {
			if !errors.Is(err, tunnelclient.ErrProxyContent) || p.Dst.Port() == 443 {
				t.Errorf("%+v, %v", p, err)
			}
		}},
		"IPv6 agent": {refrelay.Config{AgentAddr: netip.MustParseAddr("2a01:4f8::1")}, func(t *testing.T, p tunnelclient.Proxy, err error) {
			if err != nil || !p.Src.Addr().Is6() {
				t.Errorf("%+v, %v", p, err)
			}
		}},
		"R8 with an IPv6 agent": {refrelay.Config{Faults: refrelay.MappedIPv4, AgentAddr: netip.MustParseAddr("2a01:4f8::1")}, func(t *testing.T, p tunnelclient.Proxy, err error) {
			if err != nil || !p.Src.Addr().Is6() {
				t.Errorf("%+v, %v", p, err)
			}
		}},
	} {
		w := newWorld(t, tt.cfg)
		cert := w.cert(homeA, 0)
		ctl := w.session(&cert)
		_, open := w.routed(ctl, nameA)
		_, p, err := w.bound(open, &cert)
		t.Run(name, func(t *testing.T) { tt.check(t, p, err) })
	}
}

func TestAControlConnectionThatEndsVoidsItsTokens(t *testing.T) {
	w := newWorld(t, refrelay.Config{})
	cert := w.cert(homeA, 0)
	ctl := w.session(&cert)
	agent, _ := w.routed(ctl, nameA)
	ctl.Close()
	if seen := tunnelclient.Observe(agent, wait, 1); !seen.Closed {
		t.Error("the agent connection of a lost control connection stays open")
	}
}

func TestTheRelayCanBeClosedWithConnectionsOpen(t *testing.T) {
	w := newWorld(t, refrelay.Config{})
	cert := w.cert(homeA, 0)
	ctl := w.session(&cert)
	agent, _ := w.routed(ctl, nameA)
	w.relay.Close()
	w.relay.Close()
	if seen := tunnelclient.Observe(agent, wait, 1); !seen.Closed {
		t.Error("an agent connection survived Close")
	}
	if _, err := net.DialTimeout("tcp", w.addr, 200*time.Millisecond); err == nil {
		t.Error("the relay still listens")
	}
}

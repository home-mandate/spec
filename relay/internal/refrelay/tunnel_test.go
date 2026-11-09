// SPDX-License-Identifier: Apache-2.0

package refrelay_test

import (
	"crypto/tls"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/home-mandate/spec/relay/internal/frames"
	"github.com/home-mandate/spec/relay/internal/refrelay"
	"github.com/home-mandate/spec/relay/internal/tunnelclient"
)

// probe opens a control connection with the parameters and reports what the relay does: accepted
// if it answers hello with hello-ack on TLS 1.3 with X25519MLKEM768, and no resumption; refused
// if it fails or closes; else what was negotiated.
func (w *world) probe(p tunnelclient.Params) string {
	w.t.Helper()
	ctl, err := tunnelclient.OpenControl(ctx(w.t), w.d, tunnel, p)
	if err != nil {
		return "refused"
	}
	defer ctl.Close()
	if err := ctl.Hello(); err != nil {
		return "refused"
	}
	msg, err := ctl.Recv(wait)
	if err != nil || msg["type"] != "hello-ack" {
		return "refused"
	}
	s := ctl.State()
	if s.Version != tls.VersionTLS13 || s.CurveID != tls.X25519MLKEM768 || s.NegotiatedProtocol != tunnelclient.ALPN || s.DidResume {
		return fmt.Sprintf("accepted with version %x, group %v, resumed %v", s.Version, s.CurveID, s.DidResume)
	}
	return "accepted"
}

func TestTheCleanRelayFollowsSection42(t *testing.T) {
	w := newWorld(t, refrelay.Config{})
	cert := w.cert(homeA, 0)
	good := w.params(&cert)
	both := good
	both.Curves = []tls.CurveID{tls.X25519MLKEM768, tls.X25519}
	reversed := good
	reversed.Curves = []tls.CurveID{tls.X25519, tls.X25519MLKEM768}
	h2first := good
	h2first.ALPN = []string{"h2", tunnelclient.ALPN}
	tls12 := both
	tls12.MaxVersion = tls.VersionTLS12
	x25519 := good
	x25519.Curves = []tls.CurveID{tls.X25519}
	p256 := good
	p256.Curves = []tls.CurveID{tls.CurveP256}
	none := good
	none.Cert = nil
	noALPN := good
	noALPN.ALPN = []string{}
	wrongALPN := good
	wrongALPN.ALPN = []string{"h2"}
	other := refrelay.NewMem(trust).Issue(homeA, w.base, nil, nil)
	selfSigned := good
	selfSigned.Cert = &other
	for name, tt := range map[string]struct {
		p    tunnelclient.Params
		want string
	}{
		"accepted":                  {good, "accepted"},
		"MLKEM and x25519":          {both, "accepted"},
		"x25519 first":              {reversed, "accepted"},
		"h2 before hm-tunnel":       {h2first, "accepted"},
		"TLS 1.2":                   {tls12, "refused"},
		"x25519 alone":              {x25519, "refused"},
		"secp256r1 alone":           {p256, "refused"},
		"no client certificate":     {none, "refused"},
		"certificate of another CA": {selfSigned, "refused"},
		"no ALPN":                   {noALPN, "refused"},
		"another ALPN":              {wrongALPN, "refused"},
	} {
		if got := w.probe(tt.p); got != tt.want {
			t.Errorf("%s: %s, want %s", name, got, tt.want)
		}
	}
	// Resumption: the second connection is a fresh handshake.
	resume := good
	resume.Cache = tls.NewLRUClientSessionCache(4)
	for range 2 {
		if got := w.probe(resume); got != "accepted" {
			t.Errorf("with a session cache: %s", got)
		}
	}
}

func TestAnUnpairedOrDeniedCertificateIsRefused(t *testing.T) {
	w := newWorld(t, refrelay.Config{})
	denied, unpaired := w.cert(homeA, 0), w.cert(homeB, 0)
	w.reg.Deny(denied)
	w.reg.Unpair(homeB)
	for name, c := range map[string]*tls.Certificate{"denied": &denied, "unpaired": &unpaired} {
		if got := w.probe(w.params(c)); got != "refused" {
			t.Errorf("%s: %s", name, got)
		}
	}
}

func TestOpenConnectionsOfACertificateEndAfterItIsDenied(t *testing.T) {
	w := newWorld(t, refrelay.Config{})
	a, b := w.cert(homeA, 0), w.cert(homeB, 0)
	ca, cb := w.session(&a), w.session(&b)
	w.reg.Deny(a)
	w.reg.Unpair(homeB)
	for name, c := range map[string]*tunnelclient.Control{"denylist": ca, "unpaired": cb} {
		select {
		case <-c.Done():
		case <-time.After(wait):
			t.Errorf("%s: the connection stays open", name)
		}
	}
}

func TestDefectsOfTheTLSParameters(t *testing.T) {
	for name, tt := range map[string]struct {
		faults refrelay.Fault
		p      func(tunnelclient.Params) tunnelclient.Params
		want   string
	}{
		"R1 TLS 1.2": {refrelay.TLS12, func(p tunnelclient.Params) tunnelclient.Params {
			p.MaxVersion, p.Curves = tls.VersionTLS12, []tls.CurveID{tls.X25519MLKEM768, tls.X25519}
			return p
		}, "accepted with version 303, group X25519, resumed false"},
		"R2 x25519": {refrelay.GroupX25519, func(p tunnelclient.Params) tunnelclient.Params {
			p.Curves = []tls.CurveID{tls.X25519}
			return p
		}, "accepted with version 304, group X25519, resumed false"},
		"R3 resumption": {refrelay.Resumption, func(p tunnelclient.Params) tunnelclient.Params {
			p.Cache = tls.NewLRUClientSessionCache(2)
			return p
		}, "accepted with version 304, group X25519MLKEM768, resumed true"},
	} {
		w := newWorld(t, refrelay.Config{Faults: tt.faults})
		cert := w.cert(homeA, 0)
		p := tt.p(w.params(&cert))
		got := w.probe(p)
		if tt.faults == refrelay.Resumption {
			got = w.probe(p)
		}
		if got != tt.want {
			t.Errorf("%s: %q, want %q", name, got, tt.want)
		}
	}
}

func TestADefectOfTheDenylistLetsADeniedCertificateIn(t *testing.T) {
	w := newWorld(t, refrelay.Config{Faults: refrelay.NoDenylist})
	cert := w.cert(homeA, 0)
	w.reg.Deny(cert)
	w.reg.Unpair(homeA)
	ctl := w.session(&cert)
	select {
	case <-ctl.Done():
		t.Error("a relay without a denylist closed the connection")
	case <-time.After(150 * time.Millisecond):
	}
}

func TestTheRelayKeyIsInTheMetadataPinsExceptWithDefectR16(t *testing.T) {
	for _, faulty := range []bool{false, true} {
		var faults refrelay.Fault
		if faulty {
			faults = refrelay.KeyNotPinned
		}
		w := newWorld(t, refrelay.Config{Faults: faults})
		cert := w.cert(homeA, 0)
		p := w.params(&cert)
		p.Pins, p.AnyKey = nil, true
		ctl, err := tunnelclient.OpenControl(ctx(t), w.d, tunnel, p)
		if err != nil {
			t.Fatal(err)
		}
		pinned := ctl.Pin() == w.pin()
		ctl.Close()
		if pinned == faulty {
			t.Errorf("faulty %v: the key is pinned: %v", faulty, pinned)
		}
	}
}

func TestHelloIsAnsweredAndAnnouncesTheInterval(t *testing.T) {
	for name, tt := range map[string]struct {
		heartbeat time.Duration
		want      int
	}{"default": {0, 30}, "too short": {100 * time.Millisecond, 5}, "too long": {10 * time.Minute, 120}, "whole seconds": {17 * time.Second, 17}} {
		w := newWorld(t, refrelay.Config{Heartbeat: tt.heartbeat})
		cert := w.cert(homeA, 0)
		_, msg, err := w.open(&cert)
		if err != nil || msg["heartbeat_interval"] != tt.want || msg["max_streams"] != 64 || msg["pool_size"] != 0 {
			t.Errorf("%s: %v, %v", name, msg, err)
		}
	}
	w := newWorld(t, refrelay.Config{Faults: refrelay.Heartbeat3})
	cert := w.cert(homeA, 0)
	if _, _, err := w.open(&cert); !errors.Is(err, frames.ErrFrame) {
		t.Errorf("R14: %v", err)
	}
}

// sends writes a frame of the gateway and reads until the relay answers or closes.
func sends(w *world, c *tunnelclient.Control, raw []byte) (*tunnelclient.Event, bool) {
	w.t.Helper()
	if err := c.Write(raw); err != nil {
		w.t.Fatal(err)
	}
	seen, closed := c.Drain(wait)
	for _, e := range seen {
		if e.Type == "error" {
			return &e, closed
		}
	}
	return nil, closed
}

func rawFrame(t *testing.T, typ uint16, payload []byte) []byte {
	t.Helper()
	raw, err := frames.Raw(typ, payload)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestTheRelayAnswersFramesWithDefectsWithErrorAndClose(t *testing.T) {
	w := newWorld(t, refrelay.Config{})
	for name, tt := range map[string]struct {
		first []byte
		code  int
	}{
		"hello version 2 to 3": {mustHello(t, 2, 3), frames.CodeUnsupportedVersion},
		"hello with min 0":     {mustHello(t, 0, 1), frames.CodeMalformed},
	} {
		cert := w.cert(homeA, 0)
		c, err := tunnelclient.OpenControl(ctx(t), w.d, tunnel, w.params(&cert))
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		msg, closed := sends(w, c, tt.first)
		if msg == nil || msg.Code != tt.code || !closed {
			t.Errorf("%s: %v, closed %v", name, msg, closed)
		}
	}
	for name, raw := range map[string][]byte{
		"type 0":                 rawFrame(t, 0, nil),
		"pong without ping":      frames.EncodePong([8]byte{1}),
		"oversized":              {0x00, 0x03, 0x04, 0x01},
		"data-bind on a control": frames.EncodeDataBind([32]byte{}),
		"hello again":            mustHello(t, 1, 1),
		"stream-open by gateway": rawFrame(t, 0x0010, make([]byte, 34)),
		"pins from the gateway":  rawFrame(t, 0x0014, make([]byte, 6)),
	} {
		// A newer certificate each time replaces the connection before.
		cert := w.next(homeA)
		c, msg, err := w.open(&cert)
		if err != nil || msg["type"] != "hello-ack" {
			t.Fatalf("%s: hello-ack: %v, %v", name, msg, err)
		}
		ev, closed := sends(w, c, raw)
		if ev == nil || ev.Code != frames.CodeMalformed || !closed {
			t.Errorf("%s: %v, closed %v", name, ev, closed)
		}
	}
}

func mustHello(t *testing.T, min, max int) []byte {
	t.Helper()
	raw, err := frames.Hello{MinVersion: min, MaxVersion: max, Software: "g"}.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

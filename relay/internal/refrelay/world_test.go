// SPDX-License-Identifier: Apache-2.0

package refrelay_test

import (
	"context"
	"crypto/tls"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/home-mandate/spec/relay/internal/frames"
	"github.com/home-mandate/spec/relay/internal/netguard"
	"github.com/home-mandate/spec/relay/internal/refrelay"
	"github.com/home-mandate/spec/relay/internal/tunnelclient"
)

const (
	relayHost = "tunnel.relay-operator.example"
	trust     = "relay-operator.example"
	homeA     = "k7q2xwmpd4hj3n6rt5vbyc2ezu"
	homeB     = "m3n4p5q6r7s2t3u4v5w6x7y2za"
	nameA     = homeA + ".homes.example.net"
	nameB     = homeB + ".homes.example.net"
	ownA      = "home.tester.example.com"
	wait      = 8 * time.Second // longer than the relay's limit of 5 s for a first frame
	tunnel    = "relay.example:8443"
	agentAddr = "relay.example:443"
)

type world struct {
	t     *testing.T
	reg   *refrelay.Mem
	relay *refrelay.Relay
	addr  string
	d     *netguard.Dialer
	base  time.Time
	n     int
}

func newWorld(t *testing.T, cfg refrelay.Config) *world {
	t.Helper()
	cfg.Host = relayHost
	w := &world{t: t, reg: refrelay.NewMem(trust), relay: refrelay.New(cfg), base: time.Now().Add(-10 * time.Minute)}
	w.addr = w.relay.Start(w.reg)
	t.Cleanup(w.relay.Close)
	w.d = netguard.New(netguard.Options{Policy: func(netip.Addr) bool { return true }, Remap: func(string) string { return w.addr }})
	w.reg.Name(nameA, homeA, true)
	w.reg.Name(nameB, homeB, true)
	return w
}

func ctx(t *testing.T) context.Context {
	t.Helper()
	c, cancel := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)
	return c
}

func (w *world) pin() tunnelclient.Pin {
	w.t.Helper()
	pin, err := tunnelclient.ParsePin(w.relay.Pins()[0])
	if err != nil {
		w.t.Fatal(err)
	}
	return pin
}

// cert issues a tunnel certificate that starts after offset from the base time.
func (w *world) cert(home string, offset time.Duration) tls.Certificate {
	return w.reg.Issue(home, w.base.Add(offset), nil, nil)
}

// next issues a certificate that starts one second later than the one issued before.
func (w *world) next(home string) tls.Certificate {
	w.n++
	return w.cert(home, time.Duration(w.n)*time.Second)
}

func (w *world) params(c *tls.Certificate) tunnelclient.Params {
	return tunnelclient.Params{ServerName: relayHost, Pins: []tunnelclient.Pin{w.pin()}, Cert: c}
}

// open opens a control connection and reads what the relay answers to hello.
func (w *world) open(c *tls.Certificate) (*tunnelclient.Control, frames.Message, error) {
	w.t.Helper()
	ctl, err := tunnelclient.OpenControl(ctx(w.t), w.d, tunnel, w.params(c))
	if err != nil {
		w.t.Fatal(err)
	}
	w.t.Cleanup(ctl.Close)
	if err := ctl.Hello(); err != nil {
		w.t.Fatal(err)
	}
	msg, err := ctl.Recv(wait)
	return ctl, msg, err
}

// session opens a control connection that the relay accepts and starts its reader.
func (w *world) session(c *tls.Certificate) *tunnelclient.Control {
	w.t.Helper()
	ctl, msg, err := w.open(c)
	if err != nil || msg["type"] != "hello-ack" {
		w.t.Fatalf("hello-ack: %v, %v", msg, err)
	}
	ctl.Run()
	return ctl
}

// agent connects as an agent with the server name and returns the connection.
func (w *world) agent(sni string, more ...[]byte) net.Conn {
	w.t.Helper()
	c, err := tunnelclient.DialAgent(ctx(w.t), w.d, agentAddr, append([][]byte{tunnelclient.ClientHello(sni)}, more...)...)
	if err != nil {
		w.t.Fatal(err)
	}
	w.t.Cleanup(func() { _ = c.Close() })
	return c
}

// data opens a data connection with the certificate and sends first.
func (w *world) data(c *tls.Certificate, first []byte) *tunnelclient.Conn {
	w.t.Helper()
	d, err := tunnelclient.DialData(ctx(w.t), w.d, tunnel, w.params(c), first)
	if err != nil {
		w.t.Fatal(err)
	}
	w.t.Cleanup(func() { _ = d.Close() })
	return d
}

// routed connects as an agent to name and returns the connection and the token of the
// stream-open on the session.
func (w *world) routed(ctl *tunnelclient.Control, sni string) (net.Conn, tunnelclient.Open) {
	w.t.Helper()
	a := w.agent(sni)
	open, err := ctl.WaitOpen(wait)
	if err != nil {
		w.t.Fatalf("no stream-open for %q: %v", sni, err)
	}
	return a, open
}

// closedWithoutAnAnswer reports whether the data connection is closed and sent nothing.
func closedWithoutAnAnswer(d *tunnelclient.Conn) (bool, int) {
	seen := tunnelclient.Observe(d, wait, 12)
	return seen.Closed, len(seen.Bytes)
}

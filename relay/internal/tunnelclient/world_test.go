// SPDX-License-Identifier: Apache-2.0

package tunnelclient_test

import (
	"context"
	"crypto/tls"
	"net/netip"
	"testing"
	"time"

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
	wait      = 5 * time.Second
)

// world is a reference relay with a registry, and a dialer that reaches it.
type world struct {
	t     *testing.T
	reg   *refrelay.Mem
	relay *refrelay.Relay
	addr  string
	d     *netguard.Dialer
	now   time.Time
}

func newWorld(t *testing.T, cfg refrelay.Config) *world {
	t.Helper()
	cfg.Host = relayHost
	w := &world{t: t, reg: refrelay.NewMem(trust), relay: refrelay.New(cfg), now: time.Now().Add(-10 * time.Minute)}
	w.addr = w.relay.Start(w.reg)
	t.Cleanup(w.relay.Close)
	w.d = netguard.New(netguard.Options{
		Policy: func(netip.Addr) bool { return true },
		Remap:  func(string) string { return w.addr },
	})
	w.reg.Name(nameA, homeA, true)
	return w
}

func (w *world) pins() []tunnelclient.Pin {
	w.t.Helper()
	pin, err := tunnelclient.ParsePin(w.relay.Pins()[0])
	if err != nil {
		w.t.Fatal(err)
	}
	return []tunnelclient.Pin{pin}
}

// params are the parameters of a gateway with the certificate of the home, which starts after
// offset from the base time.
func (w *world) params(home string, offset time.Duration) tunnelclient.Params {
	cert := w.reg.Issue(home, w.now.Add(offset), nil, nil)
	return tunnelclient.Params{ServerName: relayHost, Pins: w.pins(), Cert: &cert}
}

func ctx(t *testing.T) context.Context {
	t.Helper()
	c, cancel := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)
	return c
}

// control opens a control connection and completes hello and hello-ack.
func (w *world) control(p tunnelclient.Params) *tunnelclient.Control {
	w.t.Helper()
	c, err := tunnelclient.OpenControl(ctx(w.t), w.d, "relay.example:8443", p)
	if err != nil {
		w.t.Fatal(err)
	}
	w.t.Cleanup(c.Close)
	if err := c.Hello(); err != nil {
		w.t.Fatal(err)
	}
	msg, err := c.Recv(wait)
	if err != nil || msg["type"] != "hello-ack" {
		w.t.Fatalf("hello-ack: %v, %v", msg, err)
	}
	return c
}

var _ = tls.VersionTLS13

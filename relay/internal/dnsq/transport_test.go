// SPDX-License-Identifier: Apache-2.0

package dnsq_test

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/home-mandate/spec/relay/internal/dnsq"
	"github.com/home-mandate/spec/relay/internal/netguard"
)

// truncatingServer answers every UDP query with an answer that is cut (TC), so that the query is
// repeated over TCP; tcp serves a connection, or is nil for no TCP listener at all. It returns the
// address every connection is sent to.
func truncatingServer(t *testing.T, tcp func(net.Conn)) string {
	t.Helper()
	udp, l := listenBoth(t, tcp != nil)
	t.Cleanup(func() { _ = udp.Close() })
	go func() {
		buf := make([]byte, 512)
		for {
			n, from, err := udp.ReadFromUDP(buf)
			if err != nil {
				return
			}
			var q dnsmessage.Message
			if q.Unpack(buf[:n]) != nil {
				continue
			}
			q.Response, q.Truncated = true, true
			out, _ := q.Pack()
			_, _ = udp.WriteToUDP(out, from)
		}
	}()
	if l != nil {
		t.Cleanup(func() { _ = l.Close() })
		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				go func() {
					defer c.Close()
					_ = c.SetDeadline(time.Now().Add(2 * time.Second))
					tcp(c)
				}()
			}
		}()
	}
	return udp.LocalAddr().String()
}

// listenBoth opens a UDP socket and, if withTCP, a TCP listener on the same port; the port is
// taken from the system, so another process may hold the TCP side, and the call tries again.
func listenBoth(t *testing.T, withTCP bool) (*net.UDPConn, net.Listener) {
	t.Helper()
	for range 20 {
		udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		if !withTCP {
			return udp, nil
		}
		if l, err := net.Listen("tcp4", udp.LocalAddr().String()); err == nil {
			return udp, l
		}
		_ = udp.Close()
	}
	t.Fatal("no port free for UDP and TCP")
	return nil, nil
}

func askVia(t *testing.T, addr string) error {
	t.Helper()
	r := &dnsq.Resolver{
		Dialer:  netguard.New(netguard.Options{Policy: func(a netip.Addr) bool { return a.IsLoopback() }, Remap: func(string) string { return addr }}),
		Timeout: time.Second,
	}
	_, err := r.Ask(context.Background(), dnsq.Server{Host: "ns", Addr: netip.MustParseAddr("127.0.0.1")}, "x.example.net", dnsq.TypeTXT)
	return err
}

func TestTheRepeatOverTCPFailsInEveryWayItCan(t *testing.T) {
	readQuery := func(c net.Conn) {
		var prefix [2]byte
		if _, err := io.ReadFull(c, prefix[:]); err == nil {
			_, _ = io.ReadFull(c, make([]byte, binary.BigEndian.Uint16(prefix[:])))
		}
	}
	for name, tt := range map[string]struct {
		serve func(net.Conn)
		want  error
	}{
		"no TCP listener":        {nil, nil},
		"closes at once":         {func(net.Conn) {}, nil},
		"closes after the query": {readQuery, nil},
		"answers garbage": {func(c net.Conn) {
			readQuery(c)
			_, _ = c.Write([]byte{0, 3, 1, 2, 3})
		}, dnsq.ErrBadAnswer},
	} {
		err := askVia(t, truncatingServer(t, tt.serve))
		if err == nil || (tt.want != nil && !errors.Is(err, tt.want)) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

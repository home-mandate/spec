// SPDX-License-Identifier: Apache-2.0

package refdns_test

import (
	"net"
	"net/netip"
	"testing"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/home-mandate/spec/relay/internal/refdns"
)

func TestTCPConnectionsThatEndEarlyAreDropped(t *testing.T) {
	d, err := refdns.New("a.example")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	addr := server(d, 0)
	for name, send := range map[string][]byte{"nothing": nil, "a prefix and no query": {0, 20, 1}} {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = c.Write(send)
		_ = c.Close()
		// The server is still there for the next query.
		raw, err := tcpExchange(t, addr, query(t, "h.a.example", refdns.TypeA))
		var m dnsmessage.Message
		if err != nil || m.Unpack(raw) != nil {
			t.Errorf("%s: the server does not answer afterwards: %v", name, err)
		}
	}
}

func TestAnswersForCNAMEsAndNamesAboveRecords(t *testing.T) {
	d, err := refdns.New("a.example")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	d.Replace("c.a.example", refdns.TypeCNAME, refdns.CNAME("c.a.example", 5, "t.example.net"))
	d.Replace("x.below.a.example", refdns.TypeA, refdns.A("x.below.a.example", 5, netip.MustParseAddr("192.0.2.9")))
	addr := server(d, 0)
	if m, _ := udpExchange(t, addr, query(t, "c.a.example", refdns.TypeA)); len(m.Answers) != 1 || m.Answers[0].Header.Type != refdns.TypeCNAME {
		t.Errorf("a CNAME is the answer for any type: %+v", m.Answers)
	}
	if m, _ := udpExchange(t, addr, query(t, "below.a.example", refdns.TypeA)); m.RCode != dnsmessage.RCodeSuccess || len(m.Answers) != 0 {
		t.Errorf("a name above a record exists without records: %+v", m)
	}
	d.SetBehavior("a.example", 0, refdns.Garbage)
	if _, err := udpExchange(t, addr, query(t, "c.a.example", refdns.TypeA)); err == nil {
		t.Error("garbage is a DNS message")
	}
}

// SPDX-License-Identifier: Apache-2.0

package refdns_test

import (
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/home-mandate/spec/relay/internal/refdns"
)

func query(t *testing.T, name string, typ dnsmessage.Type) []byte {
	t.Helper()
	m := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: 77},
		Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName(name + "."), Type: typ, Class: dnsmessage.ClassINET}},
	}
	wire, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

// server returns the real address of name server k of the zone.
func server(d *refdns.DNS, k int) string {
	hosts, _ := d.LookupNS(nil, d.Names()[0])
	addrs, _ := d.LookupAddr(nil, hosts[k])
	return d.Remap(addrs[0].String() + ":53")
}

func udpExchange(t *testing.T, addr string, wire []byte) (dnsmessage.Message, error) {
	t.Helper()
	c, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(300 * time.Millisecond))
	_, _ = c.Write(wire)
	buf := make([]byte, 4096)
	n, err := c.Read(buf)
	if err != nil {
		return dnsmessage.Message{}, err
	}
	var m dnsmessage.Message
	return m, m.Unpack(buf[:n])
}

func tcpExchange(t *testing.T, addr string, wire []byte) ([]byte, error) {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(300 * time.Millisecond))
	_, _ = c.Write(binary.BigEndian.AppendUint16(nil, uint16(len(wire))))
	_, _ = c.Write(wire)
	var prefix [2]byte
	if _, err := io.ReadFull(c, prefix[:]); err != nil {
		return nil, err
	}
	if binary.BigEndian.Uint16(prefix[:]) == 0xffff {
		return prefix[:], nil
	}
	buf := make([]byte, binary.BigEndian.Uint16(prefix[:]))
	_, err = io.ReadFull(c, buf)
	return buf, err
}

func TestServersAnswerOverUDPAndTCP(t *testing.T) {
	d, err := refdns.New("a.example")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	d.Replace("h.a.example", refdns.TypeA, refdns.A("h.a.example", 5, netip.MustParseAddr("192.0.2.5")))
	addr := server(d, 1)
	m, err := udpExchange(t, addr, query(t, "h.a.example", refdns.TypeA))
	if err != nil || len(m.Answers) != 1 || !m.Authoritative || m.ID != 77 {
		t.Fatalf("UDP: %+v %v", m, err)
	}
	raw, err := tcpExchange(t, addr, query(t, "h.a.example", refdns.TypeA))
	var tm dnsmessage.Message
	if err != nil || tm.Unpack(raw) != nil || len(tm.Answers) != 1 {
		t.Fatalf("TCP: %v", err)
	}
	if m, _ = udpExchange(t, addr, query(t, "nothing.a.example", refdns.TypeA)); m.RCode != dnsmessage.RCodeNameError {
		t.Errorf("NXDOMAIN: %+v", m.RCode)
	}
	if m, _ = udpExchange(t, addr, query(t, "x.other.example", refdns.TypeA)); m.RCode != dnsmessage.RCodeRefused {
		t.Errorf("REFUSED: %+v", m.RCode)
	}
	// A message that is no query gets no answer.
	if _, err := udpExchange(t, addr, []byte{1, 2, 3}); err == nil {
		t.Error("an answer to junk")
	}
	two := dnsmessage.Message{Questions: []dnsmessage.Question{
		{Name: dnsmessage.MustNewName("a.a.example."), Type: refdns.TypeA, Class: dnsmessage.ClassINET},
		{Name: dnsmessage.MustNewName("b.a.example."), Type: refdns.TypeA, Class: dnsmessage.ClassINET}}}
	wire, _ := two.Pack()
	if _, err := udpExchange(t, addr, wire); err == nil {
		t.Error("an answer to two questions")
	}
	if _, err := tcpExchange(t, addr, []byte{1, 2, 3}); err == nil {
		t.Error("TCP answer to junk")
	}
}

func TestBehaviorsChangeTheAnswers(t *testing.T) {
	d, _ := refdns.New("a.example")
	defer d.Close()
	d.Replace("h.a.example", refdns.TypeTXT, refdns.TXT("h.a.example", 5, "x"))
	addr := server(d, 0)
	q := query(t, "h.a.example", refdns.TypeTXT)
	check := func(b refdns.Behavior, f func(dnsmessage.Message, error) bool) {
		t.Helper()
		d.SetBehavior("a.example", 0, b)
		m, err := udpExchange(t, addr, q)
		if !f(m, err) {
			t.Errorf("behavior %d: %+v %v", b, m, err)
		}
	}
	check(refdns.Normal, func(m dnsmessage.Message, err error) bool { return err == nil && len(m.Answers) == 1 })
	check(refdns.TruncateUDP, func(m dnsmessage.Message, err error) bool { return err == nil && m.Truncated && len(m.Answers) == 0 })
	check(refdns.HugeTCP, func(m dnsmessage.Message, err error) bool { return err == nil && m.Truncated })
	check(refdns.AlwaysTruncated, func(m dnsmessage.Message, err error) bool { return err == nil && m.Truncated })
	check(refdns.WrongID, func(m dnsmessage.Message, err error) bool { return err == nil && m.ID != 77 })
	check(refdns.WrongQuestion, func(m dnsmessage.Message, err error) bool {
		return err == nil && m.Questions[0].Name.String() == "other.example."
	})
	check(refdns.NotAResponse, func(m dnsmessage.Message, err error) bool { return err == nil && !m.Response })
	check(refdns.ServFail, func(m dnsmessage.Message, err error) bool {
		return err == nil && m.RCode == dnsmessage.RCodeServerFailure
	})
	check(refdns.ManyRecords, func(m dnsmessage.Message, err error) bool { return err == nil && len(m.Answers) > 64 })
	check(refdns.Garbage, func(_ dnsmessage.Message, err error) bool { return err != nil })
	check(refdns.Silent, func(_ dnsmessage.Message, err error) bool { return err != nil })
	d.SetBehavior("a.example", 0, refdns.HugeTCP)
	if raw, err := tcpExchange(t, addr, q); err != nil || len(raw) != 2 {
		t.Errorf("HugeTCP over TCP: %v", err)
	}
	d.SetBehavior("a.example", 0, refdns.Normal)
	if _, err := tcpExchange(t, addr, q); err != nil {
		t.Errorf("TCP after the faults: %v", err)
	}
}

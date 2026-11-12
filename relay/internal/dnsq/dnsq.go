// SPDX-License-Identifier: Apache-2.0

// Package dnsq asks the authoritative name servers of a zone, each one on its own and without
// recursion (RD=0), over UDP and, for a truncated answer, over TCP (RELAY-v0 sections 5.6, 6.3
// and 8.3). Every connection goes through the address filter of package netguard. An answer
// counts only if it has the ID and the question of the query, and its size and the number of
// its records are bounded.
package dnsq

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/home-mandate/spec/relay/internal/netguard"
)

// Record types the tool asks for.
const (
	TypeA      = dnsmessage.TypeA
	TypeAAAA   = dnsmessage.TypeAAAA
	TypeTXT    = dnsmessage.TypeTXT
	TypeNS     = dnsmessage.TypeNS
	TypeCNAME  = dnsmessage.TypeCNAME
	TypeDNAME  = dnsmessage.Type(39)
	TypeCAA    = dnsmessage.Type(257)
	TypeDNSKEY = dnsmessage.Type(48)
)

const (
	// MaxServers is how many name servers of a zone are asked.
	MaxServers = 8
	// maxTCPBytes bounds a message over TCP; maxRecords the records of an answer.
	maxTCPBytes = 16 << 10
	maxRecords  = 64
	udpBytes    = 4096
	// maxZoneDepth is how many labels are cut off while looking for the apex of a zone.
	maxZoneDepth = 16
)

// Errors of a query. Their text never contains data of the server.
var (
	ErrNoZone    = errors.New("dnsq: no name servers found")
	ErrBadAnswer = errors.New("dnsq: the answer does not match the query")
)

// Resolver asks name servers. NS finds the name servers of a zone apex (the system resolver in
// the tool); the dialer resolves their names once and connects only to allowed addresses.
type Resolver struct {
	Dialer *netguard.Dialer
	NS     func(ctx context.Context, name string) ([]string, error)
	// Timeout limits one exchange with one server, UDP and TCP together.
	Timeout time.Duration
}

// Server is one address of a name server.
type Server struct {
	Host string
	Addr netip.Addr
}

func (s Server) String() string { return s.Host + " (" + s.Addr.String() + ")" }

// Zone finds the zone of name: the closest apex, going up from name, that has name servers,
// and the addresses of at most MaxServers of those servers, at most four of each.
func (r *Resolver) Zone(ctx context.Context, name string) (string, []Server, error) {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	for range maxZoneDepth {
		if !strings.Contains(name, ".") {
			break
		}
		hosts, err := r.NS(ctx, name)
		if err == nil && len(hosts) > 0 {
			servers := r.addresses(ctx, hosts[:min(len(hosts), MaxServers)])
			if len(servers) == 0 {
				return "", nil, ErrNoZone
			}
			return name, servers, nil
		}
		_, name, _ = strings.Cut(name, ".")
	}
	return "", nil, ErrNoZone
}

func (r *Resolver) addresses(ctx context.Context, hosts []string) []Server {
	var out []Server
	for _, h := range hosts {
		h = strings.TrimSuffix(strings.ToLower(h), ".")
		addrs, err := r.Dialer.Resolve(ctx, h)
		if err != nil {
			continue
		}
		for _, a := range addrs {
			out = append(out, Server{Host: h, Addr: a})
		}
	}
	return out
}

// Record is a resource record. Only the field of its type is set.
type Record struct {
	Name string
	Type dnsmessage.Type
	TTL  uint32
	// Addr is the address of an A or AAAA record.
	Addr netip.Addr
	// Text is the joined character strings of a TXT record.
	Text string
	// CAA is the data of a CAA record.
	CAA CAA
	// Target is the name of a CNAME, DNAME or NS record.
	Target string
}

// Answer is the answer of one name server.
type Answer struct {
	RCode         dnsmessage.RCode
	Authoritative bool
	Records       []Record
}

// Ask asks the server for the records of name and type, with RD=0.
func (r *Resolver) Ask(ctx context.Context, s Server, name string, typ dnsmessage.Type) (Answer, error) {
	ctx, cancel := context.WithTimeout(ctx, r.Timeout)
	defer cancel()
	id := make([]byte, 2)
	_, _ = rand.Read(id)
	qname, err := dnsmessage.NewName(strings.TrimSuffix(name, ".") + ".")
	if err != nil {
		return Answer{}, fmt.Errorf("dnsq: name: %w", err)
	}
	q := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: binary.BigEndian.Uint16(id)},
		Questions: []dnsmessage.Question{{Name: qname, Type: typ, Class: dnsmessage.ClassINET}},
	}
	// A question whose name NewName accepted can be packed.
	wire, _ := q.Pack()
	reply, err := r.udp(ctx, s, wire)
	if err != nil {
		return Answer{}, err
	}
	resp, err := parse(reply, q)
	if err != nil {
		return Answer{}, err
	}
	if resp.Truncated {
		if reply, err = r.tcp(ctx, s, wire); err != nil {
			return Answer{}, err
		}
		if resp, err = parse(reply, q); err != nil {
			return Answer{}, err
		}
		if resp.Truncated {
			return Answer{}, ErrBadAnswer
		}
	}
	return toAnswer(resp)
}

func (r *Resolver) dial(ctx context.Context, network string, s Server) (net.Conn, error) {
	c, err := r.Dialer.DialContext(ctx, network, netip.AddrPortFrom(s.Addr, 53).String())
	if err != nil {
		return nil, err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}
	return c, nil
}

func (r *Resolver) udp(ctx context.Context, s Server, wire []byte) ([]byte, error) {
	c, err := r.dial(ctx, "udp", s)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	if _, err := c.Write(wire); err != nil {
		return nil, err
	}
	buf := make([]byte, udpBytes)
	n, err := c.Read(buf)
	return buf[:n], err
}

func (r *Resolver) tcp(ctx context.Context, s Server, wire []byte) ([]byte, error) {
	c, err := r.dial(ctx, "tcp", s)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	if _, err := c.Write(binary.BigEndian.AppendUint16(nil, uint16(len(wire)))); err != nil {
		return nil, err
	}
	if _, err := c.Write(wire); err != nil {
		return nil, err
	}
	var prefix [2]byte
	if _, err := io.ReadFull(c, prefix[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(prefix[:]))
	if n > maxTCPBytes {
		return nil, ErrBadAnswer
	}
	buf := make([]byte, n)
	_, err = io.ReadFull(c, buf)
	return buf, err
}

// parse unpacks a reply and checks that it answers the query.
func parse(reply []byte, q dnsmessage.Message) (dnsmessage.Message, error) {
	var m dnsmessage.Message
	if err := m.Unpack(reply); err != nil {
		return m, ErrBadAnswer
	}
	if !m.Response || m.ID != q.ID || len(m.Questions) != 1 || len(m.Answers) > maxRecords ||
		!strings.EqualFold(m.Questions[0].Name.String(), q.Questions[0].Name.String()) ||
		m.Questions[0].Type != q.Questions[0].Type || m.Questions[0].Class != q.Questions[0].Class {
		return m, ErrBadAnswer
	}
	return m, nil
}

func toAnswer(m dnsmessage.Message) (Answer, error) {
	a := Answer{RCode: m.RCode, Authoritative: m.Authoritative}
	for _, rr := range m.Answers {
		rec := Record{Name: strings.TrimSuffix(strings.ToLower(rr.Header.Name.String()), "."), Type: rr.Header.Type, TTL: rr.Header.TTL}
		switch body := rr.Body.(type) {
		case *dnsmessage.AResource:
			rec.Addr = netip.AddrFrom4(body.A)
		case *dnsmessage.AAAAResource:
			rec.Addr = netip.AddrFrom16(body.AAAA)
		case *dnsmessage.TXTResource:
			rec.Text = strings.Join(body.TXT, "")
		case *dnsmessage.CNAMEResource:
			rec.Target = strings.TrimSuffix(body.CNAME.String(), ".")
		case *dnsmessage.NSResource:
			rec.Target = strings.TrimSuffix(body.NS.String(), ".")
		case *dnsmessage.UnknownResource:
			if rr.Header.Type == TypeCAA {
				caa, err := ParseCAA(body.Data)
				if err != nil {
					return Answer{}, err
				}
				rec.CAA = caa
			}
		}
		a.Records = append(a.Records, rec)
	}
	return withDelegation(a, m), nil
}

// withDelegation adds the NS records of the authority section whose owner is the queried name: a
// server that delegates the name answers with them, and they are not an answer to be missed.
func withDelegation(a Answer, m dnsmessage.Message) Answer {
	if len(m.Questions) == 0 {
		return a
	}
	queried := strings.TrimSuffix(strings.ToLower(m.Questions[0].Name.String()), ".")
	for _, rr := range m.Authorities {
		body, ok := rr.Body.(*dnsmessage.NSResource)
		name := strings.TrimSuffix(strings.ToLower(rr.Header.Name.String()), ".")
		if ok && name == queried {
			a.Records = append(a.Records, Record{Name: name, Type: rr.Header.Type, TTL: rr.Header.TTL, Target: strings.TrimSuffix(body.NS.String(), ".")})
		}
	}
	return a
}

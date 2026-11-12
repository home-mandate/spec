// SPDX-License-Identifier: Apache-2.0

package refdns

import (
	"encoding/binary"
	"io"
	"net"
	"slices"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// Behavior makes a name server answer wrongly, for the tests of the DNS client.
type Behavior int

// Behaviors of a name server.
const (
	// Normal answers as an authoritative server does.
	Normal Behavior = iota
	// TruncateUDP answers over UDP with the TC bit and no records.
	TruncateUDP
	// WrongID answers with another message ID.
	WrongID
	// WrongQuestion answers a question that was not asked.
	WrongQuestion
	// Silent never answers.
	Silent
	// Garbage answers bytes that are no DNS message.
	Garbage
	// NotAResponse answers without the QR bit.
	NotAResponse
	// ServFail answers with the rcode SERVFAIL.
	ServFail
	// HugeTCP announces a message of 64 KiB over TCP.
	HugeTCP
	// ManyRecords answers with more records than a client takes.
	ManyRecords
	// AlwaysTruncated sets the TC bit over TCP as well.
	AlwaysTruncated
)

// manyRecords is how many records ManyRecords sends.
const manyRecords = 70

type key struct {
	name string
	typ  dnsmessage.Type
}

// instance is one authoritative name server of a zone.
type instance struct {
	zone string
	udp  *net.UDPConn
	tcp  net.Listener

	mu       sync.Mutex
	records  map[key][]dnsmessage.Resource
	behavior Behavior
	wg       sync.WaitGroup
}

// listenUDP and listenTCP open the sockets of a name server; tests replace them to make opening fail.
var (
	listenUDP = net.ListenUDP
	listenTCP = net.Listen
)

func newInstance(zone string) (*instance, error) {
	var lastErr error
	for range 20 {
		udp, err := listenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			return nil, err
		}
		tcp, err := listenTCP("tcp4", udp.LocalAddr().String())
		if err != nil {
			_ = udp.Close()
			lastErr = err
			continue
		}
		i := &instance{zone: zone, udp: udp, tcp: tcp, records: map[key][]dnsmessage.Resource{}}
		i.wg.Add(2)
		go i.serveUDP()
		go i.serveTCP()
		return i, nil
	}
	return nil, lastErr
}

func (i *instance) addr() string { return i.udp.LocalAddr().String() }

func (i *instance) close() {
	_ = i.udp.Close()
	_ = i.tcp.Close()
	i.wg.Wait()
}

func (i *instance) setBehavior(b Behavior) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.behavior = b
}

func (i *instance) replace(name string, typ dnsmessage.Type, rrs []dnsmessage.Resource) {
	i.mu.Lock()
	defer i.mu.Unlock()
	k := key{canon(name), typ}
	if len(rrs) == 0 {
		delete(i.records, k)
		return
	}
	i.records[k] = slices.Clone(rrs)
}

func (i *instance) removeBelow(name string) {
	name = canon(name)
	i.mu.Lock()
	defer i.mu.Unlock()
	for k := range i.records {
		if k.name == name || len(k.name) > len(name) && k.name[len(k.name)-len(name)-1:] == "."+name {
			delete(i.records, k)
		}
	}
}

func (i *instance) lookup(name string, typ dnsmessage.Type) []dnsmessage.Resource {
	i.mu.Lock()
	defer i.mu.Unlock()
	return slices.Clone(i.records[key{canon(name), typ}])
}

func (i *instance) serveUDP() {
	defer i.wg.Done()
	buf := make([]byte, 4096)
	for {
		n, from, err := i.udp.ReadFromUDP(buf)
		if err != nil {
			return
		}
		i.wg.Add(1)
		go func(query []byte) {
			defer i.wg.Done()
			if out := i.answer(query, true); out != nil {
				_, _ = i.udp.WriteToUDP(out, from)
			}
		}(slices.Clone(buf[:n]))
	}
}

func (i *instance) serveTCP() {
	defer i.wg.Done()
	for {
		c, err := i.tcp.Accept()
		if err != nil {
			return
		}
		i.wg.Add(1)
		go func() {
			defer i.wg.Done()
			defer c.Close()
			i.serveConn(c)
		}()
	}
}

func (i *instance) serveConn(c net.Conn) {
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	var prefix [2]byte
	if _, err := io.ReadFull(c, prefix[:]); err != nil {
		return
	}
	query := make([]byte, binary.BigEndian.Uint16(prefix[:]))
	if _, err := io.ReadFull(c, query); err != nil {
		return
	}
	i.mu.Lock()
	behavior := i.behavior
	i.mu.Unlock()
	if behavior == HugeTCP {
		_, _ = c.Write([]byte{0xff, 0xff})
		return
	}
	out := i.answer(query, false)
	if out == nil {
		return
	}
	_, _ = c.Write(binary.BigEndian.AppendUint16(nil, uint16(len(out))))
	_, _ = c.Write(out)
}

// answer builds the answer to a query, or nil if the server stays silent.
func (i *instance) answer(query []byte, udp bool) []byte {
	i.mu.Lock()
	behavior := i.behavior
	i.mu.Unlock()
	if behavior == Silent {
		return nil
	}
	if behavior == Garbage {
		return []byte{1, 2, 3}
	}
	var q dnsmessage.Message
	if q.Unpack(query) != nil || len(q.Questions) != 1 {
		return nil
	}
	resp := i.respond(q)
	apply(&resp, behavior, udp)
	out, err := resp.Pack()
	if err != nil {
		return nil
	}
	return out
}

// respond is the answer of an authoritative server without faults.
func (i *instance) respond(q dnsmessage.Message) dnsmessage.Message {
	question := q.Questions[0]
	resp := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: q.ID, Response: true, Authoritative: true, OpCode: q.OpCode},
		Questions: q.Questions,
	}
	name := canon(question.Name.String())
	if name != i.zone && !hasSuffix(name, i.zone) {
		resp.RCode = dnsmessage.RCodeRefused
		resp.Authoritative = false
		return resp
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if rrs := i.records[key{name, question.Type}]; len(rrs) > 0 {
		resp.Answers = slices.Clone(rrs)
	} else if cname := i.records[key{name, TypeCNAME}]; len(cname) > 0 {
		resp.Answers = slices.Clone(cname)
	} else if !i.exists(name) {
		resp.RCode = dnsmessage.RCodeNameError
	}
	return resp
}

// exists reports whether any record is at name or below it. The caller holds the lock.
func (i *instance) exists(name string) bool {
	for k := range i.records {
		if k.name == name || hasSuffix(k.name, name) {
			return true
		}
	}
	return false
}

func hasSuffix(name, zone string) bool {
	return len(name) > len(zone) && name[len(name)-len(zone)-1:] == "."+zone
}

// apply changes a regular answer as the behavior says.
func apply(m *dnsmessage.Message, b Behavior, udp bool) {
	switch b {
	case TruncateUDP, HugeTCP:
		if udp {
			m.Truncated, m.Answers = true, nil
		}
	case AlwaysTruncated:
		m.Truncated, m.Answers = true, nil
	case WrongID:
		m.ID++
	case WrongQuestion:
		m.Questions = []dnsmessage.Question{{Name: dnsmessage.MustNewName("other.example."), Type: m.Questions[0].Type, Class: dnsmessage.ClassINET}}
	case NotAResponse:
		m.Response = false
	case ServFail:
		m.RCode = dnsmessage.RCodeServerFailure
	case ManyRecords:
		m.Answers = slices.Repeat([]dnsmessage.Resource{TXT("many."+m.Questions[0].Name.String(), 1, "x")}, manyRecords)
	}
}

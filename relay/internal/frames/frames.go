// SPDX-License-Identifier: Apache-2.0

// Package frames checks frames of the tunnel protocol (RELAY-v0 sections 4.3, 4.4 and 4.7)
// and the binding of a data connection (section 4.5). It is the reference for the cases in
// relay/conformance/frames-v0.json and relay/conformance/binding-v0.json, used only by tests.
package frames

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
)

// MaxPayload is the largest payload of a frame.
const MaxPayload = 1024

// headerSize is the size of type and payload length.
const headerSize = 4

// TokenSize is the size of a token and of a pin.
const TokenSize = 32

// Senders.
const (
	Gateway = "gateway"
	Relay   = "relay"
)

// Message types.
const (
	typeHello       = 0x0001
	typeHelloAck    = 0x0002
	typePing        = 0x0003
	typePong        = 0x0004
	typeStreamOpen  = 0x0010
	typeStreamClose = 0x0011
	typeError       = 0x0012
	typeDrain       = 0x0013
	typePins        = 0x0014
	typePinsAck     = 0x0015
	typeDataBind    = 0x0020
	firstExtension  = 0x0100
	firstOptional   = 0x8000
)

// ErrFrame is returned for a frame that the receiver treats as an error.
var ErrFrame = errors.New("frames: error")

// ErrCase is returned for input that is not a frame a case can hold: a payload shorter
// than its header announces, or bytes after it.
var ErrCase = errors.New("frames: not one frame")

// Frame is one frame and who sent it.
type Frame struct {
	From string
	Data []byte
}

// Message is a decoded frame, in the form of the cases.
type Message map[string]any

// split checks the header and returns type and payload. A header that announces more than
// MaxPayload is an error whatever follows it.
func split(data []byte) (uint16, []byte, error) {
	if len(data) < headerSize {
		return 0, nil, fmt.Errorf("%w: %d bytes", ErrCase, len(data))
	}
	typ := binary.BigEndian.Uint16(data)
	n := int(binary.BigEndian.Uint16(data[2:]))
	if n > MaxPayload {
		return 0, nil, fmt.Errorf("%w: payload length %d", ErrFrame, n)
	}
	if len(data) != headerSize+n {
		return 0, nil, fmt.Errorf("%w: %d bytes for a payload of %d", ErrCase, len(data)-headerSize, n)
	}
	return typ, data[headerSize:], nil
}

// reader reads the fields of a payload; the first failure sticks.
type reader struct {
	b   []byte
	err error
}

func (r *reader) fail(format string, args ...any) {
	if r.err == nil {
		r.err = fmt.Errorf("%w: "+format, append([]any{ErrFrame}, args...)...)
	}
}

func (r *reader) take(n int) []byte {
	if r.err != nil {
		return nil
	}
	if len(r.b) < n {
		r.fail("payload too short")
		return nil
	}
	out := r.b[:n]
	r.b = r.b[n:]
	return out
}

func (r *reader) u8() int {
	b := r.take(1)
	if b == nil {
		return 0
	}
	return int(b[0])
}

func (r *reader) u16() int {
	b := r.take(2)
	if b == nil {
		return 0
	}
	return int(binary.BigEndian.Uint16(b))
}

func (r *reader) u32() int64 {
	b := r.take(4)
	if b == nil {
		return 0
	}
	return int64(binary.BigEndian.Uint32(b))
}

// within checks the range of an integer read before.
func (r *reader) within(name string, v, lo, hi int) int {
	if r.err == nil && (v < lo || v > hi) {
		r.fail("%s %d out of range", name, v)
	}
	return v
}

// str reads a string of lo to hi printable ASCII bytes.
func (r *reader) str(name string, lo, hi int) string {
	n := r.u8()
	b := r.take(n)
	if r.err != nil {
		return ""
	}
	if n < lo || n > hi {
		r.fail("%s of %d bytes", name, n)
	}
	for _, c := range b {
		if c < 0x20 || c > 0x7E {
			r.fail("%s with byte %#x", name, c)
		}
	}
	return string(b)
}

// capabilities reads at most 16 non-zero capabilities in strictly ascending order.
func (r *reader) capabilities() []int {
	n := r.u8()
	if r.err == nil && n > 16 {
		r.fail("%d capabilities", n)
	}
	caps := []int{}
	for i := 0; i < n && r.err == nil; i++ {
		c := r.u16()
		if r.err == nil && (c == 0 || (len(caps) > 0 && c <= caps[len(caps)-1])) {
			r.fail("capability %d zero or not ascending", c)
		}
		caps = append(caps, c)
	}
	return caps
}

func (r *reader) hex(n int) string {
	return hex.EncodeToString(r.take(n))
}

// end requires that nothing is left.
func (r *reader) end() {
	if r.err == nil && len(r.b) != 0 {
		r.fail("%d trailing bytes", len(r.b))
	}
}

// pins reads n pins of 32 bytes in strictly ascending byte order.
func (r *reader) pins(n int) []string {
	out := []string{}
	var prev []byte
	for i := 0; i < n && r.err == nil; i++ {
		p := r.take(TokenSize)
		if p != nil && prev != nil && bytes.Compare(p, prev) <= 0 {
			r.fail("pins not in strictly ascending order")
		}
		prev = p
		out = append(out, hex.EncodeToString(p))
	}
	return out
}

// kind gives the name, the sender (empty for either) and the connection of each core type
// (section 4.3).
var kind = map[uint16]struct {
	name, from string
	data       bool
}{
	typeHello:       {"hello", Gateway, false},
	typeHelloAck:    {"hello-ack", Relay, false},
	typePing:        {"ping", "", false},
	typePong:        {"pong", "", false},
	typeStreamOpen:  {"stream-open", Relay, false},
	typeStreamClose: {"stream-close", "", false},
	typeError:       {"error", "", false},
	typeDrain:       {"drain", "", false},
	typePins:        {"pins", Relay, false},
	typePinsAck:     {"pins-ack", Gateway, false},
	typeDataBind:    {"data-bind", Gateway, true},
}

// Control checks the frames of a control connection in order, each by the rules its
// receiver applies. It returns the decoded messages and, if a frame is an error, its index;
// otherwise the index is -1.
func Control(frames []Frame) ([]Message, int, error) {
	s := NewSession()
	out := make([]Message, 0, len(frames))
	for i, f := range frames {
		m, err := s.Next(f)
		if err != nil {
			return out, i, err
		}
		out = append(out, m)
	}
	return out, -1, nil
}

// Session is the state of a control connection that the rules need, fed one frame at a time:
// the receiver of a live connection and Control use the same rules. After a frame that is an
// error the session refuses every further frame.
type Session struct {
	failed      error
	hello       Message
	acked       bool
	closed      bool
	drained     map[string]bool   // by the side that sent drain
	outstanding map[string]string // unanswered ping value by sender
	pins        map[int64]bool    // sequences of the pins the relay sent
}

// NewSession returns the state of a control connection before its first frame.
func NewSession() *Session {
	return &Session{outstanding: map[string]string{}, pins: map[int64]bool{}, drained: map[string]bool{}}
}

// Acked reports whether hello-ack has been seen.
func (s *Session) Acked() bool { return s.acked }

// Next checks one frame of the connection, in the order the frames are sent, by the rules its
// receiver applies, and returns the decoded message.
func (s *Session) Next(f Frame) (Message, error) {
	if s.failed != nil {
		return nil, s.failed
	}
	m, err := s.next(f)
	if err != nil {
		s.failed = err
	}
	return m, err
}

func (s *Session) next(f Frame) (Message, error) {
	if f.From != Gateway && f.From != Relay {
		return nil, fmt.Errorf("%w: sender %q", ErrCase, f.From)
	}
	if s.closed {
		return nil, fmt.Errorf("%w: a frame after error", ErrCase)
	}
	typ, payload, err := split(f.Data)
	if err != nil {
		return nil, err
	}
	switch {
	case typ >= firstOptional:
		if !s.acked {
			return nil, fmt.Errorf("%w: optional frame before hello-ack", ErrFrame)
		}
		return Message{"type": "ignored"}, nil
	case typ >= firstExtension:
		return nil, fmt.Errorf("%w: extension %#04x without its capability", ErrFrame, typ)
	}
	k, known := kind[typ]
	switch {
	case !known:
		return nil, fmt.Errorf("%w: type %#04x", ErrFrame, typ)
	case k.data:
		// e68 also fails on its payload; the rule matters once a data type has no payload.
		return nil, fmt.Errorf("%w: %s on a control connection", ErrFrame, k.name)
	case k.from != "" && k.from != f.From:
		return nil, fmt.Errorf("%w: %s from the %s", ErrFrame, k.name, f.From)
	}
	if err := s.phase(typ, k.name, f.From); err != nil {
		return nil, err
	}
	r := &reader{b: payload}
	m := decode(typ, r)
	r.end()
	if r.err != nil {
		return nil, r.err
	}
	m["type"] = k.name
	return m, s.apply(typ, f.From, m)
}

// phase: before hello-ack only hello, hello-ack and error are valid, and each of the first
// two only once.
// The relay sends nothing before hello, not even error.
func (s *Session) phase(typ uint16, name, from string) error {
	switch {
	case from == Relay && s.hello == nil:
		return fmt.Errorf("%w: %s from the relay before hello", ErrFrame, name)
	case typ == typeHello && s.hello != nil, typ == typeHelloAck && s.acked:
		return fmt.Errorf("%w: second %s", ErrFrame, name)
	case typ == typeHello, typ == typeError:
		return nil
	case typ == typeHelloAck && s.hello == nil:
		return fmt.Errorf("%w: hello-ack before hello", ErrFrame)
	case typ == typeHelloAck:
		return nil
	case !s.acked:
		return fmt.Errorf("%w: %s before hello-ack", ErrFrame, name)
	}
	return nil
}

func decode(typ uint16, r *reader) Message {
	switch typ {
	case typeHello:
		lo := r.u8()
		hi := r.u8()
		if r.err == nil && (lo < 1 || lo > hi) {
			r.fail("versions %d to %d", lo, hi)
		}
		software := r.str("software", 1, 64)
		return Message{"min_version": lo, "max_version": hi, "software": software, "capabilities": r.capabilities()}
	case typeHelloAck:
		version := r.u8()
		software := r.str("software", 1, 64)
		heartbeat := r.within("heartbeat interval", r.u16(), 5, 120)
		pool := r.within("pool size", r.u8(), 0, 16)
		streams := r.within("max streams", r.u16(), 1, 256)
		return Message{
			"version": version, "software": software, "heartbeat_interval": heartbeat,
			"pool_size": pool, "max_streams": streams, "capabilities": r.capabilities(),
		}
	case typePing, typePong:
		return Message{"value": r.hex(8)}
	case typeStreamOpen:
		token := r.hex(TokenSize)
		return Message{"token": token, "validity_ms": r.within("validity", r.u16(), 1, 10000)}
	case typeStreamClose:
		token := r.hex(TokenSize)
		return Message{"token": token, "reason": r.within("reason", r.u8(), 1, 4)}
	case typeError:
		code := r.u16()
		if r.err == nil && code == 0 {
			r.fail("error code 0")
		}
		text := r.str("text", 0, 128)
		return Message{"code": code, "text": text}
	case typeDrain:
		reason := r.within("reason", r.u8(), 1, 3)
		return Message{"reason": reason, "grace": r.within("grace", r.u16(), 0, 600)}
	case typePins:
		seq := r.u32()
		nActive := r.u8()
		nBackup := r.u8()
		active := r.pins(nActive)
		return Message{"sequence": seq, "active": active, "backup": r.pins(nBackup)}
	case typePinsAck:
		seq := r.u32()
		return Message{"sequence": seq, "result": r.within("result", r.u8(), 1, 2)}
	}
	return Message{}
}

// apply checks the rules between frames and updates the state.
func (s *Session) apply(typ uint16, from string, m Message) error {
	other := Relay
	if from == Relay {
		other = Gateway
	}
	switch typ {
	case typeHello:
		s.hello = m
	case typeHelloAck:
		return s.ack(m)
	case typePing:
		if _, ok := s.outstanding[from]; ok {
			return fmt.Errorf("%w: a second unanswered ping", ErrFrame)
		}
		s.outstanding[from] = m["value"].(string)
	case typePong:
		want, ok := s.outstanding[other]
		if !ok || want != m["value"] {
			return fmt.Errorf("%w: pong without a matching ping", ErrFrame)
		}
		delete(s.outstanding, other)
	case typeStreamOpen:
		// A stream-open after the gateway's drain may have crossed it; the gateway refuses
		// it with stream-close. After the relay's own drain it is an error.
		if s.drained[Relay] {
			return fmt.Errorf("%w: stream-open after the relay's drain", ErrFrame)
		}
	case typeError:
		s.closed = true
	case typeDrain:
		s.drained[from] = true
	case typePins:
		s.pins[m["sequence"].(int64)] = true
	case typePinsAck:
		if !s.pins[m["sequence"].(int64)] {
			return fmt.Errorf("%w: pins-ack for no pins", ErrFrame)
		}
	}
	return nil
}

// ack: the version is in the range of hello, and every capability was offered in hello.
func (s *Session) ack(m Message) error {
	v := m["version"].(int)
	if v < s.hello["min_version"].(int) || v > s.hello["max_version"].(int) {
		return fmt.Errorf("%w: version %d not in the range of hello", ErrFrame, v)
	}
	offered := map[int]bool{}
	for _, c := range s.hello["capabilities"].([]int) {
		offered[c] = true
	}
	for _, c := range m["capabilities"].([]int) {
		if !offered[c] {
			return fmt.Errorf("%w: capability %d not offered", ErrFrame, c)
		}
	}
	s.acked = true
	return nil
}

// DataBind checks the first frame of a data connection: a data-bind with a token of exactly
// 32 bytes. It returns the token.
func DataBind(data []byte) ([]byte, error) {
	typ, payload, err := split(data)
	if err != nil {
		return nil, err
	}
	if typ != typeDataBind || len(payload) != TokenSize {
		return nil, fmt.Errorf("%w: type %#04x with %d bytes is not a data-bind", ErrFrame, typ, len(payload))
	}
	return payload, nil
}

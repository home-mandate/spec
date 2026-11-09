// SPDX-License-Identifier: Apache-2.0

package frames

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

// ErrEncode is returned for a value that does not fit the field of its frame. Encoders do not
// judge the rules of section 4: a test tool encodes frames with deliberate defects too.
var ErrEncode = errors.New("frames: value does not fit its field")

// Error codes of the error frame (section 4.4).
const (
	CodeUnsupportedVersion = 1
	CodeMalformed          = 2
	CodeUnknownType        = 3
	CodeLimitExceeded      = 4
	CodeUnauthorized       = 5
	CodeTimeout            = 6
	CodeInternal           = 7
	CodeSuperseded         = 8
	CodeProtocol           = 9
	CodeSessionExists      = 10
)

// Reasons of stream-close (section 4.4).
const (
	ReasonAgentGone = 1
	ReasonRefused   = 2
	ReasonTimeout   = 3
	ReasonInternal  = 4
)

// Hello is the first frame of a control connection.
type Hello struct {
	MinVersion, MaxVersion int
	Software               string
	Capabilities           []int
}

// HelloAck answers a hello.
type HelloAck struct {
	Version                         int
	Software                        string
	Heartbeat, PoolSize, MaxStreams int
	Capabilities                    []int
}

// builder collects the payload of a frame; the first value that does not fit sticks.
type builder struct {
	buf []byte
	err error
}

func (b *builder) fit(name string, v, max int) bool {
	if v < 0 || v > max {
		if b.err == nil {
			b.err = fmt.Errorf("%w: %s %d", ErrEncode, name, v)
		}
		return false
	}
	return true
}

func (b *builder) u8(name string, v int) {
	if b.fit(name, v, math.MaxUint8) {
		b.buf = append(b.buf, byte(v))
	}
}

func (b *builder) u16(name string, v int) {
	if b.fit(name, v, math.MaxUint16) {
		b.buf = binary.BigEndian.AppendUint16(b.buf, uint16(v))
	}
}

func (b *builder) u32(v uint32) { b.buf = binary.BigEndian.AppendUint32(b.buf, v) }

func (b *builder) str(name, v string) {
	if b.fit(name, len(v), math.MaxUint8) {
		b.buf = append(append(b.buf, byte(len(v))), v...)
	}
}

func (b *builder) caps(list []int) {
	b.u8("capability count", len(list))
	for _, c := range list {
		b.u16("capability", c)
	}
}

func (b *builder) frame(typ uint16) ([]byte, error) {
	if b.err != nil {
		return nil, b.err
	}
	if len(b.buf) > math.MaxUint16 {
		return nil, fmt.Errorf("%w: payload of %d bytes", ErrEncode, len(b.buf))
	}
	out := binary.BigEndian.AppendUint16(nil, typ)
	out = binary.BigEndian.AppendUint16(out, uint16(len(b.buf)))
	return append(out, b.buf...), nil
}

// Encode returns the bytes of the frame.
func (h Hello) Encode() ([]byte, error) {
	b := &builder{}
	b.u8("min version", h.MinVersion)
	b.u8("max version", h.MaxVersion)
	b.str("software", h.Software)
	b.caps(h.Capabilities)
	return b.frame(typeHello)
}

// Encode returns the bytes of the frame.
func (a HelloAck) Encode() ([]byte, error) {
	b := &builder{}
	b.u8("version", a.Version)
	b.str("software", a.Software)
	b.u16("heartbeat interval", a.Heartbeat)
	b.u8("pool size", a.PoolSize)
	b.u16("max streams", a.MaxStreams)
	b.caps(a.Capabilities)
	return b.frame(typeHelloAck)
}

// EncodePing returns a ping with the value.
func EncodePing(value [8]byte) []byte { return must(Raw(typePing, value[:])) }

// EncodePong returns a pong with the value of the ping it answers.
func EncodePong(value [8]byte) []byte { return must(Raw(typePong, value[:])) }

// EncodeStreamOpen returns a stream-open.
func EncodeStreamOpen(token [TokenSize]byte, validityMS int) ([]byte, error) {
	b := &builder{buf: append([]byte{}, token[:]...)}
	b.u16("validity", validityMS)
	return b.frame(typeStreamOpen)
}

// EncodeStreamClose returns a stream-close.
func EncodeStreamClose(token [TokenSize]byte, reason int) ([]byte, error) {
	b := &builder{buf: append([]byte{}, token[:]...)}
	b.u8("reason", reason)
	return b.frame(typeStreamClose)
}

// EncodeError returns an error frame.
func EncodeError(code int, text string) ([]byte, error) {
	b := &builder{}
	b.u16("error code", code)
	b.str("text", text)
	return b.frame(typeError)
}

// EncodeDrain returns a drain.
func EncodeDrain(reason, grace int) ([]byte, error) {
	b := &builder{}
	b.u8("reason", reason)
	b.u16("grace", grace)
	return b.frame(typeDrain)
}

// EncodePins returns a pins frame; the pins are written as given.
func EncodePins(sequence uint32, active, backup [][TokenSize]byte) ([]byte, error) {
	b := &builder{}
	b.u32(sequence)
	b.u8("active pins", len(active))
	b.u8("backup pins", len(backup))
	for _, p := range append(append([][TokenSize]byte{}, active...), backup...) {
		b.buf = append(b.buf, p[:]...)
	}
	return b.frame(typePins)
}

// EncodePinsAck returns a pins-ack.
func EncodePinsAck(sequence uint32, result int) ([]byte, error) {
	b := &builder{}
	b.u32(sequence)
	b.u8("result", result)
	return b.frame(typePinsAck)
}

// EncodeDataBind returns the data-bind of a data connection.
func EncodeDataBind(token [TokenSize]byte) []byte { return must(Raw(typeDataBind, token[:])) }

// Raw returns a frame of any type with any payload of at most 65535 bytes, for frames with
// defects.
func Raw(typ uint16, payload []byte) ([]byte, error) {
	b := &builder{buf: payload}
	return b.frame(typ)
}

// must returns v and panics on an error that cannot happen: the inputs have fixed sizes.
func must[T any](v T, err error) T {
	if err != nil {
		panic("frames: " + err.Error())
	}
	return v
}

// SPDX-License-Identifier: Apache-2.0

package frames

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func tokenOf(b byte) [TokenSize]byte {
	var t [TokenSize]byte
	for i := range t {
		t[i] = b + byte(i)
	}
	return t
}

// feed passes frames to a session in order and returns the decoded messages.
func feed(t *testing.T, in ...Frame) []Message {
	t.Helper()
	msgs, at, err := Control(in)
	if err != nil {
		t.Fatalf("frame %d: %v", at, err)
	}
	return msgs
}

// ok returns an encoding that has to succeed.
func ok(b []byte, err error) []byte {
	if err != nil {
		panic(err)
	}
	return b
}

func TestEncodersProduceFramesTheSessionDecodes(t *testing.T) {
	hello := ok(Hello{MinVersion: 1, MaxVersion: 3, Software: "gw", Capabilities: []int{2, 7}}.Encode())
	ack := ok(HelloAck{Version: 1, Software: "rl", Heartbeat: 30, PoolSize: 2, MaxStreams: 64, Capabilities: []int{2}}.Encode())
	open := ok(EncodeStreamOpen(tokenOf(1), 10000))
	closeFrame := ok(EncodeStreamClose(tokenOf(1), ReasonRefused))
	errFrame := ok(EncodeError(CodeSessionExists, "again"))
	drain := ok(EncodeDrain(1, 600))
	pins := ok(EncodePins(7, [][TokenSize]byte{tokenOf(1), tokenOf(9)}, [][TokenSize]byte{tokenOf(4)}))
	pinsAck := ok(EncodePinsAck(7, 2))
	ping := EncodePing([8]byte{1, 2, 3, 4, 5, 6, 7, 8})
	pong := EncodePong([8]byte{1, 2, 3, 4, 5, 6, 7, 8})
	msgs := feed(t,
		Frame{Gateway, hello}, Frame{Relay, ack}, Frame{Relay, open}, Frame{Gateway, closeFrame},
		Frame{Relay, pins}, Frame{Gateway, pinsAck}, Frame{Relay, ping}, Frame{Gateway, pong},
		Frame{Gateway, drain}, Frame{Relay, errFrame})
	want := []Message{
		{"type": "hello", "min_version": 1, "max_version": 3, "software": "gw", "capabilities": []int{2, 7}},
		{"type": "hello-ack", "version": 1, "software": "rl", "heartbeat_interval": 30, "pool_size": 2, "max_streams": 64, "capabilities": []int{2}},
		{"type": "stream-open", "token": hexOf(tokenOf(1)), "validity_ms": 10000},
		{"type": "stream-close", "token": hexOf(tokenOf(1)), "reason": ReasonRefused},
		{"type": "pins", "sequence": int64(7), "active": []string{hexOf(tokenOf(1)), hexOf(tokenOf(9))}, "backup": []string{hexOf(tokenOf(4))}},
		{"type": "pins-ack", "sequence": int64(7), "result": 2},
		{"type": "ping", "value": "0102030405060708"},
		{"type": "pong", "value": "0102030405060708"},
		{"type": "drain", "reason": 1, "grace": 600},
		{"type": "error", "code": CodeSessionExists, "text": "again"},
	}
	for i := range want {
		if !reflect.DeepEqual(msgs[i], want[i]) {
			t.Errorf("frame %d: %v, want %v", i, msgs[i], want[i])
		}
	}
}

func hexOf(t [TokenSize]byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, 2*TokenSize)
	for _, b := range t {
		out = append(out, digits[b>>4], digits[b&15])
	}
	return string(out)
}

func TestEncodersDoNotJudgeTheRulesOfTheProtocol(t *testing.T) {
	// A heartbeat of 3 seconds is encodable: a test relay with a defect writes it.
	ack := ok(HelloAck{Version: 1, Software: "r", Heartbeat: 3, MaxStreams: 1}.Encode())
	hello := ok(Hello{MinVersion: 1, MaxVersion: 1, Software: "g"}.Encode())
	if _, at, err := Control([]Frame{{Gateway, hello}, {Relay, ack}}); !errors.Is(err, ErrFrame) || at != 1 {
		t.Errorf("at %d: %v", at, err)
	}
}

func TestEncodersRefuseValuesThatDoNotFitTheirField(t *testing.T) {
	long := strings.Repeat("x", 256)
	for name, f := range map[string]func() ([]byte, error){
		"software too long":   func() ([]byte, error) { return Hello{Software: long}.Encode() },
		"negative version":    func() ([]byte, error) { return Hello{MinVersion: -1}.Encode() },
		"version over a byte": func() ([]byte, error) { return Hello{MaxVersion: 256}.Encode() },
		"too many caps":       func() ([]byte, error) { return Hello{Capabilities: make([]int, 256)}.Encode() },
		"capability over u16": func() ([]byte, error) { return Hello{Capabilities: []int{65536}}.Encode() },
		"heartbeat over u16":  func() ([]byte, error) { return HelloAck{Heartbeat: 65536}.Encode() },
		"validity over u16":   func() ([]byte, error) { return EncodeStreamOpen(tokenOf(0), 65536) },
		"reason over a byte":  func() ([]byte, error) { return EncodeStreamClose(tokenOf(0), 256) },
		"error text long":     func() ([]byte, error) { return EncodeError(1, long) },
		"drain grace":         func() ([]byte, error) { return EncodeDrain(1, -1) },
		"too many pins":       func() ([]byte, error) { return EncodePins(1, make([][TokenSize]byte, 256), nil) },
		"result over a byte":  func() ([]byte, error) { return EncodePinsAck(1, 256) },
		"payload too long":    func() ([]byte, error) { return Raw(1, make([]byte, 65536)) },
	} {
		if out, err := f(); !errors.Is(err, ErrEncode) || out != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestRawAndDataBind(t *testing.T) {
	if got := ok(Raw(0x8000, []byte{1, 2})); !bytes.Equal(got, []byte{0x80, 0, 0, 2, 1, 2}) {
		t.Errorf("Raw: %x", got)
	}
	token, err := DataBind(EncodeDataBind(tokenOf(3)))
	if err != nil || !bytes.Equal(token, func() []byte { t := tokenOf(3); return t[:] }()) {
		t.Errorf("DataBind: %x, %v", token, err)
	}
}

// SPDX-License-Identifier: Apache-2.0

package frames

import (
	"bytes"
	"errors"
	"io"
	"testing"
	"testing/iotest"
)

func TestReadFrame(t *testing.T) {
	two := append(EncodePing([8]byte{1}), EncodePong([8]byte{1})...)
	r := bytes.NewReader(two)
	for i := range 2 {
		f, err := ReadFrame(r)
		if err != nil || len(f) != 12 {
			t.Fatalf("frame %d: %x, %v", i, f, err)
		}
	}
	if _, err := ReadFrame(r); !errors.Is(err, io.EOF) {
		t.Errorf("at the end: %v", err)
	}
	// One byte at a time still gives whole frames.
	if f, err := ReadFrame(iotest.OneByteReader(bytes.NewReader(two))); err != nil || len(f) != 12 {
		t.Errorf("one byte reader: %v", err)
	}
}

func TestReadFrameChecksTheHeaderBeforeItReadsThePayload(t *testing.T) {
	// The reader holds nothing after the header: a payload of 1025 would end in an error of
	// the reader, so the frame error shows that nothing was read.
	if _, err := ReadFrame(bytes.NewReader([]byte{0, 0x20, 0x04, 0x01})); !errors.Is(err, ErrFrame) {
		t.Errorf("1025 bytes: %v", err)
	}
	if f, err := ReadFrame(bytes.NewReader(append([]byte{0, 0x20, 0x04, 0x00}, make([]byte, MaxPayload)...))); err != nil || len(f) != headerSize+MaxPayload {
		t.Errorf("1024 bytes: %v", err)
	}
}

func TestReadFrameReturnsWhatTheReaderReports(t *testing.T) {
	for name, in := range map[string][]byte{"short header": {0, 1}, "short payload": {0, 1, 0, 4, 1}} {
		if _, err := ReadFrame(bytes.NewReader(in)); !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func FuzzReadFrame(f *testing.F) {
	for _, seed := range [][]byte{nil, {0, 1}, {0, 1, 0, 0}, {0, 0x20, 0x04, 0x01}, append([]byte{0, 0x20, 0, 0x20}, make([]byte, 32)...), {0xff, 0xff, 0xff, 0xff}} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		frame, err := ReadFrame(bytes.NewReader(data))
		if err != nil {
			if frame != nil {
				t.Fatal("a frame with an error")
			}
			return
		}
		if !bytes.HasPrefix(data, frame) || len(frame) < headerSize || len(frame) > headerSize+MaxPayload {
			t.Fatalf("frame %x of %x", frame, data)
		}
		if n := int(frame[2])<<8 | int(frame[3]); len(frame) != headerSize+n {
			t.Fatalf("length %d for %d bytes", n, len(frame))
		}
		// What ReadFrame returns is one frame for the session.
		if _, _, err := Control([]Frame{{From: Gateway, Data: frame}}); errors.Is(err, ErrCase) {
			t.Fatalf("not a frame for the session: %v", err)
		}
	})
}

func TestPeekNamesTheTypeAndTheCodeOfAnErrorWithoutTheRules(t *testing.T) {
	errFrame := ok(EncodeError(CodeSessionExists, "x"))
	for name, tt := range map[string]struct {
		in   []byte
		want string
		code int
	}{
		"error":       {errFrame, "error", CodeSessionExists},
		"short error": {[]byte{0, 0x12, 0, 0}, "error", 0},
		"pong":        {EncodePong([8]byte{}), "pong", 0},
		"data-bind":   {EncodeDataBind([32]byte{}), "data-bind", 0},
		"unassigned":  {[]byte{0, 0x05, 0, 0}, "unknown", 0},
		"optional":    {[]byte{0x80, 0, 0, 0}, "unknown", 0},
		"too short":   {[]byte{0, 1}, "unknown", 0},
	} {
		if got, code := Peek(tt.in); got != tt.want || code != tt.code {
			t.Errorf("%s: %s %d, want %s %d", name, got, code, tt.want, tt.code)
		}
	}
}

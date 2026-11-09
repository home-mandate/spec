// SPDX-License-Identifier: Apache-2.0

package frames

import (
	"encoding/binary"
	"fmt"
	"io"
)

// ReadFrame reads one frame from r and returns its bytes, header included, as Session.Next
// takes them. A header that announces more than MaxPayload is an error (ErrFrame), and nothing
// is read or allocated for its payload (section 4.3). A read error is returned as it is, so
// that a deadline can be told from a closed connection.
func ReadFrame(r io.Reader) ([]byte, error) {
	head := make([]byte, headerSize, headerSize+MaxPayload)
	if _, err := io.ReadFull(r, head); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(head[2:]))
	if n > MaxPayload {
		return nil, fmt.Errorf("%w: payload length %d", ErrFrame, n)
	}
	frame := head[:headerSize+n]
	if _, err := io.ReadFull(r, frame[headerSize:]); err != nil {
		return nil, err
	}
	return frame, nil
}

// Peek names the type of a frame and, for an error frame, its code, without applying the
// rules of a connection: a tool that sends frames with defects reads what the relay answers
// with it. The name is "unknown" for a type that section 4.3 does not assign, and the frame
// need not be valid.
func Peek(frame []byte) (name string, code int) {
	if len(frame) < headerSize {
		return "unknown", 0
	}
	typ := binary.BigEndian.Uint16(frame)
	k, known := kind[typ]
	if !known {
		return "unknown", 0
	}
	if typ == typeError && len(frame) >= headerSize+2 {
		code = int(binary.BigEndian.Uint16(frame[headerSize:]))
	}
	return k.name, code
}

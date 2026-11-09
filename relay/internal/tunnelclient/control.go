// SPDX-License-Identifier: Apache-2.0

package tunnelclient

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/home-mandate/spec/relay/internal/frames"
)

const (
	// writeTimeout is how long a write may take (section 4.4).
	writeTimeout = 5 * time.Second
	// maxPending bounds the stream-open frames kept for the caller.
	maxPending = 64
	// resultIgnored is the result of a pins-ack for a set the tool does not store.
	resultIgnored = 2
)

// ErrClosed is returned when the relay closed the control connection.
var ErrClosed = errors.New("tunnelclient: the connection was closed")

// RelayError is an error frame of the relay.
type RelayError struct {
	Code int
}

func (e *RelayError) Error() string {
	return fmt.Sprintf("tunnelclient: the relay sent error %d", e.Code)
}

// Open is a stream-open of the relay.
type Open struct {
	Token      [frames.TokenSize]byte
	ValidityMS int
}

// Control is a control connection of a gateway. The frames it receives are checked by the rules
// of the receiver (package frames). Before Run, Recv reads synchronously; after Run, a reader
// answers ping and pins and keeps what the caller waits for.
type Control struct {
	conn *Conn
	fs   *frames.Session

	wmu sync.Mutex
	mu  sync.Mutex

	opens chan Open
	done  chan struct{}
	err   error
	pins  []frames.Message
}

// OpenControl dials a control connection; Hello comes next.
func OpenControl(ctx context.Context, d Dialer, address string, p Params) (*Control, error) {
	conn, err := Dial(ctx, d, address, p)
	if err != nil {
		return nil, err
	}
	return &Control{conn: conn, fs: frames.NewSession(), opens: make(chan Open, maxPending), done: make(chan struct{})}, nil
}

// Pin returns the pin of the relay's key.
func (c *Control) Pin() Pin { return c.conn.Pin }

// State returns the state of the TLS connection.
func (c *Control) State() tls.ConnectionState { return c.conn.ConnectionState() }

// Close closes the connection.
func (c *Control) Close() { _ = c.conn.Close() }

// Hello sends a hello of version 1.
func (c *Control) Hello() error {
	raw, err := frames.Hello{MinVersion: 1, MaxVersion: 1, Software: "relay-conformance"}.Encode()
	if err != nil {
		return err
	}
	if _, err := c.observe(frames.Gateway, raw); err != nil {
		return err
	}
	return c.write(raw)
}

func (c *Control) observe(from string, raw []byte) (frames.Message, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.fs.Next(frames.Frame{From: from, Data: raw})
}

// Write sends bytes as they are, for frames with defects.
func (c *Control) Write(raw []byte) error { return c.write(raw) }

func (c *Control) write(raw []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	_ = c.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	_, err := c.conn.Write(raw)
	return err
}

// Recv reads one frame within wait; zero waits without limit. The error is ErrTimeout,
// ErrClosed, a *RelayError for an error frame, or an error of package frames for a frame that
// the rules of the gateway refuse. It is only for use before Run.
func (c *Control) Recv(wait time.Duration) (frames.Message, error) {
	setDeadline(c.conn, wait)
	raw, err := frames.ReadFrame(c.conn)
	switch {
	case errors.Is(err, os.ErrDeadlineExceeded):
		return nil, ErrTimeout
	case errors.Is(err, frames.ErrFrame):
		return nil, err
	case err != nil:
		return nil, ErrClosed
	}
	msg, err := c.observe(frames.Relay, raw)
	if err != nil {
		return nil, err
	}
	if msg["type"] == "error" {
		return msg, &RelayError{Code: msg["code"].(int)}
	}
	return msg, nil
}

// Run starts the reader of an open connection: it answers ping with pong and pins with
// pins-ack (ignored: the tool stores no pins), and keeps stream-open frames for WaitOpen.
func (c *Control) Run() { go c.run() }

func (c *Control) run() {
	defer close(c.done)
	for {
		msg, err := c.Recv(0)
		if err != nil {
			c.finish(err)
			return
		}
		switch msg["type"] {
		case "ping":
			c.answerPing(msg)
		case "pins":
			c.answerPins(msg)
		case "stream-open":
			c.keepOpen(msg)
		}
	}
}

func (c *Control) finish(err error) {
	c.mu.Lock()
	c.err = err
	c.mu.Unlock()
}

func (c *Control) answerPing(msg frames.Message) {
	var value [8]byte
	copy(value[:], decodeHex(msg["value"].(string)))
	raw := frames.EncodePong(value)
	if _, err := c.observe(frames.Gateway, raw); err == nil {
		_ = c.write(raw)
	}
}

func (c *Control) answerPins(msg frames.Message) {
	c.mu.Lock()
	c.pins = append(c.pins, msg)
	c.mu.Unlock()
	raw, _ := frames.EncodePinsAck(uint32(msg["sequence"].(int64)), resultIgnored)
	if _, err := c.observe(frames.Gateway, raw); err == nil {
		_ = c.write(raw)
	}
}

func (c *Control) keepOpen(msg frames.Message) {
	var open Open
	copy(open.Token[:], decodeHex(msg["token"].(string)))
	open.ValidityMS = msg["validity_ms"].(int)
	select {
	case c.opens <- open:
	default:
	}
}

// TryOpen returns the next stream-open if one has come.
func (c *Control) TryOpen() (Open, bool) {
	select {
	case open := <-c.opens:
		return open, true
	default:
		return Open{}, false
	}
}

// WaitOpen waits for the next stream-open; it fails when the connection ends or wait passes.
func (c *Control) WaitOpen(wait time.Duration) (Open, error) {
	select {
	case open := <-c.opens:
		return open, nil
	case <-c.done:
		return Open{}, c.Err()
	case <-time.After(wait):
		return Open{}, ErrTimeout
	}
}

// Done is closed when the connection has ended.
func (c *Control) Done() <-chan struct{} { return c.done }

// Err returns why the connection ended: ErrClosed, a *RelayError, or an error of package frames.
func (c *Control) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}

// Pins returns the pins frames the relay sent while Run read the connection.
func (c *Control) Pins() []frames.Message {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]frames.Message{}, c.pins...)
}

// StreamClose withdraws or refuses a token (the token is void afterwards).
func (c *Control) StreamClose(token [frames.TokenSize]byte, reason int) error {
	raw, err := frames.EncodeStreamClose(token, reason)
	if err != nil {
		return err
	}
	if _, err := c.observe(frames.Gateway, raw); err != nil {
		return err
	}
	return c.write(raw)
}

// Event is a frame the relay sent, as far as it is named: its type and, for an error, its code.
type Event struct {
	Type string
	Code int
}

// Drain reads frames until the connection ends or wait passes, without applying the rules of
// the connection, for a test that sent a frame with a defect. It returns the frames that came
// and whether the relay closed the connection; a frame with a header that announces more than
// 1024 bytes ends it as well.
func (c *Control) Drain(wait time.Duration) (events []Event, closed bool) {
	deadline := time.Now().Add(wait)
	for time.Until(deadline) > 0 {
		setDeadline(c.conn, time.Until(deadline))
		raw, err := frames.ReadFrame(c.conn)
		if err != nil {
			return events, Closed(err) && !errors.Is(err, frames.ErrFrame)
		}
		name, code := frames.Peek(raw)
		events = append(events, Event{Type: name, Code: code})
	}
	return events, false
}

// decodeHex reads the hex of a decoded frame; the frames package only produces valid hex.
func decodeHex(s string) []byte {
	raw, _ := hex.DecodeString(s)
	return raw
}

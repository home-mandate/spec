// SPDX-License-Identifier: Apache-2.0

package refrelay

import (
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/netip"
)

var (
	errPeeked   = errors.New("refrelay: server name read")
	errTooLarge = errors.New("refrelay: ClientHello too large")
)

// replayConn reads the first bytes of a connection without consuming them (the pattern of
// tcpproxy): while it peeks, everything read is kept and everything written is discarded, so
// that the TLS server that parses the ClientHello cannot send an alert to the agent. After
// rewind, the kept bytes are read again, then the rest of the connection.
type replayConn struct {
	net.Conn
	buf     []byte
	off     int
	peeking bool
}

func newReplayConn(c net.Conn) *replayConn { return &replayConn{Conn: c, peeking: true} }

func (c *replayConn) Read(p []byte) (int, error) {
	if c.off < len(c.buf) {
		n := copy(p, c.buf[c.off:])
		c.off += n
		return n, nil
	}
	if c.peeking && len(c.buf) >= maxHello {
		return 0, errTooLarge
	}
	n, err := c.Conn.Read(p)
	if c.peeking {
		c.buf = append(c.buf, p[:n]...)
		c.off = len(c.buf)
	}
	return n, err
}

func (c *replayConn) Write(p []byte) (int, error) {
	if c.peeking {
		return len(p), nil
	}
	return c.Conn.Write(p)
}

// rewind ends the peek: the kept bytes are read again, and writes go through.
func (c *replayConn) rewind() {
	c.peeking = false
	c.off = 0
}

// release ends the peek for an agent connection: the kept bytes stay with the caller, who
// writes them to the gateway, and reads go on after them.
func (c *replayConn) release() {
	c.peeking = false
	c.off = len(c.buf)
}

// kept returns the bytes read while peeking.
func (c *replayConn) kept() []byte { return c.buf }

// CloseWrite half-closes the connection; the relay only wraps TCP connections.
func (c *replayConn) CloseWrite() error { return c.Conn.(*net.TCPConn).CloseWrite() }

// serverName reads the server name of the ClientHello without answering.
func (c *replayConn) serverName() (string, error) {
	var name string
	srv := tls.Server(c, &tls.Config{GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
		name = h.ServerName
		return nil, errPeeked
	}})
	if err := srv.Handshake(); !errors.Is(err, errPeeked) {
		return "", err
	}
	return name, nil
}

// proxySignature opens a PROXY protocol version 2 header (section 4.6).
var proxySignature = []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}

// takeProxyHeader reads the source address of a PROXY version 2 header that an agent sends
// before its ClientHello, and drops the header. This is what a relay must not do (defect R10).
func (c *replayConn) takeProxyHeader() (netip.AddrPort, bool) {
	head := make([]byte, 16)
	n, err := io.ReadFull(c.Conn, head)
	c.buf = append(c.buf, head[:n]...)
	if err != nil || string(head[:12]) != string(proxySignature) || head[13] != 0x11 {
		return netip.AddrPort{}, false
	}
	block := make([]byte, 12)
	if _, err := io.ReadFull(c.Conn, block); err != nil {
		return netip.AddrPort{}, false
	}
	c.buf = c.buf[:0]
	src, _ := netip.AddrFromSlice(block[:4])
	return netip.AddrPortFrom(src, uint16(block[8])<<8|uint16(block[9])), true
}

// SPDX-License-Identifier: Apache-2.0

package tunnelclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"time"
)

// recorder is a connection that keeps what is written to it and answers nothing.
type recorder struct {
	net.Conn
	written bytes.Buffer
}

func (r *recorder) Write(p []byte) (int, error) { return r.written.Write(p) }
func (r *recorder) Read([]byte) (int, error)    { return 0, errors.New("no answer") }

// ClientHello returns the first flight of a TLS client that asks for the server name sni
// (none if empty): the bytes an agent sends first. They are made by the TLS stack, not by hand.
func ClientHello(sni string) []byte {
	local, remote := net.Pipe()
	_ = remote.Close()
	defer local.Close()
	rec := &recorder{Conn: local}
	_ = tls.Client(rec, &tls.Config{ServerName: sni, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}).Handshake()
	return rec.written.Bytes()
}

// EncodeProxy returns a PROXY protocol version 2 header for an IPv4 source and destination; the
// test tool sends one as an agent, which a relay must not take over (section 4.6).
func EncodeProxy(src, dst netip.AddrPort) []byte {
	out := append(append([]byte{}, proxySignature...), cmdProxyV2, tcpV4, 0, proxyV4)
	out = append(out, src.Addr().AsSlice()...)
	out = append(out, dst.Addr().AsSlice()...)
	out = binary.BigEndian.AppendUint16(out, src.Port())
	return binary.BigEndian.AppendUint16(out, dst.Port())
}

// DialAgent connects as an agent and sends the parts in order.
func DialAgent(ctx context.Context, d Dialer, address string, parts ...[]byte) (net.Conn, error) {
	c, err := d.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	for _, p := range parts {
		_ = c.SetWriteDeadline(time.Now().Add(writeTimeout))
		if _, err := c.Write(p); err != nil {
			_ = c.Close()
			return nil, err
		}
	}
	return c, nil
}

// CloseWrite half-closes a connection as an agent does at the end of its request.
func CloseWrite(c net.Conn) error {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return errors.New("tunnelclient: no half close")
}

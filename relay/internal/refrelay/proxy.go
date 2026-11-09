// SPDX-License-Identifier: Apache-2.0

package refrelay

import (
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
)

// Destinations of the PROXY header (section 4.6): addresses that reveal nothing about the relay.
var (
	destV4 = netip.MustParseAddrPort("192.0.2.1:443")
	destV6 = netip.MustParseAddrPort("[2001:db8::1]:443")
)

// proxyHeader returns the PROXY protocol version 2 header for an agent at src (section 4.6),
// with the defects R8 and R9.
func (r *Relay) proxyHeader(src netip.AddrPort) []byte {
	dst := destV4
	if src.Addr().Is6() {
		dst = destV6
	}
	if r.has(RealDestination) {
		dst = r.local
	}
	if r.has(MappedIPv4) && src.Addr().Is4() {
		src = netip.AddrPortFrom(netip.AddrFrom16(src.Addr().As16()), src.Port())
		dst = netip.AddrPortFrom(netip.AddrFrom16(dst.Addr().As16()), dst.Port())
	}
	family, size := byte(0x11), 12
	if src.Addr().Is6() {
		family, size = 0x21, 36
	}
	out := append(append([]byte{}, proxySignature...), 0x21, family)
	out = binary.BigEndian.AppendUint16(out, uint16(size))
	out = append(out, src.Addr().AsSlice()...)
	out = append(out, dst.Addr().AsSlice()...)
	out = binary.BigEndian.AppendUint16(out, src.Port())
	return binary.BigEndian.AppendUint16(out, dst.Port())
}

// pipe copies the bytes of an agent connection into the data connection after the PROXY header,
// starting with those it read for the server name, and the other way round, unchanged. The end
// of a direction is passed on: a half close of the agent as close_notify and a half close of the
// connection to the gateway, and a close_notify of the gateway as a half close towards the
// agent. A relay with the defect R17 does not send close_notify.
func (r *Relay) pipe(tc *tls.Conn, t *token) {
	defer func() {
		r.mu.Lock()
		r.streams[t.home]--
		r.mu.Unlock()
		r.forget(t.agent.Conn)
	}()
	if _, err := tc.Write(t.agent.kept()); err != nil {
		return
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, err := io.Copy(tc, t.agent); err != nil {
			_ = tc.Close()
			return
		}
		if !r.has(NoCloseNotify) {
			_ = tc.CloseWrite()
		}
		_ = tc.NetConn().(*replayConn).CloseWrite()
	}()
	if _, err := io.Copy(t.agent, tc); err != nil {
		_ = t.agent.Close()
	} else {
		_ = t.agent.CloseWrite()
	}
	<-done
}

var _ net.Conn = (*replayConn)(nil)

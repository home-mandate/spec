// SPDX-License-Identifier: Apache-2.0

package tunnelclient

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"time"
)

// DialData opens a data connection and sends first, which is a data-bind or a defective frame;
// nil sends nothing.
func DialData(ctx context.Context, d Dialer, address string, p Params, first []byte) (*Conn, error) {
	conn, err := Dial(ctx, d, address, p)
	if err != nil {
		return nil, err
	}
	if first != nil {
		_ = conn.SetWriteDeadline(time.Now().Add(writeTimeout))
		if _, err := conn.Write(first); err != nil {
			_ = conn.Close()
			return nil, err
		}
	}
	return conn, nil
}

// Seen is what a connection did within a time: the first bytes it sent, whether the other side
// closed it, and whether the time ran out.
type Seen struct {
	Bytes  []byte
	Closed bool
}

// Observe reads from c until it is closed, wait passes or limit bytes have come.
func Observe(c net.Conn, wait time.Duration, limit int) Seen {
	setDeadline(c, wait)
	buf := make([]byte, limit)
	n, err := io.ReadFull(c, buf)
	seen := Seen{Bytes: buf[:n]}
	seen.Closed = err != nil && !errors.Is(err, os.ErrDeadlineExceeded) && Closed(err)
	return seen
}

// Proxy is the content of a PROXY protocol version 2 header.
type Proxy struct {
	Src, Dst netip.AddrPort
}

var (
	// ErrProxy is returned for a header that section 4.6 does not allow.
	ErrProxy = errors.New("tunnelclient: PROXY header")
	// ErrProxyFraming is returned for a header whose frame is wrong; the connection has no
	// defined position after it.
	ErrProxyFraming = fmt.Errorf("%w: wrong framing", ErrProxy)
	// ErrProxyContent is returned for a header of the right frame whose addresses are not allowed;
	// the whole header has been read.
	ErrProxyContent = fmt.Errorf("%w: wrong content", ErrProxy)
)

var proxySignature = []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}

const (
	proxyFixed = 16
	proxyV4    = 12
	proxyV6    = 36
	cmdProxyV2 = 0x21
	tcpV4      = 0x11
	tcpV6      = 0x21
)

// Destinations that the header must carry (section 4.6).
var (
	proxyDstV4 = netip.MustParseAddrPort("192.0.2.1:443")
	proxyDstV6 = netip.MustParseAddrPort("[2001:db8::1]:443")
)

// IsProxySignature reports whether b begins with the signature of a PROXY version 2 header.
func IsProxySignature(b []byte) bool {
	return len(b) >= len(proxySignature) && string(b[:len(proxySignature)]) == string(proxySignature)
}

// ReadPROXY reads the PROXY header of a bound data connection: exactly the 16 fixed bytes and the
// announced block (section 4.6). The error is ErrProxyFraming, ErrProxyContent or a read error.
// With ErrProxyContent the header has been read to its end and the address that were read come
// with it.
func ReadPROXY(r io.Reader) (Proxy, error) {
	head := make([]byte, proxyFixed)
	if _, err := io.ReadFull(r, head); err != nil {
		return Proxy{}, err
	}
	size := int(binary.BigEndian.Uint16(head[14:]))
	switch {
	case !IsProxySignature(head), head[12] != cmdProxyV2:
		return Proxy{}, ErrProxyFraming
	case head[13] == tcpV4 && size == proxyV4, head[13] == tcpV6 && size == proxyV6:
	default:
		return Proxy{}, ErrProxyFraming
	}
	block := make([]byte, size)
	if _, err := io.ReadFull(r, block); err != nil {
		return Proxy{}, err
	}
	half := (size - 4) / 2
	src, _ := netip.AddrFromSlice(block[:half])
	dst, _ := netip.AddrFromSlice(block[half : 2*half])
	p := Proxy{
		Src: netip.AddrPortFrom(src, binary.BigEndian.Uint16(block[2*half:])),
		Dst: netip.AddrPortFrom(dst, binary.BigEndian.Uint16(block[2*half+2:])),
	}
	if err := p.check(); err != nil {
		return p, err
	}
	return p, nil
}

// check applies the rules of section 4.6 to the addresses.
func (p Proxy) check() error {
	want := proxyDstV4
	if p.Src.Addr().Is6() {
		want = proxyDstV6
	}
	switch {
	case p.Src.Port() == 0 || p.Dst.Port() == 0:
		return fmt.Errorf("%w: a port is 0", ErrProxyContent)
	case p.Dst != want:
		return fmt.Errorf("%w: the destination is not %s", ErrProxyContent, want)
	case p.Src.Addr().Is4In6():
		return fmt.Errorf("%w: an IPv4-mapped source", ErrProxyContent)
	case !publicSource(p.Src.Addr()):
		return fmt.Errorf("%w: a source that is not a public address", ErrProxyContent)
	}
	return nil
}

var zeroNet = netip.MustParsePrefix("0.0.0.0/8")

// publicSource rejects what a gateway refuses as the source of an agent: unspecified, loopback,
// private, link-local, multicast, broadcast and 0.0.0.0/8 (section 4.6).
func publicSource(a netip.Addr) bool {
	return !(a.IsUnspecified() || a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() ||
		a.IsLinkLocalMulticast() || a.IsMulticast() || zeroNet.Contains(a) || a == netip.AddrFrom4([4]byte{255, 255, 255, 255}))
}

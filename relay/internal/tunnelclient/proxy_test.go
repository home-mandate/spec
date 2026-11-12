// SPDX-License-Identifier: Apache-2.0

package tunnelclient_test

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/home-mandate/spec/relay/internal/tunnelclient"
)

var signature = []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}

// header builds a PROXY header of family fam with the given block.
func header(fam byte, block []byte) []byte {
	out := append(append([]byte{}, signature...), 0x21, fam)
	out = binary.BigEndian.AppendUint16(out, uint16(len(block)))
	return append(out, block...)
}

func v4Block(src, dst string, sp, dp uint16) []byte {
	return append(append(netip.MustParseAddr(src).AsSlice(), netip.MustParseAddr(dst).AsSlice()...),
		byte(sp>>8), byte(sp), byte(dp>>8), byte(dp))
}

func v6Block(src, dst string, sp, dp uint16) []byte {
	return v4Block(src, dst, sp, dp)
}

func TestReadPROXYAcceptsTheFormsOfSection46(t *testing.T) {
	v4 := header(0x11, v4Block("45.33.32.156", "192.0.2.1", 50000, 443))
	p, err := tunnelclient.ReadPROXY(bytes.NewReader(v4))
	if err != nil || p.Src != netip.MustParseAddrPort("45.33.32.156:50000") || p.Dst != netip.MustParseAddrPort("192.0.2.1:443") {
		t.Errorf("IPv4: %+v, %v", p, err)
	}
	v6 := header(0x21, v6Block("2a01:4f8::1", "2001:db8::1", 4000, 443))
	if p, err := tunnelclient.ReadPROXY(bytes.NewReader(v6)); err != nil || p.Src.Port() != 4000 {
		t.Errorf("IPv6: %+v, %v", p, err)
	}
	// Exactly the header is read: what follows stays in the reader.
	r := bytes.NewReader(append(append([]byte{}, v4...), "rest"...))
	if _, err := tunnelclient.ReadPROXY(r); err != nil || r.Len() != 4 {
		t.Errorf("%v, %d bytes left", err, r.Len())
	}
}

func TestReadPROXYRefusesWhatSection46DoesNotAllow(t *testing.T) {
	good := v4Block("45.33.32.156", "192.0.2.1", 50000, 443)
	for name, tt := range map[string]struct {
		in   []byte
		want error
	}{
		"wrong signature":  {append([]byte{1}, header(0x11, good)[1:]...), tunnelclient.ErrProxyFraming},
		"version 1":        {func() []byte { h := header(0x11, good); h[12] = 0x11; return h }(), tunnelclient.ErrProxyFraming},
		"command LOCAL":    {func() []byte { h := header(0x11, good); h[12] = 0x20; return h }(), tunnelclient.ErrProxyFraming},
		"UDP":              {header(0x12, good), tunnelclient.ErrProxyFraming},
		"family unix":      {header(0x31, good), tunnelclient.ErrProxyFraming},
		"IPv4 with a TLV":  {header(0x11, append(append([]byte{}, good...), 0, 0, 0)), tunnelclient.ErrProxyFraming},
		"IPv6 with IPv4":   {header(0x21, good), tunnelclient.ErrProxyFraming},
		"IPv4 with IPv6":   {header(0x11, v6Block("2a01:4f8::1", "2001:db8::1", 1, 443)), tunnelclient.ErrProxyFraming},
		"source port 0":    {header(0x11, v4Block("45.33.32.156", "192.0.2.1", 0, 443)), tunnelclient.ErrProxyContent},
		"destination port": {header(0x11, v4Block("45.33.32.156", "192.0.2.1", 1, 0)), tunnelclient.ErrProxyContent},
		"real destination": {header(0x11, v4Block("45.33.32.156", "127.0.0.1", 1, 8443)), tunnelclient.ErrProxyContent},
		"destination v6":   {header(0x21, v6Block("2a01:4f8::1", "2001:db8::2", 1, 443)), tunnelclient.ErrProxyContent},
		"mapped IPv4":      {header(0x21, v6Block("::ffff:45.33.32.156", "::ffff:192.0.2.1", 1, 443)), tunnelclient.ErrProxyContent},
		"mapped source":    {header(0x21, v6Block("::ffff:45.33.32.156", "2001:db8::1", 1, 443)), tunnelclient.ErrProxyContent},
		"loopback":         {header(0x11, v4Block("127.0.0.1", "192.0.2.1", 1, 443)), tunnelclient.ErrProxyContent},
		"private":          {header(0x11, v4Block("10.1.2.3", "192.0.2.1", 1, 443)), tunnelclient.ErrProxyContent},
		"unique local":     {header(0x21, v6Block("fd00::1", "2001:db8::1", 1, 443)), tunnelclient.ErrProxyContent},
		"link-local":       {header(0x11, v4Block("169.254.1.1", "192.0.2.1", 1, 443)), tunnelclient.ErrProxyContent},
		"multicast":        {header(0x11, v4Block("224.0.0.1", "192.0.2.1", 1, 443)), tunnelclient.ErrProxyContent},
		"broadcast":        {header(0x11, v4Block("255.255.255.255", "192.0.2.1", 1, 443)), tunnelclient.ErrProxyContent},
		"unspecified":      {header(0x11, v4Block("0.0.0.0", "192.0.2.1", 1, 443)), tunnelclient.ErrProxyContent},
		"0.0.0.0/8":        {header(0x11, v4Block("0.1.2.3", "192.0.2.1", 1, 443)), tunnelclient.ErrProxyContent},
	} {
		p, err := tunnelclient.ReadPROXY(bytes.NewReader(tt.in))
		if !errors.Is(err, tt.want) || !errors.Is(err, tunnelclient.ErrProxy) {
			t.Errorf("%s: %v, want %v", name, err, tt.want)
		}
		if errors.Is(err, tunnelclient.ErrProxyContent) && !p.Src.IsValid() {
			t.Errorf("%s: no addresses with a content error", name)
		}
	}
}

func TestReadPROXYReturnsReadErrors(t *testing.T) {
	full := header(0x11, v4Block("45.33.32.156", "192.0.2.1", 1, 443))
	for _, n := range []int{0, 10, 16, 20} {
		if _, err := tunnelclient.ReadPROXY(bytes.NewReader(full[:n])); err == nil || errors.Is(err, tunnelclient.ErrProxy) {
			t.Errorf("%d bytes: %v", n, err)
		}
	}
}

func FuzzPROXY(f *testing.F) {
	f.Add(header(0x11, v4Block("45.33.32.156", "192.0.2.1", 50000, 443)))
	f.Add(header(0x21, v6Block("2a01:4f8::1", "2001:db8::1", 4000, 443)))
	f.Add(header(0x11, v4Block("127.0.0.1", "192.0.2.1", 1, 443)))
	f.Add(signature)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		r := bytes.NewReader(data)
		p, err := tunnelclient.ReadPROXY(r)
		used := len(data) - r.Len()
		if used > 16+36 {
			t.Fatalf("read %d bytes for a header", used)
		}
		if err != nil {
			return
		}
		// A header that is accepted has the form of section 4.6 and nothing else.
		if used != 28 && used != 52 {
			t.Fatalf("accepted a header of %d bytes", used)
		}
		if p.Src.Port() == 0 || p.Dst.Port() == 0 || p.Src.Addr().Is4In6() || p.Src.Addr().IsLoopback() || p.Src.Addr().IsPrivate() {
			t.Fatalf("accepted %+v", p)
		}
		if p.Dst != netip.MustParseAddrPort("192.0.2.1:443") && p.Dst != netip.MustParseAddrPort("[2001:db8::1]:443") {
			t.Fatalf("accepted the destination %s", p.Dst)
		}
		// What the tool writes is read back.
		if p.Src.Addr().Is4() && !bytes.Equal(tunnelclient.EncodeProxy(p.Src, p.Dst), data[:28]) {
			t.Fatalf("not the encoding of its content: %x", data[:28])
		}
	})
}

func TestEncodeProxyIsAHeaderOfSection46(t *testing.T) {
	src, dst := netip.MustParseAddrPort("45.45.45.45:4545"), netip.MustParseAddrPort("192.0.2.1:443")
	p, err := tunnelclient.ReadPROXY(bytes.NewReader(tunnelclient.EncodeProxy(src, dst)))
	if err != nil || p.Src != src || p.Dst != dst {
		t.Errorf("%+v, %v", p, err)
	}
	if !tunnelclient.IsProxySignature(signature) || tunnelclient.IsProxySignature(signature[:11]) || tunnelclient.IsProxySignature([]byte("GET / HTTP/1.1\r\n")) {
		t.Error("IsProxySignature")
	}
}

// serverNameOf parses a ClientHello the way a relay does.
func serverNameOf(t *testing.T, hello []byte) string {
	t.Helper()
	c, s := net.Pipe()
	defer c.Close()
	go func() {
		_, _ = c.Write(hello)
		// What the server answers is of no interest, but it must not block.
		_, _ = io.Copy(io.Discard, c)
	}()
	var name string
	errStop := errors.New("stop")
	srv := tls.Server(s, &tls.Config{GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
		name = h.ServerName
		return nil, errStop
	}})
	_ = s.SetDeadline(time.Now().Add(wait))
	if err := srv.Handshake(); !errors.Is(err, errStop) {
		t.Fatalf("handshake: %v", err)
	}
	return name
}

func TestClientHelloCarriesTheServerNameAsGiven(t *testing.T) {
	for _, sni := range []string{"home.example.org", "HoMe.Example.ORG"} {
		if got := serverNameOf(t, tunnelclient.ClientHello(sni)); got != sni {
			t.Errorf("server name %q, want %q", got, sni)
		}
	}
	if got := serverNameOf(t, tunnelclient.ClientHello("")); got != "" {
		t.Errorf("a ClientHello without a name carries %q", got)
	}
}

func TestObserveReportsBytesCloseAndSilence(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	if seen := tunnelclient.Observe(a, 30*time.Millisecond, 4); seen.Closed || len(seen.Bytes) != 0 {
		t.Errorf("silence: %+v", seen)
	}
	go func() {
		_, _ = b.Write([]byte("ab"))
		_ = b.Close()
	}()
	if seen := tunnelclient.Observe(a, wait, 4); !seen.Closed || string(seen.Bytes) != "ab" {
		t.Errorf("bytes then close: %+v", seen)
	}
	c, d := net.Pipe()
	defer c.Close()
	go func() { _, _ = d.Write([]byte("abcdef")) }()
	if seen := tunnelclient.Observe(c, wait, 4); seen.Closed || string(seen.Bytes) != "abcd" {
		t.Errorf("limit: %+v", seen)
	}
	e, f := net.Pipe()
	_ = f.Close()
	if _, err := io.ReadAll(e); err != nil {
		t.Fatal(err)
	}
	if err := tunnelclient.CloseWrite(e); err == nil {
		t.Error("a pipe has no half close")
	}
}

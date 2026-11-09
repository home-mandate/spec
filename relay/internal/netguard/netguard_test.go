// SPDX-License-Identifier: Apache-2.0

package netguard

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
)

func TestAllowed(t *testing.T) {
	for addr, want := range map[string]bool{
		"8.8.8.8":                 true,
		"93.184.216.34":           true,
		"2606:4700:4700::1111":    true,
		"::ffff:8.8.8.8":          true,
		"::ffff:127.0.0.1":        false,
		"127.0.0.1":               false,
		"::1":                     false,
		"0.0.0.0":                 false,
		"::":                      false,
		"10.1.2.3":                false,
		"172.16.0.1":              false,
		"192.168.1.1":             false,
		"169.254.169.254":         false,
		"100.64.0.1":              false,
		"192.0.0.8":               false,
		"192.0.2.10":              false,
		"198.18.0.1":              false,
		"198.51.100.7":            false,
		"203.0.113.9":             false,
		"224.0.0.1":               false,
		"240.0.0.1":               false,
		"255.255.255.255":         false,
		"192.88.99.1":             false,
		"fe80::1":                 false,
		"fc00::1":                 false,
		"fd12:3456::1":            false,
		"ff02::1":                 false,
		"2001:db8::10":            false,
		"2001::1":                 false,
		"2002:808:808::":          false,
		"3fff::1":                 false,
		"64:ff9b::808:808":        false,
		"100::1":                  false,
		"::7f00:1":                false,
		"fe80::1%eth0":            false,
		"2606:4700:4700::1111%lo": false,
	} {
		a, err := netip.ParseAddr(addr)
		if err != nil {
			t.Fatalf("%s: %v", addr, err)
		}
		if got := Allowed(a); got != want {
			t.Errorf("Allowed(%s) = %v, want %v", addr, got, want)
		}
	}
	if Allowed(netip.Addr{}) {
		t.Error("the zero address is allowed")
	}
}

func listen(t *testing.T) (net.Listener, chan struct{}) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan struct{}, 8)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			accepted <- struct{}{}
			_ = c.Close()
		}
	}()
	t.Cleanup(func() { _ = l.Close() })
	return l, accepted
}

func TestDefaultDialerRefusesLoopbackWithoutConnecting(t *testing.T) {
	l, accepted := listen(t)
	d := New(Options{})
	for _, target := range []string{l.Addr().String(), "localhost:" + portOf(t, l)} {
		_, err := d.DialContext(context.Background(), "tcp", target)
		if !errors.Is(err, ErrBlocked) {
			t.Errorf("dial %s: %v, want ErrBlocked", target, err)
		}
	}
	select {
	case <-accepted:
		t.Fatal("the listener accepted a connection")
	default:
	}
}

func portOf(t *testing.T, l net.Listener) string {
	t.Helper()
	_, port, err := net.SplitHostPort(l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return port
}

// closedPort returns a loopback port nothing listens on.
func closedPort(t *testing.T) string {
	t.Helper()
	l, _ := listen(t)
	port := portOf(t, l)
	_ = l.Close()
	return port
}

func loopbackOK(a netip.Addr) bool { return a.IsLoopback() }

func TestDialerConnectsWithTheCheckedAddress(t *testing.T) {
	l, accepted := listen(t)
	var looked []string
	d := New(Options{
		Policy: loopbackOK,
		Lookup: func(_ context.Context, host string) ([]netip.Addr, error) {
			looked = append(looked, host)
			return []netip.Addr{netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("127.0.0.1")}, nil
		},
	})
	c, err := d.DialContext(context.Background(), "tcp", "operator.example:"+portOf(t, l))
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	<-accepted
	if len(looked) != 1 || looked[0] != "operator.example" {
		t.Errorf("lookups = %v, want exactly one for the host", looked)
	}
}

func TestDialerRemapsInTests(t *testing.T) {
	l, accepted := listen(t)
	d := New(Options{Policy: loopbackOK, Remap: func(string) string { return l.Addr().String() }})
	c, err := d.DialContext(context.Background(), "tcp", "operator.example:443")
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	<-accepted
}

func TestDialerErrors(t *testing.T) {
	failing := errors.New("no such host")
	closed := closedPort(t)
	for name, tt := range map[string]struct {
		opts    Options
		network string
		addr    string
		want    error
	}{
		"bad network":    {Options{}, "ip", "8.8.8.8:1", ErrNetwork},
		"no port":        {Options{}, "tcp", "8.8.8.8", nil},
		"lookup failure": {Options{Lookup: func(context.Context, string) ([]netip.Addr, error) { return nil, failing }}, "tcp", "a.example:1", failing},
		"nothing found":  {Options{Lookup: func(context.Context, string) ([]netip.Addr, error) { return nil, nil }}, "tcp", "a.example:1", ErrBlocked},
		"all refused": {Options{Policy: loopbackOK, Lookup: func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		}}, "tcp", "a.example:" + closed, nil},
	} {
		_, err := New(tt.opts).DialContext(context.Background(), tt.network, tt.addr)
		if err == nil || (tt.want != nil && !errors.Is(err, tt.want)) {
			t.Errorf("%s: %v, want %v", name, err, tt.want)
		}
	}
}

func TestDialerTriesAtMostFourAddresses(t *testing.T) {
	var addrs []netip.Addr
	for i := 1; i <= 6; i++ {
		addrs = append(addrs, netip.MustParseAddr("127.0.0."+string(rune('0'+i))))
	}
	tried := 0
	d := New(Options{
		Policy: func(a netip.Addr) bool { tried++; return loopbackOK(a) },
		Lookup: func(context.Context, string) ([]netip.Addr, error) { return addrs, nil },
	})
	// Nothing listens: every attempt is refused. The policy is asked once per tried address
	// when resolving and once more by the control function.
	if _, err := d.DialContext(context.Background(), "tcp", "a.example:"+closedPort(t)); err == nil {
		t.Fatal("connected to a closed port")
	}
	if tried != 2*MaxAddresses {
		t.Errorf("policy asked %d times, want %d", tried, 2*MaxAddresses)
	}
}

func TestControlChecksTheAddressAtDialTime(t *testing.T) {
	d := New(Options{})
	for addr, ok := range map[string]bool{"8.8.8.8:443": true, "127.0.0.1:443": false, "garbage": false, "[::1]:80": false} {
		err := d.control("tcp", addr, nil)
		if (err == nil) != ok {
			t.Errorf("control(%s) = %v", addr, err)
		}
	}
}

func TestLookupDefaultResolvesLiteralsOnly(t *testing.T) {
	addrs, err := lookupDefault(context.Background(), "localhost")
	if err != nil || len(addrs) == 0 {
		t.Skipf("no resolver in this environment: %v", err)
	}
	if _, err := lookupDefault(context.Background(), "nonexistent.invalid"); err == nil {
		t.Error("resolved .invalid")
	}
}

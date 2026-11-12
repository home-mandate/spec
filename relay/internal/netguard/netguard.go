// SPDX-License-Identifier: Apache-2.0

// Package netguard filters the addresses the test tool connects to (RELAY-v0 section 8.3,
// plan "Sicherheit"): an operator must not be able to point the tool at the network of the
// tester. The filter works at dial time, for every connection: a host name is resolved once,
// every address is checked, and the connection goes to the checked address. net.Dialer.Control
// checks the address once more just before the connect.
package netguard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"syscall"
	"time"
)

// MaxAddresses is how many of the allowed addresses of a host one dial tries.
const MaxAddresses = 4

// maxLookup bounds the addresses taken from a lookup before filtering.
const maxLookup = 64

const dialTimeout = 10 * time.Second

var (
	// ErrBlocked is returned for an address, or a host without any address, that the policy
	// does not allow.
	ErrBlocked = errors.New("netguard: address not allowed")
	// ErrNetwork is returned for a network other than TCP and UDP.
	ErrNetwork = errors.New("netguard: network not allowed")
)

// blocked lists the special-purpose ranges inside what netip counts as global unicast:
// IPv4 that is not globally reachable and IPv6 documentation, translation, transition and
// protocol-assignment ranges. IPv6 outside 2000::/3 is refused as a whole.
var blocked = parsePrefixes(
	"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24",
	"198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4",
	"2001::/23", "2001:db8::/32", "2002::/16", "3fff::/20",
)

var globalV6 = netip.MustParsePrefix("2000::/3")

func parsePrefixes(list ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(list))
	for i, s := range list {
		out[i] = netip.MustParsePrefix(s)
	}
	return out
}

// Allowed reports whether addr is a globally reachable unicast address. IPv4-mapped
// addresses are judged as the IPv4 address they carry.
func Allowed(addr netip.Addr) bool {
	addr = addr.Unmap()
	if !addr.IsGlobalUnicast() || addr.Zone() != "" || addr.IsPrivate() {
		return false
	}
	if addr.Is6() && !globalV6.Contains(addr) {
		return false
	}
	for _, p := range blocked {
		if p.Contains(addr) {
			return false
		}
	}
	return true
}

// Options are the knobs of a Dialer. The zero value is the production setting; the tool
// builds nothing else (a test of the command checks that). Tests loosen the policy to reach
// a reference operator on 127.0.0.1.
type Options struct {
	// Policy decides which addresses may be dialed; nil means Allowed.
	Policy func(netip.Addr) bool
	// Lookup resolves a host name; nil means the system resolver.
	Lookup func(ctx context.Context, host string) ([]netip.Addr, error)
	// Remap rewrites the "host:port" a caller asks for; nil means no change. Tests use it
	// to reach a reference operator on a port other than 443.
	Remap func(hostport string) string
}

// Dialer dials TCP and UDP connections to addresses its policy allows.
type Dialer struct {
	policy func(netip.Addr) bool
	lookup func(context.Context, string) ([]netip.Addr, error)
	remap  func(string) string
}

// New returns a Dialer for the options.
func New(o Options) *Dialer {
	d := &Dialer{policy: o.Policy, lookup: o.Lookup, remap: o.Remap}
	if d.policy == nil {
		d.policy = Allowed
	}
	if d.lookup == nil {
		d.lookup = lookupDefault
	}
	return d
}

// Policy returns the decision function, for checks of addresses that are not dialed.
func (d *Dialer) Policy() func(netip.Addr) bool { return d.policy }

func lookupDefault(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// DialContext connects to address ("host:port"). The host is resolved once.
func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	switch network {
	case "tcp", "tcp4", "tcp6", "udp", "udp4", "udp6":
	default:
		return nil, ErrNetwork
	}
	if d.remap != nil {
		address = d.remap(address)
	}
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("netguard: %w", err)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("netguard: port: %w", err)
	}
	candidates, err := d.Resolve(ctx, host)
	if err != nil {
		return nil, err
	}
	inner := net.Dialer{Timeout: dialTimeout, Control: d.control}
	var last error
	for _, ip := range candidates {
		var c net.Conn
		c, last = inner.DialContext(ctx, network, netip.AddrPortFrom(ip, uint16(port)).String())
		if last == nil {
			return c, nil
		}
	}
	return nil, last
}

// Resolve returns at most MaxAddresses allowed addresses of host, for callers that ask each
// address on its own (the name servers of a zone). A literal address is only checked.
func (d *Dialer) Resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	found, err := netip.ParseAddr(host)
	list := []netip.Addr{found}
	if err != nil {
		if list, err = d.lookup(ctx, host); err != nil {
			return nil, fmt.Errorf("netguard: lookup: %w", err)
		}
	}
	var allowed []netip.Addr
	for _, a := range list[:min(len(list), maxLookup)] {
		if len(allowed) < MaxAddresses && d.policy(a) {
			allowed = append(allowed, a.Unmap())
		}
	}
	if len(allowed) == 0 {
		return nil, ErrBlocked
	}
	return allowed, nil
}

// control runs just before the connect system call, with the address that is about to be
// used, and refuses what the policy does not allow.
func (d *Dialer) control(_, address string, _ syscall.RawConn) error {
	ap, err := netip.ParseAddrPort(address)
	if err != nil || !d.policy(ap.Addr()) {
		return ErrBlocked
	}
	return nil
}

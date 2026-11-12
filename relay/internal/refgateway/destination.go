// SPDX-License-Identifier: Apache-2.0

package refgateway

import "net/netip"

// DestFault is a deliberate defect of the decision on the address a gateway connects to.
type DestFault uint64

// Defects of the destination check. Each of the first group allows one range that is not
// globally reachable; the second group refuses addresses next to a range or inside the
// exceptions, which must be allowed.
const (
	DestZero8 DestFault = 1 << iota
	DestPrivate10
	DestShared
	DestLoopback
	DestLinkLocal
	DestPrivate172
	DestProtocol
	DestDoc
	DestPrivate192
	DestBench
	DestMulticast
	DestReserved
	DestBroadcast
	DestUnspecified6
	DestLoopback6
	DestMapped    // an IPv4-mapped address is judged by its IPv4 part
	DestMappedAll // an IPv4-mapped address is allowed
	DestCompat    // an IPv4-compatible address is allowed
	DestCompatV4  // an IPv4-compatible address is judged by its IPv4 part
	DestNAT64     // an address of 64:ff9b::/96 is allowed whatever it embeds
	DestNAT64Local
	DestDiscard
	DestProtocol6
	DestDoc6
	DestSixToFour
	DestULA
	DestLinkLocal6
	DestSiteLocal
	DestMulticast6
	DestOutside3 // an address outside 2000::/3 that no range names is allowed
	DestBadText  // text that is not an address is allowed

	DestGrowLow         // refuses the address just below each IPv4 range
	DestGrowHigh        // refuses the address just above each IPv4 range
	DestNoExceptions    // refuses the addresses of the ranges that are globally reachable
	DestNAT64Refuse     // refuses all of 64:ff9b::/96
	DestRefuse2001      // refuses all of 2001::/16
	DestRefuse3fff      // refuses all of 3fff::/16
	DestRefuse2000      // refuses 2000::/16
	DestRefuseDoc6Wide  // refuses 2001:db8::/31
	DestRefuseV6Public  // refuses 2600::/12 and 2a00::/12
	DestRefuseV4Public1 // refuses 93.0.0.0/8 and 1.1.1.0/24
	DestRefuseAll       // refuses every address
	DestStaleRegistry   // knows the exceptions of an older registry: 2001:1::3 is refused
)

// rangeEntry is a range of addresses that are not globally reachable.
type rangeEntry struct {
	prefix netip.Prefix
	group  DestFault
	// listed marks the ranges that RELAY-v0 section 4.6 names as sources to refuse.
	listed bool
}

func p(s string) netip.Prefix { return netip.MustParsePrefix(s) }

var ranges = []rangeEntry{
	{p("0.0.0.0/8"), DestZero8, true},
	{p("10.0.0.0/8"), DestPrivate10, true},
	{p("100.64.0.0/10"), DestShared, false},
	{p("127.0.0.0/8"), DestLoopback, true},
	{p("169.254.0.0/16"), DestLinkLocal, true},
	{p("172.16.0.0/12"), DestPrivate172, true},
	{p("192.0.0.0/24"), DestProtocol, false},
	{p("192.0.2.0/24"), DestDoc, false},
	{p("198.51.100.0/24"), DestDoc, false},
	{p("203.0.113.0/24"), DestDoc, false},
	{p("192.168.0.0/16"), DestPrivate192, true},
	{p("198.18.0.0/15"), DestBench, false},
	{p("224.0.0.0/4"), DestMulticast, true},
	{p("255.255.255.255/32"), DestBroadcast, true},
	{p("240.0.0.0/4"), DestReserved, false},
	{p("::/128"), DestUnspecified6, true},
	{p("::1/128"), DestLoopback6, true},
	{p("64:ff9b:1::/48"), DestNAT64Local, false},
	{p("100::/64"), DestDiscard, false},
	{p("2001::/23"), DestProtocol6, false},
	{p("2001:db8::/32"), DestDoc6, false},
	{p("3fff::/20"), DestDoc6, false},
	{p("2002::/16"), DestSixToFour, false},
	{p("fc00::/7"), DestULA, true},
	{p("fe80::/10"), DestLinkLocal6, true},
	{p("fec0::/10"), DestSiteLocal, false},
	{p("ff00::/8"), DestMulticast6, true},
}

// exceptions are globally reachable addresses inside the ranges above.
var exceptions = []netip.Prefix{
	p("192.0.0.9/32"), p("192.0.0.10/32"),
	p("2001:1::1/128"), p("2001:1::2/128"), p("2001:1::3/128"), p("2001:3::/32"), p("2001:4:112::/48"), p("2001:20::/28"), p("2001:30::/28"),
}

var (
	global6 = p("2000::/3")
	mapped  = p("::ffff:0:0/96")
	compat  = p("::/96")
	nat64   = p("64:ff9b::/96")
	shared  = p("100.64.0.0/10")
	// staleRegistryGap is the exception that the registry gained last.
	staleRegistryGap = p("2001:1::3/128")
	strictAddrs      = []struct {
		prefix netip.Prefix
		fault  DestFault
	}{
		{p("2001::/16"), DestRefuse2001}, {p("3fff::/16"), DestRefuse3fff}, {p("2000::/16"), DestRefuse2000},
		{p("2001:db8::/31"), DestRefuseDoc6Wide}, {p("2600::/12"), DestRefuseV6Public}, {p("2a00::/12"), DestRefuseV6Public},
		{p("93.0.0.0/8"), DestRefuseV4Public1}, {p("1.1.1.0/24"), DestRefuseV4Public1},
	}
)

// Allowed reports whether a gateway connects to the address (RELAY-v0 section 3): it is a
// globally reachable unicast address.
func Allowed(text string, f DestFault) bool {
	addr, err := netip.ParseAddr(text)
	if err != nil || addr.Zone() != "" {
		return f.Has(DestBadText)
	}
	return allowedAddr(addr, f)
}

func allowedAddr(a netip.Addr, f DestFault) bool {
	for _, s := range strictAddrs {
		if f.Has(s.fault) && s.prefix.Contains(a) {
			return false
		}
	}
	if f.Has(DestRefuseAll) {
		return false
	}
	if a.Is4() {
		return allowedV4(a, f)
	}
	return allowedV6(a, f)
}

func allowedV4(a netip.Addr, f DestFault) bool {
	for _, e := range exceptions {
		if e.Contains(a) {
			return !f.Has(DestNoExceptions)
		}
	}
	if f.Has(DestRefuseAll) {
		return false
	}
	for _, r := range ranges {
		if r.prefix.Addr().Is4() && touches(r.prefix, a, f) {
			return f.Has(r.group)
		}
	}
	return true
}

// touches reports whether the address is in the range, or next to it with a defect that grows
// the ranges.
func touches(r netip.Prefix, a netip.Addr, f DestFault) bool {
	if r.Contains(a) {
		return true
	}
	return f.Has(DestGrowLow) && r.Contains(a.Next()) || f.Has(DestGrowHigh) && prevIn(r, a)
}

func prevIn(r netip.Prefix, a netip.Addr) bool {
	prev := a.Prev()
	return prev.IsValid() && r.Contains(prev)
}

func allowedV6(a netip.Addr, f DestFault) bool {
	switch {
	case mapped.Contains(a):
		return mappedAllowed(a, f)
	case nat64.Contains(a):
		return nat64Allowed(a, f)
	}
	for _, r := range ranges {
		if !r.prefix.Addr().Is4() && r.prefix.Contains(a) && !exceptional(a, f) {
			return f.Has(r.group)
		}
	}
	if compat.Contains(a) {
		return f.Has(DestCompat) || f.Has(DestCompatV4) && embeddedAllowed(a, f)
	}
	return global6.Contains(a) || f.Has(DestOutside3)
}

func exceptional(a netip.Addr, f DestFault) bool {
	for _, e := range exceptions {
		if e.Contains(a) && !(f.Has(DestStaleRegistry) && e == staleRegistryGap) {
			return true
		}
	}
	return false
}

func mappedAllowed(a netip.Addr, f DestFault) bool {
	return f.Has(DestMappedAll) || f.Has(DestMapped) && allowedV4(a.Unmap(), f)
}

func nat64Allowed(a netip.Addr, f DestFault) bool {
	if f.Has(DestNAT64Refuse) {
		return false
	}
	return f.Has(DestNAT64) || embeddedAllowed(a, f)
}

// embeddedAllowed judges the IPv4 address in the last 32 bits.
func embeddedAllowed(a netip.Addr, f DestFault) bool {
	b := a.As16()
	return allowedV4(netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}), f)
}

// IsShared reports whether the address is in 100.64.0.0/10.
func IsShared(a netip.Addr) bool { return shared.Contains(a) }

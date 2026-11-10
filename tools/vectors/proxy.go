// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/netip"
)

// relayProxyDescription is the description of relay/conformance/proxy-v0.json.
const relayProxyDescription = "The PROXY protocol version 2 header at the start of a bound data connection, as a gateway reads it, " +
	"RELAY-v0.md section 4.6. Each case: everything the gateway receives on the connection, in hex, up to the end of the stream " +
	"(a header that is cut off is never completed), and the decision. accepted: the gateway uses the source address and port and " +
	"has consumed that many bytes, and the bytes after them are the agent's and stay unread. refused: the gateway closes the connection. " +
	"either: the source address is one that Section 4.6 does not name and that is not globally reachable; a gateway may accept it, with " +
	"the source and the consumed bytes the case gives, or refuse it. The destination address and port are ignored, whatever they are. " +
	"Generated with go run ./tools/vectors relay-proxy."

const (
	proxyAccepted = "accepted"
	proxyRefused  = "refused"
	proxyEither   = "either"
)

// proxySource is the source of an accepted or optional case.
type proxySource struct {
	Address string `json:"address"`
	Port    int    `json:"port"`
}

// relayProxyCase is a case of relay/conformance/proxy-v0.json.
type relayProxyCase struct {
	ID       string       `json:"id"`
	Section  string       `json:"section"`
	Hex      string       `json:"hex"`
	Expected string       `json:"expected"`
	Source   *proxySource `json:"source,omitempty"`
	Consumed *int         `json:"consumed,omitempty"`
	Why      string       `json:"why"`
}

var proxySignature = []byte("\r\n\r\n\x00\r\nQUIT\n")

// proxyHeader builds a version 2 header from the bytes after the signature.
func proxyHeader(verCmd, family byte, length int, payload []byte) []byte {
	out := append([]byte(nil), proxySignature...)
	out = append(out, verCmd, family)
	out = binary.BigEndian.AppendUint16(out, uint16(length))
	return append(out, payload...)
}

// proxyBlock is the address block of a family: source, destination, source port, destination port.
func proxyBlock(src, dst netip.Addr, sport, dport uint16) []byte {
	out := append([]byte(nil), src.AsSlice()...)
	out = append(out, dst.AsSlice()...)
	out = binary.BigEndian.AppendUint16(out, sport)
	return binary.BigEndian.AppendUint16(out, dport)
}

var (
	proxyDst4 = netip.MustParseAddr("192.0.2.1")
	proxyDst6 = netip.MustParseAddr("2001:db8::1")
)

// proxyFrom builds the header of the form in section 4.6 for a source.
func proxyFrom(src string, sport uint16) []byte {
	a := netip.MustParseAddr(src)
	if a.Is4() {
		return proxyHeader(0x21, 0x11, 12, proxyBlock(a, proxyDst4, sport, 443))
	}
	return proxyHeader(0x21, 0x21, 36, proxyBlock(a, proxyDst6, sport, 443))
}

// proxyBuilder collects cases with numbered ids.
type proxyBuilder struct{ cases []relayProxyCase }

func (b *proxyBuilder) add(expected string, data []byte, src *proxySource, why string) {
	c := relayProxyCase{ID: fmt.Sprintf("x%02d", len(b.cases)+1), Section: "4.6", Hex: hex.EncodeToString(data), Expected: expected, Why: why}
	if expected != proxyRefused && src != nil {
		n := 16 + int(binary.BigEndian.Uint16(data[14:16]))
		c.Source, c.Consumed = src, &n
	}
	b.cases = append(b.cases, c)
}

func (b *proxyBuilder) accept(src string, port uint16, why string) {
	b.add(proxyAccepted, proxyFrom(src, port), &proxySource{netip.MustParseAddr(src).String(), int(port)}, why)
}

func (b *proxyBuilder) either(src string, why string) {
	b.add(proxyEither, proxyFrom(src, 40000), &proxySource{netip.MustParseAddr(src).String(), 40000}, why)
}

func (b *proxyBuilder) refuse(data []byte, why string) { b.add(proxyRefused, data, nil, why) }

func (b *proxyBuilder) refuseSource(src string, why string) { b.refuse(proxyFrom(src, 40000), why) }

func relayProxyCases() []relayProxyCase {
	b := &proxyBuilder{}
	addValid(b)
	addForm(b)
	addSources(b)
	return b.cases
}

func addValid(b *proxyBuilder) {
	b.accept("93.184.216.34", 51514, "an IPv4 agent, the form of section 4.6")
	b.accept("2606:4700:4700::1111", 40000, "an IPv6 agent")
	b.accept("93.184.216.34", 1, "source port 1")
	b.accept("93.184.216.34", 65535, "source port 65535")
	b.accept("2606:4700:4700::1111", 1, "IPv6 source port 1")
	b.accept("2606:4700:4700::1111", 65535, "IPv6 source port 65535")
	v4 := proxyFrom("93.184.216.34", 51514)
	b.add(proxyAccepted, append(append([]byte(nil), v4...), 0x16, 0x03, 0x01, 0x02, 0x00, 0x01), &proxySource{"93.184.216.34", 51514}, "bytes after the header (a ClientHello) are the agent's and stay unread: 28 bytes consumed")
	v6 := proxyFrom("2606:4700:4700::1111", 40000)
	b.add(proxyAccepted, append(append([]byte(nil), v6...), 0x16, 0x03, 0x01), &proxySource{"2606:4700:4700::1111", 40000}, "bytes after an IPv6 header stay unread: 52 bytes consumed")
	src := netip.MustParseAddr("93.184.216.34")
	b.add(proxyAccepted, proxyHeader(0x21, 0x11, 12, proxyBlock(src, netip.MustParseAddr("10.1.2.3"), 51514, 8443)), &proxySource{"93.184.216.34", 51514}, "another destination is ignored")
	b.add(proxyAccepted, proxyHeader(0x21, 0x11, 12, proxyBlock(src, netip.MustParseAddr("0.0.0.0"), 51514, 0)), &proxySource{"93.184.216.34", 51514}, "destination 0.0.0.0 port 0 is ignored")
	s6 := netip.MustParseAddr("2606:4700:4700::1111")
	b.add(proxyAccepted, proxyHeader(0x21, 0x21, 36, proxyBlock(s6, netip.MustParseAddr("::1"), 40000, 0)), &proxySource{"2606:4700:4700::1111", 40000}, "an IPv6 destination ::1 port 0 is ignored")
	b.add(proxyAccepted, proxyHeader(0x21, 0x21, 36, proxyBlock(s6, netip.MustParseAddr("::ffff:192.0.2.1"), 40000, 443)), &proxySource{"2606:4700:4700::1111", 40000}, "an IPv4-mapped destination is ignored")
}

func addForm(b *proxyBuilder) {
	ok := proxyFrom("93.184.216.34", 51514)
	ok6 := proxyFrom("2606:4700:4700::1111", 40000)
	mutate := func(base []byte, i int, v byte) []byte {
		out := append([]byte(nil), base...)
		out[i] = v
		return out
	}
	block4 := proxyBlock(netip.MustParseAddr("93.184.216.34"), proxyDst4, 51514, 443)
	b.refuse(nil, "an empty stream")
	b.refuse(ok[:11], "cut off inside the signature")
	b.refuse(ok[:15], "cut off after 15 bytes")
	b.refuse(ok[:16], "the fixed 16 bytes without the block")
	b.refuse(ok[:27], "the block cut off after 11 of 12 bytes")
	b.refuse(ok6[:51], "the IPv6 block cut off after 35 of 36 bytes")
	b.refuse(mutate(ok, 0, 0x0e), "the first byte of the signature is wrong")
	b.refuse(mutate(ok, 11, 0x0b), "the last byte of the signature is wrong")
	b.refuse(mutate(ok, 12, 0x20), "version 2, command LOCAL")
	b.refuse(mutate(ok, 12, 0x22), "version 2, command 2")
	b.refuse(mutate(ok, 12, 0x11), "version 1 in the version nibble")
	b.refuse(mutate(ok, 12, 0x31), "version 3")
	b.refuse(mutate(ok, 12, 0x00), "version 0")
	b.refuse(mutate(ok, 13, 0x00), "address family UNSPEC")
	b.refuse(mutate(ok, 13, 0x12), "UDP over IPv4")
	b.refuse(mutate(ok6, 13, 0x22), "UDP over IPv6")
	b.refuse(mutate(ok, 13, 0x31), "UNIX stream")
	b.refuse(mutate(ok, 13, 0x10), "IPv4 with an unspecified transport")
	b.refuse(proxyHeader(0x21, 0x11, 11, block4[:11]), "length 11 for IPv4")
	b.refuse(proxyHeader(0x21, 0x11, 13, append(append([]byte(nil), block4...), 0)), "length 13 for IPv4")
	b.refuse(proxyHeader(0x21, 0x11, 36, append(append([]byte(nil), block4...), make([]byte, 24)...)), "length 36 for IPv4")
	b.refuse(proxyHeader(0x21, 0x21, 12, block4), "length 12 for IPv6")
	b.refuse(proxyHeader(0x21, 0x21, 35, ok6[16:51]), "length 35 for IPv6")
	b.refuse(proxyHeader(0x21, 0x21, 37, append(append([]byte(nil), ok6[16:]...), 0)), "length 37 for IPv6")
	b.refuse(proxyHeader(0x21, 0x11, 0, nil), "length 0")
	tlv := append(append([]byte(nil), block4...), 0x04, 0x00, 0x03, 'a', 'b', 'c')
	b.refuse(proxyHeader(0x21, 0x11, len(tlv), tlv), "a TLV after the address block, announced in the length")
	b.refuse(proxyHeader(0x21, 0x11, 0xffff, block4), "length 65535 and a stream that ends")
	b.refuse([]byte("PROXY TCP4 93.184.216.34 192.0.2.1 51514 443\r\n"), "PROXY protocol version 1, in text")
	b.refuse(append([]byte("\x16\x03\x01\x02\x00"), ok...), "the header is not at the start of the stream")
}

func addSources(b *proxyBuilder) {
	port := proxyFrom("93.184.216.34", 0)
	b.refuse(port, "source port 0")
	b.refuse(proxyFrom("2606:4700:4700::1111", 0), "IPv6 source port 0")
	for _, s := range []struct {
		addr string
		ok   bool
		why  string
	}{
		{"0.0.0.0", false, "unspecified"}, {"0.255.255.255", false, "last address of 0.0.0.0/8"}, {"1.0.0.0", true, "above 0.0.0.0/8"},
		{"9.255.255.255", true, "below 10.0.0.0/8"}, {"10.0.0.0", false, "first address of 10.0.0.0/8"}, {"10.255.255.255", false, "last address of 10.0.0.0/8"},
		{"11.0.0.0", true, "above 10.0.0.0/8"},
		{"126.255.255.255", true, "below 127.0.0.0/8"}, {"127.0.0.1", false, "loopback"}, {"127.255.255.255", false, "last address of 127.0.0.0/8"}, {"128.0.0.0", true, "above 127.0.0.0/8"},
		{"169.253.255.255", true, "below 169.254.0.0/16"}, {"169.254.0.0", false, "first address of the link-local range"}, {"169.254.255.255", false, "last address of the link-local range"},
		{"169.255.0.0", true, "above the link-local range"},
		{"172.15.255.255", true, "below 172.16.0.0/12"}, {"172.16.0.0", false, "first address of 172.16.0.0/12"}, {"172.31.255.255", false, "last address of 172.16.0.0/12"},
		{"172.32.0.0", true, "above 172.16.0.0/12"},
		{"192.167.255.255", true, "below 192.168.0.0/16"}, {"192.168.0.0", false, "first address of 192.168.0.0/16"}, {"192.168.255.255", false, "last address of 192.168.0.0/16"},
		{"192.169.0.0", true, "above 192.168.0.0/16"},
		{"223.255.255.255", true, "below the multicast range"}, {"224.0.0.0", false, "first multicast address"}, {"239.255.255.255", false, "last multicast address"},
		{"255.255.255.255", false, "broadcast"},
		{"100.63.255.255", true, "below the shared address space"}, {"100.64.0.1", true, "the shared address space 100.64.0.0/10 is accepted: carrier-grade NAT puts real agents there"},
		{"100.127.255.254", true, "the end of the shared address space"}, {"100.128.0.1", true, "above the shared address space"},
		{"2001:4860:4860::8888", true, "a public IPv6 address"}, {"2000::1", true, "the start of 2000::/3"},
		{"64:ff9b::808:808", true, "a NAT64 address that embeds a public address"},
		{"::", false, "unspecified"}, {"::1", false, "loopback"},
		{"fc00::", false, "first address of fc00::/7"}, {"fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", false, "last address of fc00::/7"},
		{"fe80::", false, "first link-local address"}, {"febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff", false, "last link-local address"},
		{"ff00::", false, "first multicast address"}, {"ff02::1", false, "link-local multicast"},
		{"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", false, "last multicast address"},
		{"::ffff:0:0", false, "start of the IPv4-mapped range"}, {"::ffff:93.184.216.34", false, "an IPv4-mapped public address"},
		{"::ffff:10.0.0.1", false, "an IPv4-mapped private address"},
	} {
		if s.ok {
			b.accept(s.addr, 40000, s.why)
		} else {
			b.refuseSource(s.addr, s.why)
		}
	}
	for _, s := range []struct{ addr, why string }{
		{"192.0.0.1", "192.0.0.0/24, not globally reachable and not named in section 4.6"}, {"192.0.2.1", "documentation (TEST-NET-1)"},
		{"198.18.0.1", "benchmarking, 198.18.0.0/15"}, {"198.19.255.255", "the end of the benchmarking range"},
		{"198.51.100.1", "documentation (TEST-NET-2)"}, {"203.0.113.1", "documentation (TEST-NET-3)"},
		{"240.0.0.1", "reserved for future use"}, {"255.255.255.254", "the end of the reserved range"},
		{"2001:db8::1", "documentation"}, {"100::1", "discard-only prefix"}, {"3fff::1", "documentation"},
		{"64:ff9b::7f00:1", "a NAT64 address that embeds the loopback address"},
		{"fbff::1", "below fc00::/7, outside 2000::/3"}, {"fe00::1", "above fc00::/7, outside 2000::/3"}, {"fe7f::1", "below fe80::/10, outside 2000::/3"},
		{"fec0::1", "site-local (deprecated), above fe80::/10"}, {"::2", "outside 2000::/3"},
	} {
		b.either(s.addr, s.why)
	}
}

func runRelayProxy(args []string, stdout io.Writer) error {
	if len(args) != 0 {
		return errors.New("usage: vectors relay-proxy")
	}
	return writeCases(stdout, relayProxyDescription, relayProxyCases())
}

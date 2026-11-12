// SPDX-License-Identifier: Apache-2.0

package refgateway

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

// ProxyFault is a deliberate defect of ParseProxy.
type ProxyFault uint64

// Defects of the PROXY header reader. The sources a gateway must refuse are the ranges of
// RELAY-v0 section 4.6; each of the first group lets one of them through.
const (
	ProxyZero8        ProxyFault = ProxyFault(DestZero8)
	ProxyPrivate10    ProxyFault = ProxyFault(DestPrivate10)
	ProxyLoopback     ProxyFault = ProxyFault(DestLoopback)
	ProxyLinkLocal    ProxyFault = ProxyFault(DestLinkLocal)
	ProxyPrivate172   ProxyFault = ProxyFault(DestPrivate172)
	ProxyPrivate192   ProxyFault = ProxyFault(DestPrivate192)
	ProxyMulticast    ProxyFault = ProxyFault(DestMulticast)
	ProxyBroadcast    ProxyFault = ProxyFault(DestBroadcast)
	ProxyUnspecified6 ProxyFault = ProxyFault(DestUnspecified6)
	ProxyLoopback6    ProxyFault = ProxyFault(DestLoopback6)
	ProxyULA          ProxyFault = ProxyFault(DestULA)
	ProxyLinkLocal6   ProxyFault = ProxyFault(DestLinkLocal6)
	ProxyMulticast6   ProxyFault = ProxyFault(DestMulticast6)
	ProxyMapped       ProxyFault = ProxyFault(DestMappedAll)
	ProxyGrowLow      ProxyFault = ProxyFault(DestGrowLow)
	ProxyGrowHigh     ProxyFault = ProxyFault(DestGrowHigh)
)

// More defects, outside the mask of the ranges.
const (
	ProxyLocal       ProxyFault = 1 << (iota + 36) // command LOCAL is read like PROXY
	ProxyUDP                                       // UDP is read like TCP
	ProxyTLV                                       // bytes after the address block are announced and skipped
	ProxyLength                                    // the announced length is not checked against the family
	ProxyPort0                                     // source port 0
	ProxyReadBeyond                                // reads the whole stream
	ProxyShared                                    // refuses 100.64.0.0/10
	ProxyDestination                               // refuses a destination other than the one in section 4.6
	ProxyNoTrailing                                // refuses bytes after the header
	ProxyNAT64                                     // refuses 64:ff9b::/96
	ProxyV6Public                                  // refuses 2000::/4
	ProxyMinPort2                                  // refuses source port 1
	ProxyMaxPort                                   // refuses source port 65535
	ProxyRefuseAll                                 // refuses every stream
	ProxyShared8                                   // refuses 100.0.0.0/8
	ProxyShortHeader                               // accepts a stream that ends inside the 16 fixed bytes
	ProxyTruncated                                 // accepts a block that is cut off, filled up with zeros
	ProxySignature                                 // does not check the signature
	ProxyScan                                      // looks for the signature anywhere in the stream
	ProxyAnyVersion                                // does not check version and command
	ProxyAnyFamily                                 // takes the family from the announced length
	ProxyV1                                        // reads the text form of version 1
)

// ProxyResult is the decision on the first bytes of a data connection.
type ProxyResult struct {
	Accepted bool
	// Optional is set for a source that RELAY-v0 section 4.6 does not name and that is not
	// globally reachable: a gateway may refuse it.
	Optional bool
	Address  string
	Port     int
	Consumed int
}

var (
	signature  = []byte("\r\n\r\n\x00\r\nQUIT\n")
	refPrefix4 = netip.MustParseAddr("192.0.2.1")
	refPrefix6 = netip.MustParseAddr("2001:db8::1")
	top2       = p("2000::/4")
)

const headerBytes = 16

// ParseProxy reads a PROXY protocol version 2 header from the start of a stream that has
// ended (RELAY-v0 section 4.6). The destination is ignored.
func ParseProxy(data []byte, f ProxyFault) ProxyResult {
	if f.Has(ProxyRefuseAll) {
		return ProxyResult{}
	}
	if f.Has(ProxyScan) {
		if i := strings.Index(string(data), string(signature)); i > 0 {
			data = data[i:]
		}
	}
	if f.Has(ProxyV1) && bytes.HasPrefix(data, []byte("PROXY TCP4 ")) {
		return versionOne(data)
	}
	if len(data) < headerBytes {
		if f.Has(ProxyShortHeader) {
			return ProxyResult{Accepted: true, Address: "0.0.0.0", Port: 1, Consumed: len(data)}
		}
		return ProxyResult{}
	}
	if string(data[:12]) != string(signature) && !f.Has(ProxySignature) {
		return ProxyResult{}
	}
	length := int(binary.BigEndian.Uint16(data[14:16]))
	want, ok := familyLength(data[12], data[13], length, f)
	if !ok || !lengthFits(length, want, f) {
		return ProxyResult{}
	}
	lenient := f.Has(ProxyTruncated) || f.Has(ProxyLength)
	body := data[headerBytes:]
	if len(body) < want {
		if !lenient {
			return ProxyResult{}
		}
		body = append(slices.Clone(body), bytes.Repeat([]byte{8}, want-len(body))...)
	} else if len(data) < headerBytes+length && !lenient {
		return ProxyResult{}
	}
	src, sport, dst, dport := block(body, want)
	consumed := min(headerBytes+length, len(data))
	if f.Has(ProxyReadBeyond) {
		consumed = len(data)
	}
	if f.Has(ProxyNoTrailing) && len(data) > headerBytes+length {
		return ProxyResult{}
	}
	if f.Has(ProxyDestination) && (dst != refPrefix4 && dst != refPrefix6 || dport != 443) {
		return ProxyResult{}
	}
	return sourceDecision(src, sport, consumed, f)
}

// familyLength checks the version, command and family byte and returns the length of the
// address block of the family.
func familyLength(verCmd, family byte, length int, f ProxyFault) (int, bool) {
	if f.Has(ProxyAnyFamily) {
		family = map[int]byte{12: 0x11, 36: 0x21}[length]
	}
	if verCmd != 0x21 && !f.Has(ProxyAnyVersion) && !(verCmd == 0x20 && f.Has(ProxyLocal)) {
		return 0, false
	}
	switch {
	case family == 0x11 || family == 0x12 && f.Has(ProxyUDP):
		return 12, true
	case family == 0x21 || family == 0x22 && f.Has(ProxyUDP):
		return 36, true
	}
	return 0, false
}

func lengthFits(length, want int, f ProxyFault) bool {
	switch {
	case length == want:
		return true
	case length > want:
		return f.Has(ProxyTLV) || f.Has(ProxyLength)
	}
	return f.Has(ProxyLength)
}

// block reads source, destination and ports; the block has 12 or 36 bytes.
func block(b []byte, size int) (src netip.Addr, sport int, dst netip.Addr, dport int) {
	n := (size - 4) / 2
	src, _ = netip.AddrFromSlice(b[:n])
	dst, _ = netip.AddrFromSlice(b[n : 2*n])
	sport = int(binary.BigEndian.Uint16(b[2*n:]))
	dport = int(binary.BigEndian.Uint16(b[2*n+2:]))
	return src, sport, dst, dport
}

func sourceDecision(src netip.Addr, port, consumed int, f ProxyFault) ProxyResult {
	if port == 0 && !f.Has(ProxyPort0) || f.Has(ProxyMinPort2) && port == 1 || f.Has(ProxyMaxPort) && port == 65535 {
		return ProxyResult{}
	}
	switch refusal(src, f) {
	case refuse:
		return ProxyResult{}
	case optional:
		return ProxyResult{Accepted: true, Optional: true, Address: src.String(), Port: port, Consumed: consumed}
	}
	return ProxyResult{Accepted: true, Address: src.String(), Port: port, Consumed: consumed}
}

type verdict int

const (
	accept verdict = iota
	refuse
	optional
)

// refusal classifies a source: refused if section 4.6 names its range, accepted if it is
// globally reachable or in 100.64.0.0/10, and optional otherwise.
func refusal(src netip.Addr, f ProxyFault) verdict {
	switch {
	case f.Has(ProxyShared) && IsShared(src), f.Has(ProxyShared8) && p("100.0.0.0/8").Contains(src), f.Has(ProxyNAT64) && nat64.Contains(src), f.Has(ProxyV6Public) && top2.Contains(src):
		return refuse
	case mapped.Contains(src):
		return mappedVerdict(f)
	}
	for _, r := range ranges {
		if r.listed && !f.Has(ProxyFault(r.group)) && touches(r.prefix, src, DestFault(f)&(DestGrowLow|DestGrowHigh)) {
			return refuse
		}
	}
	if IsShared(src) || allowedAddr(src, 0) {
		return accept
	}
	return optional
}

func mappedVerdict(f ProxyFault) verdict {
	if f.Has(ProxyMapped) {
		return accept
	}
	return refuse
}

// versionOne reads "PROXY TCP4 <src> <dst> <sport> <dport>\r\n".
func versionOne(data []byte) ProxyResult {
	line, _, ok := bytes.Cut(data, []byte("\r\n"))
	fields := strings.Fields(string(line))
	if !ok || len(fields) != 6 {
		return ProxyResult{}
	}
	addr, err := netip.ParseAddr(fields[2])
	port, perr := strconv.Atoi(fields[4])
	if err != nil || perr != nil {
		return ProxyResult{}
	}
	return ProxyResult{Accepted: true, Address: addr.String(), Port: port, Consumed: len(line) + 2}
}

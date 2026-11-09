// SPDX-License-Identifier: Apache-2.0

package refdns

import (
	"net/netip"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
)

// Record types the reference DNS stores.
const (
	TypeA     = dnsmessage.TypeA
	TypeAAAA  = dnsmessage.TypeAAAA
	TypeTXT   = dnsmessage.TypeTXT
	TypeNS    = dnsmessage.TypeNS
	TypeCNAME = dnsmessage.TypeCNAME
	TypeCAA   = dnsmessage.Type(257)
)

// canon returns a name in lower case without the trailing dot.
func canon(name string) string { return strings.ToLower(strings.TrimSuffix(name, ".")) }

func header(name string, typ dnsmessage.Type, ttl uint32) dnsmessage.ResourceHeader {
	return dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName(canon(name) + "."), Type: typ, Class: dnsmessage.ClassINET, TTL: ttl}
}

// A returns an A or AAAA record for an address.
func A(name string, ttl uint32, ip netip.Addr) dnsmessage.Resource {
	ip = ip.Unmap()
	if ip.Is4() {
		return dnsmessage.Resource{Header: header(name, TypeA, ttl), Body: &dnsmessage.AResource{A: ip.As4()}}
	}
	return dnsmessage.Resource{Header: header(name, TypeAAAA, ttl), Body: &dnsmessage.AAAAResource{AAAA: ip.As16()}}
}

// TXT returns a TXT record with the character strings.
func TXT(name string, ttl uint32, texts ...string) dnsmessage.Resource {
	return dnsmessage.Resource{Header: header(name, TypeTXT, ttl), Body: &dnsmessage.TXTResource{TXT: texts}}
}

// CAA returns a CAA record (RFC 8659).
func CAA(name string, ttl uint32, flags byte, tag, value string) dnsmessage.Resource {
	data := append([]byte{flags, byte(len(tag))}, tag...)
	data = append(data, value...)
	return dnsmessage.Resource{Header: header(name, TypeCAA, ttl), Body: &dnsmessage.UnknownResource{Type: TypeCAA, Data: data}}
}

// CNAME returns a CNAME record.
func CNAME(name string, ttl uint32, target string) dnsmessage.Resource {
	return dnsmessage.Resource{Header: header(name, TypeCNAME, ttl),
		Body: &dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName(canon(target) + ".")}}
}

func ns(name string, ttl uint32, target string) dnsmessage.Resource {
	return dnsmessage.Resource{Header: header(name, TypeNS, ttl),
		Body: &dnsmessage.NSResource{NS: dnsmessage.MustNewName(canon(target) + ".")}}
}

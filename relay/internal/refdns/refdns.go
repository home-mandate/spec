// SPDX-License-Identifier: Apache-2.0

// Package refdns is a DNS in memory for tests of the live test tool relay-conformance: it
// serves zones from 127.0.0.1 with two authoritative name servers for each zone, over UDP and
// TCP, and nothing else. The reference operator publishes the records of its installations
// in it. Neither the tool nor the files of package relay import it (a test checks that).
package refdns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"

	"golang.org/x/net/dns/dnsmessage"
)

// Servers is the number of authoritative name servers of a zone.
const Servers = 2

// ErrNoSuchHost is returned by the lookups for a name the DNS does not know.
var ErrNoSuchHost = errors.New("refdns: no such host")

// zone is a zone with its name servers.
type zone struct {
	name  string
	index int
	inst  [Servers]*instance
}

// DNS is a set of zones.
type DNS struct {
	zones []*zone
}

// New starts the zones with two name servers each.
func New(zones ...string) (*DNS, error) {
	d := &DNS{}
	for n, name := range zones {
		z := &zone{name: canon(name), index: n}
		for k := range z.inst {
			inst, err := newInstance(z.name)
			if err != nil {
				d.Close()
				return nil, err
			}
			z.inst[k] = inst
		}
		d.zones = append(d.zones, z)
	}
	d.publishNS()
	return d, nil
}

func (d *DNS) publishNS() {
	for _, z := range d.zones {
		var rrs []dnsmessage.Resource
		for k := range z.inst {
			rrs = append(rrs, ns(z.name, 3600, nsHost(z, k)))
		}
		for _, inst := range z.inst {
			inst.replace(z.name, TypeNS, rrs)
		}
	}
}

func nsHost(z *zone, k int) string { return fmt.Sprintf("ns%d.%s", k+1, z.name) }

// nsAddr is the address that stands for name server k of zone z: it is only the key of Remap.
func nsAddr(z *zone, k int) netip.Addr {
	return netip.AddrFrom4([4]byte{127, 0, byte(z.index + 1), byte(k + 1)})
}

// Close stops all name servers.
func (d *DNS) Close() {
	for _, z := range d.zones {
		for _, inst := range z.inst {
			if inst != nil {
				inst.close()
			}
		}
	}
}

// zoneOf returns the zone that holds name.
func (d *DNS) zoneOf(name string) *zone {
	name = canon(name)
	for _, z := range d.zones {
		if name == z.name || hasSuffix(name, z.name) {
			return z
		}
	}
	return nil
}

// Replace sets the records of one name and type on both name servers; no records remove them.
// It panics for a name outside the zones: the callers are tests.
func (d *DNS) Replace(name string, typ dnsmessage.Type, rrs ...dnsmessage.Resource) {
	for k := range d.mustZone(name).inst {
		d.ReplaceOn(k, name, typ, rrs...)
	}
}

// ReplaceOn is Replace for name server k only.
func (d *DNS) ReplaceOn(k int, name string, typ dnsmessage.Type, rrs ...dnsmessage.Resource) {
	d.mustZone(name).inst[k].replace(name, typ, rrs)
}

func (d *DNS) mustZone(name string) *zone {
	z := d.zoneOf(name)
	if z == nil {
		panic("refdns: no zone for " + name)
	}
	return z
}

// RemoveBelow removes every record at name and below it, on both name servers.
func (d *DNS) RemoveBelow(name string) {
	for _, inst := range d.mustZone(name).inst {
		inst.removeBelow(name)
	}
}

// Lookup returns the records of name server k.
func (d *DNS) Lookup(k int, name string, typ dnsmessage.Type) []dnsmessage.Resource {
	return d.mustZone(name).inst[k].lookup(name, typ)
}

// SetBehavior makes name server k of the zone of name answer as b says.
func (d *DNS) SetBehavior(name string, k int, b Behavior) {
	d.mustZone(name).inst[k].setBehavior(b)
}

// LookupNS stands for the NS lookup of the resolver: it knows the apex of a zone only.
func (d *DNS) LookupNS(_ context.Context, name string) ([]string, error) {
	for _, z := range d.zones {
		if canon(name) == z.name {
			return []string{nsHost(z, 0), nsHost(z, 1)}, nil
		}
	}
	return nil, ErrNoSuchHost
}

// LookupAddr resolves the names of the name servers.
func (d *DNS) LookupAddr(_ context.Context, host string) ([]netip.Addr, error) {
	for _, z := range d.zones {
		for k := range z.inst {
			if canon(host) == nsHost(z, k) {
				return []netip.Addr{nsAddr(z, k)}, nil
			}
		}
	}
	return nil, ErrNoSuchHost
}

// Remap sends a connection to the address of a name server on port 53 to the real listener.
func (d *DNS) Remap(hostport string) string {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil || port != "53" {
		return hostport
	}
	for _, z := range d.zones {
		for k, inst := range z.inst {
			if host == nsAddr(z, k).String() {
				return inst.addr()
			}
		}
	}
	return hostport
}

// Names returns the apex names of the zones.
func (d *DNS) Names() []string {
	out := make([]string, len(d.zones))
	for i, z := range d.zones {
		out[i] = z.name
	}
	return out
}

// Covers reports whether name is in one of the zones.
func (d *DNS) Covers(name string) bool { return d.zoneOf(name) != nil }

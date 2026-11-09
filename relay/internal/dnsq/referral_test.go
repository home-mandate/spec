// SPDX-License-Identifier: Apache-2.0

package dnsq_test

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/home-mandate/spec/relay/internal/dnsq"
	"github.com/home-mandate/spec/relay/internal/netguard"
)

// referralServer answers every query with no answer and the given NS records in the authority
// section, as a name server does for a name it delegates.
func referralServer(t *testing.T, owner string) string {
	t.Helper()
	udp, _ := listenBoth(t, false)
	t.Cleanup(func() { _ = udp.Close() })
	go func() {
		buf := make([]byte, 512)
		for {
			n, from, err := udp.ReadFromUDP(buf)
			if err != nil {
				return
			}
			var q dnsmessage.Message
			if q.Unpack(buf[:n]) != nil {
				continue
			}
			q.Response = true
			q.Authorities = []dnsmessage.Resource{{
				Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName(owner), Type: dnsmessage.TypeNS, Class: dnsmessage.ClassINET, TTL: 300},
				Body:   &dnsmessage.NSResource{NS: dnsmessage.MustNewName("ns.elsewhere.example.")},
			}}
			out, _ := q.Pack()
			_, _ = udp.WriteToUDP(out, from)
		}
	}()
	return udp.LocalAddr().String()
}

func TestADelegatingNSAtTheQueriedNameIsAnUnexpectedRecord(t *testing.T) {
	for name, tt := range map[string]struct {
		owner string
		want  int
	}{
		"at the queried name": {"X.Example.Net.", 1},
		"at another name":     {"example.net.", 0},
		"at a name below it":  {"a.x.example.net.", 0},
	} {
		addr := referralServer(t, tt.owner)
		r := &dnsq.Resolver{
			Dialer:  netguard.New(netguard.Options{Policy: func(a netip.Addr) bool { return a.IsLoopback() }, Remap: func(string) string { return addr }}),
			Timeout: time.Second,
		}
		got, err := r.Ask(context.Background(), dnsq.Server{Host: "ns", Addr: netip.MustParseAddr("127.0.0.1")}, "x.example.net", dnsq.TypeNS)
		if err != nil || len(got.Records) != tt.want {
			t.Errorf("%s: %d records, %v", name, len(got.Records), err)
			continue
		}
		if tt.want == 1 && (got.Records[0].Type != dnsq.TypeNS || got.Records[0].Name != "x.example.net" || got.Records[0].Target != "ns.elsewhere.example") {
			t.Errorf("%s: %+v", name, got.Records[0])
		}
	}
}

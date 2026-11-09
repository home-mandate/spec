// SPDX-License-Identifier: Apache-2.0

package dnsq_test

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/home-mandate/spec/relay/internal/dnsq"
	"github.com/home-mandate/spec/relay/internal/netguard"
	"github.com/home-mandate/spec/relay/internal/refdns"
)

const zone = "homes.example.org"

func setup(t *testing.T) (*refdns.DNS, *dnsq.Resolver) {
	t.Helper()
	d, err := refdns.New(zone, "other.example.com")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	dialer := netguard.New(netguard.Options{
		Policy: func(a netip.Addr) bool { return a.IsLoopback() },
		Lookup: d.LookupAddr, Remap: d.Remap,
	})
	return d, &dnsq.Resolver{Dialer: dialer, NS: d.LookupNS, Timeout: 300 * time.Millisecond}
}

func firstServer(t *testing.T, r *dnsq.Resolver, name string) dnsq.Server {
	t.Helper()
	_, servers, err := r.Zone(context.Background(), name)
	if err != nil || len(servers) != 2 {
		t.Fatalf("servers %v, %v", servers, err)
	}
	return servers[0]
}

func TestZoneFindsTheApexAboveAName(t *testing.T) {
	_, r := setup(t)
	apex, servers, err := r.Zone(context.Background(), "a.b.homes.example.org.")
	if err != nil || apex != zone || len(servers) != 2 || servers[0].Host != "ns1."+zone || servers[0].String() == "" {
		t.Fatalf("%q %v %v", apex, servers, err)
	}
	if _, _, err := r.Zone(context.Background(), "nothing.example.net"); !errors.Is(err, dnsq.ErrNoZone) {
		t.Errorf("unknown zone: %v", err)
	}
	if _, _, err := r.Zone(context.Background(), "localhost"); !errors.Is(err, dnsq.ErrNoZone) {
		t.Errorf("one label: %v", err)
	}
}

func TestZoneWithoutAddressesIsNoZone(t *testing.T) {
	d, _ := setup(t)
	r := &dnsq.Resolver{
		Dialer: netguard.New(netguard.Options{Policy: func(netip.Addr) bool { return false }, Lookup: d.LookupAddr}),
		NS:     d.LookupNS, Timeout: time.Second,
	}
	if _, _, err := r.Zone(context.Background(), zone); !errors.Is(err, dnsq.ErrNoZone) {
		t.Errorf("err = %v", err)
	}
}

func TestAskReturnsEachTypeOfRecord(t *testing.T) {
	d, r := setup(t)
	name := "h1." + zone
	d.Replace(name, refdns.TypeA, refdns.A(name, 60, netip.MustParseAddr("192.0.2.1")))
	d.Replace(name, refdns.TypeAAAA, refdns.A(name, 61, netip.MustParseAddr("2001:db8::1")))
	d.Replace(name, refdns.TypeTXT, refdns.TXT(name, 62, "ab", "cd"))
	d.Replace(name, refdns.TypeCAA, refdns.CAA(name, 63, 0, "issue", ";"), refdns.CAA(name, 63, 128, "issuewild", ";"))
	s := firstServer(t, r, name)
	check := func(typ dnsmessage.Type, n int) dnsq.Answer {
		t.Helper()
		a, err := r.Ask(context.Background(), s, name, typ)
		if err != nil || len(a.Records) != n || !a.Authoritative {
			t.Fatalf("type %v: %+v, %v", typ, a, err)
		}
		return a
	}
	if a := check(dnsq.TypeA, 1); a.Records[0].Addr.String() != "192.0.2.1" || a.Records[0].TTL != 60 || a.Records[0].Name != name {
		t.Errorf("A: %+v", a.Records[0])
	}
	if a := check(dnsq.TypeAAAA, 1); a.Records[0].Addr.String() != "2001:db8::1" {
		t.Errorf("AAAA: %+v", a.Records[0])
	}
	if a := check(dnsq.TypeTXT, 1); a.Records[0].Text != "abcd" {
		t.Errorf("TXT: %+v", a.Records[0])
	}
	if a := check(dnsq.TypeCAA, 2); a.Records[1].CAA != (dnsq.CAA{Flags: 128, Tag: "issuewild", Value: ";"}) {
		t.Errorf("CAA: %+v", a.Records[1])
	}
	check(dnsq.TypeNS, 0)
	apexNS, err := r.Ask(context.Background(), s, zone, dnsq.TypeNS)
	if err != nil || len(apexNS.Records) != 2 || apexNS.Records[0].Target != "ns1."+zone {
		t.Errorf("NS: %+v %v", apexNS, err)
	}
}

func TestAskSeesACNAMEAndANameWithoutRecords(t *testing.T) {
	d, r := setup(t)
	name := "c." + zone
	d.Replace(name, refdns.TypeCNAME, refdns.CNAME(name, 60, "target.example.net"))
	s := firstServer(t, r, name)
	a, err := r.Ask(context.Background(), s, name, dnsq.TypeA)
	if err != nil || len(a.Records) != 1 || a.Records[0].Type != dnsq.TypeCNAME || a.Records[0].Target != "target.example.net" {
		t.Errorf("CNAME: %+v %v", a, err)
	}
	a, err = r.Ask(context.Background(), s, "none."+zone, dnsq.TypeA)
	if err != nil || a.RCode != dnsmessage.RCodeNameError || len(a.Records) != 0 {
		t.Errorf("NXDOMAIN: %+v %v", a, err)
	}
	d.Replace("sub.empty."+zone, refdns.TypeTXT, refdns.TXT("sub.empty."+zone, 1, "x"))
	a, err = r.Ask(context.Background(), s, "empty."+zone, dnsq.TypeA)
	if err != nil || a.RCode != dnsmessage.RCodeSuccess || len(a.Records) != 0 {
		t.Errorf("empty non-terminal: %+v %v", a, err)
	}
	a, err = r.Ask(context.Background(), s, "x.other.example.net", dnsq.TypeA)
	if err != nil || a.RCode != dnsmessage.RCodeRefused || a.Authoritative {
		t.Errorf("outside the zone: %+v %v", a, err)
	}
}

func TestATruncatedUDPAnswerIsRepeatedOverTCP(t *testing.T) {
	d, r := setup(t)
	name := "t." + zone
	d.Replace(name, refdns.TypeTXT, refdns.TXT(name, 60, "big"))
	d.SetBehavior(zone, 0, refdns.TruncateUDP)
	a, err := r.Ask(context.Background(), firstServer(t, r, name), name, dnsq.TypeTXT)
	if err != nil || len(a.Records) != 1 || a.Records[0].Text != "big" {
		t.Errorf("%+v %v", a, err)
	}
}

func TestAskRefusesWhatIsNotTheAnswerToTheQuery(t *testing.T) {
	for name, b := range map[string]refdns.Behavior{
		"wrong ID": refdns.WrongID, "wrong question": refdns.WrongQuestion, "garbage": refdns.Garbage,
		"not a response": refdns.NotAResponse, "many records": refdns.ManyRecords,
		"huge TCP": refdns.HugeTCP, "always truncated": refdns.AlwaysTruncated,
	} {
		t.Run(name, func(t *testing.T) {
			d, r := setup(t)
			d.SetBehavior(zone, 0, b)
			_, err := r.Ask(context.Background(), firstServer(t, r, zone), "x."+zone, dnsq.TypeTXT)
			if !errors.Is(err, dnsq.ErrBadAnswer) {
				t.Errorf("err = %v", err)
			}
		})
	}
}

func TestAskTimesOutOnASilentServerAndStopsWithItsContext(t *testing.T) {
	d, r := setup(t)
	d.SetBehavior(zone, 0, refdns.Silent)
	s := firstServer(t, r, zone)
	start := time.Now()
	if _, err := r.Ask(context.Background(), s, zone, dnsq.TypeNS); err == nil {
		t.Error("a silent server answered")
	}
	if time.Since(start) > 3*time.Second {
		t.Error("no timeout")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := r.Ask(ctx, s, zone, dnsq.TypeNS); err == nil {
		t.Error("a cancelled query went out")
	}
}

func TestAskReportsServFailAndTCPFailures(t *testing.T) {
	d, r := setup(t)
	d.SetBehavior(zone, 0, refdns.ServFail)
	a, err := r.Ask(context.Background(), firstServer(t, r, zone), zone, dnsq.TypeNS)
	if err != nil || a.RCode != dnsmessage.RCodeServerFailure {
		t.Errorf("%+v %v", a, err)
	}
	d.SetBehavior(zone, 0, refdns.TruncateUDP)
	s := firstServer(t, r, zone)
	d.SetBehavior(zone, 0, refdns.Silent)
	if _, err := r.Ask(context.Background(), s, zone, dnsq.TypeNS); err == nil {
		t.Error("silent")
	}
}

func TestAskRefusesAnAddressTheFilterBlocks(t *testing.T) {
	_, r := setup(t)
	blocked := &dnsq.Resolver{Dialer: netguard.New(netguard.Options{}), Timeout: time.Second}
	s := dnsq.Server{Host: "ns", Addr: netip.MustParseAddr("10.0.0.1")}
	if _, err := blocked.Ask(context.Background(), s, "a.example.net", dnsq.TypeA); !errors.Is(err, netguard.ErrBlocked) {
		t.Errorf("err = %v", err)
	}
	_ = r
}

func TestAskRejectsAnInvalidName(t *testing.T) {
	_, r := setup(t)
	long := string(make([]byte, 300))
	if _, err := r.Ask(context.Background(), dnsq.Server{Addr: netip.MustParseAddr("127.0.0.1")}, long, dnsq.TypeA); err == nil {
		t.Error("an invalid name was asked")
	}
}

func TestAMalformedCAARecordInAnAnswerIsAnError(t *testing.T) {
	d, r := setup(t)
	name := "bad." + zone
	d.Replace(name, refdns.TypeCAA, refdns.CAA(name, 60, 0, "is sue", ";"))
	if _, err := r.Ask(context.Background(), firstServer(t, r, name), name, dnsq.TypeCAA); !errors.Is(err, dnsq.ErrCAA) {
		t.Errorf("err = %v", err)
	}
}

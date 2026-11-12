// SPDX-License-Identifier: Apache-2.0

package refdns_test

import (
	"context"
	"net/http"
	"net/netip"
	"net/url"
	"testing"

	"github.com/home-mandate/spec/relay/internal/refdns"
)

func TestZonesStoreAndRemoveRecords(t *testing.T) {
	d, err := refdns.New("a.example", "b.example")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if got := d.Names(); len(got) != 2 || got[0] != "a.example" {
		t.Errorf("Names = %v", got)
	}
	name := "x.y.a.example"
	d.Replace(name, refdns.TypeTXT, refdns.TXT(name, 1, "one"))
	d.ReplaceOn(1, name, refdns.TypeTXT, refdns.TXT(name, 1, "two"))
	if len(d.Lookup(0, name, refdns.TypeTXT)) != 1 || len(d.Lookup(1, "X.Y.A.EXAMPLE.", refdns.TypeTXT)) != 1 {
		t.Error("records missing")
	}
	d.Replace("other.a.example", refdns.TypeA, refdns.A("other.a.example", 1, netip.MustParseAddr("192.0.2.1")))
	d.RemoveBelow("y.a.example")
	if len(d.Lookup(0, name, refdns.TypeTXT)) != 0 || len(d.Lookup(1, name, refdns.TypeTXT)) != 0 {
		t.Error("records below a name remain")
	}
	if len(d.Lookup(0, "other.a.example", refdns.TypeA)) != 1 {
		t.Error("RemoveBelow removed a sibling")
	}
	d.Replace("other.a.example", refdns.TypeA)
	if len(d.Lookup(0, "other.a.example", refdns.TypeA)) != 0 {
		t.Error("an empty Replace did not remove")
	}
}

func TestLookupsAndRemap(t *testing.T) {
	d, err := refdns.New("a.example")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	hosts, err := d.LookupNS(context.Background(), "A.example.")
	if err != nil || len(hosts) != 2 {
		t.Fatalf("%v %v", hosts, err)
	}
	if _, err := d.LookupNS(context.Background(), "sub.a.example"); err == nil {
		t.Error("NS of a name that is no apex")
	}
	addrs, err := d.LookupAddr(context.Background(), hosts[1])
	if err != nil || len(addrs) != 1 {
		t.Fatalf("%v %v", addrs, err)
	}
	if _, err := d.LookupAddr(context.Background(), "nobody.example"); err == nil {
		t.Error("an unknown host resolved")
	}
	real := d.Remap(addrs[0].String() + ":53")
	if real == addrs[0].String()+":53" {
		t.Error("the name server address was not remapped")
	}
	for _, same := range []string{"127.0.0.1:53", addrs[0].String() + ":80", "garbage"} {
		if d.Remap(same) != same {
			t.Errorf("%s was remapped", same)
		}
	}
}

func TestAnUnknownZonePanics(t *testing.T) {
	d, _ := refdns.New("a.example")
	defer d.Close()
	defer func() {
		if recover() == nil {
			t.Error("no panic")
		}
	}()
	d.Replace("x.other.example", refdns.TypeTXT)
}

func TestControlSetsAndRemovesATXTRecord(t *testing.T) {
	d, _ := refdns.New("a.example")
	defer d.Close()
	base, stop := d.Control()
	defer stop()
	name := "_x.h.a.example"
	call := func(method, rawName, value string) int {
		q := url.Values{"name": {rawName}, "value": {value}}
		req, _ := http.NewRequest(method, base+"/txt?"+q.Encode(), nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if call("POST", name, "v") != 200 || len(d.Lookup(1, name, refdns.TypeTXT)) != 1 {
		t.Error("set")
	}
	if call("DELETE", name, "") != 200 || len(d.Lookup(1, name, refdns.TypeTXT)) != 0 {
		t.Error("delete")
	}
	if call("POST", "x.other.example", "v") != 404 || call("GET", name, "") != 405 {
		t.Error("errors")
	}
}

func TestRecordConstructorsAndCovers(t *testing.T) {
	d, _ := refdns.New("a.example")
	defer d.Close()
	if !d.Covers("x.a.example") || d.Covers("x.b.example") {
		t.Error("Covers")
	}
	d.Replace("x.a.example", refdns.TypeAAAA, refdns.A("x.a.example", 1, netip.MustParseAddr("2001:db8::1")))
	d.Replace("c.a.example", refdns.TypeCNAME, refdns.CNAME("c.a.example", 1, "x.a.example"))
	d.Replace("x.a.example", refdns.TypeCAA, refdns.CAA("x.a.example", 1, 0, "issue", ";"))
	if len(d.Lookup(0, "x.a.example", refdns.TypeAAAA)) != 1 || len(d.Lookup(0, "c.a.example", refdns.TypeCNAME)) != 1 || len(d.Lookup(1, "x.a.example", refdns.TypeCAA)) != 1 {
		t.Error("records missing")
	}
}

// SPDX-License-Identifier: Apache-2.0

package refgateway_test

import (
	"math/rand/v2"
	"testing"

	"github.com/home-mandate/spec/relay/internal/dnsq"
	"github.com/home-mandate/spec/relay/internal/refgateway"
)

// compare checks that the parser of the tool and the one written from the ABNF agree on a value.
func compare(t *testing.T, value string) {
	t.Helper()
	got, err := dnsq.ParseIssue(value)
	want, ok := refgateway.ParseProperty(value)
	if (err == nil) != ok {
		t.Fatalf("%q: dnsq accepts = %v, the ABNF reader accepts = %v", value, err == nil, ok)
	}
	if !ok {
		return
	}
	if got.Domain != want.Domain || len(got.Params) != len(want.Params) {
		t.Fatalf("%q: dnsq reads %+v, the ABNF reader %+v", value, got, want)
	}
	for i, p := range got.Params {
		if p.Tag != want.Params[i].Tag || p.Value != want.Params[i].Value {
			t.Fatalf("%q: parameter %d differs: %+v and %+v", value, i, p, want.Params[i])
		}
	}
}

func TestParseIssueAgreesWithTheABNFReader(t *testing.T) {
	for _, v := range []string{
		"", " ", ";", " ; ", ";;", "ca.example", "ca.example;", "ca.example ; k = v ;\tl\t=\tw", "ca.example;k=v;", "ca.example;;k=v",
		"a--b.c", "a-.c", "-a.c", "a..c", "a.c.", ".a.c", "a.c; -k=v", "a.c; k-=v", "a.c; k=v w", "a.c; k=\x7f", "a.c; k=ä", "a.c\n", "%%%%%",
		"; k=v", "ca.example k=v", "ca.example; k", "ca.example; =v", "ca.example; k=", "ca.example;k=v ; ", "CA.Example; K=V",
	} {
		compare(t, v)
	}
}

// TestParseIssueAgreesOnRandomValues compares the two readers on values built from the
// characters that matter in the grammar, from a fixed seed.
func TestParseIssueAgreesOnRandomValues(t *testing.T) {
	alphabet := []byte("aZ0-.; \t=\x7f\n%\xc3")
	rng := rand.New(rand.NewPCG(1, 2))
	for range 20000 {
		b := make([]byte, rng.IntN(14))
		for i := range b {
			b[i] = alphabet[rng.IntN(len(alphabet))]
		}
		compare(t, string(b))
	}
}

func TestOddInputs(t *testing.T) {
	if _, err := refgateway.RunPins(refgateway.PinsInput{ConnectionPin: "x"}, 0); err == nil {
		t.Error("a pin of the connection that is not stored")
	}
	in := refgateway.CTInput{Pairing: "x"}
	if _, err := refgateway.CTAlarms(in, 0); err != nil {
		t.Errorf("no certificates need no times: %v", err)
	}
	cert := refgateway.Certificate{ID: "a", NotBefore: "2026-01-01T00:00:00Z", NotAfter: "2026-01-01T00:00:00Z", Logged: "2026-01-01T00:00:00Z"}
	for _, bad := range []refgateway.CTInput{
		{Pairing: "x", Now: "2026-01-01T00:00:00Z", Certificates: []refgateway.Certificate{cert}},
		{Pairing: "2026-01-01T00:00:00Z", Now: "x", Certificates: []refgateway.Certificate{cert}},
		{Pairing: "2026-01-01T00:00:00Z", Now: "2026-01-01T00:00:00Z", Certificates: []refgateway.Certificate{{ID: "a"}}},
		{Pairing: "2026-01-01T00:00:00Z", Now: "2026-01-01T00:00:00Z", Certificates: []refgateway.Certificate{cert},
			ServerKeys: refgateway.ServerKeys{Earlier: []refgateway.EarlierKey{{PublicKey: "k", Replaced: "x"}}}},
	} {
		if _, err := refgateway.CTAlarms(bad, 0); err == nil {
			t.Errorf("a time that does not parse was accepted: %+v", bad)
		}
	}
	if r := refgateway.ParseProxy([]byte("PROXY TCP4 1.2.3.4 5.6.7.8 1 2"), refgateway.ProxyV1); r.Accepted {
		t.Error("a version 1 line without the line end")
	}
	if r := refgateway.ParseProxy([]byte("PROXY TCP4 x 5.6.7.8 1 2\r\n"), refgateway.ProxyV1); r.Accepted {
		t.Error("a version 1 line with a bad address")
	}
	if r := refgateway.ParseProxy([]byte("PROXY TCP4 1.2.3.4 5.6.7.8 1 2\r\n"), refgateway.ProxyV1); !r.Accepted || r.Consumed != 32 {
		t.Errorf("a version 1 line: %+v", r)
	}
}

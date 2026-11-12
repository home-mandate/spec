// SPDX-License-Identifier: Apache-2.0

package dnsq_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/home-mandate/spec/relay/internal/dnsq"
)

func TestParseCAA(t *testing.T) {
	good := append([]byte{128, 5}, "Issue"...)
	good = append(good, "letsencrypt.org"...)
	got, err := dnsq.ParseCAA(good)
	if err != nil || got != (dnsq.CAA{Flags: 128, Tag: "issue", Value: "letsencrypt.org"}) {
		t.Errorf("%+v %v", got, err)
	}
	for name, data := range map[string][]byte{
		"empty": nil, "one byte": {0}, "no tag": {0, 0}, "tag too long": append([]byte{0, 16}, make([]byte, 16)...),
		"tag cut short": {0, 5, 'a'}, "tag with a blank": {0, 3, 'a', ' ', 'b'},
	} {
		if _, err := dnsq.ParseCAA(data); !errors.Is(err, dnsq.ErrCAA) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if got, err := dnsq.ParseCAA([]byte{0, 1, 'x'}); err != nil || got.Value != "" {
		t.Errorf("empty value: %+v %v", got, err)
	}
}

func TestParseIssue(t *testing.T) {
	tests := []struct {
		in     string
		domain string
		params []dnsq.Param
		bad    bool
	}{
		{in: ""},
		{in: "  \t "},
		{in: ";"},
		{in: " ; "},
		{in: "; "},
		{in: ";;", bad: true},
		{in: "letsencrypt.org", domain: "letsencrypt.org"},
		{in: " letsencrypt.org\t", domain: "letsencrypt.org"},
		{in: "LetsEncrypt.org ;", domain: "letsencrypt.org"},
		{in: "ca.example;", domain: "ca.example"},
		{in: "a--b.example", domain: "a--b.example"},
		{in: "xn--p1ai.example", domain: "xn--p1ai.example"},
		{in: "letsencrypt.org; accounturi=https://a.example/acct/1; validationmethods=dns-01",
			domain: "letsencrypt.org", params: []dnsq.Param{{"accounturi", "https://a.example/acct/1"}, {"validationmethods", "dns-01"}}},
		{in: "ca.example ; k = v ;\tl\t=\tw ", domain: "ca.example", params: []dnsq.Param{{"k", "v"}, {"l", "w"}}},
		{in: "ca.example;k=v;l=w", domain: "ca.example", params: []dnsq.Param{{"k", "v"}, {"l", "w"}}},
		{in: "; k=v", params: []dnsq.Param{{"k", "v"}}},
		{in: "ca.example;k=", domain: "ca.example", params: []dnsq.Param{{"k", ""}}},
		{in: "ca.example; K=V", domain: "ca.example", params: []dnsq.Param{{"K", "V"}}},
		{in: "ca.example; 9-x=1", domain: "ca.example", params: []dnsq.Param{{"9-x", "1"}}},
		{in: "ca.example;;x=y ;", bad: true},
		{in: "ca.example;k=v;", bad: true},
		{in: "ca.example;k=v ; ", bad: true},
		{in: "ca.example;;k=v", bad: true},
		{in: "ca.example; -k=v", bad: true},
		{in: "ca.example; k-=v", bad: true},
		{in: "ca.example k=v", bad: true},
		{in: "ca.example.", bad: true},
		{in: "ca..example", bad: true},
		{in: ".example", bad: true},
		{in: "bad_name.example", bad: true},
		{in: "-a.example", bad: true},
		{in: "a-.example", bad: true},
		{in: "a.example; novalue", bad: true},
		{in: "a.example; =x", bad: true},
		{in: "a.example; t=a b", bad: true},
		{in: "a.example; t=a\x01", bad: true},
		{in: "a.example; t=a\x7f", bad: true},
		{in: "a.example; t=\u00e4", bad: true},
		{in: "a.example; t!=x", bad: true},
		{in: "%%%%%", bad: true},
		{in: "a.example\n", bad: true},
	}
	for _, tt := range tests {
		got, err := dnsq.ParseIssue(tt.in)
		if tt.bad {
			if !errors.Is(err, dnsq.ErrCAA) {
				t.Errorf("%q: %v", tt.in, err)
			}
			continue
		}
		if err != nil || got.Domain != tt.domain || len(got.Params) != len(tt.params) {
			t.Errorf("%q: %+v %v", tt.in, got, err)
			continue
		}
		for i, p := range tt.params {
			if got.Params[i] != p {
				t.Errorf("%q: param %d = %+v", tt.in, i, got.Params[i])
			}
		}
	}
	issue, _ := dnsq.ParseIssue("a.example; k=v")
	if v, ok := issue.Param("k"); !ok || v != "v" {
		t.Error("Param k")
	}
	if _, ok := issue.Param("other"); ok {
		t.Error("Param other")
	}
}

func FuzzCAA(f *testing.F) {
	f.Add(append([]byte{128, 5}, "issueletsencrypt.org; accounturi=https://example.net/acct/1; validationmethods=dns-01"...))
	f.Add([]byte{0, 1, 'x'})
	f.Add([]byte{0, 9, 'i', 's', 's', 'u', 'e', 'w', 'i', 'l', 'd', ';'})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		caa, err := dnsq.ParseCAA(data)
		if err != nil {
			if !errors.Is(err, dnsq.ErrCAA) {
				t.Fatalf("an error that is not ErrCAA: %v", err)
			}
			return
		}
		if n := len(caa.Tag); n < 1 || n > 15 || len(data) != 2+n+len(caa.Value) {
			t.Fatalf("tag %q and value %q do not make up %x", caa.Tag, caa.Value, data)
		}
		for _, c := range caa.Tag {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9') {
				t.Fatalf("tag %q is not lower-case alphanumeric", caa.Tag)
			}
		}
		// The value of an issue record parses or is refused; it never panics, and what parses
		// has a domain in lower case and parameters with tags and values.
		issue, err := dnsq.ParseIssue(caa.Value)
		if err != nil {
			if !errors.Is(err, dnsq.ErrCAA) {
				t.Fatalf("an error that is not ErrCAA: %v", err)
			}
			return
		}
		if issue.Domain != strings.ToLower(issue.Domain) || strings.ContainsAny(issue.Domain, " \t;") {
			t.Fatalf("domain %q", issue.Domain)
		}
		for _, p := range issue.Params {
			if p.Tag == "" || strings.ContainsAny(p.Value, " ;") {
				t.Fatalf("parameter %+v", p)
			}
		}
	})
}

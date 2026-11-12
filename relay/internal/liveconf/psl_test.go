// SPDX-License-Identifier: Apache-2.0

package liveconf

import "testing"

func TestRegisteredDomain(t *testing.T) {
	for _, tt := range []struct {
		host, name, want string
		fail             bool
	}{
		{host: "op.example.net", name: "homes.example.org", want: "example.net"},
		{host: "homes.example.org", name: "homes.example.org", want: "example.org"},
		{host: "a.homes.example.org", name: "homes.example.org", want: "example.org"},
		// The name domain is an entry of the list: judged as if it were not.
		{host: "x.github.io", name: "github.io", want: "github.io"},
		{host: "github.io", name: "github.io", want: "github.io"},
		{host: "x.y.blogspot.com", name: "blogspot.com", want: "blogspot.com"},
		// Another site below an entry that is not the name domain keeps the entry.
		{host: "x.github.io", name: "homes.example.org", want: "x.github.io"},
		{host: "a.b.co.uk", name: "homes.example.org", want: "b.co.uk"},
		{host: "co.uk", name: "homes.example.org", fail: true},
		// An entry of the list as the name domain, two labels deep in a longer suffix.
		{host: "x.foo.co.uk", name: "foo.co.uk", want: "foo.co.uk"},
	} {
		got, err := registeredDomain(tt.host, tt.name)
		if (err != nil) != tt.fail || got != tt.want {
			t.Errorf("registeredDomain(%q, %q) = %q, %v; want %q (fail %v)", tt.host, tt.name, got, err, tt.want, tt.fail)
		}
	}
}

func TestNameRegisteredDomainWithoutItsOwnEntry(t *testing.T) {
	// github.io is an entry; without it, the suffix is io and the registered domain github.io.
	got, err := nameRegisteredDomain("github.io")
	if err != nil || got != "github.io" {
		t.Errorf("got %q, %v", got, err)
	}
	// a.github.io is no entry: it is its own registered domain.
	got, err = nameRegisteredDomain("a.github.io")
	if err != nil || got != "a.github.io" {
		t.Errorf("got %q, %v", got, err)
	}
	if got, _ := nameRegisteredDomain("homes.example.net"); got != "example.net" {
		t.Errorf("got %q", got)
	}
}

func TestLabelHelpers(t *testing.T) {
	if parentDomain("a.b.c") != "b.c" || parentDomain("a") != "" || labelCount("a.b.c") != 3 {
		t.Error("label helpers are wrong")
	}
}

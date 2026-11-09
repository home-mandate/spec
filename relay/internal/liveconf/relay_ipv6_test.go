// SPDX-License-Identifier: Apache-2.0

package liveconf

import (
	"slices"
	"strings"
	"testing"
)

// hintsOf plays newRelay for relay_addresses and returns the notes of the report.
func hintsOf(t *testing.T, addresses []string) []string {
	t.Helper()
	doc := &metadataDoc{}
	doc.Relay.Host, doc.Relay.Port, doc.RelayAddresses = "h.example", 8443, addresses
	s := &script{r: newRun(Settings{Operator: "op.example", Classes: []string{ClassRelay}}, envWithoutNetwork()), doc: doc}
	s.newRelay()
	return s.r.result().Report.Notes
}

func hasIPv6Hint(notes []string) bool {
	return slices.ContainsFunc(notes, func(n string) bool { return strings.Contains(n, "IPv6") && strings.Contains(n, "unchecked") })
}

func TestTheReportHintsThatIPv6AddressesStayUnchecked(t *testing.T) {
	for name, tt := range map[string]struct {
		addresses []string
		hint      bool
	}{
		"IPv4 only":                 {[]string{"192.0.2.1"}, false},
		"IPv4 first, IPv6 after":    {[]string{"192.0.2.1", "2001:db8::1"}, true},
		"IPv6 only, the agent uses": {[]string{"2001:db8::1"}, false},
		"second IPv6 not used":      {[]string{"2001:db8::1", "2001:db8::2"}, true},
		"an address that is no IP":  {[]string{"192.0.2.1", "not an address"}, false},
	} {
		if got := hasIPv6Hint(hintsOf(t, tt.addresses)); got != tt.hint {
			t.Errorf("%s: hint %v, want %v", name, got, tt.hint)
		}
	}
}

func TestTheIPv6HintNamesTheAddressesEscaped(t *testing.T) {
	notes := hintsOf(t, []string{"192.0.2.1", "2001:db8::1"})
	if !slices.ContainsFunc(notes, func(n string) bool { return strings.Contains(n, `"2001:db8::1"`) }) {
		t.Errorf("notes %v", notes)
	}
}

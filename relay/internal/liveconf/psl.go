// SPDX-License-Identifier: Apache-2.0

package liveconf

import (
	"fmt"
	"strings"

	"golang.org/x/net/publicsuffix"

	"github.com/home-mandate/spec/relay/internal/metadata"
)

// parentDomain returns the domain without its first label.
func parentDomain(domain string) string {
	_, rest, _ := strings.Cut(domain, ".")
	return rest
}

func labelCount(domain string) int {
	return strings.Count(domain, ".") + 1
}

// registeredDomain returns the registered domain of host as RELAY-v0 section 7.1 defines it:
// by the Public Suffix List, but as if the name domain had no entry of its own. A host at or
// below the name domain thus has the registered domain of the name domain, also when the name
// domain is itself on the list.
func registeredDomain(host, nameDomain string) (string, error) {
	if metadata.AtOrBelow(host, nameDomain) {
		return nameRegisteredDomain(nameDomain)
	}
	return publicsuffix.EffectiveTLDPlusOne(host)
}

// nameRegisteredDomain is the registered domain of the name domain without its own entry:
// the domain one label above the public suffix of its parent.
func nameRegisteredDomain(name string) (string, error) {
	if suffix, _ := publicsuffix.PublicSuffix(name); suffix != name {
		return publicsuffix.EffectiveTLDPlusOne(name)
	}
	suffix, _ := publicsuffix.PublicSuffix(parentDomain(name))
	labels := strings.Split(name, ".")
	keep := labelCount(suffix) + 1
	if keep > len(labels) {
		return "", fmt.Errorf("%q has no registered domain", name)
	}
	return strings.Join(labels[len(labels)-keep:], "."), nil
}

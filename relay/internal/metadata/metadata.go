// SPDX-License-Identifier: Apache-2.0

// Package metadata checks the rules of the operator metadata (RELAY-v0 section 3) that the
// schema relay/schema/metadata-v0.schema.json cannot express. It is the reference for the
// cases in relay/conformance/metadata-v0.json; a document is valid if it is valid against
// the schema and Check accepts it.
package metadata

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strings"

	"github.com/home-mandate/spec/internal/ijson"
	"github.com/home-mandate/spec/internal/rfc3339"
)

// MaxBytes is the largest document a gateway accepts (RELAY-v0 section 3).
const MaxBytes = 16 << 10

// maxPins bounds active and backup pins together (RELAY-v0 section 6.8).
const maxPins = 8

// pinBytes is the length of a SHA-256 digest.
const pinBytes = 32

// ErrInvalid is returned for a document that breaks a rule.
var ErrInvalid = errors.New("metadata: invalid")

// Document holds the members the rules need.
type Document struct {
	OperatorDomain string `json:"operator_domain"`
	NameDomain     string `json:"name_domain"`
	Enrollment     string `json:"enrollment"`
	Portal         string `json:"portal"`
	PrivacyPolicy  string `json:"privacy_policy"`
	Relay          struct {
		Host string `json:"host"`
		Port int    `json:"port"`
	} `json:"relay"`
	RelayAddresses        []string `json:"relay_addresses"`
	RelayAddressesPlanned *struct {
		Addresses []string `json:"addresses"`
		From      string   `json:"from"`
	} `json:"relay_addresses_planned"`
	RelayPins       []string `json:"relay_pins"`
	RelayBackupPins []string `json:"relay_backup_pins"`
}

// Check checks a document fetched from host: its size, I-JSON, and the rules beyond the
// schema. It relies on the schema for the members and their types; a member that the
// schema rejects may pass here.
func Check(host string, data []byte) error {
	if len(data) > MaxBytes {
		return fmt.Errorf("%w: %d bytes, more than %d", ErrInvalid, len(data), MaxBytes)
	}
	if err := ijson.Check(data); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	var d Document
	if err := json.Unmarshal(data, &d); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	for _, rule := range []func(string, Document) error{checkDomains, checkPins, checkAddresses} {
		if err := rule(host, d); err != nil {
			return fmt.Errorf("%w: %w", ErrInvalid, err)
		}
	}
	return nil
}

// AtOrBelow reports whether host is domain or a subdomain of it.
func AtOrBelow(host, domain string) bool {
	return host == domain || strings.HasSuffix(host, "."+domain)
}

// checkDomains: operator_domain is the host the document came from; the enrollment host is
// on the operator domain or below (section 3). The name domain is not the operator domain
// (section 3), and, as far as can be seen without the Public Suffix List, not in the same
// registered domain as the operator domain, the portal, the privacy policy, the enrollment
// endpoint or the relay host (section 7.1): neither is at or below the other.
func checkDomains(host string, d Document) error {
	if d.OperatorDomain != host {
		return fmt.Errorf("operator_domain %q is not the host %q", d.OperatorDomain, host)
	}
	enrollment, err := hostOf(d.Enrollment)
	if err != nil {
		return err
	}
	if !AtOrBelow(enrollment, d.OperatorDomain) {
		return fmt.Errorf("enrollment host %q is not on the operator domain", enrollment)
	}
	portal, err := hostOf(d.Portal)
	if err != nil {
		return err
	}
	privacy, err := hostOf(d.PrivacyPolicy)
	if err != nil {
		return err
	}
	for name, h := range map[string]string{"operator_domain": d.OperatorDomain, "enrollment": enrollment, "portal": portal, "privacy_policy": privacy, "relay": d.Relay.Host} {
		if AtOrBelow(h, d.NameDomain) || AtOrBelow(d.NameDomain, h) {
			return fmt.Errorf("%s %q and name_domain %q overlap", name, h, d.NameDomain)
		}
	}
	return nil
}

func hostOf(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return "", fmt.Errorf("URL %q without a host", raw)
	}
	return u.Hostname(), nil
}

// checkPins: every pin is the base64url of a SHA-256 digest, no pin is in both lists, and
// there are at most eight (sections 3 and 6.8).
func checkPins(_ string, d Document) error {
	if n := len(d.RelayPins) + len(d.RelayBackupPins); n > maxPins {
		return fmt.Errorf("%d pins, more than %d", n, maxPins)
	}
	active := make(map[string]bool, len(d.RelayPins))
	for _, pin := range d.RelayPins {
		active[pin] = true
	}
	for _, pin := range append(append([]string{}, d.RelayPins...), d.RelayBackupPins...) {
		decoded, err := base64.RawURLEncoding.Strict().DecodeString(pin)
		if err != nil || len(decoded) != pinBytes || base64.RawURLEncoding.EncodeToString(decoded) != pin {
			return fmt.Errorf("pin %q is not the base64url of a SHA-256 digest", pin)
		}
	}
	for _, pin := range d.RelayBackupPins {
		if active[pin] {
			return fmt.Errorf("pin %q is active and backup", pin)
		}
	}
	return nil
}

// checkAddresses: addresses are IPv4 in dotted decimal or IPv6 in the form of RFC 5952,
// which the schema's pattern only approximates; from of planned addresses is a valid time.
func checkAddresses(_ string, d Document) error {
	lists := [][]string{d.RelayAddresses}
	if p := d.RelayAddressesPlanned; p != nil {
		if _, err := rfc3339.Parse(p.From); err != nil {
			return fmt.Errorf("relay_addresses_planned.from: %w", err)
		}
		lists = append(lists, p.Addresses)
	}
	for _, list := range lists {
		for _, s := range list {
			addr, err := netip.ParseAddr(s)
			// An IPv4-mapped address has no form that is both RFC 5952 (mixed notation) and
			// allowed by the schema (none).
			if err != nil || addr.Zone() != "" || addr.Is4In6() || addr.String() != s {
				return fmt.Errorf("relay address %q is not in canonical form", s)
			}
		}
	}
	return nil
}

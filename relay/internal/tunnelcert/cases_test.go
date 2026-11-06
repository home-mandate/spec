// SPDX-License-Identifier: Apache-2.0

package tunnelcert_test

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/home-mandate/spec/jws"
	"github.com/home-mandate/spec/relay/internal/tunnelcert"
)

type csrCase struct {
	ID              string            `json:"id"`
	CSR             string            `json:"csr"`
	InstallationKey json.RawMessage   `json:"installation_key"`
	EarlierKeys     []json.RawMessage `json:"earlier_keys"`
	Expected        string            `json:"expected"`
	Why             string            `json:"why"`
}

type certificateCase struct {
	ID               string          `json:"id"`
	Chain            []string        `json:"chain"`
	NotAfter         string          `json:"not_after"`
	TunnelKey        json.RawMessage `json:"tunnel_key"`
	TrustDomain      string          `json:"trust_domain"`
	HomeID           string          `json:"home_id"`
	RequestedAt      string          `json:"requested_at"`
	EarlierNotBefore *string         `json:"earlier_not_before"`
	Expected         string          `json:"expected"`
	Why              string          `json:"why"`
}

func loadCases[T any](t *testing.T, path string) []T {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Cases []T `json:"cases"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return file.Cases
}

func parseKey(t *testing.T, id string, data json.RawMessage) crypto.PublicKey {
	t.Helper()
	key, err := jws.ParseJWK(data)
	if err != nil {
		t.Fatalf("%s: key: %v", id, err)
	}
	return key
}

func TestCSRCasesMatchTheReference(t *testing.T) {
	cases := loadCases[csrCase](t, "../../conformance/csr-v0.json")
	seen := map[string]bool{}
	for _, c := range cases {
		der, err := base64.RawURLEncoding.Strict().DecodeString(c.CSR)
		if err != nil {
			t.Fatalf("%s: csr is not base64url: %v", c.ID, err)
		}
		earlier := make([]crypto.PublicKey, 0, len(c.EarlierKeys))
		for _, k := range c.EarlierKeys {
			earlier = append(earlier, parseKey(t, c.ID, k))
		}
		_, err = tunnelcert.CheckCSR(der, parseKey(t, c.ID, c.InstallationKey), earlier)
		got := "accepted"
		if err != nil {
			if !errors.Is(err, tunnelcert.ErrBadCSR) {
				t.Fatalf("%s: unexpected error %v", c.ID, err)
			}
			got = "bad-csr"
		}
		if got != c.Expected {
			t.Errorf("%s (%s): got %s, want %s (%v)", c.ID, c.Why, got, c.Expected, err)
		}
		seen[c.Expected] = true
	}
	if !seen["accepted"] || !seen["bad-csr"] {
		t.Error("the cases do not cover both results")
	}
}

func TestCertificateCasesMatchTheReference(t *testing.T) {
	cases := loadCases[certificateCase](t, "../../conformance/certificate-v0.json")
	seen := map[string]bool{}
	for _, c := range cases {
		err := tunnelcert.CheckIssued(decodeChain(t, c), expectedOf(t, c))
		got := "valid"
		if err != nil {
			if !errors.Is(err, tunnelcert.ErrInvalid) {
				t.Fatalf("%s: unexpected error %v", c.ID, err)
			}
			got = "invalid"
		}
		if got != c.Expected {
			t.Errorf("%s (%s): got %s, want %s (%v)", c.ID, c.Why, got, c.Expected, err)
		}
		seen[c.Expected] = true
	}
	if !seen["valid"] || !seen["invalid"] {
		t.Error("the cases do not cover both results")
	}
}

func decodeChain(t *testing.T, c certificateCase) [][]byte {
	t.Helper()
	chain := make([][]byte, 0, len(c.Chain))
	for _, s := range c.Chain {
		der, err := base64.RawURLEncoding.Strict().DecodeString(s)
		if err != nil {
			t.Fatalf("%s: chain: %v", c.ID, err)
		}
		chain = append(chain, der)
	}
	return chain
}

func expectedOf(t *testing.T, c certificateCase) tunnelcert.Expected {
	t.Helper()
	at := func(s string) time.Time {
		v, err := time.Parse(time.RFC3339, s)
		if err != nil {
			t.Fatalf("%s: time %q: %v", c.ID, s, err)
		}
		return v
	}
	want := tunnelcert.Expected{
		Key: parseKey(t, c.ID, c.TunnelKey), TrustDomain: c.TrustDomain, HomeID: c.HomeID,
		NotAfter: at(c.NotAfter), RequestedAt: at(c.RequestedAt),
	}
	if c.EarlierNotBefore != nil {
		want.EarlierNotBefore = at(*c.EarlierNotBefore)
	}
	return want
}

// SPDX-License-Identifier: Apache-2.0

package jws

import (
	"crypto/ed25519"
	"errors"
	"testing"
)

// FuzzVerify: arbitrary input never panics and never verifies unless it is the JWS
// that was signed.
func FuzzVerify(f *testing.F) {
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	keys := Keys{"k": key.Public()}
	payload := []byte(`{"a":1}`)
	compact, err := Sign(payload, "k", key)
	if err != nil {
		f.Fatal(err)
	}
	detached, err := SignDetached(payload, "k", key)
	if err != nil {
		f.Fatal(err)
	}
	for _, seed := range []string{compact, detached, "", "..", "a.b.c", "eyJhbGciOiJub25lIiwia2lkIjoiayJ9..", compact + "A"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		if got, _, err := Verify(input, keys); err == nil && (input != compact || string(got) != string(payload)) {
			t.Fatalf("Verify accepted %q", input)
		}
		if _, err := VerifyDetached(input, payload, keys); err == nil && input != detached {
			t.Fatalf("VerifyDetached accepted %q", input)
		}
		if _, err := ParseJWKS([]byte(input)); err == nil && len(input) < 20 {
			t.Fatalf("ParseJWKS accepted %q", input)
		}
	})
}

// FuzzVerifyRequest: arbitrary input never panics, errors are one of the three kinds,
// and nothing verifies but the requests that were signed. ParseRequest accepts what
// VerifyRequest accepts.
func FuzzVerifyRequest(f *testing.F) {
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	const (
		nonce   = "oFvnlFP1wIhRlYS2jTaXbA"
		install = "https://relay-operator.example/enroll/installation/k7q2xwmpd4hj3n6rt5vbyc2ezu"
	)
	pair, err := SignRequest([]byte(`{"code":"ABCD"}`), RequestHeader{Nonce: nonce, URL: "https://relay-operator.example/enroll/pair", JWK: key.Public()}, key)
	if err != nil {
		f.Fatal(err)
	}
	read, err := SignRequest(nil, RequestHeader{Nonce: nonce, URL: install, Kid: install}, key)
	if err != nil {
		f.Fatal(err)
	}
	change, err := SignKeyChange([]byte(`{"installation":"`+install+`"}`), KeyChangeHeader{URL: "https://relay-operator.example/enroll/key-change"}, key)
	if err != nil {
		f.Fatal(err)
	}
	for _, seed := range []string{pair, read, change, "", "..", "a.b.c", pair + "A", read[:len(read)-2]} {
		f.Add(seed)
	}
	kinds := []error{ErrMalformed, ErrSignature, ErrKey}
	oneOf := func(t *testing.T, err error) {
		for _, kind := range kinds {
			if errors.Is(err, kind) {
				return
			}
		}
		t.Fatalf("error %v is of no kind", err)
	}
	f.Fuzz(func(t *testing.T, input string) {
		h, _, err := VerifyRequest(input, key.Public())
		if err == nil {
			if input != pair && input != read {
				t.Fatalf("VerifyRequest accepted %q", input)
			}
			if (h.JWK == nil) == (h.Kid == "") {
				t.Fatalf("header %+v has not exactly one of jwk and kid", h)
			}
			if _, _, err := ParseRequest(input); err != nil {
				t.Fatalf("ParseRequest refused what VerifyRequest accepted: %v", err)
			}
		} else {
			oneOf(t, err)
		}
		if _, _, err := VerifyKeyChange(input); err == nil && input != change {
			t.Fatalf("VerifyKeyChange accepted %q", input)
		} else if err != nil {
			oneOf(t, err)
		}
		if _, err := ParseJWK([]byte(input)); err == nil && len(input) < 40 {
			t.Fatalf("ParseJWK accepted %q", input)
		}
	})
}

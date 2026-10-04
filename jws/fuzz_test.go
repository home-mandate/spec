// SPDX-License-Identifier: Apache-2.0

package jws

import (
	"crypto/ed25519"
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

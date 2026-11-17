// SPDX-License-Identifier: Apache-2.0

package jws

import (
	"crypto/ed25519"
	"testing"
)

// maxErrorBytes bounds an error message, whatever the input: values from the input are
// quoted cut (issue #143). A cut value of 64 bytes quotes to at most 4*64+5 bytes when every
// byte is escaped as \xNN; the longest message, of ParseJWKS, quotes three such values (a
// key ID of the kid pattern, kty and crv), about 600 bytes with its text.
const maxErrorBytes = 1024

func checkErrorLength(t *testing.T, err error) {
	t.Helper()
	if err != nil && len(err.Error()) > maxErrorBytes {
		t.Fatalf("error of %d bytes: %.200s", len(err.Error()), err)
	}
}

// FuzzVerify: arbitrary input never panics, never verifies unless it is the JWS that was
// signed, and gives errors of bounded length.
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
		got, _, err := Verify(input, keys)
		if err == nil && (input != compact || string(got) != string(payload)) {
			t.Fatalf("Verify accepted %q", input)
		}
		checkErrorLength(t, err)
		_, err = VerifyDetached(input, payload, keys)
		if err == nil && input != detached {
			t.Fatalf("VerifyDetached accepted %q", input)
		}
		checkErrorLength(t, err)
		_, err = ParseJWKS([]byte(input))
		if err == nil && len(input) < 20 {
			t.Fatalf("ParseJWKS accepted %q", input)
		}
		checkErrorLength(t, err)
	})
}

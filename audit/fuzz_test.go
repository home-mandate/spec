// SPDX-License-Identifier: Apache-2.0

package audit_test

import (
	"testing"

	"github.com/mandate-spec/mandate-spec/audit"
)

// FuzzVerify: never panics, and a single arbitrary entry is only valid if it is a
// schema-valid first entry.
func FuzzVerify(f *testing.F) {
	f.Add([]byte(`{"type":"https://mandate-spec.org/audit/v0","seq":1,"prev":null}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`[1,2]`))
	f.Fuzz(func(t *testing.T, entry []byte) {
		got, err := audit.Verify([][]byte{entry})
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if got.Valid && got.Index != -1 {
			t.Fatalf("valid result with index %d", got.Index)
		}
		_, _ = audit.Digest(entry)
	})
}

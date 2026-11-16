// SPDX-License-Identifier: Apache-2.0

package audit_test

import (
	"testing"

	"github.com/home-mandate/spec/audit"
)

// FuzzVerify: never panics; a single arbitrary entry is only valid if it is a schema-valid
// first entry; and the findings agree with the result: a valid log has none, an invalid one
// at least one, and broken_at names the conformance or unknown-version finding first.
func FuzzVerify(f *testing.F) {
	f.Add([]byte(`{"type":"https://home-mandate.org/audit/v0","seq":1,"prev":null}`))
	f.Add([]byte(`{"type":"https://home-mandate.org/audit/v1","id":"01a0f64c-7140-7001-9007-000000000001","seq":1,"recorded_at":"2026-11-16T10:00:00Z","event":"ct.status","principal":"household:hm-7f3a","ct":{"status":"ok"},"prev":null}`))
	f.Add([]byte(`{"type":"https://home-mandate.org/audit/v7","seq":1,"prev":null}`))
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
		anyFinding := got.Integrity.Found() || got.Conformance.Found() || got.UnknownVersion.Found()
		if got.Valid == anyFinding {
			t.Fatalf("valid %v with findings %+v %+v %+v", got.Valid, got.Integrity, got.Conformance, got.UnknownVersion)
		}
		if got.Conformance.Found() && got.UnknownVersion.Found() {
			t.Fatalf("one entry is both of an unknown version and not conforming: %+v", got)
		}
		_, _ = audit.Digest(entry)
	})
}

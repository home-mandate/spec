// SPDX-License-Identifier: Apache-2.0

package audit_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/home-mandate/spec/audit"
)

// mandateEntry is a log of one entry of the given version, event and mandate member.
func mandateEntry(typ, event, mandate string) [][]byte {
	return [][]byte{[]byte(fmt.Sprintf(`{"type":%q,"id":"01a0f64c-7140-7001-9007-0000000c0001","seq":1,`+
		`"recorded_at":"2026-11-17T10:00:00Z","event":%q,"principal":"household:hm-7f3a",`+
		`"actor":{"kind":"system","id":"issuer-sync"},"mandate":%s,"prev":null}`, typ, event, mandate))}
}

const (
	receivedDigest = "sha256:0d4f7e3c1b2a5968778695a4b3c2d1e0f0e1d2c3b4a5968778695a4b3c2d1e0f"
	mandateDigest  = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
)

// received is the SHA-256 of the bytes of a rejected mandate as they arrived: required in
// every mandate.rejected of version 1, absent from every other event, a digest in the form
// of Section 3.2, and not a member of version 0 (SPEC-v0 section 9.1).
func TestMandateReceived(t *testing.T) {
	for name, tc := range map[string]struct {
		typ, event, mandate string
		valid               bool
	}{
		"only cause and received": {typeV1, "mandate.rejected", `{"cause":"invalid","received":"` + receivedDigest + `"}`, true},
		"with id, digest and received": {typeV1, "mandate.rejected",
			`{"id":"m-voice-assistant","digest":"` + mandateDigest + `","cause":"signature","received":"` + receivedDigest + `"}`, true},
		"received equal to digest": {typeV1, "mandate.rejected",
			`{"id":"m-voice-assistant","digest":"` + mandateDigest + `","cause":"succession","received":"` + mandateDigest + `"}`, true},
		"every cause": {typeV1, "mandate.rejected", `{"cause":"unsupported","received":"` + receivedDigest + `"}`, true},

		"without received":           {typeV1, "mandate.rejected", `{"cause":"invalid"}`, false},
		"received null":              {typeV1, "mandate.rejected", `{"cause":"invalid","received":null}`, false},
		"received a number":          {typeV1, "mandate.rejected", `{"cause":"invalid","received":1}`, false},
		"received empty":             {typeV1, "mandate.rejected", `{"cause":"invalid","received":""}`, false},
		"received without prefix":    {typeV1, "mandate.rejected", `{"cause":"invalid","received":"` + strings.TrimPrefix(receivedDigest, "sha256:") + `"}`, false},
		"received in upper case":     {typeV1, "mandate.rejected", `{"cause":"invalid","received":"sha256:` + strings.ToUpper(strings.TrimPrefix(receivedDigest, "sha256:")) + `"}`, false},
		"received of 65 digits":      {typeV1, "mandate.rejected", `{"cause":"invalid","received":"` + receivedDigest + `0"}`, false},
		"received with white space":  {typeV1, "mandate.rejected", `{"cause":"invalid","received":" ` + receivedDigest + `"}`, false},
		"received as an object":      {typeV1, "mandate.rejected", `{"cause":"invalid","received":{"sha256":"0d4f"}}`, false},
		"Received is another member": {typeV1, "mandate.rejected", `{"cause":"invalid","received":"` + receivedDigest + `","Received":"` + receivedDigest + `"}`, false},

		"version 0 without received": {typeV0, "mandate.rejected", `{"cause":"invalid"}`, true},
		"version 0 with received":    {typeV0, "mandate.rejected", `{"cause":"invalid","received":"` + receivedDigest + `"}`, false},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := audit.Verify(mandateEntry(tc.typ, tc.event, tc.mandate))
			if err != nil {
				t.Fatal(err)
			}
			if got.Valid != tc.valid {
				t.Errorf("valid = %t, want %t (%+v)", got.Valid, tc.valid, got)
			}
			if !tc.valid && (!got.Conformance.Found() || got.Integrity.Found()) {
				t.Errorf("findings %+v, want a conformance finding only", got)
			}
		})
	}
	// Every other event that has a mandate member keeps received out.
	for _, event := range []string{"mandate.created", "mandate.updated", "mandate.revoked", "mandate.removed", "mandate.proposed", "mandate.discarded"} {
		mandate := `{"id":"m-voice-assistant","digest":"` + mandateDigest + `","received":"` + receivedDigest + `"}`
		switch event {
		case "mandate.updated":
			mandate = `{"id":"m-voice-assistant","digest":"` + mandateDigest + `","previous_digest":"` + receivedDigest + `","received":"` + receivedDigest + `"}`
		case "mandate.discarded":
			mandate = `{"id":"m-voice-assistant","digest":"` + mandateDigest + `","cause":"superseded","received":"` + receivedDigest + `"}`
		}
		got, err := audit.Verify(mandateEntry(typeV1, event, mandate))
		if err != nil {
			t.Fatal(err)
		}
		if got.Valid {
			t.Errorf("%s with received accepted", event)
		}
		// The same entry without received is valid: received alone breaks it.
		without := strings.Replace(mandate, `,"received":"`+receivedDigest+`"`, "", 1)
		if got, err := audit.Verify(mandateEntry(typeV1, event, without)); err != nil || !got.Valid {
			t.Errorf("%s without received = %+v, %v; want valid", event, got, err)
		}
	}
}

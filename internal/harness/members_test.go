// SPDX-License-Identifier: Apache-2.0

package harness

import (
	"reflect"
	"testing"
)

// A response of the process binding is read as strictly as a request (SPEC-v0 section 10.2):
// a name in another case, an unknown member or a member twice fails the case.
func TestResponsesAreReadExactly(t *testing.T) {
	for _, tc := range []struct {
		op, line string
		ok       bool
	}{
		{OpValidate, `{"valid":true}`, true},
		{OpValidate, `{"valid":true,"digest":"sha256:x"}`, true},
		{OpValidate, `{"error":"unsupported"}`, true},
		{OpValidate, `{"Valid":true}`, false},
		{OpValidate, `{"valid":true,"valid":false}`, false},
		{OpValidate, `{"valid":true,"extra":1}`, false},
		{OpValidate, `{"valid":true,"decision":"allow"}`, false},
		{OpValidate, `{"valid":null}`, false},
		{OpValidate, `{"error":"x","valid":false}`, false},
		{OpValidate, `{"valid":true,"id":"c01"}`, false},
		{OpEntryDigest, `{"digest":"sha256:x"}`, true},
		{OpEntryDigest, `{"valid":false}`, false},
		{OpVerifyAudit, `{"valid":true,"entries":2,"checkpoint_gap_at":3}`, true},
	} {
		if err := exactResponse([]byte(tc.line), tc.op); (err == nil) != tc.ok {
			t.Errorf("%s %s: err = %v, want ok %v", tc.op, tc.line, err, tc.ok)
		}
	}
}

// A response of another protocol may carry members the tool does not read, but those it reads
// are spelled exactly and occur once.
func TestAuthZENResponsesKeepTheirNames(t *testing.T) {
	type decision struct {
		Decision bool `json:"decision"`
	}
	typ := reflect.TypeOf(&decision{})
	for body, ok := range map[string]bool{
		`{"decision":true}`:                          true,
		`{"decision":true,"context":{"reason":"x"}}`: true,
		`{"Decision":true}`:                          false,
		`{"decision":true,"decision":false}`:         false,
	} {
		if err := exactNames([]byte(body), typ); (err == nil) != ok {
			t.Errorf("%s: err = %v, want ok %v", body, err, ok)
		}
	}
}

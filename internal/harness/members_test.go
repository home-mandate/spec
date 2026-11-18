// SPDX-License-Identifier: Apache-2.0

package harness

import (
	"reflect"
	"testing"
)

// A response of the process binding is read as strictly as a request (SPEC-v0 section 10.2):
// a name in another case, an unknown member or a member twice fails the case.
func TestResponsesAreReadExactly(t *testing.T) {
	for line, ok := range map[string]bool{
		`{"valid":true}`:                     true,
		`{"valid":true,"digest":"sha256:x"}`: true,
		`{"Valid":true}`:                     false,
		`{"valid":true,"valid":false}`:       false,
		`{"valid":true,"extra":1}`:           false,
	} {
		if err := exactResponse([]byte(line)); (err == nil) != ok {
			t.Errorf("%s: err = %v, want ok %v", line, err, ok)
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

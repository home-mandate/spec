// SPDX-License-Identifier: Apache-2.0

package harness

import (
	"testing"

	"github.com/home-mandate/spec"
	"github.com/home-mandate/spec/evaluator"
)

// The class pdp plays every case whose stored mandates a PDP can store: the evaluation cases
// whose mandate is not revoked, and the selection cases without "pdp": false. The marking is
// data, so that the runner does not depend on the Go evaluator; this test keeps it right.
func TestThePDPMarkingMatchesTheMandates(t *testing.T) {
	cases, err := load[evaluationCase](spec.FS(), fileCases, "cases")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		text, err := c.text(spec.FS())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := evaluator.Parse([]byte(text)); err != nil {
			t.Errorf("%s: the mandate of an evaluation case is invalid: %v", c.ID, err)
		}
	}
	selection, err := load[evaluationCase](spec.FS(), fileSelection, "cases")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range selection {
		storable := true
		for _, m := range c.Mandates {
			if _, err := evaluator.Parse(m.MandateInline); err != nil {
				storable = false
			}
		}
		if marked := c.PDP == nil || *c.PDP; marked != storable {
			t.Errorf("%s: played over the HTTP binding %v, but its mandates are storable %v", c.ID, marked, storable)
		}
	}
}

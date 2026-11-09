// SPDX-License-Identifier: Apache-2.0

package refop_test

import (
	"encoding/json"
	"testing"

	"github.com/home-mandate/spec/relay/internal/enroll"
	"github.com/home-mandate/spec/relay/internal/refop"
	"github.com/home-mandate/spec/relay/internal/refrelay"
)

// TestTheOperatorIsTheRegistryOfItsRelay: the pin of the relay is in the metadata, the names and
// the state of the installations are what the relay asks, and Remap reaches the relay.
func TestTheOperatorIsTheRegistryOfItsRelay(t *testing.T) {
	host := "tunnel." + refop.DefaultOperator
	rl := refrelay.New(refrelay.Config{Host: host})
	w := newWorld(t, refop.Config{Relay: rl})
	var doc struct {
		Pins []string `json:"relay_pins"`
	}
	if err := json.Unmarshal(w.run.Operator.Metadata(), &doc); err != nil || len(doc.Pins) != 1 || doc.Pins[0] != rl.Pins()[0] {
		t.Fatalf("relay_pins %v, %v", doc.Pins, err)
	}
	if w.run.RelayAddr == "" || w.run.Remap(host+":8443") != w.run.RelayAddr || w.run.Remap("127.0.0.1:443") != w.run.RelayAddr || w.run.Remap("[::1]:443") != w.run.RelayAddr {
		t.Errorf("Remap does not reach the relay at %q", w.run.RelayAddr)
	}
	if w.run.Remap(w.run.Operator.Domain()+":443") != w.run.Addr {
		t.Error("Remap of the operator")
	}
	op := w.run.Operator
	if len(op.Routes()) != 0 || op.Active("nobody") || op.Denied("00") || op.TrustDomain() != refop.DefaultOperator {
		t.Error("an empty operator serves something")
	}
	id, paired := w.pair(refop.DefaultCodes[0], enroll.AlgEdDSA)
	home := paired.Installation.HomeID
	std := paired.Installation.PublicName
	if r := op.Routes()[std]; r.Home != home || !r.Verified || !op.Active(home) || len(op.Roots().Subjects()) != 1 {
		t.Errorf("route %+v, active %v", r, op.Active(home))
	}
	// An own-domain name is routed, pending until the TXT record is there.
	own := "home." + refop.DefaultTesterZone
	if _, err := w.c.SetOwnDomain(w.ctx, id, own); err != nil {
		t.Fatal(err)
	}
	if r := op.Routes()[own]; r.Home != home || r.Verified {
		t.Errorf("pending own-domain name: %+v", r)
	}
	op.Block(id.URL, true)
	if op.Active(home) {
		t.Error("a blocked installation is active")
	}
	op.Block(id.URL, false)
	if _, err := w.c.Unpair(w.ctx, id); err != nil {
		t.Fatal(err)
	}
	if len(op.Routes()) != 0 || op.Active(home) || len(op.Denylist()) != 1 || !op.Denied(op.Denylist()[0]) {
		t.Errorf("after unpairing: %v, active %v, denylist %v", op.Routes(), op.Active(home), op.Denylist())
	}
}

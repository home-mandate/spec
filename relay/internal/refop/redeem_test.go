// SPDX-License-Identifier: Apache-2.0

package refop_test

import (
	"testing"

	"github.com/home-mandate/spec/relay/internal/enroll"
	"github.com/home-mandate/spec/relay/internal/refop"
)

// afterKeyConflict pairs A, tries the second code with A's key, and then with a new key.
func afterKeyConflict(t *testing.T, f refop.Fault) (conflict, retry string) {
	t.Helper()
	w := newWorld(t, refop.Config{Faults: f})
	a, _ := w.pair(refop.DefaultCodes[0], enroll.AlgEdDSA)
	_, _, err := w.c.Pair(w.ctx, a.Signer, refop.DefaultCodes[1], w.csr(w.signer(enroll.AlgES256)))
	conflict = apiName(err)
	_, _, err = w.c.Pair(w.ctx, w.signer(enroll.AlgES256), refop.DefaultCodes[1], w.csr(w.signer(enroll.AlgES256)))
	return conflict, apiName(err)
}

func TestAKeyConflictLeavesTheCodeUsable(t *testing.T) {
	for name, tt := range map[string]struct {
		fault         refop.Fault
		conflict, run string
	}{
		"clean":                  {0, "key-conflict", "ok"},
		"E21 key-conflict burns": {refop.KeyConflictBurnsCode, "key-conflict", "pairing-refused"},
	} {
		t.Run(name, func(t *testing.T) {
			conflict, retry := afterKeyConflict(t, tt.fault)
			if conflict != tt.conflict || retry != tt.run {
				t.Errorf("got %s then %s, want %s then %s", conflict, retry, tt.conflict, tt.run)
			}
		})
	}
}

// tokenAfterRemoval registers the name, removes it and registers it again.
func tokenAfterRemoval(t *testing.T, f refop.Fault) (first, second string) {
	t.Helper()
	w := newWorld(t, refop.Config{Faults: f})
	a, _ := w.pair(refop.DefaultCodes[0], enroll.AlgEdDSA)
	one, err := w.c.SetOwnDomain(w.ctx, a, ownNm)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.c.SetOwnDomain(w.ctx, a, ""); err != nil {
		t.Fatal(err)
	}
	two, err := w.c.SetOwnDomain(w.ctx, a, ownNm)
	if err != nil {
		t.Fatal(err)
	}
	return one.OwnDomain.Token, two.OwnDomain.Token
}

func TestATokenIsNotUsedAgainAfterItsRegistrationEnded(t *testing.T) {
	first, second := tokenAfterRemoval(t, 0)
	if first == second {
		t.Error("the token came back")
	}
	first, second = tokenAfterRemoval(t, refop.TokenReused)
	if first != second {
		t.Error("E22 token reused: the token changed")
	}
}

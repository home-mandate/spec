// SPDX-License-Identifier: Apache-2.0

package errquote_test

import (
	"strconv"
	"strings"
	"testing"

	"github.com/home-mandate/spec/internal/errquote"
)

func TestQuoteKeepsShortValues(t *testing.T) {
	for _, s := range []string{"", "short", strings.Repeat("a", errquote.MaxBytes), "tab\there"} {
		if got, want := errquote.Quote(s), strconv.Quote(s); got != want {
			t.Errorf("Quote(%q) = %s, want %s", s, got, want)
		}
	}
}

func TestQuoteCutsLongValues(t *testing.T) {
	long := strings.Repeat("A", 5000)
	if got, want := errquote.Quote(long), `"`+long[:errquote.MaxBytes]+`"...`; got != want {
		t.Errorf("Quote(long) = %s, want %s", got, want)
	}
	// A cut through a multi-byte character stays escaped, never invalid.
	if cut := errquote.Quote(strings.Repeat("a", errquote.MaxBytes-1) + "ü" + long); !strings.HasSuffix(cut, `\xc3"...`) {
		t.Errorf("cut through ü = %s", cut)
	}
}

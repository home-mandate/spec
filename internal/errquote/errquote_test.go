// SPDX-License-Identifier: Apache-2.0

package errquote_test

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

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

func TestBoundCutsLongErrorsAndKeepsTheChain(t *testing.T) {
	base := errors.New("base")
	long := fmt.Errorf("%w: %s", base, strings.Repeat("ä", 400))
	got := errquote.Bound(long)
	if len(got.Error()) > errquote.MaxErrorBytes+3 || !strings.HasSuffix(got.Error(), "...") || !utf8.ValidString(got.Error()) {
		t.Errorf("Bound = %d bytes %q", len(got.Error()), got.Error()[len(got.Error())-8:])
	}
	if !errors.Is(got, base) {
		t.Error("the chain is lost")
	}
	short := fmt.Errorf("%w: short", base)
	if errquote.Bound(short) != short || errquote.Bound(nil) != nil {
		t.Error("a short error or nil was changed")
	}
	exact := errors.New(strings.Repeat("a", errquote.MaxErrorBytes))
	if errquote.Bound(exact) != exact {
		t.Error("an error of exactly MaxErrorBytes was cut")
	}
	over := errquote.Bound(errors.New(strings.Repeat("a", errquote.MaxErrorBytes+1)))
	if over.Error() != strings.Repeat("a", errquote.MaxErrorBytes)+"..." {
		t.Errorf("one byte over: %d bytes", len(over.Error()))
	}
}

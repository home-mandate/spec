// SPDX-License-Identifier: Apache-2.0

// Package displaytext checks text that is displayed to humans, for example in an
// approval request (SPEC-v0 section 3.1 item 8). It uses the code point list of the
// specification, not the Unicode tables of the Go runtime, so that the result does not
// change with the Go version.
package displaytext

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sync"
	"unicode/utf8"

	"github.com/home-mandate/spec/data"
)

// ErrMisleading means a text could mislead the human who reads it.
var ErrMisleading = errors.New("displaytext: text not permitted for display")

type table struct {
	UnicodeVersion string    `json:"unicode_version"`
	Forbidden      [][2]rune `json:"forbidden"`
	Joiners        []rune    `json:"joiners"`
	NotFirst       [][2]rune `json:"not_first"`
}

// The list is embedded and covered by the tests; a list that cannot be read forbids
// every text.
var load = sync.OnceValue(func() table {
	var t table
	if err := json.Unmarshal(data.ForbiddenCodepoints(), &t); err != nil {
		return table{Forbidden: [][2]rune{{0, utf8.MaxRune}}}
	}
	return t
})

// UnicodeVersion is the version of the Unicode Character Database the list was derived from.
func UnicodeVersion() string { return load().UnicodeVersion }

// Check reports whether s may be displayed: no forbidden code point, no space at either
// end, no combining character at the start, and a joiner (ZWNJ, ZWJ) only between two
// other code points. The error wraps ErrMisleading.
func Check(s string) error {
	if s == "" {
		return fmt.Errorf("%w: empty", ErrMisleading)
	}
	if !utf8.ValidString(s) {
		return fmt.Errorf("%w: not UTF-8", ErrMisleading)
	}
	t := load()
	first, _ := utf8.DecodeRuneInString(s)
	last, _ := utf8.DecodeLastRuneInString(s)
	for _, edge := range []rune{first, last} {
		if edge == ' ' {
			return fmt.Errorf("%w: space at the start or end", ErrMisleading)
		}
		if slices.Contains(t.Joiners, edge) {
			return fmt.Errorf("%w: joiner U+%04X at the start or end", ErrMisleading, edge)
		}
	}
	if in(t.NotFirst, first) {
		return fmt.Errorf("%w: starts with the combining character U+%04X", ErrMisleading, first)
	}
	afterJoiner := false
	for _, r := range s {
		if in(t.Forbidden, r) {
			return fmt.Errorf("%w: contains U+%04X", ErrMisleading, r)
		}
		joiner := slices.Contains(t.Joiners, r)
		if joiner && afterJoiner {
			return fmt.Errorf("%w: joiner U+%04X follows a joiner", ErrMisleading, r)
		}
		afterJoiner = joiner
	}
	return nil
}

// in reports whether r lies in one of the sorted inclusive ranges.
func in(ranges [][2]rune, r rune) bool {
	_, found := slices.BinarySearchFunc(ranges, r, func(span [2]rune, r rune) int {
		switch {
		case r < span[0]:
			return 1
		case r > span[1]:
			return -1
		}
		return 0
	})
	return found
}

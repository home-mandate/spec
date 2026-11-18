// SPDX-License-Identifier: Apache-2.0

// Package errquote quotes values from untrusted input for error messages, cut to a bound,
// so that a sender cannot fill logs or responses through the errors.
package errquote

import (
	"strconv"
	"unicode/utf8"
)

// MaxBytes bounds how much of a value an error message quotes.
const MaxBytes = 64

// Quote quotes s like strconv.Quote, at most its first MaxBytes bytes; a longer value is
// cut and marked with "...". A cut through a multi-byte character stays escaped.
func Quote(s string) string {
	if len(s) <= MaxBytes {
		return strconv.Quote(s)
	}
	return strconv.Quote(s[:MaxBytes]) + "..."
}

// MaxErrorBytes bounds the whole text of an error that Bound returns.
const MaxErrorBytes = 512

// Bound returns err with its text cut to MaxErrorBytes bytes, at a character boundary and
// marked with "...", for an error that may echo untrusted values from places that do not
// quote them (a schema validator, for example). errors.Is and errors.As still see err. A nil
// err stays nil.
func Bound(err error) error {
	if err == nil || len(err.Error()) <= MaxErrorBytes {
		return err
	}
	return bounded{err}
}

type bounded struct{ err error }

func (b bounded) Error() string {
	text := b.err.Error()
	n := MaxErrorBytes
	for n > 0 && !utf8.RuneStart(text[n]) {
		n--
	}
	return text[:n] + "..."
}

func (b bounded) Unwrap() error { return b.err }

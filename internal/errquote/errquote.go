// SPDX-License-Identifier: Apache-2.0

// Package errquote quotes values from untrusted input for error messages, cut to a bound,
// so that a sender cannot fill logs or responses through the errors.
package errquote

import "strconv"

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

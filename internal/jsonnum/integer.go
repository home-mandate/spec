// SPDX-License-Identifier: Apache-2.0

package jsonnum

import (
	"errors"
	"strings"
)

// MaxInteger is 2^53 − 1, the largest magnitude of an integer in a document of the
// specification: the integers that are exact in every JSON implementation (RFC 7493).
const MaxInteger = 1<<53 - 1

// maxIntegerDigits is the number of decimal digits of MaxInteger.
const maxIntegerDigits = 16

// maxExponent bounds the magnitude of an exponent as it is read. It is far beyond any
// number of digits an input can have, so that saturating at it changes no result.
const maxExponent = 1 << 30

// Why a JSON number is no integer of a document; ExactInteger returns them.
var (
	ErrNoNumber   = errors.New("jsonnum: no JSON number")
	ErrNoInteger  = errors.New("jsonnum: not an integer")
	ErrOutOfRange = errors.New("jsonnum: a magnitude of 2^53 or more")
)

// ExactInteger reads a JSON number (RFC 8259) by its exact decimal value, without rounding
// through floating point: 20, 20.0 and 2e1 are 20, while 20.000000000000000001 and 1e-400 are
// no integers, although floating point reads them as 20 and 0. The error is ErrNoNumber for
// text that is no JSON number, ErrNoInteger for a fraction and ErrOutOfRange for a magnitude of
// 2^53 or more. The work is linear in the length of s, whatever its exponent.
func ExactInteger(s string) (int64, error) {
	negative := strings.HasPrefix(s, "-")
	s = strings.TrimPrefix(s, "-")
	mantissa, exponentText, hasExponent := strings.Cut(strings.ToLower(s), "e")
	whole, fraction, hasFraction := strings.Cut(mantissa, ".")
	if !decimalDigits(whole) || (len(whole) > 1 && whole[0] == '0') ||
		(hasFraction && !decimalDigits(fraction)) {
		return 0, ErrNoNumber
	}
	exponent, ok := 0, true
	digits := strings.TrimLeft(whole+fraction, "0")
	if hasExponent {
		exponent, ok = readExponent(exponentText)
		if !ok {
			return 0, ErrNoNumber
		}
	}
	if digits == "" {
		return 0, nil
	}
	// value = digits × 10^(exponent − len(fraction)); trailing zeros move to the exponent.
	trimmed := strings.TrimRight(digits, "0")
	exponent += len(digits) - len(trimmed) - len(fraction)
	if exponent < 0 {
		return 0, ErrNoInteger
	}
	if len(trimmed)+exponent > maxIntegerDigits {
		return 0, ErrOutOfRange
	}
	var value int64
	for i := 0; i < len(trimmed); i++ {
		value = value*10 + int64(trimmed[i]-'0')
	}
	for range exponent {
		value *= 10
	}
	if value > MaxInteger {
		return 0, ErrOutOfRange
	}
	if negative {
		value = -value
	}
	return value, nil
}

// readExponent reads [+-]digits, saturating at maxExponent.
func readExponent(s string) (int, bool) {
	sign := 1
	switch {
	case strings.HasPrefix(s, "+"):
		s = s[1:]
	case strings.HasPrefix(s, "-"):
		s, sign = s[1:], -1
	}
	if !decimalDigits(s) {
		return 0, false
	}
	n := 0
	for i := 0; i < len(s) && n < maxExponent; i++ {
		n = n*10 + int(s[i]-'0')
	}
	return sign * min(n, maxExponent), true
}

// decimalDigits reports whether s is one or more ASCII digits.
func decimalDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

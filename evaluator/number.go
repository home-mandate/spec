// SPDX-License-Identifier: Apache-2.0

package evaluator

import (
	"errors"

	"github.com/home-mandate/spec/internal/jsonnum"
)

// Why a JSON value is no parameter value; Value.UnmarshalJSON returns them.
var (
	errNoNumberOrString = errors.New("evaluator: a parameter value is an integer or a string")
	errNoInteger        = errors.New("evaluator: a parameter value is no integer: mandates and requests contain no fractions")
	errOutOfRange       = errors.New("evaluator: a parameter value has a magnitude of 2^53 or more")
)

// exactInteger reads a JSON number (RFC 8259) by its exact decimal value, without
// rounding through floating point (jsonnum.ExactInteger). The error is errNoNumberOrString
// for text that is no JSON number, errNoInteger for a fraction and errOutOfRange for a
// magnitude of 2^53 or more.
func exactInteger(s string) (int64, error) {
	value, err := jsonnum.ExactInteger(s)
	switch {
	case errors.Is(err, jsonnum.ErrNoNumber):
		return 0, errNoNumberOrString
	case errors.Is(err, jsonnum.ErrNoInteger):
		return 0, errNoInteger
	case errors.Is(err, jsonnum.ErrOutOfRange):
		return 0, errOutOfRange
	}
	return value, nil
}

// SPDX-License-Identifier: Apache-2.0

package evaluator

import (
	"bytes"
	"encoding/json"
	"strconv"
)

// maxStringLength is the length limit of a string parameter value; it follows the rules
// for area identifiers (SPEC-v0 sections 3.4 and 4.5).
const maxStringLength = 64

// Types of a parameter in the vocabulary (SPEC-v0 sections 4.5 and 5).
const (
	typeInteger = "integer"
	typeString  = "string"
)

type valueKind uint8

const (
	kindNone valueKind = iota
	kindInteger
	kindString
)

// Value is the value of a parameter (SPEC-v0 section 4.5): an integer in the unit of the
// vocabulary or a string. Values are comparable with ==; an integer never equals a
// string. The zero Value is neither and makes a request invalid.
type Value struct {
	kind    valueKind
	integer int64
	text    string
}

// IntegerValue returns an integer value. A magnitude of 2^53 or more yields a value that a
// request may not carry: Evaluate denies it with ReasonInvalidRequest.
func IntegerValue(n int64) Value { return Value{kind: kindInteger, integer: n} }

// StringValue returns a string value. Strings are compared exactly per byte, without
// normalization and case-sensitive. A string that is not 1 to 64 printable ASCII
// characters without space yields a value that a request may not carry: Evaluate denies
// it with ReasonInvalidRequest.
func StringValue(s string) Value { return Value{kind: kindString, text: s} }

// AsInteger returns the integer and true if v is an integer.
func (v Value) AsInteger() (int64, bool) { return v.integer, v.kind == kindInteger }

// AsString returns the string and true if v is a string.
func (v Value) AsString() (string, bool) { return v.text, v.kind == kindString }

// valid reports whether a request may carry v (SPEC-v0 section 4, step 0): an integer of
// magnitude at most 2^53 − 1 or a string of 1 to 64 printable ASCII characters without
// space.
func (v Value) valid() bool {
	switch v.kind {
	case kindInteger:
		return v.integer <= maxParameter && v.integer >= -maxParameter
	case kindString:
		return opaque(v.text, maxStringLength)
	}
	return false
}

// UnmarshalJSON reads a JSON string as a string and a JSON number by its exact value as
// an integer (20, 20.0 and 2e1 are the same). Every other JSON value, a number that is no
// integer, and a number whose magnitude is 2^53 or more are errors, each with its own
// message. Whether a string is a valid value is decided by the evaluation, not here.
func (v *Value) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if len(data) > 0 && data[0] == '"' {
		var s string
		if err := json.Unmarshal(data, &s); err != nil {
			return err
		}
		*v = StringValue(s)
		return nil
	}
	var n json.Number
	if err := json.Unmarshal(data, &n); err != nil || n == "" {
		return errNoNumberOrString
	}
	integer, err := exactInteger(n.String())
	if err != nil {
		return err
	}
	*v = IntegerValue(integer)
	return nil
}

// MarshalJSON writes an integer as a JSON number and a string as a JSON string.
func (v Value) MarshalJSON() ([]byte, error) {
	switch v.kind {
	case kindInteger:
		return strconv.AppendInt(nil, v.integer, 10), nil
	case kindString:
		return json.Marshal(v.text)
	}
	return nil, errNoNumberOrString
}

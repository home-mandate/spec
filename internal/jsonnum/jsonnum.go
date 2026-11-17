// SPDX-License-Identifier: Apache-2.0

// Package jsonnum prepares decoded JSON for the schema validator. It is not part of the
// public API.
package jsonnum

import (
	"encoding/json"
	"strings"
)

// ZeroNumbers returns the decoded value with every zero written as 0, whatever its
// exponent: numbers count by their value (SPEC-v0 section 3.2), but the schema validator
// gives up on an exponent beyond its range. The input stays unchanged.
func ZeroNumbers(v any) any {
	switch value := v.(type) {
	case json.Number:
		mantissa, _, _ := strings.Cut(strings.ToLower(value.String()), "e")
		if strings.Trim(mantissa, "-0.") == "" {
			return json.Number("0")
		}
	case []any:
		list := make([]any, len(value))
		for i, item := range value {
			list[i] = ZeroNumbers(item)
		}
		return list
	case map[string]any:
		object := make(map[string]any, len(value))
		for name, member := range value {
			object[name] = ZeroNumbers(member)
		}
		return object
	}
	return v
}

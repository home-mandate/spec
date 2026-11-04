// SPDX-License-Identifier: Apache-2.0

// Package data provides the normative data files of the Home-Mandate Specification v0 that are neither a
// schema nor a conformance case.
package data

import (
	"bytes"
	_ "embed"
)

//go:embed forbidden-codepoints-v0.json
var forbiddenCodepoints []byte

//go:embed corrections-v0.json
var corrections []byte

// Corrections returns a copy of the list of corrections (SPEC-v0 section 14).
func Corrections() []byte { return bytes.Clone(corrections) }

// ForbiddenCodepoints returns a copy of the list of code points for text displayed to
// humans (SPEC-v0 section 3.1 item 8).
func ForbiddenCodepoints() []byte { return bytes.Clone(forbiddenCodepoints) }

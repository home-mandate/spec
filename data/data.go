// SPDX-License-Identifier: Apache-2.0

// Package data provides the normative data files of mandate-spec v0 that are neither a
// schema nor a conformance case.
package data

import (
	"bytes"
	_ "embed"
)

//go:embed forbidden-codepoints-v0.json
var forbiddenCodepoints []byte

// ForbiddenCodepoints returns a copy of the list of code points for text displayed to
// humans (SPEC-v0 section 3.1 item 8).
func ForbiddenCodepoints() []byte { return bytes.Clone(forbiddenCodepoints) }

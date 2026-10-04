// SPDX-License-Identifier: Apache-2.0

// Package vocabulary provides the normative vocabulary of mandate-spec v0
// (SPEC-v0 section 5) as the specification ships it.
package vocabulary

import (
	"bytes"
	_ "embed"
)

//go:embed v0.json
var v0 []byte

// V0 returns a copy of vocabulary/v0.json.
func V0() []byte { return bytes.Clone(v0) }

// SPDX-License-Identifier: Apache-2.0

// Command mandate-conformance tests any implementation of the Home-Mandate Specification v0 against the
// conformance cases of this version (SPEC-v0 sections 8 and 10), independent of language
// and vendor:
//
//	mandate-conformance -exec ./my-implementation --flag
//	mandate-conformance -authzen https://pdp.test -control https://pdp.test/test/state
//
// The cases are embedded; the report names the manifest they belong to.
package main

import (
	"context"
	"os"

	"github.com/home-mandate/spec"
	"github.com/home-mandate/spec/internal/harness"
)

func main() {
	os.Exit(harness.Main(context.Background(), spec.FS(), os.Args[1:], os.Stdout, os.Stderr))
}

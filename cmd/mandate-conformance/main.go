// SPDX-License-Identifier: Apache-2.0

// Command mandate-conformance tests any implementation of mandate-spec v0 against the
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

	mandatespec "github.com/mandate-spec/mandate-spec"
	"github.com/mandate-spec/mandate-spec/internal/harness"
)

func main() {
	os.Exit(harness.Main(context.Background(), mandatespec.FS(), os.Args[1:], os.Stdout, os.Stderr))
}

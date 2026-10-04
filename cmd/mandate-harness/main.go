// SPDX-License-Identifier: Apache-2.0

// Command mandate-harness offers the reference code of this repository over the process
// binding of the test interface (SPEC-v0 section 10.2): it reads one request per line
// from standard input and writes one response per line to standard output. It is the
// example of what an implementation provides so that mandate-conformance can test it:
//
//	mandate-conformance -exec mandate-harness
package main

import (
	"fmt"
	"os"

	"github.com/mandate-spec/mandate-spec/internal/harness"
)

func main() {
	if err := harness.Serve(os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "mandate-harness:", err)
		os.Exit(1)
	}
}

// SPDX-License-Identifier: Apache-2.0

// Command mandate-harness offers the reference code of this repository over the test
// interface (SPEC-v0 section 10). Without flags it speaks the process binding (section 10.2):
// it reads one request per line from standard input and writes one response per line to
// standard output. It is the example of what an implementation provides so that
// mandate-conformance can test it:
//
//	mandate-conformance -exec mandate-harness
//
// With -serve-authzen it offers the reference PDP over the HTTP binding (section 10.3) on a
// loopback address, for the class pdp, and prints the arguments for mandate-conformance:
//
//	mandate-harness -serve-authzen 127.0.0.1:8080
//	mandate-conformance -authzen http://127.0.0.1:8080 -control http://127.0.0.1:8080/test/state
package main

import (
	"context"
	"os"
	"os/signal"

	"github.com/home-mandate/spec/internal/harness"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	code := harness.HarnessMain(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

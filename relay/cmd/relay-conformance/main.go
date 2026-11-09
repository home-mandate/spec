// SPDX-License-Identifier: Apache-2.0

// Command relay-conformance tests a live operator of the Home-Mandate Relay Specification
// (RELAY-v0 section 8.3): it plays a gateway and an agent against the operator and reports
// whether the operator conforms.
//
//	relay-conformance -operator relay-operator.example -code-file code1 -code-file code2 \
//	    -own-domain x.relay-test.example -dns-hook ./set-txt -report report.json
//	relay-conformance -cleanup relay-conformance-1a2b3c4d.state.json
//	relay-conformance -list
//
// Exit codes: 0 conformant, 1 not conformant, 2 wrong call, 3 incomplete (a code or the own
// domain is missing, the rate is too high, the operator cannot be reached), 4 clean-up failed
// (the message names -cleanup). The tool never connects to addresses that are not globally
// reachable.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/home-mandate/spec/relay/internal/liveconf"
)

// version is set with -ldflags "-X main.version=v0.1.0"; without it the module version of
// the build is used (go install ...@version).
var version string

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Getenv, os.Stdout, os.Stderr, production)
	stop()
	os.Exit(code)
}

// production is the only executor the command has: it runs with the address filter without
// exceptions and the real time values.
var production = executor{run: liveconf.Execute, cleanup: liveconf.ExecuteCleanup}

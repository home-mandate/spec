// SPDX-License-Identifier: Apache-2.0

//go:build !(linux || darwin || freebsd || netbsd || openbsd)

package liveconf

import "os"

// noFollow does not exist on this system.
const noFollow = 0

// flock does not lock on this system; the state file is still never overwritten.
func flock(*os.File) error { return nil }

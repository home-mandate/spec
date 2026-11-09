// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin || freebsd || netbsd || openbsd

package liveconf

import (
	"os"
	"syscall"
)

// noFollow keeps a symbolic link from redirecting the opening of a file.
const noFollow = syscall.O_NOFOLLOW

// flock takes an exclusive lock that ends with the process, also when it is killed.
func flock(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
}

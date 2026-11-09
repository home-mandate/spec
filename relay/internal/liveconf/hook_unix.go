// SPDX-License-Identifier: Apache-2.0

//go:build unix

package liveconf

import (
	"os/exec"
	"syscall"
)

// isolate puts the hook in a process group of its own and makes a timeout kill the group.
func isolate(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
}

// killGroup kills what the hook left running in its group.
func killGroup(cmd *exec.Cmd) {
	if cmd.Process != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}

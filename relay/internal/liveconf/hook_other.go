// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package liveconf

import "os/exec"

func isolate(*exec.Cmd) {}

func killGroup(*exec.Cmd) {}

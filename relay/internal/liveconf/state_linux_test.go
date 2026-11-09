// SPDX-License-Identifier: Apache-2.0

//go:build linux

package liveconf

import (
	"errors"
	"flag"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"testing"
)

// diskFullChildEnv names the directory in which the child process of the test below works; it is
// also what tells the child that it is one.
const diskFullChildEnv = "LIVECONF_DISK_FULL_DIR"

// skipped is the exit code of the child for a limit that cannot be set.
const skipped = 77

// TestSaveFailsWhenTheDiskRefusesTheWrite runs the failing save in a process of its own: it limits
// the size of the files that process may write (RLIMIT_FSIZE), which is a limit of the whole
// process and would break the writes of every other test that runs at the same time.
func TestSaveFailsWhenTheDiskRefusesTheWrite(t *testing.T) {
	args := []string{"-test.run=^TestSaveFailsWhenTheDiskRefusesTheWriteInTheChild$"}
	// The child reports its coverage with that of its parent.
	if f := flag.Lookup("test.gocoverdir"); f != nil && f.Value.String() != "" {
		args = append(args, "-test.gocoverdir="+f.Value.String())
	}
	cmd := exec.Command(os.Args[0], args...)
	cmd.Env = append(os.Environ(), diskFullChildEnv+"="+t.TempDir())
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	switch {
	case errors.As(err, &exit) && exit.ExitCode() == skipped:
		t.Skip("the limit of file sizes cannot be set")
	case err != nil:
		t.Fatalf("the child failed: %v\n%s", err, out)
	}
}

// TestSaveFailsWhenTheDiskRefusesTheWriteInTheChild is the work of the child process; in the
// parent process it does nothing.
func TestSaveFailsWhenTheDiskRefusesTheWriteInTheChild(t *testing.T) {
	dir := os.Getenv(diskFullChildEnv)
	if dir == "" {
		return
	}
	f, err := CreateState(filepath.Join(dir, "state.json"), sampleState())
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var old syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_FSIZE, &old); err != nil {
		os.Exit(skipped)
	}
	signal.Ignore(syscall.SIGXFSZ)
	if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &syscall.Rlimit{Cur: 1, Max: old.Max}); err != nil {
		os.Exit(skipped)
	}
	err = f.Save(sampleState())
	_ = syscall.Setrlimit(syscall.RLIMIT_FSIZE, &old)
	if !errors.Is(err, ErrState) {
		t.Errorf("save with a full disk: %v", err)
	}
	if _, err := os.Stat(f.path + ".tmp"); err == nil {
		t.Error("temporary file left behind")
	}
}

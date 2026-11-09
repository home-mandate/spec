// SPDX-License-Identifier: Apache-2.0

package liveconf

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// shellHook writes a shell script and returns the command line that runs it.
func shellHook(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "hook.sh")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body+"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	return "/bin/sh " + path
}

func TestHookGetsTheArgumentsAndAMinimalEnvironment(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "out")
	h := newExecHook(shellHook(t, `echo "$@" > `+out+`; env | sort >> `+out), 5*time.Second)
	if err := h.Set(context.Background(), "_home-mandate-relay.home.tester.example.com", "tokenvalue_123"); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(out)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if lines[0] != "set _home-mandate-relay.home.tester.example.com tokenvalue_123" {
		t.Errorf("arguments %q", lines[0])
	}
	for _, line := range lines[1:] {
		if !strings.HasPrefix(line, "PATH=") && !strings.HasPrefix(line, "LC_ALL=") && !strings.HasPrefix(line, "PWD=") && !strings.HasPrefix(line, "_=") && !strings.HasPrefix(line, "SHLVL=") {
			t.Errorf("environment variable %q", line)
		}
	}
	if err := h.Delete(context.Background(), "_home-mandate-relay.home.tester.example.com"); err != nil {
		t.Fatal(err)
	}
	if data, _ = os.ReadFile(out); !strings.HasPrefix(string(data), "delete _home-mandate-relay.home.tester.example.com\n") {
		t.Errorf("delete: %q", data)
	}
}

func TestHookRefusesArgumentsThatAreNoNamesOrValues(t *testing.T) {
	h := newExecHook("/bin/true", time.Second)
	for _, name := range []string{"", "-rf", "a b", "A.EXAMPLE", "a;b.example", strings.Repeat("a", 300)} {
		if err := h.Set(context.Background(), name, "v"); err == nil {
			t.Errorf("name %q", name)
		}
		if err := h.Delete(context.Background(), name); err == nil {
			t.Errorf("delete name %q", name)
		}
	}
	for _, value := range []string{"", "-x", "a b", "a;b", "$(x)", strings.Repeat("a", 200)} {
		if err := h.Set(context.Background(), "a.example", value); err == nil {
			t.Errorf("value %q", value)
		}
	}
	for token, ok := range map[string]bool{"abcdefghijklmnopqrstuv": true, "-bcdefghijklmnopqrstuv": false, "short": false, "abcdefghijklmnopqrstu!": false} {
		if validToken(token) != ok {
			t.Errorf("token %q", token)
		}
	}
}

func TestHookFailuresSayWhatHappenedWithoutTheArguments(t *testing.T) {
	err := newExecHook(shellHook(t, `echo "boom: $2"; exit 3`), 5*time.Second).Set(context.Background(), "a.example", "secretvalue")
	if err == nil || !strings.Contains(err.Error(), "exit status 3") || !strings.Contains(err.Error(), "boom") {
		t.Errorf("err = %v", err)
	}
	if err := newExecHook("/nonexistent/hook", time.Second).Delete(context.Background(), "a.example"); err == nil || !strings.Contains(err.Error(), "could not be started") {
		t.Errorf("not startable: %v", err)
	}
}

func TestHookOutputIsCapped(t *testing.T) {
	err := newExecHook(shellHook(t, `head -c 100000 /dev/zero | tr '\0' x; exit 1`), 5*time.Second).Delete(context.Background(), "a.example")
	if err == nil || len(err.Error()) > 2*maxText+100 {
		t.Errorf("error of %d bytes", len(err.Error()))
	}
	var b capBuffer
	n, _ := b.Write(bytes.Repeat([]byte("y"), hookOutputMax*2))
	if n != hookOutputMax*2 || len(b.String()) != hookOutputMax {
		t.Errorf("wrote %d, kept %d", n, len(b.String()))
	}
	_, _ = b.Write([]byte("more"))
	if len(b.String()) != hookOutputMax {
		t.Error("the cap moved")
	}
}

func TestHookTimeoutKillsTheWholeProcessGroup(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	h := newExecHook(shellHook(t, `sleep 60 & echo $! > `+pidFile+`; wait`), 300*time.Millisecond)
	start := time.Now()
	err := h.Delete(context.Background(), "a.example")
	if err == nil || !strings.Contains(err.Error(), "killed") || time.Since(start) > 10*time.Second {
		t.Fatalf("err = %v after %v", err, time.Since(start))
	}
	data, _ := os.ReadFile(pidFile)
	pid, perr := strconv.Atoi(strings.TrimSpace(string(data)))
	if perr != nil {
		t.Fatal(perr)
	}
	deadline := time.Now().Add(3 * time.Second)
	for syscall.Kill(pid, 0) == nil && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if syscall.Kill(pid, 0) == nil {
		t.Error("the child of the hook is still running")
	}
}

func TestHookKillsWhatItLeftBehind(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	h := newExecHook(shellHook(t, `(sleep 60 >/dev/null 2>&1 </dev/null & echo $! > `+pidFile+`)`), 5*time.Second)
	if err := h.Delete(context.Background(), "a.example"); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(pidFile)
	pid, _ := strconv.Atoi(strings.TrimSpace(string(data)))
	deadline := time.Now().Add(3 * time.Second)
	for syscall.Kill(pid, 0) == nil && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if syscall.Kill(pid, 0) == nil {
		t.Error("a process left behind survives")
	}
}

func TestManualHookPrintsWhatToDo(t *testing.T) {
	var out bytes.Buffer
	h := manualHook{out: &out}
	if err := h.Set(context.Background(), "_x.a.example", "v1"); err != nil {
		t.Fatal(err)
	}
	if err := h.Delete(context.Background(), "_x.a.example"); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`set the TXT record _x.a.example to "v1"`, "remove the TXT record _x.a.example"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output lacks %q: %s", want, out.String())
		}
	}
	if h.Set(context.Background(), "-bad", "v") == nil || h.Set(context.Background(), "a.example", "-v") == nil || h.Delete(context.Background(), "-bad") == nil {
		t.Error("manual hook took a bad argument")
	}
}

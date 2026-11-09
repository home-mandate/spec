// SPDX-License-Identifier: Apache-2.0

package liveconf

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func sampleState() State {
	return newState("op.example.net", []StateKey{{ID: "k1", Alg: "Ed25519", Private: "AAAA"}})
}

func statePath(t *testing.T) string { return filepath.Join(t.TempDir(), "state.json") }

func TestCreateStateIsExclusivePrivateAndComplete(t *testing.T) {
	path := statePath(t)
	f, err := CreateState(path, sampleState())
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v, %v", info.Mode(), err)
	}
	if _, err := os.Stat(path + ".tmp"); err == nil {
		t.Error("temporary file left behind")
	}
	// No overwriting, also not by a process that cannot take the lock: the second call fails
	// at the lock; release it and the existing file stops the call.
	if _, err := CreateState(path, sampleState()); !errors.Is(err, ErrState) {
		t.Errorf("second create while locked: %v", err)
	}
	_ = f.Close()
	if _, err := CreateState(path, sampleState()); !errors.Is(err, ErrState) {
		t.Errorf("second create over the file: %v", err)
	}
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), `"operator": "op.example.net"`) {
		t.Errorf("state file: %s", data)
	}
}

func TestCreateStateRefusesASymbolicLink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("precious"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "state.json")
	if err := os.Symlink(target, path); err != nil {
		t.Skip(err)
	}
	if _, err := CreateState(path, sampleState()); !errors.Is(err, ErrState) {
		t.Errorf("create over a link: %v", err)
	}
	if _, err := OpenState(path); !errors.Is(err, ErrState) {
		t.Errorf("open a link: %v", err)
	}
	if data, _ := os.ReadFile(target); string(data) != "precious" {
		t.Errorf("the target was changed: %q", data)
	}
	lock := filepath.Join(dir, "other.json")
	if err := os.Symlink(target, lock+".lock"); err != nil {
		t.Skip(err)
	}
	if _, err := CreateState(lock, sampleState()); !errors.Is(err, ErrState) {
		t.Errorf("create with a linked lock file: %v", err)
	}
}

func TestStateFileSaveOpenRemove(t *testing.T) {
	path := statePath(t)
	f, err := CreateState(path, sampleState())
	if err != nil {
		t.Fatal(err)
	}
	st := f.State().WithInstallation(StateInstallation{URL: "https://op.example.net/enroll/i/1", Key: "k1"})
	if len(f.State().Installations) != 0 {
		t.Error("WithInstallation changed the original")
	}
	if err := f.Save(st); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenState(path); !errors.Is(err, ErrState) {
		t.Errorf("open while another holds the lock: %v", err)
	}
	_ = f.Close()
	g, err := OpenState(path)
	if err != nil {
		t.Fatal(err)
	}
	got := g.State()
	if len(got.Installations) != 1 || got.Pending() != 1 {
		t.Fatalf("state: %+v", got)
	}
	done := got.WithUnpaired(0)
	if got.Installations[0].Unpaired || done.Pending() != 0 {
		t.Error("WithUnpaired is wrong")
	}
	if err := g.Remove(); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{path, path + ".lock"} {
		if _, err := os.Stat(p); err == nil {
			t.Errorf("%s still exists", p)
		}
	}
	if err := g.Remove(); err == nil {
		t.Error("removing twice succeeded")
	}
}

func TestOpenStateIsStrict(t *testing.T) {
	good := `{"version":1,"operator":"op.example.net","created":"x","keys":[],"installations":[]}`
	for name, content := range map[string]string{
		"unknown member":    `{"version":1,"operator":"op.example.net","keys":[],"installations":[],"extra":1}`,
		"trailing data":     good + good,
		"wrong version":     strings.Replace(good, `"version":1`, `"version":2`, 1),
		"bad operator":      strings.Replace(good, "op.example.net", "OP", 1),
		"too many keys":     `{"version":1,"operator":"op.example.net","keys":[{},{},{},{},{},{},{},{},{}],"installations":[]}`,
		"too many installs": `{"version":1,"operator":"op.example.net","keys":[],"installations":[{},{},{},{}]}`,
		"not JSON":          `nope`,
		"too large":         good + strings.Repeat(" ", maxStateBytes),
	} {
		path := statePath(t)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenState(path); !errors.Is(err, ErrState) {
			t.Errorf("%s: %v", name, err)
		}
		// The failed open must not keep the lock.
		if l, err := lockFile(path); err != nil {
			t.Errorf("%s: lock kept after a failed open: %v", name, err)
		} else {
			_ = l.Close()
		}
	}
	path := statePath(t)
	if err := os.WriteFile(path, []byte(good), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := OpenState(path)
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	if _, err := OpenState(filepath.Join(t.TempDir(), "missing.json")); !errors.Is(err, ErrState) {
		t.Errorf("missing file: %v", err)
	}
}

func TestStateFileFailsWhenTheDirectoryIsGone(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "state.json")
	if _, err := CreateState(path, sampleState()); !errors.Is(err, ErrState) {
		t.Errorf("create in a missing directory: %v", err)
	}
	// A directory where the temporary file goes makes the write fail.
	path = filepath.Join(dir, "state.json")
	if err := os.Mkdir(path+".tmp", 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := CreateState(path, sampleState()); !errors.Is(err, ErrState) {
		t.Errorf("create with a blocked temporary file: %v", err)
	}
	// Save over a path that became a directory: the rename fails.
	path2 := filepath.Join(dir, "s2.json")
	f, err := CreateState(path2, sampleState())
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := os.Remove(path2); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path2, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := f.Save(sampleState()); !errors.Is(err, ErrState) {
		t.Errorf("save over a directory: %v", err)
	}
	if _, err := os.Stat(path2 + ".tmp"); err == nil {
		t.Error("temporary file left behind after a failed save")
	}
	if err := syncDir(filepath.Join(dir, "nope")); !errors.Is(err, ErrState) {
		t.Errorf("syncDir: %v", err)
	}
}

func TestCheckInstallationURL(t *testing.T) {
	const enrollment = "https://op.example.net/enroll/directory"
	for raw, ok := range map[string]bool{
		"https://op.example.net/enroll/i/1":      true,
		"https://op.example.net:443/enroll/i/1":  false,
		"https://op.example.net:8443/enroll/i/1": false,
		"http://op.example.net/enroll/i/1":       false,
		"https://evil.example/enroll/i/1":        false,
		"https://op.example.net.evil.example/i":  false,
		"https://user@op.example.net/enroll/i/1": false,
		"https://op.example.net@evil.example/i":  false,
		"https://op.example.net/enroll/i/1#frag": false,
		"https:///enroll":                        false,
		"%":                                      false,
		"":                                       false,
		"/enroll/i/1":                            false,
		"https://OP.example.net/enroll/i/1":      false,
	} {
		if err := CheckInstallationURL(raw, enrollment); (err == nil) != ok {
			t.Errorf("CheckInstallationURL(%q) = %v", raw, err)
		}
	}
	if err := CheckInstallationURL("https://op.example.net/i", "%"); err == nil {
		t.Error("accepted an unparseable enrollment URL")
	}
	if err := CheckInstallationURL("https://op.example.net/i", ""); err == nil {
		t.Error("accepted any URL without an enrollment URL")
	}
}

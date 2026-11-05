// SPDX-License-Identifier: Apache-2.0

// Package releasebase tests .github/scripts/release-base.sh, the guard of release.yml that
// decides on which branch a tag may stand (RELEASING.md).
package releasebase

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// repository builds this history and returns the commits by name:
//
//	root ── onMain            origin/main
//	   └─── onRelease01       origin/release/0.1
//	   └─── onRelease02       origin/release/0.2
//	   └─── elsewhere         origin/fix/other
func repository(t *testing.T) (dir string, commits map[string]string) {
	t.Helper()
	dir = t.TempDir()
	git := func(args ...string) string {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.org",
			"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.org")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	commit := func(parent, message string) string {
		args := []string{"commit-tree", "4b825dc642cb6eb9a060e54bf8d69288fbee4904", "-m", message}
		if parent != "" {
			args = append(args, "-p", parent)
		}
		return git(args...)
	}
	git("init", "-q")
	git("hash-object", "-t", "tree", "-w", "--stdin", "/dev/null")
	root := commit("", "root")
	commits = map[string]string{"root": root}
	for name, branch := range map[string]string{"onMain": "main", "onRelease01": "release/0.1", "onRelease02": "release/0.2", "elsewhere": "fix/other"} {
		commits[name] = commit(root, name)
		git("update-ref", "refs/remotes/origin/"+branch, commits[name])
	}
	return dir, commits
}

func TestReleaseBase(t *testing.T) {
	script, err := filepath.Abs("../../.github/scripts/release-base.sh")
	if err != nil {
		t.Fatal(err)
	}
	dir, commits := repository(t)
	for _, tc := range []struct {
		tag, commit, want string // want "" means refused
	}{
		// A minor version comes from main only.
		{"v0.2.0", "onMain", "main"},
		{"v0.2.0-rc.1", "onMain", "main"},
		{"v0.2.0-alpha.1", "onMain", "main"},
		{"v0.1.0", "onRelease01", ""},
		{"v0.1.0-rc.2", "onRelease01", ""},
		{"v0.2.0", "onRelease02", ""},
		// A patch comes from its own release branch only: main holds functions of the next
		// minor version, and a patch must not publish them.
		{"v0.1.1", "onRelease01", "release/0.1"},
		{"v0.1.1-rc.1", "onRelease01", "release/0.1"},
		{"v0.1.1-alpha.1", "onRelease01", "release/0.1"},
		{"v0.1.10", "onRelease01", "release/0.1"},
		{"v0.2.3", "onRelease02", "release/0.2"},
		{"v0.1.1", "onMain", ""},
		{"v0.1.1-rc.1", "onMain", ""},
		// History the branches share: main's for a minor version, the branch's for a patch.
		{"v0.2.0", "root", "main"},
		{"v0.1.1", "root", "release/0.1"},
		// Never from another release branch.
		{"v0.1.2", "onRelease02", ""},
		{"v0.2.1", "onRelease01", ""},
		// A branch that does not exist.
		{"v0.3.1", "onRelease01", ""},
		{"v0.3.1", "onMain", ""},
		// Never from anywhere else.
		{"v0.1.1", "elsewhere", ""},
		{"v0.2.0", "elsewhere", ""},
		// Not a version.
		{"v0.1", "onMain", ""},
		{"v0.2.0-beta.1", "onMain", ""},
		{"0.2.0", "onMain", ""},
		{"v0.2.0-rc.1;x", "onMain", ""},
		{"v0.2.0\nv0.2.1", "onMain", ""},
	} {
		cmd := exec.Command("bash", script, tc.tag, commits[tc.commit])
		cmd.Dir = dir
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		err := cmd.Run()
		got := strings.TrimSpace(stdout.String())
		switch {
		case tc.want == "" && (err == nil || got != ""):
			t.Errorf("%q on %s = %q, %v; want refused", tc.tag, tc.commit, got, err)
		case tc.want == "" && !strings.Contains(stderr.String(), "::error::"):
			t.Errorf("%q on %s: refusal without an annotation: %q", tc.tag, tc.commit, stderr.String())
		case tc.want != "" && (err != nil || got != tc.want):
			t.Errorf("%q on %s = %q, %v (%s); want %q", tc.tag, tc.commit, got, err, stderr.String(), tc.want)
		}
	}
}

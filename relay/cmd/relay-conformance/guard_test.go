// SPDX-License-Identifier: Apache-2.0

package main

import (
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const modulePath = "github.com/home-mandate/spec/"

// referencePackages are the packages that hold test keys, reference operators and faults;
// nothing the tool or the files of package relay (which are not tests) import may reach them
// (RELAY-v0 section 8.2: test keys must not be used with a live operator).
var referencePackages = []string{"refop", "refrelay", "refdns"}

// importsOf returns every package that the non-test files of the package in dir import,
// directly and indirectly, within this module.
func importsOf(t *testing.T, dir string, seen map[string]bool) {
	t.Helper()
	pkg, err := build.ImportDir(dir, 0)
	if err != nil {
		t.Fatalf("%s: %v", dir, err)
	}
	for _, imp := range pkg.Imports {
		if seen[imp] {
			continue
		}
		seen[imp] = true
		if sub, ok := strings.CutPrefix(imp, modulePath); ok {
			importsOf(t, filepath.Join("..", "..", "..", filepath.FromSlash(sub)), seen)
		}
	}
}

func TestToolAndEmbeddedFilesNeverReachTheReferenceOperator(t *testing.T) {
	for name, dir := range map[string]string{
		"relay-conformance":           ".",
		"package relay":               filepath.Join("..", ".."),
		"relay/internal/liveconf":     filepath.Join("..", "..", "internal", "liveconf"),
		"relay/internal/netguard":     filepath.Join("..", "..", "internal", "netguard"),
		"relay/internal/dnsq":         filepath.Join("..", "..", "internal", "dnsq"),
		"relay/internal/enroll":       filepath.Join("..", "..", "internal", "enroll"),
		"relay/internal/enrollcases":  filepath.Join("..", "..", "internal", "enrollcases"),
		"relay/internal/tunnelclient": filepath.Join("..", "..", "internal", "tunnelclient"),
		"relay/internal/frames":       filepath.Join("..", "..", "internal", "frames"),
		"relay/internal/tunnelcert":   filepath.Join("..", "..", "internal", "tunnelcert"),
	} {
		seen := map[string]bool{}
		importsOf(t, dir, seen)
		if len(seen) == 0 {
			t.Fatalf("%s: no imports found; the guard checks nothing", name)
		}
		for imp := range seen {
			for _, ref := range referencePackages {
				if strings.HasSuffix(imp, "/"+ref) || strings.Contains(imp, "/"+ref+"/") {
					t.Errorf("%s imports %s", name, imp)
				}
			}
		}
	}
}

func TestGuardSeesAnImportOfTheReference(t *testing.T) {
	// The test package imports liveconf, whose tests import refop; the guard must see an
	// import that exists: scan the test files of liveconf as a stand-in.
	seen := map[string]bool{}
	pkg, err := build.ImportDir(filepath.Join("..", "..", "internal", "liveconf"), 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, imp := range pkg.TestImports {
		seen[imp] = true
	}
	if !slices.Contains(mapKeys(seen), modulePath+"relay/internal/refop") {
		t.Error("the tests of liveconf do not import refop: the guard cannot be shown to work")
	}
}

func mapKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestCommandBuildsOnlyTheFilteringExecutor: the command uses liveconf.Execute and
// liveconf.ExecuteCleanup, which build the address filter without exceptions, and nothing of
// liveconf or netguard that lets a caller change the filter, the roots, the time values or
// the unpairing.
func TestCommandBuildsOnlyTheFilteringExecutor(t *testing.T) {
	forbidden := []string{"RunWith", "CleanupWith", "Env", "Timing", "DefaultTiming", "Options", "New", "Dialer", "Allowed"}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	used := map[string]bool{}
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(token.NewFileSet(), name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range f.Imports {
			if strings.Contains(imp.Path.Value, "netguard") {
				t.Errorf("%s imports netguard: the dialer is built in liveconf only", name)
			}
		}
		ast.Inspect(f, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "liveconf" {
				used[sel.Sel.Name] = true
			}
			return true
		})
	}
	for _, name := range forbidden {
		if used[name] {
			t.Errorf("the command uses liveconf.%s", name)
		}
	}
	for _, name := range []string{"Execute", "ExecuteCleanup"} {
		if !used[name] {
			t.Errorf("the command does not use liveconf.%s", name)
		}
	}
}

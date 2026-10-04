// SPDX-License-Identifier: Apache-2.0

// Package manifest lists the machine-readable files of a version of the specification
// with their SHA-256 and, for conformance files, the number of cases. With it, anyone
// can state exactly which files and cases a conformance run covered.
package manifest

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"slices"
	"strings"
)

// Path of the manifest within the repository; the manifest does not list itself.
const Path = "conformance/manifest.json"

const specVersion = "v0"

// roots are the directories whose JSON files belong to the specification.
var roots = []string{"conformance", "data", "examples", "schema", "vocabulary"}

// caseKeys are the members that hold the cases of a conformance file.
var caseKeys = []string{"cases", "logs"}

// Manifest is the content of conformance/manifest.json.
type Manifest struct {
	Spec  string `json:"spec"`
	Files []File `json:"files"`
}

// File is one file of the specification. Cases is set for conformance files only.
type File struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Cases  int    `json:"cases,omitempty"`
}

// Build computes the manifest of the files in fsys, sorted by path. Roots that do not
// exist are skipped.
func Build(fsys fs.FS) (Manifest, error) {
	m := Manifest{Spec: specVersion, Files: []File{}}
	for _, root := range roots {
		if _, err := fs.Stat(fsys, root); err != nil {
			continue
		}
		err := fs.WalkDir(fsys, root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || path.Ext(p) != ".json" || p == Path {
				return nil
			}
			f, err := describe(fsys, p)
			if err != nil {
				return err
			}
			m.Files = append(m.Files, f)
			return nil
		})
		if err != nil {
			return Manifest{}, fmt.Errorf("manifest: %w", err)
		}
	}
	slices.SortFunc(m.Files, func(a, b File) int { return strings.Compare(a.Path, b.Path) })
	return m, nil
}

func describe(fsys fs.FS, p string) (File, error) {
	data, err := fs.ReadFile(fsys, p)
	if err != nil {
		return File{}, err
	}
	sum := sha256.Sum256(data)
	f := File{Path: p, SHA256: hex.EncodeToString(sum[:])}
	if path.Dir(p) != "conformance" {
		return f, nil
	}
	if f.Cases, err = countCases(data); err != nil {
		return File{}, fmt.Errorf("%s: %w", p, err)
	}
	return f, nil
}

func countCases(data []byte) (int, error) {
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(data, &doc); err != nil {
		return 0, err
	}
	for _, key := range caseKeys {
		raw, ok := doc[key]
		if !ok {
			continue
		}
		var cases []json.RawMessage
		if err := json.Unmarshal(raw, &cases); err != nil {
			return 0, err
		}
		if len(cases) == 0 {
			return 0, fmt.Errorf("%q is empty", key)
		}
		return len(cases), nil
	}
	return 0, fmt.Errorf("no cases found")
}

// Encode returns the manifest as indented JSON with a trailing newline.
func Encode(m Manifest) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(m); err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}
	return buf.Bytes(), nil
}

// Decode reads a manifest; unknown fields are an error.
func Decode(data []byte) (Manifest, error) {
	var m Manifest
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return Manifest{}, fmt.Errorf("manifest: %w", err)
	}
	return m, nil
}

// Diff describes how got differs from want, one line per file; empty if they agree.
func Diff(want, got Manifest) []string {
	var out []string
	if want.Spec != got.Spec {
		out = append(out, fmt.Sprintf("spec: %q, want %q", got.Spec, want.Spec))
	}
	index := func(m Manifest) map[string]File {
		byPath := make(map[string]File, len(m.Files))
		for _, f := range m.Files {
			byPath[f.Path] = f
		}
		return byPath
	}
	wantFiles, gotFiles := index(want), index(got)
	for _, w := range want.Files {
		g, ok := gotFiles[w.Path]
		switch {
		case !ok:
			out = append(out, w.Path+": missing")
		case g != w:
			out = append(out, w.Path+": changed")
		}
	}
	for _, g := range got.Files {
		if _, ok := wantFiles[g.Path]; !ok {
			out = append(out, g.Path+": not expected")
		}
	}
	return out
}

// SPDX-License-Identifier: Apache-2.0

// Command vectors maintains the conformance files of the specification:
//
//	vectors manifest [-check]   write or check conformance/manifest.json
//	vectors digest <mandate>    print the digest of a mandate (SPEC-v0 section 3.2)
//	vectors chain < entries     link a JSON array of audit entries by prev and print them
//	                            with their digests (SPEC-v0 section 9.4)
//	vectors codepoints <ucd>    print data/forbidden-codepoints-v0.json from the Unicode
//	                            Character Database (SPEC-v0 section 3.1 item 8)
//
// Run it from the repository root: go run ./tools/vectors <command>.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/mandate-spec/mandate-spec/audit"
	"github.com/mandate-spec/mandate-spec/evaluator"
	"github.com/mandate-spec/mandate-spec/internal/ijson"
	"github.com/mandate-spec/mandate-spec/internal/manifest"
)

func main() {
	if err := run(os.Args[1:], ".", os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "vectors:", err)
		os.Exit(1)
	}
}

// run executes one command with paths relative to dir.
func run(args []string, dir string, stdin io.Reader, stdout io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: vectors manifest [-check] | digest <mandate> | chain | codepoints <ucd>")
	}
	switch args[0] {
	case "manifest":
		return runManifest(args[1:], dir, stdout)
	case "digest":
		return runDigest(args[1:], dir, stdout)
	case "chain":
		return runChain(stdin, stdout)
	case "codepoints":
		return runCodepoints(args[1:], stdout)
	}
	return fmt.Errorf("unknown command %q", args[0])
}

func runManifest(args []string, dir string, stdout io.Writer) error {
	flags := flag.NewFlagSet("manifest", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	check := flags.Bool("check", false, "compare instead of writing")
	if err := flags.Parse(args); err != nil {
		return err
	}
	built, err := manifest.Build(os.DirFS(dir))
	if err != nil {
		return err
	}
	target := filepath.Join(dir, filepath.FromSlash(manifest.Path))
	if !*check {
		data, err := manifest.Encode(built)
		if err != nil {
			return err
		}
		if err := os.WriteFile(target, data, 0o644); err != nil {
			return fmt.Errorf("write manifest: %w", err)
		}
		_, err = fmt.Fprintf(stdout, "%s: %d files\n", manifest.Path, len(built.Files))
		return err
	}
	data, err := os.ReadFile(target)
	if err != nil {
		return fmt.Errorf("read manifest: %w", err)
	}
	stored, err := manifest.Decode(data)
	if err != nil {
		return err
	}
	if diff := manifest.Diff(built, stored); len(diff) > 0 {
		return fmt.Errorf("%s is out of date: %v", manifest.Path, diff)
	}
	return nil
}

func runDigest(args []string, dir string, stdout io.Writer) error {
	if len(args) != 1 {
		return errors.New("usage: vectors digest <mandate>")
	}
	path := args[0]
	if !filepath.IsAbs(path) {
		path = filepath.Join(dir, path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read mandate: %w", err)
	}
	m, err := evaluator.Parse(data)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(stdout, m.Digest())
	return err
}

// chained is the output of chain, in the shape of a log in conformance/audit-v0.json.
type chained struct {
	EntryDigests []string          `json:"entry_digests"`
	Entries      []json.RawMessage `json:"entries"`
}

// runChain sets prev of every entry to the digest of its predecessor (null for the
// first) and leaves everything else, including seq, as given.
func runChain(stdin io.Reader, stdout io.Writer) error {
	input, err := io.ReadAll(stdin)
	if err != nil {
		return fmt.Errorf("read entries: %w", err)
	}
	if err := ijson.Check(input); err != nil {
		return fmt.Errorf("entries are not I-JSON: %w", err)
	}
	var entries []map[string]json.RawMessage
	dec := json.NewDecoder(bytes.NewReader(input))
	if err := dec.Decode(&entries); err != nil {
		return fmt.Errorf("entries must be a JSON array of objects: %w", err)
	}
	out := chained{EntryDigests: []string{}, Entries: []json.RawMessage{}}
	prev := json.RawMessage("null")
	for i, e := range entries {
		e["prev"] = prev
		data, err := json.Marshal(e)
		if err != nil {
			return fmt.Errorf("entry %d: %w", i, err)
		}
		digest, err := audit.Digest(data)
		if err != nil {
			return fmt.Errorf("entry %d: %w", i, err)
		}
		out.Entries = append(out.Entries, data)
		out.EntryDigests = append(out.EntryDigests, digest)
		prev = json.RawMessage(`"` + digest + `"`)
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mandate-spec/mandate-spec/audit"
	"github.com/mandate-spec/mandate-spec/internal/manifest"
)

const entryTemplate = `{"type":"https://mandate-spec.org/audit/v0","id":"01928b2e-7c3a-7000-8000-00000000000N","seq":N,` +
	`"recorded_at":"2026-10-12T21:14:03+02:00","event":"emergency_stop.activated","principal":"household:h1",` +
	`"actor":{"kind":"user","id":"u"},"prev":null}`

func entry(seq string) string { return strings.ReplaceAll(entryTemplate, "N", seq) }

func runTool(t *testing.T, dir, stdin string, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	err := run(args, dir, strings.NewReader(stdin), &out)
	return out.String(), err
}

func TestChainLinksEntriesIntoAValidLog(t *testing.T) {
	out, err := runTool(t, ".", "["+entry("1")+","+entry("2")+","+entry("3")+"]", "chain")
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		EntryDigests []string          `json:"entry_digests"`
		Entries      []json.RawMessage `json:"entries"`
	}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, out)
	}
	if len(result.Entries) != 3 || len(result.EntryDigests) != 3 {
		t.Fatalf("got %d entries and %d digests, want 3 and 3", len(result.Entries), len(result.EntryDigests))
	}
	entries := make([][]byte, len(result.Entries))
	for i, e := range result.Entries {
		entries[i] = e
		d, err := audit.Digest(e)
		if err != nil || d != result.EntryDigests[i] {
			t.Errorf("entry %d: digest %s (%v), reported %s", i, d, err, result.EntryDigests[i])
		}
	}
	if r, err := audit.Verify(entries); err != nil || !r.Valid {
		t.Errorf("chained log is not valid: %+v, %v", r, err)
	}
}

func TestChainRejectsBrokenInput(t *testing.T) {
	for name, in := range map[string]string{
		"not json":      "nope",
		"not an array":  `{"a":1}`,
		"not objects":   `[1,2]`,
		"duplicate key": `[{"a":1,"a":2}]`,
	} {
		if _, err := runTool(t, ".", in, "chain"); err == nil {
			t.Errorf("%s: chain accepted the input", name)
		}
	}
}

func TestDigestPrintsTheMandateDigest(t *testing.T) {
	out, err := runTool(t, "../..", "", "digest", "examples/voice-assistant.json")
	if err != nil {
		t.Fatal(err)
	}
	// d01 in conformance/digest-v0.json.
	data, _ := os.ReadFile("../../conformance/digest-v0.json")
	if !strings.Contains(string(data), strings.TrimSpace(out)) || !strings.HasPrefix(out, "sha256:") {
		t.Errorf("digest %q is not the one of the conformance cases", out)
	}
	if _, err := runTool(t, "../..", "", "digest", "README.md"); err == nil {
		t.Error("digest accepted a file that is no mandate")
	}
	if _, err := runTool(t, "../..", "", "digest", "missing.json"); err == nil {
		t.Error("digest accepted a missing file")
	}
	if _, err := runTool(t, "../..", "", "digest"); err == nil {
		t.Error("digest accepted a call without a file")
	}
}

func TestManifestWritesAndChecks(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "conformance"), 0o755); err != nil {
		t.Fatal(err)
	}
	cases := filepath.Join(dir, "conformance", "cases-v0.json")
	if err := os.WriteFile(cases, []byte(`{"cases":[{}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := runTool(t, dir, "", "manifest", "-check"); err == nil {
		t.Error("manifest -check passed without a manifest")
	}
	if _, err := runTool(t, dir, "", "manifest"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, manifest.Path))
	if err != nil {
		t.Fatal(err)
	}
	m, err := manifest.Decode(data)
	if err != nil || len(m.Files) != 1 || m.Files[0].Cases != 1 {
		t.Fatalf("manifest = %+v, %v", m, err)
	}
	if _, err := runTool(t, dir, "", "manifest", "-check"); err != nil {
		t.Errorf("manifest -check after writing: %v", err)
	}
	if err := os.WriteFile(cases, []byte(`{"cases":[{},{}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := runTool(t, dir, "", "manifest", "-check"); err == nil {
		t.Error("manifest -check passed although a file changed")
	}
	if err := os.WriteFile(cases, []byte(`broken`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := runTool(t, dir, "", "manifest"); err == nil {
		t.Error("manifest accepted a broken conformance file")
	}
}

func TestUnknownCommandIsAnError(t *testing.T) {
	for _, args := range [][]string{nil, {"nope"}, {"manifest", "-nope"}} {
		if _, err := runTool(t, ".", "", args...); err == nil {
			t.Errorf("run(%v) succeeded", args)
		}
	}
}

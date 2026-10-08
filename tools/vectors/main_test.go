// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/home-mandate/spec/audit"
	"github.com/home-mandate/spec/internal/manifest"
	"github.com/home-mandate/spec/jws"
)

const entryTemplate = `{"type":"https://home-mandate.org/audit/v0","id":"01928b2e-7c3a-7000-8000-00000000000N","seq":N,` +
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

const testPrivateKeys = `{"keys":[
 {"kty":"OKP","crv":"Ed25519","kid":"test-ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"}]}`

func TestCheckpointSignsWithATestKey(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "keys.json")
	if err := os.WriteFile(keyFile, []byte(testPrivateKeys), 0o600); err != nil {
		t.Fatal(err)
	}
	const logID = "0198f1c2-7c3a-7000-8000-0000000000aa"
	digest := "sha256:" + strings.Repeat("a", 64)
	out, err := runTool(t, dir, "", "checkpoint", keyFile, "test-ed25519", logID, "2", digest)
	if err != nil {
		t.Fatal(err)
	}
	want, err := audit.SignCheckpoint(logID, 2, digest, "test-ed25519", ed25519.NewKeyFromSeed(mustDecode(t, "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A")))
	if err != nil || strings.TrimSpace(out) != want {
		t.Errorf("checkpoint = %q, want %q (%v)", out, want, err)
	}
	for name, args := range map[string][]string{
		"too few arguments": {"checkpoint", keyFile, "test-ed25519", logID, "2"},
		"unknown key":       {"checkpoint", keyFile, "nope", logID, "2", digest},
		"seq not a number":  {"checkpoint", keyFile, "test-ed25519", logID, "two", digest},
		"missing key file":  {"checkpoint", filepath.Join(dir, "none.json"), "test-ed25519", logID, "2", digest},
		"bad log ID":        {"checkpoint", keyFile, "test-ed25519", "log", "2", digest},
	} {
		if _, err := runTool(t, dir, "", args...); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	for name, content := range map[string]string{
		"not JSON":      `nope`,
		"public only":   `{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"test-ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}]}`,
		"bad seed":      `{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"test-ed25519","d":"AQAB"}]}`,
		"bad EC scalar": `{"keys":[{"kty":"EC","crv":"P-256","kid":"test-ed25519","d":"AQAB"}]}`,
		"unknown type":  `{"keys":[{"kty":"RSA","kid":"test-ed25519","d":"AQAB"}]}`,
		"d not base64":  `{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"test-ed25519","d":"!!"}]}`,
	} {
		if err := os.WriteFile(keyFile, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := runTool(t, dir, "", "checkpoint", keyFile, "test-ed25519", logID, "2", digest); err == nil {
			t.Errorf("key file %s: accepted", name)
		}
	}
}

func mustDecode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSignProducesASignedMandate(t *testing.T) {
	dir := t.TempDir()
	keyFile, file := filepath.Join(dir, "keys.json"), filepath.Join(dir, "m.json")
	if err := os.WriteFile(keyFile, []byte(testPrivateKeys), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte(`{ "b": 1,  "a": 2 }`), 0o600); err != nil {
		t.Fatal(err)
	}
	keys := jws.Keys{"test-ed25519": ed25519.NewKeyFromSeed(mustDecode(t, "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A")).Public()}
	for flag, want := range map[string]string{"": `{"a":2,"b":1}`, "-raw": `{ "b": 1,  "a": 2 }`} {
		args := []string{"sign", keyFile, "test-ed25519", file}
		if flag != "" {
			args = []string{"sign", flag, keyFile, "test-ed25519", file}
		}
		out, err := runTool(t, dir, "", args...)
		if err != nil {
			t.Fatal(err)
		}
		payload, _, err := jws.Verify(strings.TrimSpace(out), keys)
		if err != nil || string(payload) != want {
			t.Errorf("sign %s: payload %q, %v; want %q", flag, payload, err, want)
		}
	}
	if err := os.WriteFile(file, []byte(`nope`), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, args := range map[string][]string{
		"too few arguments": {"sign", keyFile, "test-ed25519"},
		"unknown key":       {"sign", keyFile, "nope", file},
		"missing file":      {"sign", keyFile, "test-ed25519", filepath.Join(dir, "none.json")},
		"not JSON":          {"sign", keyFile, "test-ed25519", file},
	} {
		if _, err := runTool(t, dir, "", args...); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

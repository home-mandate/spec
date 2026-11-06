// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/home-mandate/spec/internal/manifest"
)

// TestRelayJWSFileIsUpToDate: the stored cases are those the generator writes, byte for
// byte: ES256 signatures are deterministic (RFC 6979).
func TestRelayJWSFileIsUpToDate(t *testing.T) {
	out, err := runTool(t, "../..", "", "relay-jws", "relay/conformance/keys/test-keys.private.json")
	if err != nil {
		t.Fatal(err)
	}
	stored, err := os.ReadFile("../../relay/conformance/jws-v0.json")
	if err != nil {
		t.Fatal(err)
	}
	var got, want struct {
		Description string         `json:"description"`
		Cases       []relayJWSCase `json:"cases"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("output is not JSON: %v", err)
	}
	if err := json.Unmarshal(stored, &want); err != nil {
		t.Fatal(err)
	}
	if got.Description != want.Description || len(got.Cases) != len(want.Cases) {
		t.Fatalf("description or number of cases differ; run: go run ./tools/vectors relay-jws relay/conformance/keys/test-keys.private.json > relay/conformance/jws-v0.json")
	}
	for i, g := range got.Cases {
		w := want.Cases[i]
		if g.ID != w.ID || g.Kind != w.Kind || g.JWS != w.JWS || !bytes.Equal(g.Key, w.Key) || g.URL != w.URL || g.Expected != w.Expected || g.Why != w.Why {
			t.Errorf("case %s differs from the generator", w.ID)
		}
	}
	if out != string(stored) {
		t.Error("relay/conformance/jws-v0.json is not byte for byte what the generator writes")
	}
}

func TestRelayJWSRejectsBadArguments(t *testing.T) {
	for _, args := range [][]string{{"relay-jws"}, {"relay-jws", "nope.json"}, {"relay-jws", "conformance/keys/test-keys.private.json"}} {
		if _, err := runTool(t, "../..", "", args...); err == nil {
			t.Errorf("run(%v) succeeded", args)
		}
	}
	if _, err := rawRelayJWS("{}", "", "key"); err == nil {
		t.Error("rawRelayJWS accepted an unsupported key")
	}
	if _, err := relayJWSCases(relaySigners{}); err == nil {
		t.Error("relayJWSCases accepted no keys")
	}
}

func TestManifestWritesAndChecksTheRelayManifest(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "relay", "conformance"), 0o755); err != nil {
		t.Fatal(err)
	}
	cases := filepath.Join(dir, "relay", "conformance", "jws-v0.json")
	if err := os.WriteFile(cases, []byte(`{"cases":[{}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := runTool(t, dir, "", "manifest"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(manifest.RelayPath)))
	if err != nil {
		t.Fatal(err)
	}
	if m, err := manifest.Decode(data); err != nil || m.Spec != "relay-v0" || len(m.Files) != 1 || m.Files[0].Cases != 1 {
		t.Fatalf("manifest = %+v, %v", m, err)
	}
	if _, err := os.Stat(filepath.Join(dir, filepath.FromSlash(manifest.Path))); err == nil {
		t.Error("a tree without conformance/ got its manifest")
	}
	if err := os.WriteFile(cases, []byte(`{"cases":[{},{}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := runTool(t, dir, "", "manifest", "-check"); err == nil {
		t.Error("manifest -check passed although a relay file changed")
	}
}

// TestRelayCertificateFilesAreUpToDate: the stored CSR and certificate cases are those the
// generator writes, byte for byte.
func TestRelayCertificateFilesAreUpToDate(t *testing.T) {
	for command, file := range map[string]string{"relay-csr": "csr-v0.json", "relay-certificate": "certificate-v0.json"} {
		out, err := runTool(t, "../..", "", command, "relay/conformance/keys/test-keys.private.json")
		if err != nil {
			t.Fatalf("%s: %v", command, err)
		}
		stored, err := os.ReadFile("../../relay/conformance/" + file)
		if err != nil {
			t.Fatal(err)
		}
		if out != string(stored) {
			t.Errorf("relay/conformance/%s is not what the generator writes; run: go run ./tools/vectors %s relay/conformance/keys/test-keys.private.json > relay/conformance/%s", file, command, file)
		}
	}
}

func TestRelayCertificateCommandsRejectBadArguments(t *testing.T) {
	for _, command := range []string{"relay-csr", "relay-certificate"} {
		for _, args := range [][]string{{command}, {command, "nope.json"}, {command, "conformance/keys/test-keys.private.json"}} {
			if _, err := runTool(t, "../..", "", args...); err == nil {
				t.Errorf("run(%v) succeeded", args)
			}
		}
	}
	if _, err := relayCSRCases(relaySigners{}); err == nil {
		t.Error("relayCSRCases accepted no keys")
	}
	if _, err := relayCertificateCases(relaySigners{}); err == nil {
		t.Error("relayCertificateCases accepted no keys")
	}
	if _, err := resign([]byte{0x30, 0x00}, oidEd25519, nil); err == nil {
		t.Error("resign accepted a request that is not one")
	}
	for _, der := range [][]byte{{0x30}, {0x30, 0x82, 0x01, 0x00}} {
		if _, err := longFormLength(der); err == nil {
			t.Errorf("longFormLength(%x) succeeded", der)
		}
	}
	if got, err := longFormLength([]byte{0x30, 0x81, 0x80}); err != nil || len(got) != 4 {
		t.Errorf("longFormLength of a one-byte long form = %x, %v", got, err)
	}
}

// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/x509"
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

func TestPrivateKeyRefusesBrokenRSAKeys(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keys.json")
	for name, key := range map[string]string{
		"member missing": `{"kty":"RSA","kid":"k","d":"AQ","n":"AQ","e":"AQAB","p":"AQ"}`,
		"not a key":      `{"kty":"RSA","kid":"k","d":"AQ","n":"AQ","e":"AQAB","p":"Aw","q":"BQ"}`,
		"not base64url":  `{"kty":"RSA","kid":"k","d":"AQ","n":"A*","e":"AQAB","p":"Aw","q":"BQ"}`,
	} {
		if err := os.WriteFile(path, []byte(`{"keys":[`+key+`]}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := privateKey(path, "k"); err == nil {
			t.Errorf("%s: privateKey accepted it", name)
		}
	}
}

func TestCertificateGeneratorRefusesKeysOfTheWrongType(t *testing.T) {
	signers, err := loadSigners("../..", "relay/conformance/keys/test-keys.private.json", relayCertKids)
	if err != nil {
		t.Fatal(err)
	}
	signers["relay-tunnel-ca"] = signers["relay-tunnel-p256"]
	if _, err := relayCertificateCases(signers); err == nil {
		t.Error("a P-256 CA key was accepted")
	}
	signers, err = loadSigners("../..", "relay/conformance/keys/test-keys.private.json", relayCSRKids)
	if err != nil {
		t.Fatal(err)
	}
	signers["relay-tunnel"] = signers["relay-tunnel-p256"]
	if _, err := relayCSRCases(signers); err == nil {
		t.Error("a P-256 key as relay-tunnel was accepted")
	}
	if _, _, err := issue("x", leafSpec{key: "missing"}, relaySigners{"missing": "not a key"}, nil); err == nil {
		t.Error("issue accepted a key that cannot sign")
	}
}

func TestCSRHelpersRefuseUnsupportedKeys(t *testing.T) {
	if _, err := compressedCSR("not a key"); err == nil {
		t.Error("compressedCSR accepted a key that is not P-256")
	}
	signers, err := loadSigners("../..", "relay/conformance/keys/test-keys.private.json", []string{"relay-tunnel"})
	if err != nil {
		t.Fatal(err)
	}
	der, err := makeCSR(&x509.CertificateRequest{}, signers["relay-tunnel"])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := resign(der, oidEd25519, "not a key"); err == nil {
		t.Error("resign accepted a key it cannot use")
	}
}

// TestRelayProxyFileIsUpToDate: the stored PROXY cases are those the generator writes, byte
// for byte.
func TestRelayProxyFileIsUpToDate(t *testing.T) {
	out, err := runTool(t, "../..", "", "relay-proxy")
	if err != nil {
		t.Fatal(err)
	}
	stored, err := os.ReadFile("../../relay/conformance/proxy-v0.json")
	if err != nil {
		t.Fatal(err)
	}
	if out != string(stored) {
		t.Error("relay/conformance/proxy-v0.json is not what the generator writes; run: go run ./tools/vectors relay-proxy > relay/conformance/proxy-v0.json")
	}
	if _, err := runTool(t, "../..", "", "relay-proxy", "extra"); err == nil {
		t.Error("relay-proxy accepted an argument")
	}
}

// TestRelayProxyCasesAreConsistent: every accepted or optional case names the source and the
// bytes consumed that its header holds, and a refused case names neither.
func TestRelayProxyCasesAreConsistent(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range relayProxyCases() {
		seen[c.Expected] = true
		if (c.Expected == proxyRefused) != (c.Source == nil && c.Consumed == nil) {
			t.Errorf("%s: source and consumed do not fit %s", c.ID, c.Expected)
		}
		if c.Consumed != nil && *c.Consumed != 28 && *c.Consumed != 52 {
			t.Errorf("%s: consumed %d", c.ID, *c.Consumed)
		}
	}
	if !seen[proxyAccepted] || !seen[proxyRefused] || !seen[proxyEither] {
		t.Errorf("results covered: %v", seen)
	}
}

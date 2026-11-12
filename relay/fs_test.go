// SPDX-License-Identifier: Apache-2.0

package relay_test

import (
	"crypto/sha256"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/home-mandate/spec/internal/manifest"
	"github.com/home-mandate/spec/relay"
)

func TestFSHoldsSchemasExamplesAndCases(t *testing.T) {
	for _, p := range []string{relay.MetadataSchemaPath, relay.MetadataExamplePath, relay.ManifestPath,
		"conformance/metadata-v0.json", "conformance/schema/metadata-v0.schema.json"} {
		if _, err := fs.Stat(relay.FS(), p); err != nil {
			t.Errorf("%s: %v", p, err)
		}
	}
}

func TestFSNeverEmbedsTheTestKeys(t *testing.T) {
	if _, err := fs.Stat(relay.FS(), "conformance/keys"); err == nil {
		t.Fatal("conformance/keys is embedded")
	}
	keys, err := filepath.Glob("conformance/keys/*")
	if err != nil || len(keys) == 0 {
		t.Fatalf("no test keys found to compare with: %v", err)
	}
	private := map[string]bool{}
	for _, k := range keys {
		data, err := os.ReadFile(k)
		if err != nil {
			t.Fatal(err)
		}
		private[string(data)] = true
	}
	err = fs.WalkDir(relay.FS(), ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if strings.Contains(p, "keys") {
			t.Errorf("embedded path %s mentions keys", p)
		}
		if d.IsDir() {
			return nil
		}
		data, err := fs.ReadFile(relay.FS(), p)
		if private[string(data)] {
			t.Errorf("%s is a test key file", p)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestFSHoldsEveryFileOfTheManifest: every file that conformance/manifest.json lists, apart
// from conformance/keys, can be read through FS with the recorded digest (spec#144).
func TestFSHoldsEveryFileOfTheManifest(t *testing.T) {
	data, err := fs.ReadFile(relay.FS(), relay.ManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := manifest.Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	read, keys := 0, 0
	for _, file := range stored.Files {
		name, ok := strings.CutPrefix(file.Path, "relay/")
		if !ok {
			t.Errorf("%s is outside relay/", file.Path)
			continue
		}
		if strings.HasPrefix(name, "conformance/keys/") {
			keys++
			continue
		}
		data, err := fs.ReadFile(relay.FS(), name)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(data)); got != file.SHA256 {
			t.Errorf("%s: sha256 %s, manifest %s", name, got, file.SHA256)
		}
		read++
	}
	if read+keys != len(stored.Files) || read == 0 {
		t.Errorf("read %d files and skipped %d keys of %d in the manifest", read, keys, len(stored.Files))
	}
}

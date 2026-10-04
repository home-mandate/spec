// SPDX-License-Identifier: Apache-2.0

package manifest_test

import (
	"strings"
	"testing"
	"testing/fstest"

	"github.com/mandate-spec/mandate-spec/internal/manifest"
)

func testFS() fstest.MapFS {
	return fstest.MapFS{
		"conformance/cases-v0.json":      {Data: []byte(`{"description":"d","cases":[{"id":"c01"},{"id":"c02"}]}`)},
		"conformance/audit-v0.json":      {Data: []byte(`{"description":"d","logs":[{"id":"a01"}]}`)},
		"conformance/mandates/time.json": {Data: []byte(`{}`)},
		"conformance/manifest.json":      {Data: []byte(`stale`)},
		"conformance/schema/cases.json":  {Data: []byte(`{}`)},
		"examples/voice.json":            {Data: []byte(`{}`)},
		"schema/mandate-v0.schema.json":  {Data: []byte(`{}`)},
		"schema/schema.go":               {Data: []byte(`package schema`)},
		"vocabulary/v0.json":             {Data: []byte(`{}`)},
		"data/forbidden-codepoints.json": {Data: []byte(`{}`)},
		"unrelated/x.json":               {Data: []byte(`{}`)},
	}
}

func TestBuildListsSpecFilesSortedWithDigestAndCount(t *testing.T) {
	m, err := manifest.Build(testFS())
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, f := range m.Files {
		paths = append(paths, f.Path)
	}
	want := "conformance/audit-v0.json conformance/cases-v0.json conformance/mandates/time.json " +
		"conformance/schema/cases.json data/forbidden-codepoints.json examples/voice.json " +
		"schema/mandate-v0.schema.json vocabulary/v0.json"
	if got := strings.Join(paths, " "); got != want {
		t.Fatalf("paths = %s\nwant    %s", got, want)
	}
	if m.Files[0].Cases != 1 || m.Files[1].Cases != 2 || m.Files[2].Cases != 0 {
		t.Errorf("counts = %d %d %d, want 1 2 0", m.Files[0].Cases, m.Files[1].Cases, m.Files[2].Cases)
	}
	// SHA-256 of "{}".
	if got := m.Files[2].SHA256; got != "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a" {
		t.Errorf("sha256 = %s", got)
	}
}

func TestBuildRejectsConformanceFileWithoutCases(t *testing.T) {
	fsys := testFS()
	fsys["conformance/digest-v0.json"] = &fstest.MapFile{Data: []byte(`{"description":"d"}`)}
	if _, err := manifest.Build(fsys); err == nil {
		t.Fatal("Build accepted a conformance file without cases")
	}
	fsys["conformance/digest-v0.json"] = &fstest.MapFile{Data: []byte(`not json`)}
	if _, err := manifest.Build(fsys); err == nil {
		t.Fatal("Build accepted a conformance file that is not JSON")
	}
}

func TestEncodeIsStableAndRoundTrips(t *testing.T) {
	m, err := manifest.Build(testFS())
	if err != nil {
		t.Fatal(err)
	}
	a, err := manifest.Encode(m)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(string(a), "}\n") {
		t.Error("encoded manifest does not end with a newline")
	}
	back, err := manifest.Decode(a)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := manifest.Encode(back)
	if string(a) != string(b) {
		t.Error("Encode(Decode(x)) differs from x")
	}
	if _, err := manifest.Decode([]byte(`{"spec":"v0","files":[],"extra":1}`)); err == nil {
		t.Error("Decode accepted an unknown field")
	}
}

func TestDiffReportsChangedMissingAndExtraFiles(t *testing.T) {
	m, _ := manifest.Build(testFS())
	if d := manifest.Diff(m, m); len(d) != 0 {
		t.Fatalf("Diff of equal manifests = %v", d)
	}
	other := manifest.Manifest{Spec: m.Spec, Files: append([]manifest.File(nil), m.Files[1:]...)}
	other.Files[0].SHA256 = "00"
	other.Files = append(other.Files, manifest.File{Path: "zz/new.json"})
	d := strings.Join(manifest.Diff(m, other), "\n")
	for _, want := range []string{"conformance/audit-v0.json", "conformance/cases-v0.json", "zz/new.json"} {
		if !strings.Contains(d, want) {
			t.Errorf("Diff does not mention %s:\n%s", want, d)
		}
	}
}

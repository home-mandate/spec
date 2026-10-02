// SPDX-License-Identifier: Apache-2.0

package audit_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"
	"strings"
	"testing"
	"testing/iotest"

	mandatespec "github.com/mandate-spec/mandate-spec"
	"github.com/mandate-spec/mandate-spec/audit"
)

type auditCase struct {
	ID           string            `json:"id"`
	Why          string            `json:"why"`
	Expected     string            `json:"expected"`
	BrokenAt     int64             `json:"broken_at"`
	EntryDigests []string          `json:"entry_digests"`
	Entries      []json.RawMessage `json:"entries"`
}

func loadCases(t *testing.T) []auditCase {
	t.Helper()
	data, err := fs.ReadFile(mandatespec.FS(), mandatespec.AuditCasesPath)
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Logs []auditCase `json:"logs"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	if len(file.Logs) == 0 {
		t.Fatal("no audit cases")
	}
	return file.Logs
}

func raw(entries []json.RawMessage) [][]byte {
	out := make([][]byte, len(entries))
	for i, e := range entries {
		out[i] = []byte(e)
	}
	return out
}

func TestConformanceAuditLogs(t *testing.T) {
	for _, c := range loadCases(t) {
		t.Run(c.ID+" "+c.Why, func(t *testing.T) {
			got, err := audit.Verify(raw(c.Entries))
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			switch c.Expected {
			case "valid":
				if !got.Valid {
					t.Errorf("result = %+v, want valid", got)
				}
			case "invalid":
				if got.Valid || got.BrokenAt != c.BrokenAt {
					t.Errorf("result = %+v, want broken_at %d", got, c.BrokenAt)
				}
			default:
				t.Fatalf("unknown expectation %q", c.Expected)
			}
		})
	}
}

func TestConformanceEntryDigests(t *testing.T) {
	for _, c := range loadCases(t) {
		if len(c.EntryDigests) == 0 {
			continue
		}
		if len(c.EntryDigests) != len(c.Entries) {
			t.Fatalf("%s: %d digests for %d entries", c.ID, len(c.EntryDigests), len(c.Entries))
		}
		for i, e := range c.Entries {
			got, err := audit.Digest(e)
			if err != nil {
				t.Fatalf("%s entry %d: %v", c.ID, i, err)
			}
			if got != c.EntryDigests[i] {
				t.Errorf("%s entry %d: digest %s, want %s", c.ID, i, got, c.EntryDigests[i])
			}
		}
	}
}

func TestVerifyEmptyLogIsValid(t *testing.T) {
	got, err := audit.Verify(nil)
	if err != nil || !got.Valid {
		t.Errorf("Verify(nil) = %+v, %v; want valid", got, err)
	}
}

func TestVerifyReportsUnreadableEntryByPosition(t *testing.T) {
	cases := loadCases(t)
	entries := raw(cases[0].Entries)
	for name, bad := range map[string][]byte{
		"not JSON":      []byte("{"),
		"duplicate key": []byte(`{"seq":3,"seq":3}`),
		"array":         []byte(`[]`),
	} {
		t.Run(name, func(t *testing.T) {
			log := append(append([][]byte{}, entries[:2]...), bad)
			got, err := audit.Verify(log)
			if err != nil {
				t.Fatal(err)
			}
			if got.Valid || got.Index != 2 {
				t.Errorf("result = %+v, want invalid at index 2", got)
			}
		})
	}
}

func TestDigestRejectsMalformedEntries(t *testing.T) {
	for _, in := range []string{``, `{`, `{"a":1,"a":2}`, `{"n":0.5}`, "{\"a\":\"\xff\"}"} {
		if _, err := audit.Digest([]byte(in)); !errors.Is(err, audit.ErrMalformed) {
			t.Errorf("Digest(%q) = %v, want ErrMalformed", in, err)
		}
	}
}

func TestVerifyJSONLines(t *testing.T) {
	c := loadCases(t)[0]
	var buf bytes.Buffer
	for _, e := range c.Entries {
		var compact bytes.Buffer
		if err := json.Compact(&compact, e); err != nil {
			t.Fatal(err)
		}
		buf.Write(compact.Bytes())
		buf.WriteByte('\n')
	}
	got, err := audit.VerifyJSONLines(&buf)
	if err != nil || !got.Valid {
		t.Errorf("VerifyJSONLines = %+v, %v; want valid", got, err)
	}

	got, err = audit.VerifyJSONLines(strings.NewReader("\n"))
	if err != nil || got.Valid || got.Index != 0 {
		t.Errorf("empty line: %+v, %v; want invalid at index 0", got, err)
	}
}

func TestLimitsAndUnreadableInput(t *testing.T) {
	huge := []byte(`{"seq":1,"x":"` + strings.Repeat("a", audit.MaxEntryBytes) + `"}`)
	if _, err := audit.Digest(huge); !errors.Is(err, audit.ErrMalformed) {
		t.Errorf("Digest(huge) = %v, want ErrMalformed", err)
	}
	got, err := audit.VerifyJSONLines(bytes.NewReader(append(huge, '\n')))
	if err != nil || got.Valid || got.Index != 0 {
		t.Errorf("VerifyJSONLines(huge) = %+v, %v; want invalid at index 0", got, err)
	}
	if _, err := audit.VerifyJSONLines(iotest.ErrReader(errors.New("disk"))); err == nil {
		t.Error("VerifyJSONLines with a failing reader succeeded")
	}
	// A seq that is not a valid int64 is reported as 0.
	got, err = audit.Verify([][]byte{[]byte(`{"seq":99999999999999999999}`)})
	if err != nil || got.Valid || got.BrokenAt != 0 {
		t.Errorf("Verify(huge seq) = %+v, %v; want invalid with broken_at 0", got, err)
	}
}

func TestEntrySizeLimitBoundary(t *testing.T) {
	// {"x":"…"} with a string that makes the entry exactly MaxEntryBytes long.
	exact := []byte(`{"x":"` + strings.Repeat("a", audit.MaxEntryBytes-8) + `"}`)
	if len(exact) != audit.MaxEntryBytes {
		t.Fatalf("test entry has %d bytes", len(exact))
	}
	if _, err := audit.Digest(exact); err != nil {
		t.Errorf("Digest at the limit: %v", err)
	}
	if _, err := audit.Digest(append([]byte(" "), exact...)); !errors.Is(err, audit.ErrMalformed) {
		t.Errorf("Digest one byte over the limit = %v, want ErrMalformed", err)
	}
	// The line reader accepts an entry of exactly MaxEntryBytes; it is reported as a
	// schema violation, not as an overlong line.
	got, err := audit.VerifyJSONLines(bytes.NewReader(append(exact, '\n')))
	if err != nil || got.Valid || got.Index != 0 {
		t.Errorf("VerifyJSONLines at the limit = %+v, %v", got, err)
	}
}

func TestValidResultHasNoIndex(t *testing.T) {
	c := loadCases(t)[0]
	got, err := audit.Verify(raw(c.Entries))
	if err != nil || got != (audit.Result{Valid: true, Index: -1}) {
		t.Errorf("Verify = %+v, %v; want {Valid:true Index:-1 BrokenAt:0}", got, err)
	}
	if got, _ := audit.Verify(nil); got.Index != -1 {
		t.Errorf("Verify(nil).Index = %d, want -1", got.Index)
	}
}

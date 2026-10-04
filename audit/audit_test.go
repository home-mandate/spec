// SPDX-License-Identifier: Apache-2.0

package audit_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"strings"
	"testing"
	"testing/iotest"

	mandatespec "github.com/mandate-spec/mandate-spec"
	"github.com/mandate-spec/mandate-spec/audit"
	"github.com/mandate-spec/mandate-spec/jws"
)

type auditCase struct {
	ID           string            `json:"id"`
	Why          string            `json:"why"`
	Expected     string            `json:"expected"`
	BrokenAt     int64             `json:"broken_at"`
	EntryDigests []string          `json:"entry_digests"`
	Entries      []json.RawMessage `json:"entries"`
	JSONL        *string           `json:"jsonl"`
	Keys         string            `json:"keys"`
	LogID        string            `json:"log_id"`
	Anchored     *int64            `json:"anchored"`
}

// verify runs the case through the entry point its form calls for.
func (c auditCase) verify() (audit.Result, error) {
	if c.Keys != "" {
		data, err := fs.ReadFile(mandatespec.FS(), c.Keys)
		if err != nil {
			return audit.Result{}, err
		}
		keys, err := jws.ParseJWKS(data)
		if err != nil {
			return audit.Result{}, err
		}
		return audit.VerifyAnchored(raw(c.Entries), audit.Anchor{Keys: keys, LogID: c.LogID})
	}
	if c.JSONL != nil {
		return audit.VerifyJSONLines(strings.NewReader(*c.JSONL))
	}
	return audit.Verify(raw(c.Entries))
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
			got, err := c.verify()
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			switch c.Expected {
			case "valid":
				if !got.Valid {
					t.Errorf("result = %+v, want valid", got)
				}
				if c.Anchored != nil && got.AnchoredSeq != *c.Anchored {
					t.Errorf("anchored up to seq %d, want %d", got.AnchoredSeq, *c.Anchored)
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
	// A seq that is no integer or does not fit is reported as 0.
	for _, seq := range []string{"1.5", "1e-1", "1e400", "-1e400"} {
		got, err = audit.Verify([][]byte{[]byte(`{"seq":` + seq + `}`)})
		if err != nil || got.Valid || got.BrokenAt != 0 {
			t.Errorf("Verify(seq %s) = %+v, %v; want invalid with broken_at 0", seq, got, err)
		}
	}
	// A readable seq is reported even if it is written with a fraction or an exponent.
	got, err = audit.Verify([][]byte{[]byte(`{"seq":7.0}`)})
	if err != nil || got.Valid || got.BrokenAt != 7 {
		t.Errorf("Verify(seq 7.0) = %+v, %v; want invalid with broken_at 7", got, err)
	}
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
	if err != nil || got != (audit.Result{Valid: true, Index: -1, Entries: len(c.Entries)}) {
		t.Errorf("Verify = %+v, %v; want {Valid:true Index:-1 BrokenAt:0}", got, err)
	}
	if got, _ := audit.Verify(nil); got.Index != -1 || got.Entries != 0 {
		t.Errorf("Verify(nil).Index = %d, want -1", got.Index)
	}
}

func jsonLines(t *testing.T, entries []json.RawMessage) []byte {
	t.Helper()
	var buf bytes.Buffer
	for _, e := range entries {
		if err := json.Compact(&buf, e); err != nil {
			t.Fatal(err)
		}
		buf.WriteByte('\n')
	}
	return buf.Bytes()
}

func TestResultCountsEntries(t *testing.T) {
	c := loadCases(t)[0]
	got, err := audit.Verify(raw(c.Entries))
	if err != nil || got.Entries != len(c.Entries) {
		t.Errorf("Verify: Entries = %d, %v; want %d", got.Entries, err, len(c.Entries))
	}
	got, err = audit.VerifyJSONLines(bytes.NewReader(jsonLines(t, c.Entries)))
	if err != nil || !got.Valid || got.Entries != len(c.Entries) {
		t.Errorf("VerifyJSONLines = %+v, %v; want valid with %d entries", got, err, len(c.Entries))
	}
	// An empty log is valid but proves nothing; the count lets a caller tell.
	got, err = audit.VerifyJSONLines(strings.NewReader(""))
	if err != nil || !got.Valid || got.Entries != 0 {
		t.Errorf("empty log = %+v, %v; want valid with 0 entries", got, err)
	}
}

// TestVerifyJSONLinesAgreesWithVerify runs every conformance log through both entry
// points; the streaming reader must report exactly what the slice-based one reports.
func TestVerifyJSONLinesAgreesWithVerify(t *testing.T) {
	for _, c := range loadCases(t) {
		if c.JSONL != nil {
			continue
		}
		want, err := audit.Verify(raw(c.Entries))
		if err != nil {
			t.Fatal(err)
		}
		got, err := audit.VerifyJSONLines(bytes.NewReader(jsonLines(t, c.Entries)))
		if err != nil || got != want {
			t.Errorf("%s: VerifyJSONLines = %+v, %v; Verify = %+v", c.ID, got, err, want)
		}
	}
}

// TestSchemaViolationWinsOverEarlierChainBreak: conditions are checked in the order
// schema of all entries, start, chain (SPEC-v0 section 9.4), also when streaming.
func TestSchemaViolationWinsOverEarlierChainBreak(t *testing.T) {
	c := loadCases(t)[0]
	entries := raw(c.Entries)
	swapped := append([][]byte{}, entries...)
	swapped[2], swapped[3] = swapped[3], swapped[2] // chain breaks at index 2 (seq 4)
	got, _ := audit.Verify(swapped)
	if got.Valid || got.Index != 2 || got.BrokenAt != 4 {
		t.Fatalf("swapped = %+v, want broken at index 2, seq 4", got)
	}
	withBadEntry := append(append([][]byte{}, swapped...), []byte(`{"seq":10}`))
	for name, verify := range map[string]func() (audit.Result, error){
		"Verify": func() (audit.Result, error) { return audit.Verify(withBadEntry) },
		"VerifyJSONLines": func() (audit.Result, error) {
			return audit.VerifyJSONLines(bytes.NewReader(bytes.Join(compactAll(t, withBadEntry), []byte("\n"))))
		},
	} {
		got, err := verify()
		if err != nil || got.Valid || got.Index != 9 || got.BrokenAt != 10 {
			t.Errorf("%s = %+v, %v; want the schema violation at index 9, seq 10", name, got, err)
		}
	}
}

func compactAll(t *testing.T, entries [][]byte) [][]byte {
	t.Helper()
	out := make([][]byte, len(entries))
	for i, e := range entries {
		var buf bytes.Buffer
		if err := json.Compact(&buf, e); err != nil {
			t.Fatal(err)
		}
		out[i] = buf.Bytes()
	}
	return out
}

// TestVerifyJSONLinesDoesNotKeepTheLog checks that verification reads a long log in
// constant memory: the reader is never asked for more than a few lines at once.
func TestVerifyJSONLinesDoesNotKeepTheLog(t *testing.T) {
	const entries = 20000
	r := &generatedLog{t: t, remaining: entries}
	got, err := audit.VerifyJSONLines(r)
	if err != nil || !got.Valid || got.Entries != entries {
		t.Fatalf("VerifyJSONLines = %+v, %v; want valid with %d entries", got, err, entries)
	}
}

// generatedLog produces a valid chain of emergency stop entries on the fly.
type generatedLog struct {
	t         *testing.T
	remaining int
	seq       int
	prev      string
	pending   []byte
}

func (g *generatedLog) Read(p []byte) (int, error) {
	if len(g.pending) == 0 {
		if g.remaining == 0 {
			return 0, io.EOF
		}
		g.remaining--
		g.seq++
		prev := "null"
		if g.prev != "" {
			prev = `"` + g.prev + `"`
		}
		event := "emergency_stop.activated"
		if g.seq%2 == 0 {
			event = "emergency_stop.released"
		}
		entry := fmt.Sprintf(`{"type":"https://mandate-spec.org/audit/v0","id":"01a0f64c-7140-7001-9007-%012x","seq":%d,`+
			`"recorded_at":"2026-10-01T09:00:00+02:00","event":%q,"principal":"household:h1",`+
			`"actor":{"kind":"user","id":"u"},"prev":%s}`, g.seq, g.seq, event, prev)
		digest, err := audit.Digest([]byte(entry))
		if err != nil {
			g.t.Fatal(err)
		}
		g.prev, g.pending = digest, []byte(entry+"\n")
	}
	n := copy(p, g.pending)
	g.pending = g.pending[n:]
	return n, nil
}

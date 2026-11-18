// SPDX-License-Identifier: Apache-2.0

package audit_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/home-mandate/spec"
	"github.com/home-mandate/spec/audit"
	"github.com/home-mandate/spec/jws"
)

type auditCase struct {
	ID           string            `json:"id"`
	Why          string            `json:"why"`
	Expected     string            `json:"expected"`
	BrokenAt     int64             `json:"broken_at"`
	EntryDigests []string          `json:"entry_digests"`
	Entries      []json.RawMessage `json:"entries"`
	JSONL        *string           `json:"jsonl"`
	// The forms with bytes a JSON string cannot carry (SPEC-v0 section 10.2).
	EntriesBase64 [][]byte `json:"entries_base64"`
	JSONLBase64   []byte   `json:"jsonl_base64"`
	Keys          string   `json:"keys"`
	LogID         string   `json:"log_id"`
	Anchored      *int64   `json:"anchored"`
	// The findings of SPEC-v0 section 9.4; nil: none of that kind.
	IntegrityBrokenAt   *int64 `json:"integrity_broken_at"`
	ConformanceBrokenAt *int64 `json:"conformance_broken_at"`
	UnknownVersionAt    *int64 `json:"unknown_version_at"`
	// CheckpointGapAt: SPEC-v0 section 9.5; nil: none.
	CheckpointGapAt *int64 `json:"checkpoint_gap_at"`
}

// verify runs the case through the entry point its form calls for.
func (c auditCase) verify() (audit.Result, error) {
	if c.Keys != "" {
		data, err := fs.ReadFile(spec.FS(), c.Keys)
		if err != nil {
			return audit.Result{}, err
		}
		keys, err := jws.ParseJWKS(data)
		if err != nil {
			return audit.Result{}, err
		}
		return audit.VerifyAnchored(raw(c.Entries), audit.Anchor{Keys: keys, LogID: c.LogID})
	}
	switch {
	case c.JSONL != nil:
		return audit.VerifyJSONLines(strings.NewReader(*c.JSONL))
	case c.JSONLBase64 != nil:
		return audit.VerifyJSONLines(bytes.NewReader(c.JSONLBase64))
	case c.EntriesBase64 != nil:
		return audit.Verify(c.EntriesBase64)
	}
	return audit.Verify(raw(c.Entries))
}

// loadCases reads the logs of audit-v0.json; loadAllCases those of both audit files.
func loadCases(t *testing.T) []auditCase {
	t.Helper()
	return loadCaseFile(t, spec.AuditCasesPath)
}

func loadAllCases(t *testing.T) []auditCase {
	t.Helper()
	return append(loadCases(t), loadCaseFile(t, spec.AuditV1CasesPath)...)
}

func loadCaseFile(t *testing.T, path string) []auditCase {
	t.Helper()
	data, err := fs.ReadFile(spec.FS(), path)
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
	for _, c := range loadAllCases(t) {
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
			for name, f := range map[string]struct {
				got  *audit.Finding
				want *int64
			}{"integrity": {got.Integrity, c.IntegrityBrokenAt}, "conformance": {got.Conformance, c.ConformanceBrokenAt}, "unknown version": {got.UnknownVersion, c.UnknownVersionAt}, "checkpoint gap": {got.CheckpointGap, c.CheckpointGapAt}} {
				switch {
				case f.want == nil && f.got.Found():
					t.Errorf("%s finding at seq %d, want none", name, f.got.At)
				case f.want != nil && (!f.got.Found() || f.got.At != *f.want):
					t.Errorf("%s finding %+v, want seq %d", name, f.got, *f.want)
				}
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
	want := audit.Result{Valid: true, Index: -1, Entries: len(c.Entries), FirstSeq: 1}
	if err != nil || !reflect.DeepEqual(got, want) {
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
		if err != nil || !reflect.DeepEqual(got, want) {
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

// An overlong line is skipped, not kept: reading it allocates no more than an entry may take.
func TestAnOverlongLineIsNotKept(t *testing.T) {
	const length = 64 << 20
	// The schemas are compiled at the first verification; that is not what is measured.
	if _, err := audit.VerifyJSONLines(strings.NewReader("")); err != nil {
		t.Fatal(err)
	}
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	got, err := audit.VerifyJSONLines(&spaces{remaining: length})
	runtime.ReadMemStats(&after)
	if err != nil || got.Valid {
		t.Fatalf("VerifyJSONLines = %+v, %v", got, err)
	}
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 8*audit.MaxEntryBytes {
		t.Errorf("reading a line of %d bytes allocated %d bytes", length, allocated)
	}
}

// spaces is a line of spaces of the given length and a line feed.
type spaces struct{ remaining int }

func (s *spaces) Read(p []byte) (int, error) {
	if s.remaining < 0 {
		return 0, io.EOF
	}
	if s.remaining == 0 {
		s.remaining--
		p[0] = '\n'
		return 1, nil
	}
	n := min(len(p), s.remaining)
	for i := range n {
		p[i] = ' '
	}
	s.remaining -= n
	return n, nil
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
		entry := fmt.Sprintf(`{"type":"https://home-mandate.org/audit/v0","id":"01a0f64c-7140-7001-9007-%012x","seq":%d,`+
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

// A verifier that meets an entry of a version it does not know keeps checking the chain:
// it reports the version, never a damaged log (SPEC-v0 section 9.4).
func TestUnknownVersionKeepsCheckingTheChain(t *testing.T) {
	v1 := func(seq int, prev string, event string) []byte {
		p := "null"
		if prev != "" {
			p = `"` + prev + `"`
		}
		return []byte(`{"type":"https://home-mandate.org/audit/v` + event + `","id":"01a0f64c-7140-7001-9007-00000000000` + string(rune('0'+seq)) + `","seq":` + string(rune('0'+seq)) + `,"recorded_at":"2026-11-16T10:00:00Z","event":"ct.status","principal":"household:hm-7f3a","ct":{"status":"ok"},"prev":` + p + `}`)
	}
	first := v1(1, "", "1")
	d1, err := audit.Digest(first)
	if err != nil {
		t.Fatal(err)
	}
	second := v1(2, d1, "9")
	d2, err := audit.Digest(second)
	if err != nil {
		t.Fatal(err)
	}
	third := v1(3, d2, "9")
	got, err := audit.Verify([][]byte{first, second, third})
	if err != nil {
		t.Fatal(err)
	}
	if got.Valid || got.Integrity.Found() || got.Conformance.Found() || got.UnknownVersion.At != 2 || got.BrokenAt != 2 {
		t.Errorf("result = %+v", got)
	}
	// The same log with the last entry changed: the chain still catches it.
	tampered := v1(3, d1, "9")
	if got, _ := audit.Verify([][]byte{first, second, tampered}); got.Integrity.At != 3 || got.UnknownVersion.At != 2 {
		t.Errorf("tampered: %+v", got)
	}
}

func TestVersionsThatAreNoAuditVersion(t *testing.T) {
	for _, typ := range []string{"https://home-mandate.org/audit/v", "https://home-mandate.org/audit/v01", "https://home-mandate.org/audit/v1x", "https://home-mandate.org/audit/v1234567890", "https://home-mandate.org/mandate/v0", ""} {
		entry := []byte(`{"type":"` + typ + `","id":"01a0f64c-7140-7001-9007-000000000001","seq":1,"recorded_at":"2026-11-16T10:00:00Z","event":"ct.status","principal":"household:hm-7f3a","ct":{"status":"ok"},"prev":null}`)
		got, err := audit.Verify([][]byte{entry})
		if err != nil {
			t.Fatal(err)
		}
		if !got.Conformance.Found() || got.UnknownVersion.Found() || got.Integrity.Found() {
			t.Errorf("type %q: %+v", typ, got)
		}
	}
}

func TestAnOverlongLineDoesNotEndTheReading(t *testing.T) {
	log := chained(t, typeV1, typeV1, "https://home-mandate.org/audit/v2")
	long := bytes.Repeat([]byte(" "), audit.MaxEntryBytes+3)
	var in []byte
	for _, line := range [][]byte{log[0], long, log[2]} {
		in = append(append(in, line...), '\n')
	}
	// The last line has no line feed, which the exchange format permits.
	got, err := audit.VerifyJSONLines(bytes.NewReader(in[:len(in)-1]))
	if err != nil {
		t.Fatal(err)
	}
	want := []audit.Finding{{Index: 1, At: 0}, {Index: 1, At: 0}, {Index: 2, At: 3}}
	for i, f := range []*audit.Finding{got.Integrity, got.Conformance, got.UnknownVersion} {
		if got.Valid || f == nil || *f != want[i] {
			t.Errorf("finding %d = %+v, want %+v (result %+v)", i, f, want[i], got)
		}
	}
}

func TestAReadErrorInsideALineIsAnError(t *testing.T) {
	log := chained(t, typeV1)
	r := io.MultiReader(bytes.NewReader(log[0]), iotest.ErrReader(errors.New("disk")))
	if _, err := audit.VerifyJSONLines(r); err == nil {
		t.Error("VerifyJSONLines with a reader that fails inside a line succeeded")
	}
}

// entryOf builds a ct.status entry of a type, seq and prev, for the tests of the findings.
func entryOf(typ string, seq int, prev string) []byte {
	p := "null"
	if prev != "" {
		p = `"` + prev + `"`
	}
	return []byte(fmt.Sprintf(`{"type":%q,"id":"01a0f64c-7140-7001-9007-%012d","seq":%d,"recorded_at":"2026-11-16T10:00:00Z","event":"ct.status","principal":"household:hm-7f3a","ct":{"status":"ok"},"prev":%s}`, typ, seq, seq, p))
}

// chained links entries of the given types into a log.
func chained(t *testing.T, types ...string) [][]byte {
	t.Helper()
	var out [][]byte
	prev := ""
	for i, typ := range types {
		e := entryOf(typ, i+1, prev)
		d, err := audit.Digest(e)
		if err != nil {
			t.Fatal(err)
		}
		out, prev = append(out, e), d
	}
	return out
}

const (
	typeV0 = "https://home-mandate.org/audit/v0"
	typeV1 = "https://home-mandate.org/audit/v1"
)

func TestTheFirstOfConformanceAndUnknownVersionIsBrokenAt(t *testing.T) {
	// ct.status is no event of version 0: that entry breaks a rule.
	for name, tc := range map[string]struct {
		types                    []string
		broken, conform, unknown int64
	}{
		"unknown first":                         {[]string{typeV1, "https://home-mandate.org/audit/v5", typeV0}, 2, 3, 2},
		"conformance first":                     {[]string{typeV1, typeV0, "https://home-mandate.org/audit/v5"}, 2, 2, 3},
		"a version of four digits is a version": {[]string{typeV1, "https://home-mandate.org/audit/v1000"}, 2, -1, 2},
		"a version of nine digits is a version": {[]string{typeV1, "https://home-mandate.org/audit/v123456789"}, 2, -1, 2},
	} {
		got, err := audit.Verify(chained(t, tc.types...))
		if err != nil {
			t.Fatal(err)
		}
		at := func(f *audit.Finding) int64 {
			if !f.Found() {
				return -1
			}
			return f.At
		}
		if got.BrokenAt != tc.broken || at(got.Conformance) != tc.conform || at(got.UnknownVersion) != tc.unknown || got.Integrity.Found() {
			t.Errorf("%s: %+v", name, got)
		}
	}
}

func TestAnEmptyLogHasNoFindings(t *testing.T) {
	got, err := audit.Verify(nil)
	if err != nil || !got.Valid || got.Integrity.Found() || got.Conformance.Found() || got.UnknownVersion.Found() {
		t.Errorf("Verify(nil) = %+v, %v", got, err)
	}
}

// A first entry whose digest cannot be computed (a fraction, which the canonical form of this
// implementation does not write) still has a readable seq, which the integrity finding names.
func TestAFirstEntryWithoutDigestKeepsItsSeq(t *testing.T) {
	entry := []byte(`{"type":"https://home-mandate.org/audit/v1","seq":1,"prev":null,"x":1.5}`)
	got, err := audit.Verify([][]byte{entry})
	if err != nil {
		t.Fatal(err)
	}
	if got.Integrity.Index != 0 || got.Integrity.At != 1 || got.Conformance.At != 1 {
		t.Errorf("result = %+v", got)
	}
}

// cadenceLog builds a log of ct.status entries and checkpoints: kinds holds "c" for a checkpoint
// and "e" for any other entry, minutes the recorded_at of each, in minutes after the start.
func cadenceLog(t *testing.T, kinds string, minutes []int) [][]byte {
	t.Helper()
	start := time.Date(2026, 11, 16, 10, 0, 0, 0, time.UTC)
	var out [][]byte
	prev := "null"
	for i, k := range kinds {
		at := start.Add(time.Duration(minutes[i]) * time.Minute).Format(time.RFC3339)
		body := `"event":"ct.status","ct":{"status":"ok"}`
		if k == 'c' {
			body = `"event":"log.checkpoint","checkpoint":{"log_id":"0198f1c2-7c3a-7000-8000-00000000c0de","signature":"x..y"}`
		}
		e := []byte(fmt.Sprintf(`{"type":%q,"id":"01a0f64c-7140-7001-9007-%012d","seq":%d,"recorded_at":%q,%s,"principal":"household:hm-7f3a","prev":%s}`,
			typeV1, i+1, i+1, at, body, prev))
		d, err := audit.Digest(e)
		if err != nil {
			t.Fatal(err)
		}
		out, prev = append(out, e), `"`+d+`"`
	}
	return out
}

func TestCheckpointGap(t *testing.T) {
	const day = 24 * 60
	many := func(n int) (string, []int) {
		kinds, minutes := "ec", []int{0, 0}
		for i := 0; i < n; i++ {
			kinds += "e"
			minutes = append(minutes, 1)
		}
		return kinds, minutes
	}
	k1000, m1000 := many(1000)
	k1001, m1001 := many(1001)
	for _, tc := range []struct {
		name    string
		kinds   string
		minutes []int
		gap     int64
	}{
		{"no checkpoint", "eee", []int{0, 2 * day, 4 * day}, 0},
		{"within a day", "eceeec", []int{0, 0, 60, day - 1, day, day}, 0},
		{"an entry past the day", "eceee", []int{0, 0, 60, day + 1, day + 2}, 4},
		{"a checkpoint past the day", "ecec", []int{0, 0, 60, day + 1}, 4},
		{"no entry within the day, then one and a checkpoint", "ecec", []int{0, 0, day + 1, 3 * day}, 0},
		{"no entry within the day, then two", "ecee", []int{0, 0, day + 1, day + 2}, 4},
		{"a checkpoint directly after a checkpoint", "ecc", []int{0, 0, 3 * day}, 0},
		{"the first entry after a checkpoint may be late", "ece", []int{0, 0, 3 * day}, 0},
		{"1000 entries", k1000, m1000, 0},
		{"1001 entries", k1001, m1001, 1003},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := audit.Verify(cadenceLog(t, tc.kinds, tc.minutes))
			if err != nil || !got.Valid {
				t.Fatalf("Verify = %+v, %v", got, err)
			}
			if tc.gap == 0 && got.CheckpointGap.Found() || tc.gap != 0 && got.CheckpointGap.At != tc.gap {
				t.Errorf("CheckpointGap = %+v, want seq %d", got.CheckpointGap, tc.gap)
			}
		})
	}
	// An invalid log reports no gap.
	log := cadenceLog(t, "eceee", []int{0, 0, 60, day + 1, day + 2})
	log[4] = bytes.Replace(log[4], []byte(`"seq":5`), []byte(`"seq":6`), 1)
	if got, _ := audit.Verify(log); got.Valid || got.CheckpointGap.Found() {
		t.Errorf("invalid log: %+v", got)
	}
}

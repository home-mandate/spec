// SPDX-License-Identifier: Apache-2.0

// Package audit computes entry digests and verifies the hash chain of audit logs
// according to SPEC-v0 section 9. Implementations write their own entries and use this
// package to check them, so that audit logs of different implementations can be
// verified with the same code.
package audit

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/mandate-spec/mandate-spec/displaytext"
	"github.com/mandate-spec/mandate-spec/internal/ijson"
	"github.com/mandate-spec/mandate-spec/jcs"
	"github.com/mandate-spec/mandate-spec/schema"
)

// ErrMalformed means an entry is not I-JSON or cannot be canonicalized.
var ErrMalformed = errors.New("audit: malformed entry")

// MaxEntryBytes bounds a single entry; real entries are a few hundred bytes.
const MaxEntryBytes = 64 << 10

const eventTruncated = "log.truncated"

// Result is the outcome of a verification (SPEC-v0 section 9.4).
type Result struct {
	Valid bool
	// Index is the position of the first violating entry in file order, starting at 0;
	// -1 if the log is valid.
	Index int
	// BrokenAt is the seq of that entry ("broken_at"); 0 if it has no readable seq.
	BrokenAt int64
	// Entries is the number of entries of a valid log; 0 for an invalid one. A valid log
	// with 0 entries proves nothing: an emptied log looks the same.
	Entries int
	// AnchoredSeq is the seq up to which a verified checkpoint covers a valid log; 0 if
	// none does or the signatures were not checked (SPEC-v0 section 9.5).
	AnchoredSeq int64
	// LogID is the identifier the checkpoints of a valid log carry; empty without one.
	LogID string
}

var auditSchema = sync.OnceValues(func() (*jsonschema.Schema, error) {
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(schema.Audit()))
	if err != nil {
		return nil, err
	}
	c := jsonschema.NewCompiler()
	c.AssertFormat()
	if err := c.AddResource(schema.AuditID, doc); err != nil {
		return nil, err
	}
	return c.Compile(schema.AuditID)
})

// Digest returns the digest of one entry: "sha256:" + hex(SHA-256(JCS(entry))).
func Digest(entry []byte) (string, error) {
	v, err := decode(entry)
	if err != nil {
		return "", err
	}
	return digestOf(v)
}

func decode(entry []byte) (any, error) {
	if len(entry) > MaxEntryBytes {
		return nil, fmt.Errorf("%w: %d bytes, limit %d", ErrMalformed, len(entry), MaxEntryBytes)
	}
	if err := ijson.Check(entry); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	v, err := jsonschema.UnmarshalJSON(bytes.NewReader(entry))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	return v, nil
}

func digestOf(v any) (string, error) {
	d, err := jcs.Digest(v)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	return d, nil
}

// link is what the chain check needs from a schema-valid entry.
type link struct {
	seq        int64
	prev       string // empty for null
	event      string
	upToSeq    int64
	lastDigest string
	digest     string
	logID      string // of a checkpoint
	signature  string // of a checkpoint
}

// Verify checks entries in file order: first the schema of all entries, then the start
// of the log, then the chain (SPEC-v0 section 9.4). The error is reserved for failures
// of the verifier itself; an invalid log is reported in the Result.
func Verify(entries [][]byte) (Result, error) {
	return verifyEntries(entries, nil)
}

func verifyEntries(entries [][]byte, anchor *Anchor) (Result, error) {
	v, err := newVerifier(anchor)
	if err != nil {
		return Result{}, err
	}
	for _, e := range entries {
		if r, done := v.add(e); done {
			return r, nil
		}
	}
	return v.finish(), nil
}

// verifier checks a log entry by entry and keeps only what the rest of the log can
// still depend on, so that a log of any length is verified in constant memory.
type verifier struct {
	compiled *jsonschema.Schema
	count    int
	first    link
	previous link
	// startCovered: a log.truncated entry accounts for everything before the first entry.
	startCovered bool
	// chainBreak is the first violation of the chain. It is reported only at the end,
	// because a schema violation further down and a wrong start come first.
	chainBreak *Result
	// anchor is nil if the signatures of checkpoints are not checked.
	anchor      *Anchor
	logID       string
	anchoredSeq int64
	// checkpointBreak is the first checkpoint that violates section 9.5; it comes last.
	checkpointBreak *Result
}

func newVerifier(anchor *Anchor) (*verifier, error) {
	compiled, err := auditSchema()
	if err != nil {
		return nil, fmt.Errorf("audit: load schema: %w", err)
	}
	return &verifier{compiled: compiled, anchor: anchor}, nil
}

// add checks the next entry. done is true if the result is final: the entry violates
// the schema.
func (v *verifier) add(entry []byte) (result Result, done bool) {
	l, ok := check(v.compiled, entry)
	if !ok {
		return broken(v.count, l.seq), true
	}
	switch {
	case v.count == 0:
		v.first = l
	case l.event == eventTruncated && l.upToSeq == v.first.seq-1 && l.lastDigest == v.first.prev:
		v.startCovered = true
	}
	if v.count > 0 && v.chainBreak == nil && (l.seq != v.previous.seq+1 || l.prev != v.previous.digest) {
		r := broken(v.count, l.seq)
		v.chainBreak = &r
	}
	if l.event == eventCheckpoint && v.checkpointBreak == nil && v.checkpoint(l) {
		r := broken(v.count, l.seq)
		v.checkpointBreak = &r
	}
	v.previous = l
	v.count++
	return Result{}, false
}

func (v *verifier) finish() Result {
	switch {
	case v.count == 0:
		return valid(0)
	case v.first.seq != 1 && !v.startCovered:
		return broken(0, v.first.seq)
	case v.chainBreak != nil:
		return *v.chainBreak
	case v.checkpointBreak != nil:
		return *v.checkpointBreak
	}
	r := valid(v.count)
	r.AnchoredSeq, r.LogID = v.anchoredSeq, v.logID
	return r
}

// check validates one entry against the schema. On failure it still returns the seq if
// it can be read, for the report.
func check(compiled *jsonschema.Schema, entry []byte) (link, bool) {
	v, err := decode(entry)
	if err != nil {
		return link{}, false
	}
	obj, _ := v.(map[string]any)
	l := link{seq: intField(obj, "seq")}
	if compiled.Validate(v) != nil || !displayable(obj) {
		return l, false
	}
	digest, err := digestOf(v)
	if err != nil {
		return l, false
	}
	l.prev, _ = obj["prev"].(string)
	l.event, _ = obj["event"].(string)
	l.digest = digest
	if c, ok := obj["checkpoint"].(map[string]any); ok {
		l.logID, _ = c["log_id"].(string)
		l.signature, _ = c["signature"].(string)
	}
	if t, ok := obj["truncated"].(map[string]any); ok {
		l.upToSeq = intField(t, "up_to_seq")
		l.lastDigest, _ = t["last_digest"].(string)
	}
	return l, true
}

// displayedFields are the members that user interfaces show to humans; the rule for
// displayed text applies to them as in a mandate (SPEC-v0 section 3.1 item 8).
var displayedFields = [][2]string{{"actor", "id"}, {"agent", "display_name"}, {"approval", "by"}}

func displayable(obj map[string]any) bool {
	for _, path := range displayedFields {
		parent, _ := obj[path[0]].(map[string]any)
		if text, ok := parent[path[1]].(string); ok && displaytext.Check(text) != nil {
			return false
		}
	}
	return true
}

// maxExactInteger is the largest integer that I-JSON (RFC 7493) guarantees to be exact.
const maxExactInteger = 1 << 53

// intField reads an integer by its value, not by its spelling: 1, 1.0 and 1e0 are the
// same number and have the same canonical form (RFC 8785). It returns 0 if the member
// is missing, is no integer or lies outside the exact range.
func intField(obj map[string]any, key string) int64 {
	n, ok := obj[key].(json.Number)
	if !ok {
		return 0
	}
	f, err := strconv.ParseFloat(n.String(), 64)
	if err != nil || f != math.Trunc(f) || math.Abs(f) > maxExactInteger {
		return 0
	}
	return int64(f)
}

func valid(entries int) Result { return Result{Valid: true, Index: -1, Entries: entries} }

func broken(index int, seq int64) Result { return Result{Index: index, BrokenAt: seq} }

// VerifyJSONLines verifies an audit log in the exchange format: one entry per line,
// separated by line feeds, UTF-8, in ascending seq order (SPEC-v0 section 9.4). It
// reads the log as a stream and does not keep it in memory.
func VerifyJSONLines(r io.Reader) (Result, error) {
	return verifyLines(r, nil)
}

func verifyLines(r io.Reader, anchor *Anchor) (Result, error) {
	v, err := newVerifier(anchor)
	if err != nil {
		return Result{}, err
	}
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 4096), MaxEntryBytes+1)
	for scanner.Scan() {
		if result, done := v.add(scanner.Bytes()); done {
			return result, nil
		}
	}
	if err := scanner.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			return broken(v.count, 0), nil
		}
		return Result{}, fmt.Errorf("audit: read: %w", err)
	}
	return v.finish(), nil
}

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
}

// Verify checks entries in file order: first the schema of all entries, then the start
// of the log, then the chain (SPEC-v0 section 9.4). The error is reserved for failures
// of the verifier itself; an invalid log is reported in the Result.
func Verify(entries [][]byte) (Result, error) {
	compiled, err := auditSchema()
	if err != nil {
		return Result{}, fmt.Errorf("audit: load schema: %w", err)
	}
	links := make([]link, len(entries))
	for i, e := range entries {
		l, ok := check(compiled, e)
		if !ok {
			return broken(i, l.seq), nil
		}
		links[i] = l
	}
	if len(links) == 0 {
		return valid(), nil
	}
	if !validStart(links) {
		return broken(0, links[0].seq), nil
	}
	for i := 1; i < len(links); i++ {
		if links[i].seq != links[i-1].seq+1 || links[i].prev != links[i-1].digest {
			return broken(i, links[i].seq), nil
		}
	}
	return valid(), nil
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

// validStart: the first entry has seq 1, or a later log.truncated entry covers
// everything before it.
func validStart(links []link) bool {
	first := links[0]
	if first.seq == 1 {
		return true
	}
	for _, l := range links[1:] {
		if l.event == eventTruncated && l.upToSeq == first.seq-1 && l.lastDigest == first.prev {
			return true
		}
	}
	return false
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

func valid() Result { return Result{Valid: true, Index: -1} }

func broken(index int, seq int64) Result { return Result{Index: index, BrokenAt: seq} }

// VerifyJSONLines verifies an audit log in the exchange format: one entry per line,
// UTF-8, in ascending seq order (SPEC-v0 section 9.4).
func VerifyJSONLines(r io.Reader) (Result, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 4096), MaxEntryBytes+1)
	var entries [][]byte
	for scanner.Scan() {
		entries = append(entries, bytes.Clone(scanner.Bytes()))
	}
	if err := scanner.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			return broken(len(entries), 0), nil
		}
		return Result{}, fmt.Errorf("audit: read: %w", err)
	}
	return Verify(entries)
}

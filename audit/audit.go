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
	"math/big"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/home-mandate/spec/displaytext"
	"github.com/home-mandate/spec/ijson"
	"github.com/home-mandate/spec/internal/jsonnum"
	"github.com/home-mandate/spec/internal/origin"
	"github.com/home-mandate/spec/jcs"
	"github.com/home-mandate/spec/rfc3339"
	"github.com/home-mandate/spec/schema"
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
	// FirstSeq is the seq of the first entry of a valid log; greater than 1 if the
	// beginning was deleted and a log.truncated entry accounts for it.
	FirstSeq int64
	// TruncationAnchored is true if FirstSeq is greater than 1 and the log.truncated
	// entry that accounts for the deleted beginning is covered by a verified checkpoint.
	// Otherwise whoever can write the log may have deleted the beginning.
	TruncationAnchored bool

	// The three findings of SPEC-v0 section 9.4, reported apart because they mean different
	// things to a household. Valid and BrokenAt above keep their meaning.
	//
	// Integrity: the first entry at which the log is not complete and unaltered (conditions
	// 2, 3 and 4, and an entry whose digest cannot be computed).
	// Each is nil if there is no such entry, so that the zero value of a Result has none.
	Integrity *Finding
	// Conformance: the first entry of a known version that breaks a rule of condition 1.
	Conformance *Finding
	// UnknownVersion: the first entry of an audit version this verifier does not know. The
	// content of the entries from there on is not checked; the chain is.
	UnknownVersion *Finding

	// CheckpointGap is, for a valid log with a checkpoint, the first entry at which the writer
	// did not keep the cadence of checkpoints of SPEC-v0 section 9.5. It is no finding, and it
	// means something only for a log whose checkpoints verify with keys: without keys anyone
	// can write a checkpoint entry. nil if there is none.
	CheckpointGap *Finding
}

// Finding names the first entry of a kind of violation.
type Finding struct {
	// Index is the position of the entry in file order, starting at 0.
	Index int
	// At is the seq of the entry, as in broken_at: 0 if it has no readable seq.
	At int64
}

// Found reports whether there is such an entry: f is not nil.
func (f *Finding) Found() bool { return f != nil }

// note records the first finding of a kind.
func note(f **Finding, index int, seq int64) {
	if *f == nil {
		*f = &Finding{Index: index, At: seq}
	}
}

// The audit versions this package reads (SPEC-v0 section 14): the type of an entry is
// typePrefix and the number of its version.
const (
	typePrefix = "https://home-mandate.org/audit/v"
	// newestVersion is the newest version this package reads and writes.
	newestVersion = 1
	// firstStrictVersion is the first version to which no correction applies (SPEC-v0
	// section 14): in an entry of it, a deviation that a correction tolerates in an earlier
	// version breaks condition 1, and the entry keeps its digest and its place in the chain.
	firstStrictVersion = 1
	// maxVersionDigits bounds the number of a version, as the grammar of SPEC-v0 section 14
	// does: a longer number names no audit version.
	maxVersionDigits = 9
)

// auditSchemas are the compiled schemas, by version.
var auditSchemas = sync.OnceValues(func() ([]*jsonschema.Schema, error) {
	var out []*jsonschema.Schema
	for _, s := range []struct {
		id  string
		doc []byte
	}{{schema.AuditID, schema.Audit()}, {schema.AuditV1ID, schema.AuditV1()}} {
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(s.doc))
		if err != nil {
			return nil, err
		}
		c := jsonschema.NewCompiler()
		c.AssertFormat()
		if err := c.AddResource(s.id, doc); err != nil {
			return nil, err
		}
		compiled, err := c.Compile(s.id)
		if err != nil {
			return nil, err
		}
		out = append(out, compiled)
	}
	return out, nil
})

// versionOf reads the version an entry names in its type: ok is false if the type names no
// audit version at all. A version is written in decimal without a leading zero.
func versionOf(obj map[string]any) (version int, ok bool) {
	t, _ := obj["type"].(string)
	digits, found := strings.CutPrefix(t, typePrefix)
	if !found || digits == "" || len(digits) > maxVersionDigits || (digits[0] == '0' && digits != "0") ||
		strings.Trim(digits, "0123456789") != "" {
		return 0, false
	}
	n, err := strconv.Atoi(digits)
	return n, err == nil
}

// Digest returns the digest of one entry: "sha256:" + hex(SHA-256(JCS(entry))).
func Digest(entry []byte) (string, error) {
	v, err := decode(entry)
	if err != nil {
		return "", err
	}
	return digestOf(v)
}

// CheckNew checks that an entry may be written: the rules for a new entry are stricter than
// what Verify accepts in an existing log (SPEC-v0 section 14, Correction).
func CheckNew(entry []byte) error {
	return checkEntry(entry, ijson.Check)
}

func checkEntry(entry []byte, check func([]byte) error) error {
	if len(entry) > MaxEntryBytes {
		return fmt.Errorf("%w: %d bytes, limit %d", ErrMalformed, len(entry), MaxEntryBytes)
	}
	if err := check(entry); err != nil {
		return fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	return nil
}

func decode(entry []byte) (any, error) {
	if err := checkEntry(entry, ijson.CheckRecorded); err != nil {
		return nil, err
	}
	v, err := jsonschema.UnmarshalJSON(bytes.NewReader(entry))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	return jsonnum.ZeroNumbers(v), nil
}

func digestOf(v any) (string, error) {
	d, err := jcs.Digest(v)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	return d, nil
}

// link is what the chain check needs from an entry.
type link struct {
	seq        int64
	prev       string // empty for null
	event      string
	upToSeq    int64
	lastDigest string
	digest     string
	logID      string // of a checkpoint
	signature  string // of a checkpoint
	recordedAt string // of a checkpoint, as written: the signature covers it
	// at is the time recorded_at names; zero if it cannot be read.
	at time.Time
	// conforming: the entry is of a known version and keeps condition 1.
	conforming bool
}

// Verify checks entries in file order: first the schema of all entries, then the start
// of the log, then the chain (SPEC-v0 section 9.4). The error is reserved for failures
// of the verifier itself; an invalid log is reported in the Result.
func Verify(entries [][]byte) (Result, error) {
	return verifyEntries(entries, Options{})
}

func verifyEntries(entries [][]byte, opts Options) (Result, error) {
	v, err := newVerifier(opts)
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
	schemas []*jsonschema.Schema
	count   int
	// lost: the previous entry has no digest or no readable seq, so the chain cannot be
	// checked at the next one; the integrity finding names that entry already.
	lost bool
	// newest is the newest known version of an entry so far; an older one after it breaks
	// condition 1 (SPEC-v0 section 14).
	newest int
	// integrity, conformance and unknown are the findings of the Result.
	integrity, conformance, unknown *Finding
	first                           link
	previous                        link
	// startCovered: a log.truncated entry accounts for everything before the first entry;
	// coveredAt is the seq of that entry.
	startCovered bool
	coveredAt    int64
	// chainBreak is the first violation of the chain. It is reported only at the end,
	// because a schema violation further down and a wrong start come first.
	chainBreak *Result
	// anchor is nil if the signatures of checkpoints are not checked.
	anchor      *Anchor
	logID       string
	anchoredSeq int64
	// checkpointBreak is the first checkpoint that violates section 9.5; it comes last.
	checkpointBreak *Result
	// known holds the vocabularies an unenforced deny is checked against.
	known actionsByCategory
	// cadence follows the checkpoints for CheckpointGap.
	cadence cadence
}

// The cadence of checkpoints a writer keeps (SPEC-v0 section 9.5, "The signer", item 3).
const (
	maxEntriesBetweenCheckpoints = 1000
	maxTimeBetweenCheckpoints    = 24 * time.Hour
)

// cadence follows the entries since the last checkpoint.
type cadence struct {
	seen  bool      // a checkpoint has been read
	at    time.Time // its recorded_at
	since int       // entries after it that are no checkpoint
	// firstLate: the first of them was recorded more than 24 hours after the checkpoint, so the
	// next checkpoint was due at once.
	firstLate bool
	gap       *Finding
}

// late reports whether t lies more than 24 hours after the last checkpoint.
func (c *cadence) late(t time.Time) bool {
	return !c.at.IsZero() && !t.IsZero() && t.Sub(c.at) > maxTimeBetweenCheckpoints
}

// next takes the next entry in file order. A checkpoint is due 24 hours after the previous
// one if an entry was appended in that time, and at once if the first entry since came later;
// and at the latest after 1000 further entries (SPEC-v0 section 9.5).
func (c *cadence) next(index int, l link) {
	checkpoint := l.event == eventCheckpoint
	if c.seen {
		switch {
		case checkpoint:
			if c.since > 0 && !c.firstLate && c.late(l.at) {
				note(&c.gap, index, l.seq)
			}
		case c.since == 0:
			c.firstLate = c.late(l.at)
		case c.firstLate || c.late(l.at) || c.since >= maxEntriesBetweenCheckpoints:
			note(&c.gap, index, l.seq)
		}
	}
	if checkpoint {
		c.seen, c.at, c.since, c.firstLate = true, l.at, 0, false
		return
	}
	if c.seen {
		c.since++
	}
}

func newVerifier(opts Options) (*verifier, error) {
	schemas, err := auditSchemas()
	if err != nil {
		return nil, fmt.Errorf("audit: load schema: %w", err)
	}
	known, err := knownActions(opts.Vocabularies)
	if err != nil {
		return nil, err
	}
	return &verifier{schemas: schemas, anchor: opts.Anchor, known: known}, nil
}

// add checks the next entry. Every entry is read: the findings on integrity, conformance
// and unknown versions each need the whole log. done is never true; it is kept so that a
// caller can stop early in a later version.
func (v *verifier) add(entry []byte) (result Result, done bool) {
	index := v.count
	v.count++
	l, linked := v.check(index, entry)
	if !linked {
		note(&v.integrity, index, l.seq)
		v.lost = true
		return Result{}, false
	}
	switch {
	case index == 0:
		v.first = l
	case l.event == eventTruncated && l.upToSeq == v.first.seq-1 && l.lastDigest == v.first.prev:
		if !v.startCovered {
			v.startCovered, v.coveredAt = true, l.seq
		}
	}
	if index > 0 && !v.lost && (l.seq != v.previous.seq+1 || l.prev != v.previous.digest) {
		note(&v.integrity, index, l.seq)
		if v.chainBreak == nil {
			r := broken(index, l.seq)
			v.chainBreak = &r
		}
	}
	// A checkpoint is checked whatever its version and whether or not it keeps the rules: it
	// is what anchors the log, and an entry made unreadable on purpose must not escape it.
	if l.event == eventCheckpoint && v.checkpoint(l) {
		note(&v.integrity, index, l.seq)
		if v.checkpointBreak == nil {
			r := broken(index, l.seq)
			v.checkpointBreak = &r
		}
	}
	v.cadence.next(index, l)
	v.previous, v.lost = l, false
	return Result{}, false
}

func (v *verifier) finish() Result {
	if v.count > 0 && v.first.seq != 1 && !v.startCovered && !v.lostFirst() {
		// Condition 2 is about the first entry: it comes before every other break of integrity.
		v.integrity = &Finding{Index: 0, At: v.first.seq}
	}
	var r Result
	switch {
	case v.count == 0:
		r = valid(0)
	case v.conformance.Found() || v.unknown.Found():
		// Condition 1 of the original rule: an entry of an unknown version breaks the schema
		// of every version this verifier knows.
		first := v.conformance
		if !first.Found() || (v.unknown.Found() && v.unknown.Index < first.Index) {
			first = v.unknown
		}
		r = broken(first.Index, first.At)
	case v.first.seq != 1 && !v.startCovered:
		r = broken(0, v.first.seq)
	case v.chainBreak != nil:
		r = *v.chainBreak
	case v.checkpointBreak != nil:
		r = *v.checkpointBreak
	default:
		r = valid(v.count)
		r.AnchoredSeq, r.LogID, r.FirstSeq = v.anchoredSeq, v.logID, v.first.seq
		r.TruncationAnchored = v.startCovered && v.first.seq != 1 && v.coveredAt <= v.anchoredSeq
		r.CheckpointGap = v.cadence.gap
	}
	r.Integrity, r.Conformance, r.UnknownVersion = v.integrity, v.conformance, v.unknown
	return r
}

// lostFirst reports whether the first entry could not be linked, which the integrity
// finding names already.
func (v *verifier) lostFirst() bool {
	return v.integrity.Found() && v.integrity.Index == 0
}

// check reads one entry. linked is false if the entry cannot take part in the chain: its
// digest cannot be computed or it has no readable seq. The entry is checked against the
// schema of its version and the rules of section 9.1 if this verifier knows the version; a
// violation is a conformance finding, an unknown version a finding of its own.
func (v *verifier) check(index int, entry []byte) (l link, linked bool) {
	value, err := decode(entry)
	if err != nil {
		note(&v.conformance, index, 0)
		return link{}, false
	}
	obj, isObject := value.(map[string]any)
	l = link{seq: intField(obj, "seq")}
	digest, err := digestOf(value)
	if !isObject || err != nil {
		note(&v.conformance, index, l.seq)
		return l, false
	}
	l.digest = digest
	l.prev, _ = obj["prev"].(string)
	version, isAudit := versionOf(obj)
	switch {
	case !isAudit || version < v.newest:
		// No audit version, or an older version after a newer one, known or not.
		note(&v.conformance, index, l.seq)
	case version > newestVersion:
		note(&v.unknown, index, l.seq)
	case conforms(v.schemas[version], v.known, value, obj) && (version < firstStrictVersion || ijson.Check(entry) == nil):
		l.conforming = true
	default:
		note(&v.conformance, index, l.seq)
	}
	if isAudit {
		v.newest = max(v.newest, version)
	}
	// What the chain, the start and the checkpoints need is read from every entry, also from
	// one that breaks a rule or is of an unknown version: the integrity of a log does not
	// depend on whether its writer kept the rules (section 9.4).
	l.event, _ = obj["event"].(string)
	if recorded, ok := obj["recorded_at"].(string); ok {
		l.at, _ = rfc3339.Parse(recorded)
	}
	if c, ok := obj["checkpoint"].(map[string]any); ok {
		l.logID, _ = c["log_id"].(string)
		l.signature, _ = c["signature"].(string)
		l.recordedAt, _ = obj["recorded_at"].(string)
	}
	if t, ok := obj["truncated"].(map[string]any); ok {
		l.upToSeq = intField(t, "up_to_seq")
		l.lastDigest, _ = t["last_digest"].(string)
	}
	return l, l.seq >= 1
}

// conforms checks an entry of a known version against its schema and against the rules of
// section 9.1 that a schema cannot express.
func conforms(compiled *jsonschema.Schema, known actionsByCategory, value any, obj map[string]any) bool {
	return compiled.Validate(value) == nil && displayable(obj) && distinctFormerValues(obj) && distinctAreas(obj) &&
		truncatesEarlier(obj) && exportsEarlier(obj) && enforcedConsistent(obj, known) && vocabularyConsistent(obj, known) &&
		publicOriginValid(obj) && trustedProxyValid(obj)
}

// displayedFields are the members that user interfaces show to humans; the rule for
// displayed text applies to them as in a mandate (SPEC-v0 section 3.1 item 8).
var displayedFields = [][2]string{
	{"actor", "id"}, {"agent", "display_name"}, {"approval", "by"}, {"template", "name"}, {"approver", "id"},
}

func displayable(obj map[string]any) bool {
	for _, path := range displayedFields {
		parent, _ := obj[path[0]].(map[string]any)
		if text, ok := parent[path[1]].(string); ok && displaytext.Check(text) != nil {
			return false
		}
	}
	return true
}

// formerValues are the members of a change that name the former value next to the
// current one: member, current, former (SPEC-v0 section 9.1).
var formerValues = [][3]string{
	{"directory", "entity_id", "previous_entity_id"},
	{"directory", "category", "previous_category"},
	{"mandate", "digest", "previous_digest"},
	{"template", "digest", "previous_digest"},
	{"config", "value", "previous_value"},
	{"ct", "status", "previous_status"},
	{"relay", "status", "previous_status"},
	{"relay", "level", "previous_level"},
}

// distinctFormerValues reports whether every change that names a former value names one
// other than the current one; JSON Schema cannot compare two members.
func distinctFormerValues(obj map[string]any) bool {
	for _, path := range formerValues {
		change, _ := obj[path[0]].(map[string]any)
		if former, ok := change[path[2]].(string); ok && former == change[path[1]] {
			return false
		}
	}
	return true
}

// publicOriginValid reports whether a change of the public origin names values in the one
// form of SPEC-v0 section 11.7 item 1, which a pattern cannot fully express.
func publicOriginValid(obj map[string]any) bool {
	config, _ := obj["config"].(map[string]any)
	if setting, _ := config["setting"].(string); setting != "public_origin" {
		return true
	}
	for _, key := range []string{"value", "previous_value"} {
		if value, ok := config[key].(string); ok && origin.Valid(value) != nil {
			return false
		}
	}
	return true
}

// trustedProxyValid reports whether a change of a trusted proxy names an address or a prefix
// in its one canonical text form (SPEC-v0 section 9.1), which a pattern cannot fully express:
// what netip writes back for it, IPv6 as RFC 5952 recommends, and a prefix without host bits.
func trustedProxyValid(obj map[string]any) bool {
	config, _ := obj["config"].(map[string]any)
	if setting, _ := config["setting"].(string); setting != "trusted_proxy" {
		return true
	}
	for _, key := range []string{"value", "previous_value"} {
		if value, ok := config[key].(string); ok && !canonicalProxy(value) {
			return false
		}
	}
	return true
}

func canonicalProxy(value string) bool {
	if strings.Contains(value, "/") {
		p, err := netip.ParsePrefix(value)
		return err == nil && p.Masked() == p && p.String() == value
	}
	a, err := netip.ParseAddr(value)
	return err == nil && a.Zone() == "" && a.String() == value
}

// truncatesEarlier reports whether a log.truncated entry accounts only for entries before
// itself: its up_to_seq is smaller than its own seq (SPEC-v0 section 9.4). JSON Schema
// cannot compare two members.
func truncatesEarlier(obj map[string]any) bool {
	t, ok := obj["truncated"].(map[string]any)
	return !ok || intField(t, "up_to_seq") < intField(obj, "seq")
}

// distinctAreas reports whether an areas_changed entry names two different sets of areas
// (SPEC-v0 section 9.1): the order of the members does not count. JSON Schema cannot
// compare two members.
func distinctAreas(obj map[string]any) bool {
	directory, _ := obj["directory"].(map[string]any)
	current, ok := directory["areas"].([]any)
	if !ok {
		return true
	}
	former, ok := directory["previous_areas"].([]any)
	if !ok {
		return true
	}
	return !sameSet(current, former)
}

// sameSet reports whether two JSON arrays of strings hold the same members. The schema
// has already made each a set of strings.
func sameSet(a, b []any) bool {
	if len(a) != len(b) {
		return false
	}
	members := make(map[any]bool, len(a))
	for _, m := range a {
		members[m] = true
	}
	for _, m := range b {
		if !members[m] {
			return false
		}
	}
	return true
}

// exportsEarlier reports whether a log.exported entry names a range of entries before
// itself: from_seq is at most to_seq, and to_seq is smaller than its own seq (SPEC-v0
// section 9.1). JSON Schema cannot compare two members.
func exportsEarlier(obj map[string]any) bool {
	e, ok := obj["exported"].(map[string]any)
	if !ok {
		return true
	}
	from, to := intField(e, "from_seq"), intField(e, "to_seq")
	return from <= to && to < intField(obj, "seq")
}

// maxExactInteger is 2^53; integers below it are exact in every JSON implementation
// (RFC 7493).
const maxExactInteger = 1 << 53

// intField reads an integer by its value, not by its spelling: 1, 1.0 and 1e0 are the
// same number and have the same canonical form (RFC 8785). It returns 0 if the member
// is missing, is no integer or lies outside the exact range.
func intField(obj map[string]any, key string) int64 {
	n, ok := obj[key].(json.Number)
	if !ok {
		return 0
	}
	// Exactly, not through floating point: 1.00000000000000000001 is no integer.
	r, ok := new(big.Rat).SetString(n.String())
	if !ok || !r.IsInt() || r.Num().CmpAbs(big.NewInt(maxExactInteger)) >= 0 {
		return 0
	}
	return r.Num().Int64()
}

func valid(entries int) Result {
	return Result{Valid: true, Index: -1, Entries: entries}
}

func broken(index int, seq int64) Result {
	return Result{Index: index, BrokenAt: seq}
}

// VerifyJSONLines verifies an audit log in the exchange format: one entry per line,
// separated by line feeds, UTF-8, in ascending seq order (SPEC-v0 section 9.4). It
// reads the log as a stream and does not keep it in memory. It reads to the end of the
// stream, whatever its size; a caller that reads a log from a source it does not trust
// bounds the stream, for example with io.LimitReader.
func VerifyJSONLines(r io.Reader) (Result, error) {
	return verifyLines(r, Options{})
}

func verifyLines(r io.Reader, opts Options) (Result, error) {
	v, err := newVerifier(opts)
	if err != nil {
		return Result{}, err
	}
	lines := bufio.NewReader(r)
	for {
		line, err := readEntry(lines)
		if errors.Is(err, io.EOF) {
			return v.finish(), nil
		}
		if err != nil {
			return Result{}, fmt.Errorf("audit: read: %w", err)
		}
		if result, done := v.add(line); done {
			return result, nil
		}
	}
}

// readEntry reads the next line of the exchange format without its line feed and without a
// carriage return before it. A line longer than an entry may be is read to its end and
// returned as nil, an entry without a readable seq, so that the entries after it are still
// read (SPEC-v0 section 9.4). io.EOF means there is no further line; a line feed after the
// last entry starts none.
func readEntry(r *bufio.Reader) ([]byte, error) {
	var line []byte
	tooLong := false
	for {
		chunk, err := r.ReadSlice('\n')
		// Room for an entry of the maximum size, a carriage return and the line feed.
		if !tooLong && len(line)+len(chunk) <= MaxEntryBytes+2 {
			line = append(line, chunk...)
		} else {
			tooLong, line = true, nil
		}
		switch {
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		case errors.Is(err, io.EOF) && (len(line) > 0 || tooLong):
			// The last line has no line feed.
		case err != nil:
			return nil, err
		}
		if tooLong {
			return nil, nil
		}
		line = bytes.TrimSuffix(line, []byte("\n"))
		return bytes.TrimSuffix(line, []byte("\r")), nil
	}
}

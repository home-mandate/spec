// SPDX-License-Identifier: Apache-2.0

package audit_test

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"strings"
	"testing"

	"github.com/mandate-spec/mandate-spec/audit"
	"github.com/mandate-spec/mandate-spec/jws"
)

const testLogID = "0198f1c2-7c3a-7000-8000-0000000000aa"

func testSigner() ed25519.PrivateKey { return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32)) }

// logBuilder writes a chained log of emergency stop entries and checkpoints.
type logBuilder struct {
	t       *testing.T
	entries [][]byte
	prev    string
}

func (b *logBuilder) add(body string) {
	b.t.Helper()
	seq := len(b.entries) + 1
	prev := "null"
	if b.prev != "" {
		prev = `"` + b.prev + `"`
	}
	entry := fmt.Sprintf(`{"type":"https://mandate-spec.org/audit/v0","id":"01a0f64c-7140-7001-9007-%012x","seq":%d,`+
		`"recorded_at":"2026-10-01T09:00:00+02:00","principal":"household:h1",%s,"prev":%s}`, seq, seq, body, prev)
	digest, err := audit.Digest([]byte(entry))
	if err != nil {
		b.t.Fatalf("entry %d: %v", seq, err)
	}
	b.entries, b.prev = append(b.entries, []byte(entry)), digest
}

func (b *logBuilder) stop() {
	b.add(`"event":"emergency_stop.activated","actor":{"kind":"user","id":"u"}`)
}

// checkpoint appends a checkpoint over everything written so far.
func (b *logBuilder) checkpoint(logID, kid string, signer any) {
	b.t.Helper()
	sig, err := audit.SignCheckpoint(logID, int64(len(b.entries)), b.prev, kid, signer)
	if err != nil {
		b.t.Fatal(err)
	}
	b.checkpointWith(logID, sig)
}

func (b *logBuilder) checkpointWith(logID, signature string) {
	b.add(fmt.Sprintf(`"event":"log.checkpoint","checkpoint":{"log_id":%q,"signature":%q}`, logID, signature))
}

func anchor() audit.Anchor {
	return audit.Anchor{Keys: jws.Keys{"log-key-1": testSigner().Public()}, LogID: testLogID}
}

func TestCheckpointAnchorsTheLog(t *testing.T) {
	b := &logBuilder{t: t}
	b.stop()
	b.stop()
	b.checkpoint(testLogID, "log-key-1", testSigner())
	b.stop()
	got, err := audit.VerifyAnchored(b.entries, anchor())
	if err != nil || !got.Valid || got.AnchoredSeq != 2 || got.LogID != testLogID || got.Entries != 4 {
		t.Fatalf("VerifyAnchored = %+v, %v; want valid, anchored up to seq 2", got, err)
	}
	b.checkpoint(testLogID, "log-key-1", testSigner())
	got, _ = audit.VerifyAnchored(b.entries, anchor())
	if !got.Valid || got.AnchoredSeq != 4 {
		t.Errorf("second checkpoint: %+v, want anchored up to seq 4", got)
	}
	// The stream reader reports the same.
	stream, err := audit.VerifyJSONLinesAnchored(bytes.NewReader(bytes.Join(b.entries, []byte("\n"))), anchor())
	if err != nil || stream != got {
		t.Errorf("VerifyJSONLinesAnchored = %+v, %v; want %+v", stream, err, got)
	}
	// Without keys the chain is checked, the signatures are not.
	plain, _ := audit.Verify(b.entries)
	if !plain.Valid || plain.AnchoredSeq != 0 || plain.LogID != testLogID {
		t.Errorf("Verify = %+v, want valid without anchor", plain)
	}
}

func TestLogWithoutCheckpointIsNotAnchored(t *testing.T) {
	b := &logBuilder{t: t}
	b.stop()
	got, err := audit.VerifyAnchored(b.entries, anchor())
	if err != nil || !got.Valid || got.AnchoredSeq != 0 || got.LogID != "" {
		t.Errorf("VerifyAnchored = %+v, %v; want valid, not anchored", got, err)
	}
}

func TestRewrittenLogDoesNotMatchItsCheckpoint(t *testing.T) {
	// The attacker rewrites the first entry, recomputes the chain and keeps the
	// signature of the original checkpoint.
	original := &logBuilder{t: t}
	original.stop()
	original.stop()
	sig, err := audit.SignCheckpoint(testLogID, 2, original.prev, "log-key-1", testSigner())
	if err != nil {
		t.Fatal(err)
	}
	forged := &logBuilder{t: t}
	forged.add(`"event":"emergency_stop.released","actor":{"kind":"user","id":"u"}`)
	forged.stop()
	forged.checkpointWith(testLogID, sig)
	if plain, _ := audit.Verify(forged.entries); !plain.Valid {
		t.Fatalf("the forged chain itself must be consistent: %+v", plain)
	}
	got, err := audit.VerifyAnchored(forged.entries, anchor())
	if err != nil || got.Valid || got.BrokenAt != 3 || got.Index != 2 {
		t.Errorf("VerifyAnchored = %+v, %v; want broken at the checkpoint (seq 3)", got, err)
	}
}

func TestCheckpointViolations(t *testing.T) {
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, 32))
	const otherLog = "0198f1c2-7c3a-7000-8000-0000000000bb"
	for name, build := range map[string]func(b *logBuilder){
		"signed with another key": func(b *logBuilder) { b.checkpoint(testLogID, "log-key-1", other) },
		"unknown key ID":          func(b *logBuilder) { b.checkpoint(testLogID, "log-key-2", testSigner()) },
		"another log":             func(b *logBuilder) { b.checkpoint(otherLog, "log-key-1", testSigner()) },
		"signature for another position": func(b *logBuilder) {
			sig, _ := audit.SignCheckpoint(testLogID, 1, b.prev, "log-key-1", testSigner())
			b.checkpointWith(testLogID, sig)
		},
		"signature for another digest": func(b *logBuilder) {
			sig, _ := audit.SignCheckpoint(testLogID, 2, "sha256:"+strings.Repeat("0", 64), "log-key-1", testSigner())
			b.checkpointWith(testLogID, sig)
		},
	} {
		t.Run(name, func(t *testing.T) {
			b := &logBuilder{t: t}
			b.stop()
			b.stop()
			build(b)
			b.stop()
			got, err := audit.VerifyAnchored(b.entries, anchor())
			if err != nil || got.Valid || got.BrokenAt != 3 {
				t.Errorf("VerifyAnchored = %+v, %v; want broken at seq 3", got, err)
			}
		})
	}
}

func TestCheckpointsOfOneLogShareTheLogID(t *testing.T) {
	b := &logBuilder{t: t}
	b.stop()
	b.checkpoint(testLogID, "log-key-1", testSigner())
	b.checkpoint("0198f1c2-7c3a-7000-8000-0000000000bb", "log-key-1", testSigner())
	// Also without keys: two log IDs in one log are a violation.
	got, err := audit.Verify(b.entries)
	if err != nil || got.Valid || got.BrokenAt != 3 {
		t.Errorf("Verify = %+v, %v; want broken at seq 3", got, err)
	}
	// Without an expected log ID the first checkpoint sets it.
	b2 := &logBuilder{t: t}
	b2.stop()
	b2.checkpoint(testLogID, "log-key-1", testSigner())
	free := audit.Anchor{Keys: anchor().Keys}
	if got, _ := audit.VerifyAnchored(b2.entries, free); !got.Valid || got.AnchoredSeq != 1 {
		t.Errorf("without expected log ID: %+v", got)
	}
}

func TestCheckpointCannotBeTheFirstEntryOfALog(t *testing.T) {
	b := &logBuilder{t: t}
	b.checkpointWith(testLogID, "eyJhbGciOiJFZERTQSIsImtpZCI6ImsifQ..AAAA")
	got, _ := audit.Verify(b.entries)
	if got.Valid || got.BrokenAt != 1 {
		t.Errorf("Verify = %+v, want a schema violation at seq 1", got)
	}
}

func TestChainBreakComesBeforeACheckpointViolation(t *testing.T) {
	b := &logBuilder{t: t}
	b.stop()
	b.stop()
	b.stop()
	b.checkpoint(testLogID, "log-key-2", testSigner()) // unknown key: violation at seq 4
	b.entries[1], b.entries[2] = b.entries[2], b.entries[1]
	got, _ := audit.VerifyAnchored(b.entries, anchor())
	if got.Valid || got.BrokenAt != 3 || got.Index != 1 {
		t.Errorf("VerifyAnchored = %+v, want the chain break at index 1", got)
	}
}

func TestSignCheckpointRejectsBadInput(t *testing.T) {
	good := "sha256:" + strings.Repeat("a", 64)
	for name, call := range map[string]func() (string, error){
		"bad log ID": func() (string, error) { return audit.SignCheckpoint("log", 1, good, "k", testSigner()) },
		"seq zero":   func() (string, error) { return audit.SignCheckpoint(testLogID, 0, good, "k", testSigner()) },
		"bad digest": func() (string, error) { return audit.SignCheckpoint(testLogID, 1, "sha256:x", "k", testSigner()) },
		"bad key":    func() (string, error) { return audit.SignCheckpoint(testLogID, 1, good, "k", "key") },
	} {
		if _, err := call(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// TestResultReportsWhereTheLogStarts: a log whose beginning was deleted is valid if a
// log.truncated entry accounts for it; the result says from which seq the log is present.
func TestResultReportsWhereTheLogStarts(t *testing.T) {
	b := &logBuilder{t: t}
	b.stop()
	b.stop()
	b.stop()
	b.checkpoint(testLogID, "log-key-1", testSigner())
	full, _ := audit.VerifyAnchored(b.entries, anchor())
	if !full.Valid || full.FirstSeq != 1 {
		t.Fatalf("full log: %+v, want FirstSeq 1", full)
	}
	// Someone with write access removes the first two entries and appends a matching
	// log.truncated after the last checkpoint.
	secondDigest, _ := audit.Digest(b.entries[1])
	b.add(`"event":"log.truncated","actor":{"kind":"system","id":"retention"},"truncated":{"up_to_seq":2,"last_digest":"` + secondDigest + `"}`)
	cut, err := audit.VerifyAnchored(b.entries[2:], anchor())
	if err != nil || !cut.Valid || cut.FirstSeq != 3 || cut.TruncationAnchored {
		t.Errorf("cut log: %+v, %v; want valid, FirstSeq 3, truncation not anchored", cut, err)
	}
	// A checkpoint after the truncation anchors it.
	b.checkpoint(testLogID, "log-key-1", testSigner())
	anchored, _ := audit.VerifyAnchored(b.entries[2:], anchor())
	if !anchored.Valid || anchored.FirstSeq != 3 || !anchored.TruncationAnchored {
		t.Errorf("after a checkpoint: %+v, want the truncation anchored", anchored)
	}
}

// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strconv"

	"github.com/mandate-spec/mandate-spec/jcs"
	"github.com/mandate-spec/mandate-spec/jws"
)

const (
	eventCheckpoint = "log.checkpoint"
	// checkpointType identifies the signed statement of a checkpoint.
	checkpointType = "https://mandate-spec.org/audit-checkpoint/v0"
)

var (
	logIDPattern  = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// Anchor is what a verifier knows from outside the log (SPEC-v0 section 9.5).
type Anchor struct {
	// Keys are the public keys that may sign checkpoints of the log, by key ID.
	Keys jws.Keys
	// LogID is the expected identifier of the log; empty accepts the one of the first
	// checkpoint.
	LogID string
}

// checkpointPayload is the statement a checkpoint signs: the log, the seq of the last
// entry it covers and that entry's digest, in canonical form.
func checkpointPayload(logID string, seq int64, digest string) ([]byte, error) {
	return jcs.Canonicalize(map[string]any{
		"type":   checkpointType,
		"log_id": logID,
		"seq":    json.Number(strconv.FormatInt(seq, 10)),
		"digest": digest,
	})
}

// SignCheckpoint returns the signature of a checkpoint over the log up to and including
// the entry seq with the given digest: a compact JWS with detached payload. The
// log.checkpoint entry that carries it is the next entry, with seq+1 and prev = digest.
// signer is an ed25519.PrivateKey or an *ecdsa.PrivateKey on P-256.
func SignCheckpoint(logID string, seq int64, digest, kid string, signer any) (string, error) {
	if !logIDPattern.MatchString(logID) {
		return "", fmt.Errorf("audit: log ID %q is not a UUID in lower case", logID)
	}
	if seq < 1 || !digestPattern.MatchString(digest) {
		return "", fmt.Errorf("audit: checkpoint needs a seq of at least 1 and a digest")
	}
	payload, err := checkpointPayload(logID, seq, digest)
	if err != nil {
		return "", fmt.Errorf("audit: %w", err)
	}
	return jws.SignDetached(payload, kid, signer)
}

// VerifyAnchored is Verify plus the check of the checkpoints against the anchor.
func VerifyAnchored(entries [][]byte, anchor Anchor) (Result, error) {
	return verifyEntries(entries, &anchor)
}

// VerifyJSONLinesAnchored is VerifyJSONLines plus the check of the checkpoints against
// the anchor.
func VerifyJSONLinesAnchored(r io.Reader, anchor Anchor) (Result, error) {
	return verifyLines(r, &anchor)
}

// checkpoint checks a log.checkpoint entry and reports whether it violates section 9.5.
func (v *verifier) checkpoint(l link) (violation bool) {
	switch {
	case v.logID == "" && v.anchor != nil && v.anchor.LogID != "" && l.logID != v.anchor.LogID:
		return true
	case v.logID == "":
		v.logID = l.logID
	case l.logID != v.logID:
		return true
	}
	if v.anchor == nil {
		return false
	}
	payload, err := checkpointPayload(l.logID, l.seq-1, l.prev)
	if err != nil {
		return true
	}
	if _, err := jws.VerifyDetached(l.signature, payload, v.anchor.Keys); err != nil {
		return true
	}
	v.anchoredSeq = l.seq - 1
	return false
}

// SPDX-License-Identifier: Apache-2.0

package harness

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"time"

	"github.com/home-mandate/spec/audit"
	"github.com/home-mandate/spec/evaluator"
	"github.com/home-mandate/spec/jws"
	"github.com/home-mandate/spec/rfc3339"
)

// maxLineBytes bounds one request: a mandate of 256 KiB inside a JSON string, several
// times for the selection, with room for escaping.
const maxLineBytes = 16 << 20

// Serve answers requests from r, one JSON object per line, with one line each on w,
// until r ends. It is the reference implementation's side of the process binding.
func Serve(r io.Reader, w io.Writer) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64<<10), maxLineBytes)
	enc := json.NewEncoder(w)
	for scanner.Scan() {
		if len(scanner.Bytes()) == 0 {
			continue
		}
		resp := Response{Error: "malformed request"}
		if req, err := decodeRequest(scanner.Bytes()); err == nil {
			resp = Answer(req)
		}
		if err := enc.Encode(resp); err != nil {
			return fmt.Errorf("harness: write: %w", err)
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("harness: read: %w", err)
	}
	return nil
}

// Version is the release of the reference code that capabilities reports (SPEC-v0 section
// 10.4), set at build time with
// -ldflags "-X github.com/home-mandate/spec/internal/harness.Version=0.1.0".
var Version = "devel"

// Answer answers one request with the reference code.
func Answer(req Request) Response {
	switch req.Op {
	case OpCapabilities:
		return Response{Name: "Home-Mandate reference (Go)", Version: Version, Ops: []string{
			OpValidate, OpEvaluate, OpSelect, OpSuccession, OpVerifySigned, OpVerifyAudit, OpEntryDigest}}
	case OpValidate:
		doc, bad := document("mandate", req.Mandate, req.MandateBase64)
		if bad != nil {
			return *bad
		}
		m, err := evaluator.Parse(doc)
		return Response{Valid: ptr(err == nil), Digest: m.Digest()}
	case OpEvaluate:
		doc, bad := document("mandate", req.Mandate, req.MandateBase64)
		if bad != nil {
			return *bad
		}
		if req.Request == nil {
			return missing("request")
		}
		m, _ := evaluator.Parse(doc) // nil evaluates to invalid_mandate
		er, ok := evaluation(*req.Request)
		if !ok {
			return invalidRequest(m)
		}
		return result(evaluator.Evaluate(m, er))
	case OpSelect:
		return selectMandate(req)
	case OpSuccession:
		return succession(req)
	case OpVerifySigned:
		return verifySigned(req)
	case OpVerifyAudit:
		return verifyAudit(req)
	case OpEntryDigest:
		if req.Entry == nil {
			return missing("entry")
		}
		digest, err := audit.Digest([]byte(*req.Entry))
		if err != nil {
			return Response{Error: "entry without a digest: " + err.Error()}
		}
		return Response{Digest: digest}
	}
	return Response{Error: ErrorUnsupported}
}

func ptr[T any](v T) *T { return &v }

// document is the bytes of a document member: its text, or the bytes of its base64
// alternative (SPEC-v0 section 10.2). A request carries exactly one of the two; bad is the
// error response otherwise.
func document(name string, text *string, b64 []byte) (doc []byte, bad *Response) {
	switch {
	case text != nil && b64 != nil:
		return nil, &Response{Error: "both " + name + " and " + name + "_base64"}
	case b64 != nil:
		return b64, nil
	case text != nil:
		return []byte(*text), nil
	}
	return nil, ptr(missing(name))
}

func missing(what string) Response { return Response{Error: "missing " + what} }

// evaluation converts the request; ok is false if the PEP could not express it: a point
// in time that is no RFC 3339 timestamp or a parameter that is neither an integer nor a
// string.
func evaluation(e Evaluation) (evaluator.Request, bool) {
	at, err := rfc3339.Parse(e.Time)
	if err != nil {
		return evaluator.Request{}, false
	}
	parameters := make(map[string]evaluator.Value, len(e.Parameters))
	for name, data := range e.Parameters {
		var value evaluator.Value
		if err := value.UnmarshalJSON(data); err != nil {
			return evaluator.Request{}, false
		}
		parameters[name] = value
	}
	status := evaluator.StatusActive
	if e.Revoked {
		status = evaluator.StatusRevoked
	}
	return evaluator.Request{
		Resource:   evaluator.Resource{EntityID: e.Resource.EntityID, Category: e.Resource.Category, Areas: e.Resource.Areas, Critical: e.Resource.Critical},
		Action:     e.Action,
		Parameters: parameters,
		Time:       at,
		TimeZone:   e.Timezone,
		Status:     status,
	}, true
}

// invalidRequest is the result for a request that could not be expressed. An invalid
// mandate comes first (SPEC-v0 section 4.1).
func invalidRequest(m *evaluator.Mandate) Response {
	if m == nil {
		return result(evaluator.Evaluate(nil, evaluator.Request{}))
	}
	return Response{Decision: string(evaluator.Deny), Reason: string(evaluator.ReasonInvalidRequest), MandateDigest: m.Digest()}
}

func result(r evaluator.Result) Response {
	resp := Response{Decision: string(r.Decision), Reason: string(r.Reason), MandateDigest: r.MandateDigest}
	if r.RuleID != "" {
		resp.RuleID = &r.RuleID
	}
	if r.Approval != nil {
		resp.ApprovalTimeout, resp.Approvers = r.Approval.Timeout, r.Approval.Approvers
	}
	if r.NotEnforced {
		resp.Enforced = ptr(false)
	}
	resp.Confirm = r.Confirm
	return resp
}

func selectMandate(req Request) Response {
	if req.Subject == nil || req.Request == nil {
		return missing("subject and request")
	}
	stored := make([]evaluator.Stored, len(req.Mandates))
	for i, s := range req.Mandates {
		status := evaluator.StatusActive
		if s.Revoked {
			status = evaluator.StatusRevoked
		}
		stored[i] = evaluator.NewStored([]byte(s.Mandate), status)
	}
	er, ok := evaluation(*req.Request)
	if !ok {
		return inexpressible(stored, req)
	}
	selected, r := evaluator.SelectAndEvaluate(stored, req.Subject.ClientID, req.Subject.Principal, er)
	resp := result(r)
	if selected != nil {
		resp.Selected = ptr(selected.ID())
	}
	return resp
}

// inexpressible answers a selection whose request the PEP could not express. The
// selection still comes first (SPEC-v0 section 4.1: no_mandate, ambiguous_mandate and
// invalid_mandate precede invalid_request), so the answer names the selected mandate.
// Without a readable point in time, nothing can be current: a sole candidate is selected
// (SPEC-v0 section 4.3 step 3), several cannot be told apart.
func inexpressible(stored []evaluator.Stored, req Request) Response {
	invalid := Response{Decision: string(evaluator.Deny), Reason: string(evaluator.ReasonInvalidRequest)}
	if !evaluator.ValidSubject(req.Subject.ClientID, req.Subject.Principal) {
		return invalid
	}
	var selected *evaluator.Mandate
	if at, err := rfc3339.Parse(req.Request.Time); err == nil {
		var r evaluator.Result
		if selected, r = evaluator.SelectAndEvaluate(stored, req.Subject.ClientID, req.Subject.Principal, evaluator.Request{Time: at}); selected == nil {
			return result(r)
		}
	} else {
		candidates := evaluator.Candidates(stored, req.Subject.ClientID, req.Subject.Principal)
		switch {
		case len(candidates) == 0:
			return Response{Decision: string(evaluator.Deny), Reason: string(evaluator.ReasonNoMandate)}
		case len(candidates) > 1:
			return invalid
		case candidates[0].Mandate() == nil:
			return result(evaluator.Evaluate(nil, evaluator.Request{}))
		}
		selected = candidates[0].Mandate()
	}
	invalid.MandateDigest, invalid.Selected = selected.Digest(), ptr(selected.ID())
	return invalid
}

func succession(req Request) Response {
	if req.Stored == nil || req.Offered == nil {
		return missing("stored and offered")
	}
	stored, err := evaluator.Parse([]byte(*req.Stored))
	if err != nil {
		return Response{Error: "stored mandate is invalid"}
	}
	offered, _ := evaluator.Parse([]byte(*req.Offered))
	if evaluator.CheckSuccessor(stored, offered) != nil {
		return Response{Accept: ptr(false)}
	}
	status := evaluator.StatusActive
	if req.StoredRevoked {
		status = evaluator.StatusRevoked
	}
	return Response{Accept: ptr(true), Confirm: evaluator.NeedsConfirmation(stored, status, time.Time{}, offered)}
}

func verifySigned(req Request) Response {
	// A key set with a key that cannot be used verifies nothing (SPEC-v0 section 10.2).
	keys, err := jws.ParseJWKS([]byte(req.Keys))
	if err != nil {
		return Response{Valid: ptr(false)}
	}
	m, err := evaluator.ParseSigned(req.JWS, evaluator.Issuers{req.Issuer: keys})
	return Response{Valid: ptr(err == nil), Digest: m.Digest()}
}

func verifyAudit(req Request) Response {
	var anchor *audit.Anchor
	if len(req.Keys) > 0 {
		keys, err := jws.ParseJWKS([]byte(req.Keys))
		if err != nil {
			return Response{Error: "keys: " + err.Error()}
		}
		anchor = &audit.Anchor{Keys: keys, LogID: req.LogID}
		if req.LastSeen != nil {
			anchor.LastSeen = &audit.Position{Seq: req.LastSeen.Seq, Digest: req.LastSeen.Digest}
		}
	} else if req.LastSeen != nil {
		return Response{Error: "last_seen without keys"}
	}
	forms := 0
	for _, given := range []bool{req.JSONL != nil, req.Entries != nil, req.JSONLBase64 != nil, req.EntriesBase64 != nil} {
		if given {
			forms++
		}
	}
	if forms > 1 {
		return Response{Error: "more than one of jsonl, entries, jsonl_base64 and entries_base64"}
	}
	list := entries(req.Entries)
	if req.EntriesBase64 != nil {
		list = req.EntriesBase64
	}
	isJSONL, jsonl := req.JSONL != nil || req.JSONLBase64 != nil, req.JSONLBase64
	if req.JSONL != nil {
		jsonl = []byte(*req.JSONL)
	}
	var r audit.Result
	var err error
	switch {
	case isJSONL && anchor != nil:
		r, err = audit.VerifyJSONLinesAnchored(bytes.NewReader(jsonl), *anchor)
	case isJSONL:
		r, err = audit.VerifyJSONLines(bytes.NewReader(jsonl))
	case anchor != nil:
		r, err = audit.VerifyAnchored(list, *anchor)
	default:
		r, err = audit.Verify(list)
	}
	if err != nil {
		return Response{Error: err.Error()}
	}
	resp := Response{Valid: ptr(r.Valid), Entries: ptr(r.Entries)}
	if !r.Valid {
		resp.BrokenAt = ptr(r.BrokenAt)
	} else if anchor != nil {
		resp.Anchored = ptr(r.AnchoredSeq)
	}
	resp.IntegrityBrokenAt = findingAt(r.Integrity)
	resp.ConformanceBrokenAt = findingAt(r.Conformance)
	resp.UnknownVersionAt = findingAt(r.UnknownVersion)
	resp.CheckpointGapAt = findingAt(r.CheckpointGap)
	return resp
}

// findingAt is the seq of a finding, or nil if there is none.
func findingAt(f *audit.Finding) *int64 {
	if !f.Found() {
		return nil
	}
	return ptr(f.At)
}

func entries(texts []string) [][]byte {
	out := make([][]byte, len(texts))
	for i, text := range texts {
		out[i] = []byte(text)
	}
	return out
}

// decodeRequest reads one request and refuses members the protocol does not define, so
// that a client using a former member name (such as "area") gets an error instead of an
// evaluation without that member.
func decodeRequest(line []byte) (Request, error) {
	if err := exactMembers(line); err != nil {
		return Request{}, err
	}
	var req Request
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		return Request{}, err
	}
	if dec.More() {
		return Request{}, errors.New("harness: more than one JSON value on a line")
	}
	if err := membersOfOp(line, req.Op); err != nil {
		return Request{}, err
	}
	return req, nil
}

// opMembers are the members each operation defines besides op and id (SPEC-v0 section 10.2).
// A member that another operation defines is as malformed as an unknown one.
var opMembers = map[string][]string{
	OpCapabilities: nil,
	OpValidate:     {"mandate", "mandate_base64"},
	OpEvaluate:     {"mandate", "mandate_base64", "request"},
	OpSelect:       {"mandates", "subject", "request"},
	OpSuccession:   {"stored", "offered", "stored_revoked"},
	OpVerifySigned: {"jws", "issuer", "keys"},
	OpVerifyAudit:  {"entries", "jsonl", "entries_base64", "jsonl_base64", "keys", "log_id"},
	OpEntryDigest:  {"entry"},
}

// membersOfOp reports a top-level member of a request that its operation does not define.
// An operation the protocol does not know is left to Answer, which answers unsupported.
func membersOfOp(line []byte, op string) error {
	allowed, known := opMembers[op]
	if !known {
		return nil
	}
	return eachMember(line, func(name string, _ []byte) error {
		if name == "op" || name == "id" || slices.Contains(allowed, name) {
			return nil
		}
		return fmt.Errorf("harness: member %q is not one of %s", name, op)
	})
}

// SPDX-License-Identifier: Apache-2.0

package harness

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/mandate-spec/mandate-spec/audit"
	"github.com/mandate-spec/mandate-spec/evaluator"
	"github.com/mandate-spec/mandate-spec/jws"
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
		var req Request
		resp := Response{Error: "malformed request"}
		if err := json.Unmarshal(scanner.Bytes(), &req); err == nil {
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

// Answer answers one request with the reference code.
func Answer(req Request) Response {
	switch req.Op {
	case OpCapabilities:
		return Response{Name: "mandate-spec reference (Go)", Version: "v0", Ops: []string{
			OpValidate, OpEvaluate, OpSelect, OpSuccession, OpVerifySigned, OpVerifyAudit, OpEntryDigest}}
	case OpValidate:
		if req.Mandate == nil {
			return missing("mandate")
		}
		m, err := evaluator.Parse([]byte(*req.Mandate))
		return Response{Valid: ptr(err == nil), Digest: m.Digest()}
	case OpEvaluate:
		if req.Mandate == nil || req.Request == nil {
			return missing("mandate and request")
		}
		m, _ := evaluator.Parse([]byte(*req.Mandate)) // nil evaluates to invalid_mandate
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
		return Response{Valid: ptr(err == nil), Digest: digest}
	}
	return Response{Error: ErrorUnsupported}
}

func ptr[T any](v T) *T { return &v }

func missing(what string) Response { return Response{Error: "missing " + what} }

// evaluation converts the request; ok is false if the PEP could not express it: a point
// in time that is no RFC 3339 timestamp or a parameter that is no integer.
func evaluation(e Evaluation) (evaluator.Request, bool) {
	at, err := time.Parse(time.RFC3339, e.Time)
	if err != nil {
		return evaluator.Request{}, false
	}
	parameters := make(map[string]int64, len(e.Parameters))
	for name, n := range e.Parameters {
		f, err := n.Float64()
		if err != nil || f != float64(int64(f)) {
			return evaluator.Request{}, false
		}
		parameters[name] = int64(f)
	}
	status := evaluator.StatusActive
	if e.Revoked {
		status = evaluator.StatusRevoked
	}
	return evaluator.Request{
		Resource:   evaluator.Resource{EntityID: e.Resource.EntityID, Category: e.Resource.Category, Area: e.Resource.Area, Critical: e.Resource.Critical},
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
		return Response{Decision: string(evaluator.Deny), Reason: string(evaluator.ReasonInvalidRequest)}
	}
	selected, r := evaluator.SelectAndEvaluate(stored, req.Subject.ClientID, req.Subject.Principal, er)
	resp := result(r)
	if selected != nil {
		resp.Selected = ptr(selected.ID())
	}
	return resp
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
	return Response{Accept: ptr(evaluator.CheckSuccessor(stored, offered) == nil)}
}

func verifySigned(req Request) Response {
	keys, err := jws.ParseJWKS(req.Keys)
	if err != nil {
		return Response{Error: "keys: " + err.Error()}
	}
	m, err := evaluator.ParseSigned(req.JWS, evaluator.Issuers{req.Issuer: keys})
	return Response{Valid: ptr(err == nil), Digest: m.Digest()}
}

func verifyAudit(req Request) Response {
	var anchor *audit.Anchor
	if len(req.Keys) > 0 {
		keys, err := jws.ParseJWKS(req.Keys)
		if err != nil {
			return Response{Error: "keys: " + err.Error()}
		}
		anchor = &audit.Anchor{Keys: keys, LogID: req.LogID}
	}
	var r audit.Result
	var err error
	switch {
	case req.JSONL != nil && anchor != nil:
		r, err = audit.VerifyJSONLinesAnchored(strings.NewReader(*req.JSONL), *anchor)
	case req.JSONL != nil:
		r, err = audit.VerifyJSONLines(strings.NewReader(*req.JSONL))
	case anchor != nil:
		r, err = audit.VerifyAnchored(entries(req.Entries), *anchor)
	default:
		r, err = audit.Verify(entries(req.Entries))
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
	return resp
}

func entries(texts []string) [][]byte {
	out := make([][]byte, len(texts))
	for i, text := range texts {
		out[i] = []byte(text)
	}
	return out
}

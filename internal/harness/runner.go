// SPDX-License-Identifier: Apache-2.0

package harness

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"slices"

	"github.com/home-mandate/spec/manifest"
)

// Conformance classes (SPEC-v0 section 8.1).
const (
	ClassEvaluator  = "evaluator"
	ClassSelection  = "selection"
	ClassSignatures = "signatures"
	ClassAudit      = "audit"
	ClassAnchored   = "audit-anchored"
	ClassPDP        = "pdp"
)

// Implementation answers requests of the process binding.
type Implementation interface {
	Do(Request) (Response, error)
}

// Local is the reference code of this repository as an Implementation.
type Local struct{}

// Do answers with the reference code.
func (Local) Do(req Request) (Response, error) { return Answer(req), nil }

// Report is the machine-readable result of a conformance run.
type Report struct {
	Spec string `json:"spec"`
	// Manifest is the SHA-256 of conformance/manifest.json: it identifies the cases.
	Manifest       string                  `json:"manifest"`
	Binding        string                  `json:"binding"`
	Implementation Described               `json:"implementation"`
	Classes        map[string]*ClassResult `json:"classes"`
	Failures       []Failure               `json:"failures"`
	// Unsupported are the optional algorithms the implementation answered unsupported for,
	// sorted; a claim of conformance names them (SPEC-v0 section 8.1).
	Unsupported []string `json:"unsupported_algorithms,omitempty"`
}

// Described is what an implementation says about itself.
type Described struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// ClassResult counts the cases of one conformance class. An implementation conforms to
// the class if it passed every case; a case it does not support counts against it.
type ClassResult struct {
	Cases    int  `json:"cases"`
	Passed   int  `json:"passed"`
	Failed   int  `json:"failed"`
	Skipped  int  `json:"skipped"`
	Conforms bool `json:"conforms"`
	// NotApplicable counts the cases that require an optional algorithm the implementation
	// does not support (SPEC-v0 section 10.2, member requires). They are not in Cases and
	// do not count against the class.
	NotApplicable int `json:"not_applicable,omitempty"`
	// NotApplicableCases are their IDs, in the order they were played (SPEC-v0 section 10.2:
	// the report lists them).
	NotApplicableCases []string `json:"not_applicable_cases,omitempty"`
}

// Failure is one case that did not yield the expected result.
type Failure struct {
	Class string `json:"class"`
	File  string `json:"file"`
	ID    string `json:"id"`
	Got   string `json:"got"`
	Want  string `json:"want"`
}

// Conforms reports whether the implementation conforms to every class it was tested for.
func (r Report) Conforms(classes ...string) bool {
	for _, class := range classes {
		if c := r.Classes[class]; c == nil || !c.Conforms {
			return false
		}
	}
	return len(classes) > 0
}

// runner collects results while cases are played.
type runner struct {
	fsys   fs.FS
	impl   Implementation
	report Report
}

func newReport(fsys fs.FS, binding string) (Report, error) {
	data, err := fs.ReadFile(fsys, manifest.Path)
	if err != nil {
		return Report{}, fmt.Errorf("conformance: %w", err)
	}
	sum := sha256.Sum256(data)
	return Report{Spec: "v0", Manifest: hex.EncodeToString(sum[:]), Binding: binding,
		Classes: map[string]*ClassResult{}, Failures: []Failure{}}, nil
}

// Run plays every conformance file of fsys that the process binding covers against impl.
func Run(fsys fs.FS, impl Implementation) (Report, error) {
	report, err := newReport(fsys, "process")
	if err != nil {
		return Report{}, err
	}
	r := &runner{fsys: fsys, impl: impl, report: report}
	caps, err := impl.Do(Request{Op: OpCapabilities})
	if err != nil {
		return Report{}, fmt.Errorf("conformance: capabilities: %w", err)
	}
	r.report.Implementation = Described{Name: caps.Name, Version: caps.Version}
	for _, play := range []func() error{r.evaluation, r.invalid, r.digests, r.selection, r.succession, r.signed, r.audit} {
		if err := play(); err != nil {
			return Report{}, err
		}
	}
	r.finish()
	return r.report, nil
}

func (r *runner) finish() {
	for _, c := range r.report.Classes {
		c.Conforms = c.Cases > 0 && c.Passed == c.Cases
	}
}

func (r *runner) class(name string) *ClassResult {
	c, ok := r.report.Classes[name]
	if !ok {
		c = &ClassResult{}
		r.report.Classes[name] = c
	}
	return c
}

// record counts one case: got and want are compared as text.
func (r *runner) record(class, file, id string, resp Response, err error, got, want string) {
	r.recordRequiring("", class, file, id, resp, err, got, want)
}

// recordRequiring is record for a case that requires an optional algorithm (requires): an
// implementation without it answers unsupported, and the case does not count.
func (r *runner) recordRequiring(requires, class, file, id string, resp Response, err error, got, want string) {
	c := r.class(class)
	if requires != "" && err == nil && resp.Error == ErrorUnsupported {
		c.NotApplicable++
		c.NotApplicableCases = append(c.NotApplicableCases, id)
		if !slices.Contains(r.report.Unsupported, requires) {
			r.report.Unsupported = append(r.report.Unsupported, requires)
			slices.Sort(r.report.Unsupported)
		}
		return
	}
	c.Cases++
	switch {
	case err != nil:
		got = "error: " + err.Error()
	case resp.Error == ErrorUnsupported:
		c.Skipped++
		return
	case resp.Error != "":
		got = "error: " + resp.Error
	case got == want:
		c.Passed++
		return
	}
	c.Failed++
	r.report.Failures = append(r.report.Failures, Failure{Class: class, File: file, ID: id, Got: got, Want: want})
}

// mandateSource is how conformance files refer to a mandate. MandateBase64 holds bytes
// that a JSON string cannot carry; it goes to the implementation as mandate_base64.
type mandateSource struct {
	Mandate       string          `json:"mandate"`
	MandateInline json.RawMessage `json:"mandate_inline"`
	MandateRaw    *string         `json:"mandate_raw"`
	MandateBase64 []byte          `json:"mandate_base64"`
}

// put sets the mandate of req in the form the case gives.
func (s mandateSource) put(fsys fs.FS, req *Request) error {
	if s.MandateBase64 != nil {
		req.MandateBase64 = s.MandateBase64
		return nil
	}
	text, err := s.text(fsys)
	req.Mandate = &text
	return err
}

func (s mandateSource) text(fsys fs.FS) (string, error) {
	switch {
	case s.Mandate != "":
		data, err := fs.ReadFile(fsys, s.Mandate)
		return string(data), err
	case s.MandateRaw != nil:
		return *s.MandateRaw, nil
	case s.MandateBase64 != nil:
		// The HTTP binding passes mandates as text: it stores only valid mandates, and the
		// bytes of a valid mandate are UTF-8.
		return string(s.MandateBase64), nil
	}
	return string(s.MandateInline), nil
}

func load[T any](fsys fs.FS, path, key string) ([]T, error) {
	data, err := fs.ReadFile(fsys, path)
	if err != nil {
		return nil, fmt.Errorf("conformance: %w", err)
	}
	var file map[string]json.RawMessage
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("conformance: %s: %w", path, err)
	}
	var cases []T
	if err := json.Unmarshal(file[key], &cases); err != nil {
		return nil, fmt.Errorf("conformance: %s: %w", path, err)
	}
	return cases, nil
}

// evaluationCase is a case of cases-v0.json and, with mandates and subject, of
// selection-v0.json.
type evaluationCase struct {
	ID string `json:"id"`
	mandateSource
	Mandates []struct {
		MandateInline json.RawMessage `json:"mandate_inline"`
		Revoked       bool            `json:"revoked"`
	} `json:"mandates"`
	Subject    *Subject                   `json:"subject"`
	Resource   Resource                   `json:"resource"`
	Action     string                     `json:"action"`
	Parameters map[string]json.RawMessage `json:"parameters"`
	Time       string                     `json:"time"`
	Timezone   string                     `json:"timezone"`
	Revoked    bool                       `json:"revoked"`
	// PDP is false for a selection case with a stored mandate that is invalid, which a PDP
	// never stores; such a case is not played over the HTTP binding.
	PDP             *bool           `json:"pdp"`
	Expected        string          `json:"expected"`
	Reason          string          `json:"reason"`
	RuleID          json.RawMessage `json:"rule_id"`
	ApprovalTimeout string          `json:"approval_timeout"`
	Enforced        *bool           `json:"enforced"`
	Confirm         bool            `json:"confirm"`
	Selected        json.RawMessage `json:"selected"`
}

func (c evaluationCase) request() *Evaluation {
	return &Evaluation{Resource: c.Resource, Action: c.Action, Parameters: c.Parameters, Time: c.Time, Timezone: c.Timezone, Revoked: c.Revoked}
}

// outcome renders what a case fixes about a result. A member the case does not give is
// not compared, except enforced and confirm: a case without them expects an enforced
// result that requires no confirmation beyond its decision.
func (c evaluationCase) outcome(decision, reason string, ruleID *string, timeout string, enforced *bool, confirm bool, selected *string) (got, want string) {
	got, want = decision+" "+reason, c.Expected+" "+c.Reason
	if notEnforced(enforced) {
		got += " enforced=false"
	}
	if notEnforced(c.Enforced) {
		want += " enforced=false"
	}
	if confirm {
		got += " confirm=true"
	}
	if c.Confirm {
		want += " confirm=true"
	}
	if c.RuleID != nil {
		got, want = got+" rule_id="+optional(ruleID), want+" rule_id="+rawOptional(c.RuleID)
	}
	if c.ApprovalTimeout != "" {
		got, want = got+" approval_timeout="+timeout, want+" approval_timeout="+c.ApprovalTimeout
	}
	if c.Selected != nil {
		got, want = got+" selected="+optional(selected), want+" selected="+rawOptional(c.Selected)
	}
	return got, want
}

// notEnforced reports whether enforced is false. Only false is meaningful; absent
// enforces.
func notEnforced(enforced *bool) bool {
	return enforced != nil && !*enforced
}

func optional(s *string) string {
	if s == nil {
		return "null"
	}
	return *s
}

// rawOptional renders a JSON string or null.
func rawOptional(raw json.RawMessage) string {
	var s *string
	if err := json.Unmarshal(raw, &s); err != nil {
		return string(raw)
	}
	return optional(s)
}

const (
	fileCases      = "conformance/cases-v0.json"
	fileInvalid    = "conformance/invalid-v0.json"
	fileDigest     = "conformance/digest-v0.json"
	fileSelection  = "conformance/selection-v0.json"
	fileSuccession = "conformance/succession-v0.json"
	fileSigned     = "conformance/signed-v0.json"
	fileAudit      = "conformance/audit-v0.json"
	fileAuditV1    = "conformance/audit-v1.json"
)

func (r *runner) evaluation() error {
	cases, err := load[evaluationCase](r.fsys, fileCases, "cases")
	for _, c := range cases {
		req := Request{Op: OpEvaluate, ID: c.ID, Request: c.request()}
		if readErr := c.put(r.fsys, &req); readErr != nil {
			return fmt.Errorf("conformance: case %s: %w", c.ID, readErr)
		}
		resp, doErr := r.impl.Do(req)
		got, want := c.outcome(resp.Decision, resp.Reason, resp.RuleID, resp.ApprovalTimeout, resp.Enforced, resp.Confirm, nil)
		r.record(ClassEvaluator, fileCases, c.ID, resp, doErr, got, want)
	}
	return err
}

func (r *runner) selection() error {
	cases, err := load[evaluationCase](r.fsys, fileSelection, "cases")
	for _, c := range cases {
		req := Request{Op: OpSelect, ID: c.ID, Subject: c.Subject, Request: c.request(), Mandates: []StoredMandate{}}
		for _, m := range c.Mandates {
			req.Mandates = append(req.Mandates, StoredMandate{Mandate: string(m.MandateInline), Revoked: m.Revoked})
		}
		resp, doErr := r.impl.Do(req)
		got, want := c.outcome(resp.Decision, resp.Reason, resp.RuleID, resp.ApprovalTimeout, resp.Enforced, resp.Confirm, resp.Selected)
		r.record(ClassSelection, fileSelection, c.ID, resp, doErr, got, want)
	}
	return err
}

type validityCase struct {
	ID string `json:"id"`
	mandateSource
	Digest string `json:"digest"`
}

func validity(resp Response) string {
	if resp.Valid != nil && *resp.Valid {
		return "valid " + resp.Digest
	}
	return "invalid"
}

func (r *runner) invalid() error {
	return r.validate(fileInvalid, func(validityCase) string { return "invalid" })
}

func (r *runner) digests() error {
	return r.validate(fileDigest, func(c validityCase) string { return "valid " + c.Digest })
}

func (r *runner) validate(file string, want func(validityCase) string) error {
	cases, err := load[validityCase](r.fsys, file, "cases")
	for _, c := range cases {
		req := Request{Op: OpValidate, ID: c.ID}
		if readErr := c.put(r.fsys, &req); readErr != nil {
			return fmt.Errorf("conformance: case %s: %w", c.ID, readErr)
		}
		resp, doErr := r.impl.Do(req)
		r.record(ClassEvaluator, file, c.ID, resp, doErr, validity(resp), want(c))
	}
	return err
}

func (r *runner) succession() error {
	type successionCase struct {
		ID            string          `json:"id"`
		Stored        json.RawMessage `json:"stored"`
		StoredRevoked bool            `json:"stored_revoked"`
		Offered       json.RawMessage `json:"offered"`
		Expected      string          `json:"expected"`
		Confirm       bool            `json:"confirm"`
	}
	cases, err := load[successionCase](r.fsys, fileSuccession, "cases")
	for _, c := range cases {
		stored, offered := string(c.Stored), string(c.Offered)
		resp, doErr := r.impl.Do(Request{Op: OpSuccession, ID: c.ID, Stored: &stored, StoredRevoked: c.StoredRevoked, Offered: &offered})
		got, want := "reject", c.Expected
		if resp.Accept != nil && *resp.Accept {
			got = "accept"
			if resp.Confirm {
				got += " confirm"
			}
		}
		if c.Confirm {
			want += " confirm"
		}
		r.record(ClassSignatures, fileSuccession, c.ID, resp, doErr, got, want)
	}
	return err
}

func (r *runner) signed() error {
	type signedCase struct {
		ID       string `json:"id"`
		JWS      string `json:"jws"`
		Keys     string `json:"keys"`
		Issuer   string `json:"issuer"`
		Expected string `json:"expected"`
		Digest   string `json:"digest"`
		Requires string `json:"requires"`
	}
	cases, err := load[signedCase](r.fsys, fileSigned, "cases")
	for _, c := range cases {
		keys, readErr := fs.ReadFile(r.fsys, c.Keys)
		if readErr != nil {
			return fmt.Errorf("conformance: case %s: %w", c.ID, readErr)
		}
		resp, doErr := r.impl.Do(Request{Op: OpVerifySigned, ID: c.ID, JWS: c.JWS, Issuer: c.Issuer, Keys: string(keys)})
		want := "invalid"
		if c.Expected == "valid" {
			want = "valid " + c.Digest
		}
		r.recordRequiring(c.Requires, ClassSignatures, fileSigned, c.ID, resp, doErr, validity(resp), want)
	}
	return err
}

type auditCase struct {
	ID           string            `json:"id"`
	Expected     string            `json:"expected"`
	BrokenAt     int64             `json:"broken_at"`
	EntryDigests []string          `json:"entry_digests"`
	Entries      []json.RawMessage `json:"entries"`
	JSONL        *string           `json:"jsonl"`
	// The forms with bytes a JSON string cannot carry (SPEC-v0 section 10.2).
	EntriesBase64 [][]byte  `json:"entries_base64"`
	JSONLBase64   []byte    `json:"jsonl_base64"`
	Keys          string    `json:"keys"`
	LogID         string    `json:"log_id"`
	LastSeen      *Position `json:"last_seen"`
	Anchored      *int64    `json:"anchored"`
	// Requires names an optional algorithm the case needs (SPEC-v0 section 10.2).
	Requires string `json:"requires"`
	// The findings of SPEC-v0 section 9.4; absent: none of that kind.
	IntegrityBrokenAt   *int64 `json:"integrity_broken_at"`
	ConformanceBrokenAt *int64 `json:"conformance_broken_at"`
	UnknownVersionAt    *int64 `json:"unknown_version_at"`
	// CheckpointGapAt: SPEC-v0 section 9.5; absent: none.
	CheckpointGapAt *int64 `json:"checkpoint_gap_at"`
}

func (r *runner) audit() error {
	for _, file := range []string{fileAudit, fileAuditV1} {
		if err := r.auditFile(file); err != nil {
			return err
		}
	}
	return nil
}

// auditFile plays the logs of one audit conformance file.
func (r *runner) auditFile(file string) error {
	cases, err := load[auditCase](r.fsys, file, "logs")
	for _, c := range cases {
		req := Request{Op: OpVerifyAudit, ID: c.ID, JSONL: c.JSONL, LogID: c.LogID, LastSeen: c.LastSeen,
			JSONLBase64: c.JSONLBase64, EntriesBase64: c.EntriesBase64}
		for _, e := range c.Entries {
			req.Entries = append(req.Entries, string(e))
		}
		class := ClassAudit
		if c.Keys != "" {
			class = ClassAnchored
			keys, readErr := fs.ReadFile(r.fsys, c.Keys)
			if readErr != nil {
				return fmt.Errorf("conformance: log %s: %w", c.ID, readErr)
			}
			req.Keys = string(keys)
		}
		if len(c.EntryDigests) > len(c.Entries) {
			return fmt.Errorf("conformance: log %s has more digests than entries", c.ID)
		}
		resp, doErr := r.impl.Do(req)
		got, want := auditOutcome(c, resp)
		r.recordRequiring(c.Requires, class, file, c.ID, resp, doErr, got, want)
		for i, digest := range c.EntryDigests {
			entry := string(c.Entries[i])
			resp, doErr := r.impl.Do(Request{Op: OpEntryDigest, ID: c.ID, Entry: &entry})
			r.record(class, file, fmt.Sprintf("%s entry %d", c.ID, i+1), resp, doErr, resp.Digest, digest)
		}
	}
	return err
}

func auditOutcome(c auditCase, resp Response) (got, want string) {
	want = c.Expected
	if c.Expected == "invalid" {
		want = fmt.Sprintf("invalid broken_at=%d", c.BrokenAt)
	} else if c.Anchored != nil {
		want = fmt.Sprintf("valid anchored=%d", *c.Anchored)
	}
	// A valid log is reported with the number of its entries (SPEC-v0 section 9.4).
	countEntries := c.Expected == "valid" && c.JSONL == nil && c.JSONLBase64 == nil
	if countEntries {
		want += fmt.Sprintf(" entries=%d", len(c.Entries)+len(c.EntriesBase64))
	}
	// The findings are compared in every case: an implementation that does not report them
	// fails the cases of an invalid log.
	want += findings(c.IntegrityBrokenAt, c.ConformanceBrokenAt, c.UnknownVersionAt)
	// The cadence of checkpoints is compared for a valid log only: an implementation that does
	// not report it fails the cases of a gap.
	if c.Expected == "valid" {
		want += gapOf(c.CheckpointGapAt)
	}

	switch {
	case resp.Valid == nil:
		return "no result", want
	case !*resp.Valid && resp.BrokenAt != nil:
		got = fmt.Sprintf("invalid broken_at=%d", *resp.BrokenAt)
	case !*resp.Valid:
		got = "invalid"
	case c.Anchored != nil && resp.Anchored != nil:
		got = fmt.Sprintf("valid anchored=%d", *resp.Anchored)
	default:
		got = "valid"
	}
	if countEntries && *resp.Valid && resp.Entries != nil {
		got += fmt.Sprintf(" entries=%d", *resp.Entries)
	}
	got += findings(resp.IntegrityBrokenAt, resp.ConformanceBrokenAt, resp.UnknownVersionAt)
	if c.Expected == "valid" {
		got += gapOf(resp.CheckpointGapAt)
	}
	return got, want
}

// gapOf writes the checkpoint gap of SPEC-v0 section 9.5 for a comparison.
func gapOf(at *int64) string {
	if at == nil {
		return " gap=-"
	}
	return fmt.Sprintf(" gap=%d", *at)
}

// findings writes the findings of SPEC-v0 section 9.4 for a comparison; an absent one is "-".
func findings(integrity, conformance, unknown *int64) string {
	show := func(v *int64) string {
		if v == nil {
			return "-"
		}
		return fmt.Sprint(*v)
	}
	return fmt.Sprintf(" integrity=%s conformance=%s unknown_version=%s", show(integrity), show(conformance), show(unknown))
}

// ClassNames returns the classes of a report in a fixed order.
func (r Report) ClassNames() []string {
	names := make([]string, 0, len(r.Classes))
	for name := range r.Classes {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

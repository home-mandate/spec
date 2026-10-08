// SPDX-License-Identifier: Apache-2.0

package harness

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"slices"

	"github.com/home-mandate/spec/internal/manifest"
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
	c := r.class(class)
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

// mandateSource is how conformance files refer to a mandate.
type mandateSource struct {
	Mandate       string          `json:"mandate"`
	MandateInline json.RawMessage `json:"mandate_inline"`
	MandateRaw    *string         `json:"mandate_raw"`
}

func (s mandateSource) text(fsys fs.FS) (string, error) {
	switch {
	case s.Mandate != "":
		data, err := fs.ReadFile(fsys, s.Mandate)
		return string(data), err
	case s.MandateRaw != nil:
		return *s.MandateRaw, nil
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
	Subject         *Subject               `json:"subject"`
	Resource        Resource               `json:"resource"`
	Action          string                 `json:"action"`
	Parameters      map[string]json.Number `json:"parameters"`
	Time            string                 `json:"time"`
	Timezone        string                 `json:"timezone"`
	Revoked         bool                   `json:"revoked"`
	Expected        string                 `json:"expected"`
	Reason          string                 `json:"reason"`
	RuleID          json.RawMessage        `json:"rule_id"`
	ApprovalTimeout string                 `json:"approval_timeout"`
	Selected        json.RawMessage        `json:"selected"`
}

func (c evaluationCase) request() *Evaluation {
	return &Evaluation{Resource: c.Resource, Action: c.Action, Parameters: c.Parameters, Time: c.Time, Timezone: c.Timezone, Revoked: c.Revoked}
}

// outcome renders what a case fixes about a result. A member the case does not give is
// not compared.
func (c evaluationCase) outcome(decision, reason string, ruleID *string, timeout string, selected *string) (got, want string) {
	got, want = decision+" "+reason, c.Expected+" "+c.Reason
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
)

func (r *runner) evaluation() error {
	cases, err := load[evaluationCase](r.fsys, fileCases, "cases")
	for _, c := range cases {
		text, readErr := c.text(r.fsys)
		if readErr != nil {
			return fmt.Errorf("conformance: case %s: %w", c.ID, readErr)
		}
		resp, doErr := r.impl.Do(Request{Op: OpEvaluate, ID: c.ID, Mandate: &text, Request: c.request()})
		got, want := c.outcome(resp.Decision, resp.Reason, resp.RuleID, resp.ApprovalTimeout, nil)
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
		got, want := c.outcome(resp.Decision, resp.Reason, resp.RuleID, resp.ApprovalTimeout, resp.Selected)
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
		text, readErr := c.text(r.fsys)
		if readErr != nil {
			return fmt.Errorf("conformance: case %s: %w", c.ID, readErr)
		}
		resp, doErr := r.impl.Do(Request{Op: OpValidate, ID: c.ID, Mandate: &text})
		r.record(ClassEvaluator, file, c.ID, resp, doErr, validity(resp), want(c))
	}
	return err
}

func (r *runner) succession() error {
	type successionCase struct {
		ID       string          `json:"id"`
		Stored   json.RawMessage `json:"stored"`
		Offered  json.RawMessage `json:"offered"`
		Expected string          `json:"expected"`
	}
	cases, err := load[successionCase](r.fsys, fileSuccession, "cases")
	for _, c := range cases {
		stored, offered := string(c.Stored), string(c.Offered)
		resp, doErr := r.impl.Do(Request{Op: OpSuccession, ID: c.ID, Stored: &stored, Offered: &offered})
		got := "reject"
		if resp.Accept != nil && *resp.Accept {
			got = "accept"
		}
		r.record(ClassSignatures, fileSuccession, c.ID, resp, doErr, got, c.Expected)
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
	}
	cases, err := load[signedCase](r.fsys, fileSigned, "cases")
	for _, c := range cases {
		keys, readErr := fs.ReadFile(r.fsys, c.Keys)
		if readErr != nil {
			return fmt.Errorf("conformance: case %s: %w", c.ID, readErr)
		}
		resp, doErr := r.impl.Do(Request{Op: OpVerifySigned, ID: c.ID, JWS: c.JWS, Issuer: c.Issuer, Keys: keys})
		want := "invalid"
		if c.Expected == "valid" {
			want = "valid " + c.Digest
		}
		r.record(ClassSignatures, fileSigned, c.ID, resp, doErr, validity(resp), want)
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
	Keys         string            `json:"keys"`
	LogID        string            `json:"log_id"`
	Anchored     *int64            `json:"anchored"`
}

func (r *runner) audit() error {
	cases, err := load[auditCase](r.fsys, fileAudit, "logs")
	for _, c := range cases {
		req := Request{Op: OpVerifyAudit, ID: c.ID, JSONL: c.JSONL, LogID: c.LogID}
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
			req.Keys = keys
		}
		if len(c.EntryDigests) > len(c.Entries) {
			return fmt.Errorf("conformance: log %s has more digests than entries", c.ID)
		}
		resp, doErr := r.impl.Do(req)
		got, want := auditOutcome(c, resp)
		r.record(class, fileAudit, c.ID, resp, doErr, got, want)
		for i, digest := range c.EntryDigests {
			entry := string(c.Entries[i])
			resp, doErr := r.impl.Do(Request{Op: OpEntryDigest, ID: c.ID, Entry: &entry})
			r.record(class, fileAudit, fmt.Sprintf("%s entry %d", c.ID, i+1), resp, doErr, resp.Digest, digest)
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
	if c.Expected == "valid" && c.JSONL == nil {
		want += fmt.Sprintf(" entries=%d", len(c.Entries))
		defer func() {
			if resp.Valid != nil && *resp.Valid && resp.Entries != nil {
				got += fmt.Sprintf(" entries=%d", *resp.Entries)
			}
		}()
	}
	switch {
	case resp.Valid == nil:
		got = "no result"
	case !*resp.Valid && resp.BrokenAt != nil:
		got = fmt.Sprintf("invalid broken_at=%d", *resp.BrokenAt)
	case !*resp.Valid:
		got = "invalid"
	case c.Anchored != nil && resp.Anchored != nil:
		got = fmt.Sprintf("valid anchored=%d", *resp.Anchored)
	default:
		got = "valid"
	}
	return got, want
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

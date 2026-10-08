// SPDX-License-Identifier: Apache-2.0

package harness_test

import (
	"errors"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/home-mandate/spec"
	"github.com/home-mandate/spec/internal/harness"
)

func TestReferenceConformsToEveryClass(t *testing.T) {
	report, err := harness.Run(spec.FS(), harness.Local{})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range report.Failures {
		t.Errorf("%s %s %s: got %q, want %q", f.Class, f.File, f.ID, f.Got, f.Want)
	}
	classes := []string{harness.ClassEvaluator, harness.ClassSelection, harness.ClassSignatures, harness.ClassAudit, harness.ClassAnchored}
	if !report.Conforms(classes...) || strings.Join(report.ClassNames(), " ") != "audit audit-anchored evaluator selection signatures" {
		t.Errorf("classes = %+v", report.Classes)
	}
	if report.Classes[harness.ClassEvaluator].Cases < 250 || len(report.Manifest) != 64 || report.Implementation.Name == "" {
		t.Errorf("report = %+v", report)
	}
	if report.Conforms() || report.Conforms("unknown") {
		t.Error("Conforms without classes or with an unknown class must be false")
	}
}

// faulty changes the answers of the reference to simulate a non-conforming implementation.
type faulty struct {
	change func(harness.Request, harness.Response) (harness.Response, error)
}

func (f faulty) Do(req harness.Request) (harness.Response, error) {
	return f.change(req, harness.Answer(req))
}

func TestRunDetectsDeviations(t *testing.T) {
	yes := true
	for name, tt := range map[string]struct {
		change func(harness.Request, harness.Response) (harness.Response, error)
		class  string
	}{
		"allows what must be denied": {func(req harness.Request, r harness.Response) (harness.Response, error) {
			if req.Op == harness.OpEvaluate && r.Decision == "deny" {
				r.Decision = "allow"
			}
			return r, nil
		}, harness.ClassEvaluator},
		"wrong reason": {func(req harness.Request, r harness.Response) (harness.Response, error) {
			if r.Reason == "no_match" {
				r.Reason = "rule"
			}
			return r, nil
		}, harness.ClassEvaluator},
		"wrong rule": {func(req harness.Request, r harness.Response) (harness.Response, error) {
			r.RuleID = nil
			return r, nil
		}, harness.ClassEvaluator},
		"accepts invalid mandates": {func(req harness.Request, r harness.Response) (harness.Response, error) {
			if req.Op == harness.OpValidate {
				r.Valid = &yes
			}
			return r, nil
		}, harness.ClassEvaluator},
		"wrong digest": {func(req harness.Request, r harness.Response) (harness.Response, error) {
			if req.Op == harness.OpValidate && r.Digest != "" {
				r.Digest = "sha256:" + strings.Repeat("0", 64)
			}
			return r, nil
		}, harness.ClassEvaluator},
		"selects a revoked mandate": {func(req harness.Request, r harness.Response) (harness.Response, error) {
			if req.Op == harness.OpSelect && r.Reason == "no_mandate" {
				r.Decision, r.Reason = "allow", "rule"
			}
			return r, nil
		}, harness.ClassSelection},
		"accepts every successor": {func(req harness.Request, r harness.Response) (harness.Response, error) {
			if req.Op == harness.OpSuccession {
				r.Accept = &yes
			}
			return r, nil
		}, harness.ClassSignatures},
		"accepts every signature": {func(req harness.Request, r harness.Response) (harness.Response, error) {
			if req.Op == harness.OpVerifySigned {
				r.Valid = &yes
			}
			return r, nil
		}, harness.ClassSignatures},
		"accepts every log": {func(req harness.Request, r harness.Response) (harness.Response, error) {
			if req.Op == harness.OpVerifyAudit {
				r.Valid, r.BrokenAt = &yes, nil
			}
			return r, nil
		}, harness.ClassAudit},
		"does not check checkpoints": {func(req harness.Request, r harness.Response) (harness.Response, error) {
			if req.Op == harness.OpVerifyAudit && len(req.Keys) > 0 {
				req.Keys = nil
				return harness.Answer(req), nil
			}
			return r, nil
		}, harness.ClassAnchored},
		"wrong entry digest": {func(req harness.Request, r harness.Response) (harness.Response, error) {
			if req.Op == harness.OpEntryDigest {
				r.Digest = "sha256:x"
			}
			return r, nil
		}, harness.ClassAudit},
		"reports no entry count": {func(req harness.Request, r harness.Response) (harness.Response, error) {
			r.Entries = nil
			return r, nil
		}, harness.ClassAudit},
		"reports a wrong entry count": {func(req harness.Request, r harness.Response) (harness.Response, error) {
			if r.Entries != nil {
				wrong := *r.Entries + 1
				r.Entries = &wrong
			}
			return r, nil
		}, harness.ClassAnchored},
		"reports no result for logs": {func(req harness.Request, r harness.Response) (harness.Response, error) {
			if req.Op == harness.OpVerifyAudit {
				return harness.Response{}, nil
			}
			return r, nil
		}, harness.ClassAudit},
		"invalid without broken_at": {func(req harness.Request, r harness.Response) (harness.Response, error) {
			r.BrokenAt = nil
			return r, nil
		}, harness.ClassAudit},
		"answers with an error": {func(req harness.Request, r harness.Response) (harness.Response, error) {
			if req.Op == harness.OpEvaluate {
				return harness.Response{Error: "boom"}, nil
			}
			return r, nil
		}, harness.ClassEvaluator},
		"breaks down": {func(req harness.Request, r harness.Response) (harness.Response, error) {
			if req.Op == harness.OpSelect {
				return harness.Response{}, errors.New("pipe closed")
			}
			return r, nil
		}, harness.ClassSelection},
	} {
		t.Run(name, func(t *testing.T) {
			report, err := harness.Run(spec.FS(), faulty{tt.change})
			if err != nil {
				t.Fatal(err)
			}
			c := report.Classes[tt.class]
			if c.Conforms || c.Failed == 0 || len(report.Failures) == 0 {
				t.Errorf("class %s = %+v, want failures", tt.class, c)
			}
		})
	}
}

func TestUnsupportedOperationsAreSkippedAndDoNotConform(t *testing.T) {
	report, err := harness.Run(spec.FS(), faulty{func(req harness.Request, r harness.Response) (harness.Response, error) {
		if req.Op == harness.OpVerifySigned || req.Op == harness.OpSuccession {
			return harness.Response{Error: harness.ErrorUnsupported}, nil
		}
		return r, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	c := report.Classes[harness.ClassSignatures]
	if c.Conforms || c.Skipped != c.Cases || c.Failed != 0 || len(report.Failures) != 0 {
		t.Errorf("signatures = %+v, failures %d", c, len(report.Failures))
	}
	if !report.Conforms(harness.ClassEvaluator, harness.ClassAudit) {
		t.Error("the other classes must still conform")
	}
}

func TestRunFailsWithoutCasesOrCapabilities(t *testing.T) {
	if _, err := harness.Run(fstest.MapFS{}, harness.Local{}); err == nil {
		t.Error("Run without a manifest succeeded")
	}
	onlyManifest := fstest.MapFS{"conformance/manifest.json": {Data: []byte(`{}`)}}
	if _, err := harness.Run(onlyManifest, harness.Local{}); err == nil {
		t.Error("Run without conformance files succeeded")
	}
	broken := fstest.MapFS{"conformance/manifest.json": {Data: []byte(`{}`)}, "conformance/cases-v0.json": {Data: []byte(`nope`)}}
	if _, err := harness.Run(broken, harness.Local{}); err == nil {
		t.Error("Run with a broken conformance file succeeded")
	}
	_, err := harness.Run(spec.FS(), faulty{func(req harness.Request, r harness.Response) (harness.Response, error) {
		return r, errors.New("no process")
	}})
	if err == nil {
		t.Error("Run without capabilities succeeded")
	}
}

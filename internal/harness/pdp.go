// SPDX-License-Identifier: Apache-2.0

package harness

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"strings"

	"github.com/mandate-spec/mandate-spec/evaluator"
)

// maxResponseBytes bounds what the tool reads from the implementation under test.
const maxResponseBytes = 1 << 20

// PDP addresses an implementation over the HTTP binding (SPEC-v0 section 10.3).
type PDP struct {
	// AuthZEN is the base URL of the AuthZEN API; the tool appends /access/v1/evaluation.
	AuthZEN string
	// Control is the URL of the test control resource that takes the state.
	Control string
	// Header is sent with every request, for example Authorization.
	Header http.Header
	Client *http.Client
}

// State is what the tool sets before a request: everything the PDP otherwise takes from
// its mandate store, its resource directory, its clock and the household configuration.
type State struct {
	Mandates  []StoredMandate `json:"mandates"`
	Directory []Resource      `json:"directory"`
	Time      string          `json:"time"`
	Timezone  string          `json:"timezone,omitempty"`
}

// AuthZEN request and response (SPEC-v0 section 6).
type (
	authzenRequest struct {
		Subject  authzenSubject  `json:"subject"`
		Action   authzenAction   `json:"action"`
		Resource authzenResource `json:"resource"`
	}
	authzenSubject struct {
		Type       string            `json:"type"`
		ID         string            `json:"id"`
		Properties map[string]string `json:"properties"`
	}
	authzenAction struct {
		Name       string                 `json:"name"`
		Properties map[string]json.Number `json:"properties,omitempty"`
	}
	authzenResource struct {
		ID string `json:"id"`
	}
	authzenResponse struct {
		Decision bool `json:"decision"`
		Context  struct {
			Outcome         string  `json:"outcome"`
			Reason          string  `json:"reason"`
			RuleID          *string `json:"rule_id"`
			ApprovalTimeout string  `json:"approval_timeout"`
		} `json:"context"`
	}
)

// RunPDP plays the evaluation and selection cases against a PDP over HTTP.
func RunPDP(ctx context.Context, fsys fs.FS, pdp PDP) (Report, error) {
	report, err := newReport(fsys, "http")
	if err != nil {
		return Report{}, err
	}
	if pdp.Client == nil {
		pdp.Client = http.DefaultClient
	}
	r := &runner{fsys: fsys, report: report}
	cases, err := load[evaluationCase](fsys, fileCases, "cases")
	if err != nil {
		return Report{}, err
	}
	for _, c := range cases {
		text, err := c.text(fsys)
		if err != nil {
			return Report{}, fmt.Errorf("conformance: case %s: %w", c.ID, err)
		}
		// A PDP stores only valid mandates and never selects a revoked one; those cases
		// belong to the evaluator class and to the selection cases.
		m, err := evaluator.Parse([]byte(text))
		if err != nil || c.Revoked {
			continue
		}
		c.Subject = &Subject{ClientID: m.ClientID(), Principal: m.Principal()}
		r.pdpCase(ctx, pdp, fileCases, c, []StoredMandate{{Mandate: text}})
	}
	selection, err := load[evaluationCase](fsys, fileSelection, "cases")
	if err != nil {
		return Report{}, err
	}
	for _, c := range selection {
		stored := []StoredMandate{}
		storable := true
		for _, m := range c.Mandates {
			if _, err := evaluator.Parse(m.MandateInline); err != nil {
				storable = false
			}
			stored = append(stored, StoredMandate{Mandate: string(m.MandateInline), Revoked: m.Revoked})
		}
		if storable {
			r.pdpCase(ctx, pdp, fileSelection, c, stored)
		}
	}
	r.finish()
	return r.report, nil
}

func (r *runner) pdpCase(ctx context.Context, pdp PDP, file string, c evaluationCase, stored []StoredMandate) {
	state := State{Mandates: stored, Directory: []Resource{}, Time: c.Time, Timezone: c.Timezone}
	if c.Resource.Category != "" {
		state.Directory = append(state.Directory, c.Resource)
	}
	var resp authzenResponse
	err := pdp.call(ctx, http.MethodPut, pdp.Control, state, nil)
	if err == nil {
		err = pdp.call(ctx, http.MethodPost, strings.TrimSuffix(pdp.AuthZEN, "/")+"/access/v1/evaluation", authzenRequest{
			Subject:  authzenSubject{Type: "agent", ID: c.Subject.ClientID, Properties: map[string]string{"principal": c.Subject.Principal}},
			Action:   authzenAction{Name: c.Action, Properties: c.Parameters},
			Resource: authzenResource{ID: c.Resource.EntityID},
		}, &resp)
	}
	// selected is not visible through AuthZEN; the decision is.
	c.Selected = nil
	got, want := c.outcome(resp.Context.Outcome, resp.Context.Reason, resp.Context.RuleID, resp.Context.ApprovalTimeout, nil)
	got, want = fmt.Sprintf("decision=%t %s", resp.Decision, got), fmt.Sprintf("decision=%t %s", c.Expected == "allow", want)
	r.record(ClassPDP, file, c.ID, Response{}, err, got, want)
}

func (p PDP) call(ctx context.Context, method, url string, body, out any) error {
	encoded, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(encoded))
	if err != nil {
		return err
	}
	for name, values := range p.Header {
		req.Header[name] = values
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("%s %s: status %d", method, url, resp.StatusCode)
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(data, out)
}

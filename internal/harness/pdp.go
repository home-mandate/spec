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
	"reflect"
	"strings"
	"time"
)

// requestTimeout bounds one request to the implementation under test.
const requestTimeout = 30 * time.Second

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
	// Name and Version name the implementation in the report: the HTTP binding has no
	// capabilities (SPEC-v0 section 10.4).
	Name, Version string
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
		Name       string                     `json:"name"`
		Properties map[string]json.RawMessage `json:"properties,omitempty"`
	}
	authzenResource struct {
		// Type is required by AuthZEN; the PDP takes the category from the state the
		// control resource set (SPEC-v0 section 10.3).
		Type string `json:"type"`
		ID   string `json:"id"`
	}
	authzenResponse struct {
		Decision bool `json:"decision"`
		Context  struct {
			Outcome         string  `json:"outcome"`
			Reason          string  `json:"reason"`
			RuleID          *string `json:"rule_id"`
			ApprovalTimeout string  `json:"approval_timeout"`
			// Enforced is false only for a deny the PEP does not enforce (SPEC-v0 section 6).
			Enforced *bool `json:"enforced"`
			// Confirm is true only for a deny that is not enforced and requires a
			// confirmation (SPEC-v0 section 6).
			Confirm bool `json:"confirm"`
			// MandateID names the evaluated mandate, with its digest (SPEC-v0 section 6).
			MandateID *string `json:"mandate_id"`
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
		// No redirects: a redirected POST would arrive as a GET without its body.
		pdp.Client = &http.Client{Timeout: requestTimeout, CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}}
	}
	report.Implementation = Described{Name: pdp.Name, Version: pdp.Version}
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
		// A PDP never evaluates a revoked mandate: the cases with revoked: true test the order
		// of the reasons in direct evaluation and belong to the evaluator class; the revoked
		// result of a PDP is covered by the selection cases (SPEC-v0 sections 4.3 and 8.1).
		if c.Revoked {
			continue
		}
		var m struct {
			ID        json.RawMessage `json:"id"`
			Principal string          `json:"principal"`
			Agent     struct {
				ClientID string `json:"client_id"`
			} `json:"agent"`
		}
		if err := json.Unmarshal([]byte(text), &m); err != nil {
			return Report{}, fmt.Errorf("conformance: case %s: %w", c.ID, err)
		}
		c.Subject = &Subject{ClientID: m.Agent.ClientID, Principal: m.Principal}
		// The stored mandate is the one evaluated; the response names it in mandate_id.
		c.Selected = m.ID
		r.pdpCase(ctx, pdp, fileCases, c, []StoredMandate{{Mandate: text}})
	}
	selection, err := load[evaluationCase](fsys, fileSelection, "cases")
	if err != nil {
		return Report{}, err
	}
	for _, c := range selection {
		if c.Subject == nil {
			return Report{}, fmt.Errorf("conformance: case %s has no subject", c.ID)
		}
		if c.PDP != nil && !*c.PDP {
			continue
		}
		stored := []StoredMandate{}
		for _, m := range c.Mandates {
			stored = append(stored, StoredMandate{Mandate: string(m.MandateInline), Revoked: m.Revoked})
		}
		r.pdpCase(ctx, pdp, fileSelection, c, stored)
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
			Resource: authzenResource{Type: resourceType(c.Resource), ID: c.Resource.EntityID},
		}, &resp)
	}
	// selected is visible through AuthZEN as mandate_id in the response context.
	got, want := c.outcome(resp.Context.Outcome, resp.Context.Reason, resp.Context.RuleID, resp.Context.ApprovalTimeout,
		resp.Context.Enforced, resp.Context.Confirm, resp.Context.MandateID)
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
	if err := exactNames(data, reflect.TypeOf(out)); err != nil {
		return fmt.Errorf("%s %s: %w", method, url, err)
	}
	return json.Unmarshal(data, out)
}

// resourceType is the resource.type the tool sends: the category of the resource, or
// unknown for a resource the directory does not contain (SPEC-v0 section 10.3).
func resourceType(r Resource) string {
	if r.Category == "" {
		return "unknown"
	}
	return r.Category
}

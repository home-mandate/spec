// SPDX-License-Identifier: Apache-2.0

package evaluator

import (
	"encoding/json"
	"regexp"
	"time"

	"github.com/home-mandate/spec/internal/ijson"
)

// principalPattern is the pattern of principal in the mandate schema.
var principalPattern = regexp.MustCompile(`^(household|person):[A-Za-z0-9_-]{1,64}$`)

// ValidSubject reports whether a request names its subject in a form a mandate could
// name: a non-empty client ID and a principal that matches the pattern of the schema.
// A request that does not is deny with invalid_request before any mandate is selected
// (SPEC-v0 sections 4.3 and 6).
func ValidSubject(clientID, principal string) bool {
	return clientID != "" && principalPattern.MatchString(principal)
}

// Stored is a mandate as an implementation has stored it, with its status. It is
// created by NewStored.
type Stored struct {
	mandate   *Mandate // nil if the stored document is not a valid mandate
	status    MandateStatus
	clientID  string
	principal string
	// readable is false if not even agent and principal could be read; such a document
	// counts for every agent and principal, so that it is never silently ignored.
	readable bool
}

// NewStored parses a stored mandate. A document that is not a valid mandate (for
// example after the specification became stricter) stays a candidate of the selection
// and denies.
func NewStored(document []byte, status MandateStatus) Stored {
	s := Stored{status: status}
	if m, err := Parse(document); err == nil {
		s.mandate, s.clientID, s.principal, s.readable = m, m.clientID, m.principal, true
		return s
	}
	// A document that is not I-JSON cannot be attributed reliably (which of two equal
	// keys counts?); it then counts for every agent and principal.
	if ijson.Check(document) != nil {
		return s
	}
	var top map[string]json.RawMessage
	var agent map[string]json.RawMessage
	var principal, clientID string
	if json.Unmarshal(document, &top) == nil && json.Unmarshal(top["agent"], &agent) == nil &&
		json.Unmarshal(top["principal"], &principal) == nil && json.Unmarshal(agent["client_id"], &clientID) == nil {
		s.clientID, s.principal, s.readable = clientID, principal, true
	}
	return s
}

// Mandate returns the stored mandate, nil if the stored document is not a valid mandate.
func (s Stored) Mandate() *Mandate { return s.mandate }

// Candidates are the stored mandates of the agent and the principal that are not
// revoked, an invalid document that concerns them included (SPEC-v0 section 4.3 step 1).
// It is what a selection can do without a point in time: a sole candidate is selected
// whether or not it is current.
func Candidates(stored []Stored, clientID, principal string) []Stored {
	var candidates []Stored
	for _, s := range stored {
		if s.status != StatusRevoked && s.concerns(clientID, principal) {
			candidates = append(candidates, s)
		}
	}
	return candidates
}

func (s Stored) concerns(clientID, principal string) bool {
	return !s.readable || (s.clientID == clientID && s.principal == principal)
}

// validAt reports whether the mandate is within its validity period; an invalid
// document counts as valid at every time.
func (s Stored) validAt(t time.Time) bool {
	m := s.mandate
	if m == nil {
		return true
	}
	return !t.Before(m.validFrom) && (!m.hasExpires || t.Before(m.expires))
}

// SelectAndEvaluate selects the mandate for an agent and a principal among the stored
// mandates (SPEC-v0 section 4.3) and evaluates req against it. The status in req is
// ignored; the status of the selected mandate applies. It returns the selected
// mandate, nil if none was selected or the selected document is invalid.
//
// A subject that is not valid (ValidSubject) is deny with invalid_request before any
// mandate is selected.
//
// Selection: revoked mandates are never selected. Of the others, the one that is valid
// at the point in time is selected; if several are, none is (ambiguous_mandate). If
// none is valid at that time and there is exactly one, it is selected and yields
// not_yet_valid or expired; otherwise the result is no_mandate.
func SelectAndEvaluate(stored []Stored, clientID, principal string, req Request) (*Mandate, Result) {
	// A subject no mandate could name is rejected before any mandate is selected, so
	// that two PDPs answer alike: invalid_request, never no_mandate (SPEC-v0 section 6).
	if !ValidSubject(clientID, principal) {
		return nil, Result{Decision: Deny, Reason: ReasonInvalidRequest}
	}
	candidates := Candidates(stored, clientID, principal)
	var valid []Stored
	for _, s := range candidates {
		if s.validAt(req.Time) {
			valid = append(valid, s)
		}
	}
	var selected Stored
	switch {
	case len(valid) == 1:
		selected = valid[0]
	case len(valid) > 1:
		return nil, Result{Decision: Deny, Reason: ReasonAmbiguousMandate}
	case len(candidates) == 1:
		selected = candidates[0]
	default:
		return nil, Result{Decision: Deny, Reason: ReasonNoMandate}
	}
	req.Status = selected.status
	return selected.mandate, Evaluate(selected.mandate, req)
}

// SPDX-License-Identifier: Apache-2.0

package evaluator

import (
	"encoding/json"
	"time"
)

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
	var loose struct {
		Principal *string `json:"principal"`
		Agent     struct {
			ClientID *string `json:"client_id"`
		} `json:"agent"`
	}
	if json.Unmarshal(document, &loose) == nil && loose.Principal != nil && loose.Agent.ClientID != nil {
		s.clientID, s.principal, s.readable = *loose.Agent.ClientID, *loose.Principal, true
	}
	return s
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
// Selection: revoked mandates are never selected. Of the others, the one that is valid
// at the point in time is selected; if several are, none is (ambiguous_mandate). If
// none is valid at that time and there is exactly one, it is selected and yields
// not_yet_valid or expired; otherwise the result is no_mandate.
func SelectAndEvaluate(stored []Stored, clientID, principal string, req Request) (*Mandate, Result) {
	var candidates, valid []Stored
	for _, s := range stored {
		if s.status == StatusRevoked || !s.concerns(clientID, principal) {
			continue
		}
		candidates = append(candidates, s)
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

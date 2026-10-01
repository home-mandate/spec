// SPDX-License-Identifier: Apache-2.0

// Package evaluator ist die Referenz-Auswertung von mandate-spec v0 (SPEC-v0.md
// Abschnitt 3.1, 3.2 und 4). Sie nutzt nur die Standardbibliothek und einen
// JSON-Schema-Validator. Im Zweifel ist das Ergebnis immer Deny.
package evaluator

import (
	"slices"
	"time"
)

// Decision ist die Entscheidung der Auswertung.
type Decision string

// Entscheidungen nach SPEC-v0 Abschnitt 2.
const (
	Allow Decision = "allow"
	Ask   Decision = "ask"
	Deny  Decision = "deny"
)

// Reason ist der Begründungscode nach SPEC-v0 Abschnitt 4.1.
type Reason string

// Begründungscodes in der Vorrangreihenfolge aus SPEC-v0 Abschnitt 4.1.
const (
	ReasonInvalidMandate   Reason = "invalid_mandate"
	ReasonInvalidRequest   Reason = "invalid_request"
	ReasonUnknownCategory  Reason = "unknown_category"
	ReasonUnknownAction    Reason = "unknown_action"
	ReasonRevoked          Reason = "revoked"
	ReasonNotYetValid      Reason = "not_yet_valid"
	ReasonExpired          Reason = "expired"
	ReasonNoMatch          Reason = "no_match"
	ReasonCriticalDemotion Reason = "critical_demotion"
	ReasonRule             Reason = "rule"
)

// Resource ist die angefragte Ressource mit bereits aufgelöster Kategorie und Bereich.
type Resource struct {
	EntityID string
	Category string
	Area     string
}

// Request ist die Eingabe der Auswertung.
type Request struct {
	Resource Resource
	Action   string
	Time     time.Time
	// TimeZone ist die Zeitzone des Haushalts als IANA-Name. Leer: es gilt der Offset von Time.
	TimeZone string
	Revoked  bool
}

// Approval ist die Freigabe-Einstellung für eine Rückfrage.
type Approval struct {
	Timeout   string
	Approvers []string
}

// Result ist das Ergebnis der Auswertung nach SPEC-v0 Abschnitt 4.1.
type Result struct {
	Decision Decision
	Reason   Reason
	// RuleID ist leer, wenn keine Regel die Entscheidung trägt.
	RuleID string
	// Approval ist nur bei Ask gesetzt.
	Approval *Approval
	// MandateDigest ist bei ReasonInvalidMandate leer.
	MandateDigest string
}

// Evaluate wertet req gegen m nach SPEC-v0 Abschnitt 4 aus. Das Ergebnis enthält Kopien;
// Änderungen daran wirken nicht auf m zurück.
func Evaluate(m *Mandate, req Request) Result {
	if m == nil {
		return Result{Decision: Deny, Reason: ReasonInvalidMandate}
	}
	local, critical, reason := precheck(m, req)
	if reason != "" {
		return Result{Decision: Deny, Reason: reason, MandateDigest: m.digest}
	}
	matched := matchingRules(m, req, local)
	if len(matched) == 0 {
		return Result{Decision: Deny, Reason: ReasonNoMatch, MandateDigest: m.digest}
	}
	return decide(m, matched, critical)
}

// precheck setzt Schritt 0 und 1 aus SPEC-v0 Abschnitt 4 in der Vorrangreihenfolge von
// Abschnitt 4.1 um. Liefert die Ortszeit, ob die Aktion kritisch ist, und bei Ablehnung den Grund.
func precheck(m *Mandate, req Request) (local time.Time, critical bool, reason Reason) {
	local, ok := localTime(req.Time, req.TimeZone)
	if req.Resource.Category == "" || !ok {
		return time.Time{}, false, ReasonInvalidRequest
	}
	categoryKnown, actionKnown, critical := lookupAction(req.Resource.Category, req.Action)
	switch {
	case !categoryKnown:
		return time.Time{}, false, ReasonUnknownCategory
	case !actionKnown:
		return time.Time{}, false, ReasonUnknownAction
	case req.Revoked:
		return time.Time{}, false, ReasonRevoked
	case req.Time.Before(m.validFrom):
		return time.Time{}, false, ReasonNotYetValid
	case m.hasExpires && !req.Time.Before(m.expires):
		return time.Time{}, false, ReasonExpired
	}
	return local, critical, ""
}

// matchingRules setzt Schritt 2 um und behält die Dokumentreihenfolge bei.
func matchingRules(m *Mandate, req Request, local time.Time) []*rule {
	var matched []*rule
	for i := range m.rules {
		r := &m.rules[i]
		if r.selector.matches(req.Resource) && r.coversAction(req.Action) && r.conditionsMet(local) {
			matched = append(matched, r)
		}
	}
	return matched
}

func (s selector) matches(res Resource) bool {
	if s.any {
		return true
	}
	return (s.entityID == "" || s.entityID == res.EntityID) &&
		(s.category == "" || s.category == res.Category) &&
		(s.area == "" || s.area == res.Area)
}

func (r *rule) coversAction(action string) bool {
	for _, a := range r.actions {
		if a == "*" || a == action {
			return true
		}
	}
	return false
}

// decide setzt Schritt 4 und 5 sowie Abschnitt 4.1 um; matched ist nicht leer.
func decide(m *Mandate, matched []*rule, critical bool) Result {
	final := Allow
	for _, r := range matched {
		if strictness(r.decision) > strictness(final) {
			final = r.decision
		}
	}
	result := Result{Decision: final, Reason: ReasonRule, MandateDigest: m.digest}
	for _, r := range matched {
		if r.decision == final {
			result.RuleID = r.id
			break
		}
	}
	switch {
	case final == Ask:
		result.Approval = askApproval(m, matched)
	case final == Allow && critical:
		for _, r := range matched {
			if !r.allowCritical {
				result.Decision, result.Reason, result.RuleID = Ask, ReasonCriticalDemotion, r.id
				result.Approval = m.approval.clone()
				break
			}
		}
	}
	return result
}

func strictness(d Decision) int {
	switch d {
	case Deny:
		return 2
	case Ask:
		return 1
	}
	return 0
}

// askApproval liefert die Freigabe der ersten passenden ask-Regel mit eigenem approval,
// sonst die des Mandats.
func askApproval(m *Mandate, matched []*rule) *Approval {
	for _, r := range matched {
		if r.decision == Ask && r.approval != nil {
			return r.approval.clone()
		}
	}
	return m.approval.clone()
}

func (a Approval) clone() *Approval {
	return &Approval{Timeout: a.Timeout, Approvers: slices.Clone(a.Approvers)}
}

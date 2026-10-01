// SPDX-License-Identifier: Apache-2.0

// Package evaluator ist die Referenz-Auswertung von mandate-spec v0 (SPEC-v0.md
// Abschnitt 3.1, 3.2 und 4). Sie nutzt nur die Standardbibliothek und einen
// JSON-Schema-Validator. Im Zweifel ist das Ergebnis immer Deny.
package evaluator

import (
	"regexp"
	"slices"
	"time"
)

// Muster für entity_id und area aus schema/mandate-v0.schema.json; gelten auch für die
// Anfrage (SPEC-v0 Abschnitt 4, Schritt 0). Go-Regexp: $ trifft nur das Textende.
var (
	entityIDPattern = regexp.MustCompile(`^[a-z0-9_]+\.[a-z0-9_]+$`)
	areaPattern     = regexp.MustCompile(`^[a-z0-9_]{1,64}$`)
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

// MandateStatus ist der Status des Mandats aus der Verwaltung des PEP.
type MandateStatus string

// Zulässige Status nach SPEC-v0 Abschnitt 4. Jeder andere Wert, auch der leere, ist ungültig.
const (
	StatusActive  MandateStatus = "active"
	StatusRevoked MandateStatus = "revoked"
)

// Request ist die Eingabe der Auswertung. Kategorie, Bereich, Zeit, Zeitzone und Status
// stammen vom PEP, nie vom Agenten (SPEC-v0 Abschnitt 4, Herkunft der Eingaben).
type Request struct {
	Resource Resource
	Action   string
	Time     time.Time
	// TimeZone ist die Zeitzone des Haushalts als IANA-Name. Leer: es gilt der Offset von Time.
	TimeZone string
	// Status ist Pflicht; ein vergessener Status führt zu Deny, nie zu einem aktiven Mandat.
	Status MandateStatus
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
	if m == nil || !m.valid {
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
	if !ok || !validRequest(req) {
		return time.Time{}, false, ReasonInvalidRequest
	}
	categoryKnown, actionKnown, critical := lookupAction(req.Resource.Category, req.Action)
	switch {
	case !categoryKnown:
		return time.Time{}, false, ReasonUnknownCategory
	case !actionKnown:
		return time.Time{}, false, ReasonUnknownAction
	case req.Status == StatusRevoked:
		return time.Time{}, false, ReasonRevoked
	case req.Time.Before(m.validFrom):
		return time.Time{}, false, ReasonNotYetValid
	case m.hasExpires && !req.Time.Before(m.expires):
		return time.Time{}, false, ReasonExpired
	}
	return local, critical, ""
}

// validRequest prüft die Felder der Anfrage, die Schritt 0 nennt. Ohne diese Prüfung
// würde etwa "Lock.keller" eine deny-Regel für "lock.keller" umgehen.
func validRequest(req Request) bool {
	res := req.Resource
	return res.Category != "" &&
		entityIDPattern.MatchString(res.EntityID) &&
		(res.Area == "" || areaPattern.MatchString(res.Area)) &&
		(req.Status == StatusActive || req.Status == StatusRevoked)
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
	if strictness(final) == strictness(Deny) {
		result.Decision = Deny // unbekannte Entscheidungen zählen wie deny
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

// strictness ordnet nach Schritt 4; alles außer allow und ask zählt wie deny.
func strictness(d Decision) int {
	switch d {
	case Allow:
		return 0
	case Ask:
		return 1
	}
	return 2
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

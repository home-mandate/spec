// SPDX-License-Identifier: Apache-2.0

// Package evaluator ist die Referenz-Auswertung von mandate-spec v0 (SPEC-v0.md
// Abschnitt 3.1, 3.2 und 4). Sie nutzt nur die Standardbibliothek und einen
// JSON-Schema-Validator. Im Zweifel ist das Ergebnis immer Deny.
package evaluator

import "time"

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

// Evaluate wertet req gegen m nach SPEC-v0 Abschnitt 4 aus.
func Evaluate(m *Mandate, req Request) Result {
	return Result{Decision: Deny, Reason: ReasonInvalidMandate}
}

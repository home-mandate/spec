// SPDX-License-Identifier: Apache-2.0

// Package harness defines the messages of the process binding of the test interface
// (SPEC-v0 section 10.2) and answers them with the reference code of this repository.
package harness

import "encoding/json"

// Operations of the process binding.
const (
	OpCapabilities = "capabilities"
	OpValidate     = "validate"
	OpEvaluate     = "evaluate"
	OpSelect       = "select"
	OpSuccession   = "succession"
	OpVerifySigned = "verify_signed"
	OpVerifyAudit  = "verify_audit"
	OpEntryDigest  = "entry_digest"
)

// ErrorUnsupported is the error of an operation the implementation does not offer.
const ErrorUnsupported = "unsupported"

// Request is one line the test tool writes. Mandates, audit entries and logs are
// passed as JSON text in a string, so that they reach the implementation byte for byte.
type Request struct {
	Op string `json:"op"`
	// ID names the conformance case, for diagnostics only.
	ID string `json:"id,omitempty"`

	Mandate  *string         `json:"mandate,omitempty"`
	Mandates []StoredMandate `json:"mandates,omitempty"`
	Subject  *Subject        `json:"subject,omitempty"`
	Request  *Evaluation     `json:"request,omitempty"`

	Stored  *string `json:"stored,omitempty"`
	Offered *string `json:"offered,omitempty"`

	JWS    string          `json:"jws,omitempty"`
	Issuer string          `json:"issuer,omitempty"`
	Keys   json.RawMessage `json:"keys,omitempty"`

	JSONL   *string  `json:"jsonl,omitempty"`
	Entries []string `json:"entries,omitempty"`
	LogID   string   `json:"log_id,omitempty"`
	Entry   *string  `json:"entry,omitempty"`
}

// StoredMandate is a mandate an implementation has stored, with its status.
type StoredMandate struct {
	Mandate string `json:"mandate"`
	Revoked bool   `json:"revoked,omitempty"`
}

// Subject is the agent and principal of a request.
type Subject struct {
	ClientID  string `json:"client_id"`
	Principal string `json:"principal"`
}

// Evaluation is the input of the evaluation as the PEP determined it (SPEC-v0 section 4).
type Evaluation struct {
	Resource   Resource               `json:"resource"`
	Action     string                 `json:"action"`
	Parameters map[string]json.Number `json:"parameters,omitempty"`
	Time       string                 `json:"time"`
	Timezone   string                 `json:"timezone,omitempty"`
	Revoked    bool                   `json:"revoked,omitempty"`
}

// Resource is a resource as the directory of the PEP knows it.
type Resource struct {
	EntityID string `json:"entity_id"`
	Category string `json:"category,omitempty"`
	Area     string `json:"area,omitempty"`
	Critical bool   `json:"critical,omitempty"`
}

// Response is one line the implementation writes.
type Response struct {
	Error string `json:"error,omitempty"`

	// capabilities
	Name    string   `json:"name,omitempty"`
	Version string   `json:"version,omitempty"`
	Ops     []string `json:"ops,omitempty"`

	// validate, verify_signed, verify_audit
	Valid  *bool  `json:"valid,omitempty"`
	Digest string `json:"digest,omitempty"`

	// evaluate, select
	Decision        string   `json:"decision,omitempty"`
	Reason          string   `json:"reason,omitempty"`
	RuleID          *string  `json:"rule_id,omitempty"`
	ApprovalTimeout string   `json:"approval_timeout,omitempty"`
	Approvers       []string `json:"approvers,omitempty"`
	MandateDigest   string   `json:"mandate_digest,omitempty"`
	Selected        *string  `json:"selected,omitempty"`

	// succession
	Accept *bool `json:"accept,omitempty"`

	// verify_audit
	BrokenAt *int64 `json:"broken_at,omitempty"`
	Anchored *int64 `json:"anchored,omitempty"`
	Entries  *int   `json:"entries,omitempty"`
}

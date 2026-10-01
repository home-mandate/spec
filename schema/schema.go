// SPDX-License-Identifier: Apache-2.0

// Package schema provides the normative JSON schemas of mandate-spec v0 without pulling
// in the examples and conformance cases.
package schema

import (
	"bytes"
	_ "embed"
)

// IDs of the schemas, as given in "$id".
const (
	MandateID = "https://mandate-spec.org/mandate/v0/mandate.schema.json"
	AuditID   = "https://mandate-spec.org/audit/v0/audit.schema.json"
)

var (
	//go:embed mandate-v0.schema.json
	mandateSchema []byte
	//go:embed audit-v0.schema.json
	auditSchema []byte
)

// Mandate returns a copy of the mandate schema.
func Mandate() []byte { return bytes.Clone(mandateSchema) }

// Audit returns a copy of the audit log schema.
func Audit() []byte { return bytes.Clone(auditSchema) }

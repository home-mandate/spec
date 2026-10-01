// SPDX-License-Identifier: Apache-2.0

// Package schema stellt die normativen JSON-Schemas von mandate-spec v0 bereit, ohne die
// Beispiele und Konformitätsfälle mitzubringen.
package schema

import (
	"bytes"
	_ "embed"
)

// IDs der Schemas, wie sie in "$id" stehen.
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

// Mandate liefert eine Kopie des Mandats-Schemas.
func Mandate() []byte { return bytes.Clone(mandateSchema) }

// Audit liefert eine Kopie des Protokoll-Schemas.
func Audit() []byte { return bytes.Clone(auditSchema) }

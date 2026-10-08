// SPDX-License-Identifier: Apache-2.0

// Package spec embeds the machine-readable parts of the specification:
// schemas, example mandates and conformance cases. Implementations use it to test against
// exactly the version of the specification they depend on.
package spec

import (
	"embed"
	"io/fs"
)

// Paths within FS.
const (
	MandateSchemaPath   = "schema/mandate-v0.schema.json"
	AuditSchemaPath     = "schema/audit-v0.schema.json"
	CasesPath           = "conformance/cases-v0.json"
	InvalidCasesPath    = "conformance/invalid-v0.json"
	DigestCasesPath     = "conformance/digest-v0.json"
	AuditCasesPath      = "conformance/audit-v0.json"
	SelectionCasesPath  = "conformance/selection-v0.json"
	SignedCasesPath     = "conformance/signed-v0.json"
	SuccessionCasesPath = "conformance/succession-v0.json"
	ManifestPath        = "conformance/manifest.json"
)

//go:embed schema/*.json examples conformance data/*.json vocabulary/*.json
var files embed.FS

// FS returns the embedded files, read-only. Paths are relative to the repository
// root, as in the conformance cases.
func FS() fs.FS {
	return files
}

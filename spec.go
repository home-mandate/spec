// SPDX-License-Identifier: Apache-2.0

// Package mandatespec bettet die maschinenlesbaren Teile der Spezifikation ein:
// Schemas, Beispiel-Mandate und Konformitätsfälle. Implementierungen testen damit gegen
// genau die Version der Spezifikation, die sie als Abhängigkeit einbinden.
package mandatespec

import (
	"embed"
	"io/fs"
)

// Pfade innerhalb von FS.
const (
	MandateSchemaPath = "schema/mandate-v0.schema.json"
	AuditSchemaPath   = "schema/audit-v0.schema.json"
	CasesPath         = "conformance/cases-v0.json"
	InvalidCasesPath  = "conformance/invalid-v0.json"
	DigestCasesPath   = "conformance/digest-v0.json"
	AuditCasesPath    = "conformance/audit-v0.json"
)

//go:embed schema examples conformance
var files embed.FS

// FS liefert die eingebetteten Dateien schreibgeschützt. Pfade sind relativ zum
// Wurzelverzeichnis des Repositorys, wie in den Konformitätsfällen.
func FS() fs.FS {
	return files
}

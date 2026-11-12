// SPDX-License-Identifier: Apache-2.0

package relay

import (
	"embed"
	"io/fs"
)

// Paths within FS.
const (
	MetadataSchemaPath   = "schema/metadata-v0.schema.json"
	EnrollmentSchemaPath = "schema/enrollment-v0.schema.json"
	MetadataExamplePath  = "examples/metadata.json"
	ManifestPath         = "conformance/manifest.json"
)

// The conformance/keys directory is deliberately not embedded: its private keys are public
// and MUST NOT reach a live operator (RELAY-v0 section 8.2). conformance/*.json takes the
// case files and the manifest, conformance/schema their schemas.
//
//go:embed schema/*.json examples conformance/*.json conformance/schema
var files embed.FS

// FS returns the embedded schemas, examples and conformance cases of the Relay
// Specification, read-only. Paths are relative to the directory relay/ of the repository.
func FS() fs.FS {
	return files
}

// SPDX-License-Identifier: Apache-2.0

// Package relay holds the tests of the machine-readable files of the Home-Mandate Relay
// Specification (RELAY-v0.md): the schemas of the operator metadata and of the enrollment
// messages, their examples, and the conformance cases in conformance/ with their manifest.
// The requests are checked with the package jws, the metadata with relay/internal/metadata.
// FS embeds the schemas, examples and cases, never conformance/keys, for the test tool
// relay/cmd/relay-conformance. The files are not embedded in the root package, because they
// are not part of v0.1.0.
package relay

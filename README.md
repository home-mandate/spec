# Home-Mandate Specification

Vendor-neutral specification for **mandates of software agents in the household**: what an
AI agent may do on behalf of a household, with the decisions allow, ask and
deny, plus test tools with which any implementation demonstrates its conformance.

Status: Draft v0. The reference evaluator is the Go code in this repository; the first
product that implements the specification is Home-Mandate for Home Assistant.

## Contents

| Path | Contents | License |
|---|---|---|
| `SPEC-v0.md` | Specification: data model, evaluation rule, vocabulary, AuthZEN mapping | CC BY 4.0 |
| `vocabulary/v0.json` | Vocabulary: categories, actions, critical actions (normative) | Apache 2.0 |
| `schema/vocabulary-v0.schema.json` | JSON Schema of a vocabulary file, also for extensions | Apache 2.0 |
| `profiles/` | Informative mappings of platforms (Home Assistant, Matter) to the vocabulary | Apache 2.0 |
| `schema/mandate-v0.schema.json` | JSON Schema of the mandate (Draft 2020-12) | Apache 2.0 |
| `schema/audit-v0.schema.json` | JSON Schema of an audit log entry (Draft 2020-12) | Apache 2.0 |
| `data/forbidden-codepoints-v0.json` | Code points not permitted in text displayed to humans (SPEC-v0 section 3.1 item 8), derived from Unicode 17.0.0 | Apache 2.0 |
| `examples/` | Example mandates | Apache 2.0 |
| `conformance/cases-v0.json` | Conformance cases | Apache 2.0 |
| `conformance/selection-v0.json` | Cases for the selection of the mandate among several stored ones | Apache 2.0 |
| `conformance/succession-v0.json` | Cases for the succession of mandate versions (rollback protection) | Apache 2.0 |
| `conformance/signed-v0.json` | Signed mandates that are accepted or rejected | Apache 2.0 |
| `conformance/keys/` | Test keys of the conformance cases; the private parts are public | Apache 2.0 |
| `conformance/invalid-v0.json` | Invalid mandates that MUST be rejected | Apache 2.0 |
| `conformance/mandates/` | Test mandates for edge cases | Apache 2.0 |
| `conformance/digest-v0.json` | Digests of mandates (RFC 8785 + SHA-256) | Apache 2.0 |
| `conformance/audit-v0.json` | Audit logs with the expected result of the hash chain verification | Apache 2.0 |
| `conformance/schema/` | JSON Schemas of the conformance files, so that they can be used without the Go code | Apache 2.0 |
| `conformance/manifest.json` | All machine-readable files with SHA-256 and number of cases; `make manifest` rewrites it | Apache 2.0 |
| `evaluator/` | Reference evaluator as a Go library (`github.com/home-mandate/spec/evaluator`), standard library only plus a JSON Schema validator | Apache 2.0 |
| `audit/` | Entry digests and hash-chain verification of audit logs (SPEC-v0 section 9), checked against `conformance/audit-v0.json` | Apache 2.0 |
| `displaytext/` | Check of text displayed to humans against the code point list | Apache 2.0 |
| `jws/` | The part of JSON Web Signature the specification uses: compact serialization, EdDSA and ES256, JWK Sets; standard library only | Apache 2.0 |
| `ratelimit/` | Reference for the rate limit bound of SPEC-v0 section 11.2 | Apache 2.0 |
| `jcs/` | JSON Canonicalization Scheme (RFC 8785) for the digests of mandates and audit entries | Apache 2.0 |
| `schema/*.go`, `spec.go` | Go packages that embed the schemas (`schema`) and the schemas, examples and conformance cases (root package), respectively | Apache 2.0 |
| `tools/vectors/` | Helper for maintaining the conformance files: manifest, mandate digests, chaining audit entries | Apache 2.0 |
| `Makefile` | Checks: `make check` (vet, staticcheck, coverage ≥ 95 %, govulncheck), `make fuzz`, `make mutation` (≥ 90 %) | Apache 2.0 |
| `cmd/mandate-conformance/` | Test tool: plays the conformance cases against any implementation, over standard input and output or over HTTP (SPEC-v0 section 10) | Apache 2.0 |
| `cmd/mandate-harness/` | The reference code behind the process binding of the test interface; example for implementers | Apache 2.0 |

## Testing an implementation

```
go install github.com/home-mandate/spec/cmd/mandate-conformance@latest
mandate-conformance -report report.json -exec ./your-harness
```

Your harness reads one JSON request per line and writes one JSON response per line
(SPEC-v0 section 10.2); it can be written in any language and needs no network. The
report states which conformance classes the implementation passes and for which exact
set of cases.

## Licenses

The specification text (`SPEC-*.md`) is licensed under CC BY 4.0, see `LICENSE-docs`.
Everything else is licensed under Apache 2.0, see `LICENSE`.
The name Home-Mandate and its logo are not covered by these licenses.

Contributing: `CONTRIBUTING.md`. Reporting vulnerabilities: `SECURITY.md`.

## Why a separate repository

- **Neutrality:** Other vendors are more likely to adopt a standard if it does not live in a
  competitor's product repository.
- **License:** Apache 2.0 with a patent clause for everything that others integrate; the product itself
  remains AGPL.
- **Versioning:** The specification has its own, slower cadence (tags `v0.1.0` …).
  Implementations refer to a specific version.
- **Credibility of testing:** Test cases and the test tool are maintained independently of the product;
  Home-Mandate for Home Assistant must pass them as well.

## Rules for changes

- Every change to the evaluation rule requires new or modified conformance cases.
- Bugs in an implementation that stem from an ambiguity in the specification are
  first clarified here.
- Until v1.0, incompatible changes are permitted but must be recorded in the Changelog.

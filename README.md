# mandate-spec

Vendor-neutral specification for **mandates of software agents in the household**: what an
AI agent may do on behalf of a household, with the decisions allow, ask and
deny, plus test tools with which any implementation demonstrates its conformance.

Status: Draft v0. Reference implementation: Home-Mandate.

## Contents

| Path | Contents | License |
|---|---|---|
| `SPEC-v0.md` | Specification: data model, evaluation rule, vocabulary, AuthZEN mapping | CC BY 4.0 |
| `schema/mandate-v0.schema.json` | JSON Schema of the mandate (Draft 2020-12) | Apache 2.0 |
| `schema/audit-v0.schema.json` | JSON Schema of an audit log entry (Draft 2020-12) | Apache 2.0 |
| `examples/` | Example mandates | Apache 2.0 |
| `conformance/cases-v0.json` | Conformance cases | Apache 2.0 |
| `conformance/invalid-v0.json` | Invalid mandates that MUST be rejected | Apache 2.0 |
| `conformance/mandates/` | Test mandates for edge cases | Apache 2.0 |
| `conformance/digest-v0.json` | Digests of mandates (RFC 8785 + SHA-256) | Apache 2.0 |
| `conformance/audit-v0.json` | Audit logs with the expected result of the hash chain verification | Apache 2.0 |
| `evaluator/` | Reference evaluator as a Go library (`github.com/mandate-spec/mandate-spec/evaluator`), standard library only plus a JSON Schema validator | Apache 2.0 |
| `schema/*.go`, `spec.go` | Go packages that embed the schemas (`schema`) and the schemas, examples and conformance cases (root package), respectively | Apache 2.0 |
| `Makefile` | Checks: `make check` (vet, staticcheck, coverage ≥ 95 %, govulncheck), `make fuzz`, `make mutation` (≥ 90 %) | Apache 2.0 |
| `cmd/mandate-conformance/` *(planned, v0.2)* | Black-box test tool against arbitrary AuthZEN endpoints | Apache 2.0 |

## Why a separate repository

- **Neutrality:** Other vendors are more likely to adopt a standard if it does not live in a
  competitor's product repository.
- **License:** Apache 2.0 with a patent clause for everything that others integrate; the product itself
  remains AGPL.
- **Versioning:** The specification has its own, slower cadence (tags `v0.1.0` …).
  Implementations refer to a specific version.
- **Credibility of testing:** Test cases and the test tool are maintained independently of the product;
  Home-Mandate must pass them as well.

## Rules for changes

- Every change to the evaluation rule requires new or modified conformance cases.
- Bugs in an implementation that stem from an ambiguity in the specification are
  first clarified here.
- Until v1.0, incompatible changes are permitted but must be recorded in the Changelog.

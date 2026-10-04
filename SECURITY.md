# Security

## Reporting a vulnerability

Please do **not** open a public issue for anything that could put a household at risk: a
flaw in the evaluation rule, the schemas, the digest, the audit log format, the reference
code or a conformance case that requires insecure behavior.

Report it privately through this repository on GitHub: **Security → Report a vulnerability**
(GitHub private vulnerability reporting). We acknowledge within 72 hours and disclose in a
coordinated manner. A flaw in the specification affects every implementation, so we inform
known implementers before the fix is published.

## Scope

In scope: `SPEC-*.md`, `schema/`, `conformance/`, `examples/` and the Go packages in this
repository. Vulnerabilities in a product that implements the specification belong to that
product; if the cause is an ambiguity in the specification, report it here as well.

## How fixes are made

Every fix starts with a conformance case that fails, then the text of the specification,
then the reference code. The Changelog in the specification names the change and says
whether mandates that were valid before become invalid.

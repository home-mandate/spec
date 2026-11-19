# Contributing

The Home-Mandate Specification is meant to be implemented by anyone, in any language, on any
platform. Changes are judged by that goal first.

## Principles

1. **The specification is the truth.** If the reference code disagrees with the text, the
   code is wrong. If the text is unclear, the text is clarified first, then a conformance
   case is added, then the code is changed.
2. **No platform in the normative parts.** Schemas, the evaluation rule and the conformance
   cases MUST NOT depend on a product, a vendor, a programming language, a regular expression
   dialect or the version of a runtime. Knowledge about a platform belongs in an informative
   profile.
3. **Properties, not mechanisms.** Where the specification places requirements on an
   implementation, it states what must hold, not which algorithm, channel or transport
   achieves it.
4. **When in doubt, deny.** A change must never turn a `deny` into an `allow` for input that
   was valid before, unless the Changelog says so explicitly.
5. **Everything normative is machine-readable** and usable without the Go code in this
   repository.

## Making a change

- Open an issue that describes the problem before a larger change.
- Every change to the evaluation rule or to validity comes with new or changed conformance
  cases. A bug report is most useful as a failing case. A case for a rule of a referenced
  RFC gets its entry in `conformance/RFC-COVERAGE.md`.
- After changing a schema, an example or a conformance file run `make manifest`.
- `make check` must pass: vet, staticcheck, tests with the race detector, coverage of at
  least 95 %, govulncheck.
- When what runs in CI: a push to a branch runs `make check`; a pull request against main or
  a release branch additionally runs short fuzzing, which replays the inputs earlier runs
  found and gives every target 15 seconds; nothing runs after the merge. Independent of
  changes, govulncheck runs every night, and every fuzz target runs for ten minutes on
  Wednesday and Saturday and keeps what it finds; a failure opens an issue. A release
  candidate runs the release gate before it can become the version: every fuzz target for
  20 minutes, and `make mutation`.
- The reference evaluator uses the Go standard library and a JSON Schema validator, nothing
  else.
- Since `v0.1.0`, an incompatible change requires a new major version of the format
  (Section 14 of the specification): a document that was valid stays valid and is
  evaluated the same way. Compatible changes, such as a new optional member, go into the
  Changelog under "Unreleased" with what they mean for older implementations. Where
  implementations were more lenient than a rule, a correction (Section 14) enforces the rule
  without making an unaltered audit log invalid.
- Security problems: see `SECURITY.md`, not a public issue.

## Licenses

By contributing you agree that your contribution is licensed as the file it changes:
`SPEC-*.md` under CC BY 4.0 (`LICENSE-docs`), everything else under Apache 2.0 (`LICENSE`).

## Governance

Who decides what is in the organization's
[governance](https://github.com/home-mandate/.github/blob/main/GOVERNANCE.md): until v1.0 I
edit the specification, in public pull requests, guided by the principles above, and
implementers are heard before an incompatible change. The organization's
[contributing rules](https://github.com/home-mandate/.github/blob/main/CONTRIBUTING.md) and
[code of conduct](https://github.com/home-mandate/.github/blob/main/CODE_OF_CONDUCT.md) apply
here too; what implementations of the specification keep is in
[IMPLEMENTATIONS.md](https://github.com/home-mandate/.github/blob/main/IMPLEMENTATIONS.md).

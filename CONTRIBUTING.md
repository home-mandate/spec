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
  cases. A bug report is most useful as a failing case.
- After changing a schema, an example or a conformance file run `make manifest`.
- `make check` must pass: vet, staticcheck, tests with the race detector, coverage of at
  least 95 %, govulncheck. Before a release `make fuzz` and `make mutation` must pass too.
- When what runs in CI: a push to a branch runs `make check`; a pull request against main
  additionally runs short fuzzing; nothing runs after the merge, and every merge is tagged.
  Independent of changes, govulncheck runs every night and every fuzz target runs for 45
  minutes on the 1st and 15th of every month; a failure opens an issue.
- The reference evaluator uses the Go standard library and a JSON Schema validator, nothing
  else.
- Incompatible changes are permitted until v1.0 and are listed in the Changelog of the
  specification, together with what happens to mandates that were valid before.
- Security problems: see `SECURITY.md`, not a public issue.

## Licenses

By contributing you agree that your contribution is licensed as the file it changes:
`SPEC-*.md` under CC BY 4.0 (`LICENSE-docs`), everything else under Apache 2.0 (`LICENSE`).

## Governance

Until v1.0 the maintainers of the `home-mandate` organization decide on changes, in public
pull requests, guided by the principles above. Implementers of the specification are heard
before an incompatible change. The specification lives in its own repository, separate from any product, so that it
can be handed to a neutral body once more than one independent implementation exists; the
process for the vocabulary and for extensions is defined before v1.0.

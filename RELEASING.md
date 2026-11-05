# Releasing the specification

The rules are the same for the whole organization:
[RELEASING.md](https://github.com/home-mandate/.github/blob/main/RELEASING.md). This page says
only what is particular to this repository.

## What is published

A version is the text, the schemas, the conformance cases and the reference implementation at
a tag; the Go module proxy serves it from the tag. A tag runs `.github/workflows/release.yml`,
which creates the GitHub release, and `conformance-report.yml` attaches the attested report.

Merges are not tagged one by one. A pre-release (`v0.2.0-alpha.1`) is tagged on purpose, when
implementers should look at a state.

## Before a tag

- `make check`, `make fuzz` and `make mutation` pass.
- `make manifest` was run after a change to a schema, an example or a conformance file.
- A version without a suffix has its entry in the changelog of `SPEC-v0.md`, moved out of
  "Unreleased"; `release.yml` refuses it otherwise.

```sh
git switch main && git pull   # for a patch: release/X.Y
git tag -a v0.2.0-alpha.1 -m "Home-Mandate Specification v0.2.0-alpha.1"
git push origin v0.2.0-alpha.1
```

The text of the release is generated and can be edited afterwards.

## After a patch

The patch's changelog entry goes to `SPEC-v0.md` on `main` too. Implementations and
home-mandate.org follow in their own pull requests.

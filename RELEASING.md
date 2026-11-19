# Releasing the specification

The rules are the same for the whole organization:
[RELEASING.md](https://github.com/home-mandate/.github/blob/main/RELEASING.md). This page says
only what is particular to this repository.

## What is published

A version is the text, the schemas, the conformance cases and the reference implementation at
a tag; the Go module proxy serves it from the tag. A tag runs `.github/workflows/release.yml`,
which creates the GitHub release as a draft; `conformance-report.yml` attaches the attested
report to the draft, and the draft is published only with the report attached. A published
release is immutable. A run that fails before that leaves a draft, and the version needs a new
tag; the Go module proxy may serve the failed tag anyway.

Merges are not tagged one by one. A pre-release (`v0.3.0-alpha.1`) is tagged on `main` on
purpose, when implementers should look at a state.

## The release gate

After a release candidate is published, `release.yml` runs what is too long for every pull
request: every target of `FUZZ_TARGETS` for 20 minutes, on top of the corpus the runs of
`scheduled.yml` have collected, and the mutation tests (`make mutation`, at least 90 % of the
injected faults found). The job `Release gate` succeeds only if all of it passed, and a
version can only be tagged on a commit whose release candidate has that job green.

## Before a tag

- `make manifest` was run after a change to a schema, an example or a conformance file.
- A release candidate and a version have their entry in the changelog of `SPEC-v0.md`, moved
  out of "Unreleased" and without a date, before the first release candidate; `release.yml`
  refuses them otherwise. The date of a version is the date of its release.
- The dry run passes: it checks the tag without creating it.

```sh
# the release candidate, on the release branch
gh workflow run release.yml --ref release/0.3 -f tag=v0.3.0-rc.1   # dry run, publishes nothing
git switch release/0.3 && git pull
git tag -a v0.3.0-rc.1 -m "Home-Mandate Specification v0.3.0-rc.1"
git push origin v0.3.0-rc.1

# the version, on the commit of the release candidate, after its gate and the test
gh workflow run release.yml --ref release/0.3 -f tag=v0.3.0
git tag -a v0.3.0 -m "Home-Mandate Specification v0.3.0" v0.3.0-rc.1^{commit}
git push origin v0.3.0
```

The text of the release is generated and can be edited afterwards.

## After a patch

The patch's changelog entry goes to `SPEC-v0.md` on `main` too. Implementations and
home-mandate.org follow in their own pull requests.

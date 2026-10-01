# SPDX-License-Identifier: Apache-2.0

# A go.work in a parent directory must not affect this module.
export GOWORK := off

STATICCHECK := honnef.co/go/tools/cmd/staticcheck@v0.8.1
GOVULNCHECK := golang.org/x/vuln/cmd/govulncheck@v1.8.0
GREMLINS    := github.com/go-gremlins/gremlins/cmd/gremlins@v0.6.0

COVER_MIN      := 95
EFFICACY_MIN   := 90
FUZZTIME       ?= 10m
FUZZ_TARGETS   := FuzzParse FuzzEvaluate

.PHONY: check test cover vet staticcheck vulncheck fuzz mutation

## check: everything that must be green before a commit
check: vet staticcheck cover vulncheck

test:
	go test -race ./...

cover:
	go test -race -coverprofile=cover.out ./...
	@go tool cover -func=cover.out | awk -v min=$(COVER_MIN) '/^total:/ { sub("%", "", $$3); \
		if ($$3 + 0 < min) { print "Coverage " $$3 "% < " min "%"; exit 1 } else print "Coverage " $$3 "%" }'

vet:
	go vet ./...

staticcheck:
	go run $(STATICCHECK) ./...

vulncheck:
	go run $(GOVULNCHECK) ./...

## fuzz: each target for FUZZTIME, e.g. make fuzz FUZZTIME=30s
fuzz:
	@for target in $(FUZZ_TARGETS); do \
		go test ./evaluator/ -run '^$$' -fuzz "^$$target\$$" -fuzztime $(FUZZTIME) || exit 1; \
	done

## mutation: mutation tests; target ≥ 90 % killed mutants (required before a release).
## Gremlins does not reliably enforce the threshold via its exit code, so awk checks it.
## Without a higher timeout coefficient, mutants time out when the build cache is warm.
mutation:
	GOFLAGS=-count=1 go run $(GREMLINS) unleash -S lt --timeout-coefficient 20 ./evaluator | tee mutation.out
	@awk -v min=$(EFFICACY_MIN) '/^Test efficacy:/ { sub("%", "", $$3); found = 1; \
		if ($$3 + 0 < min) { print "Mutation score " $$3 "% < " min "%"; exit 1 } else print "Mutation score " $$3 "%" } \
		END { if (!found) { print "Mutation score not found"; exit 1 } }' mutation.out

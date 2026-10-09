# SPDX-License-Identifier: Apache-2.0

# A go.work in a parent directory must not affect this module.
export GOWORK := off

STATICCHECK := honnef.co/go/tools/cmd/staticcheck@v0.8.1
GOVULNCHECK := golang.org/x/vuln/cmd/govulncheck@v1.8.0
GREMLINS    := github.com/go-gremlins/gremlins/cmd/gremlins@v0.6.0

COVER_MIN      := 95
EFFICACY_MIN   := 90
FUZZTIME       ?= 10m
# package:target
FUZZ_TARGETS   := evaluator:FuzzParse evaluator:FuzzEvaluate audit:FuzzVerify jws:FuzzVerify internal/harness:FuzzServe
MUTATION_PKGS  := ./evaluator ./audit ./jcs ./jws ./displaytext ./ratelimit

.PHONY: check test cover vet staticcheck vulncheck fuzz mutation manifest

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

# Temporary (2026-10-09): staticcheck v0.8.1 cannot read Go 1.27.2's export data
# (dominikh/go-tools#1832). A run whose only output is that error (and module downloads)
# counts as a warning; any other output still fails. Remove once a compatible staticcheck
# release is pinned.
STATICCHECK_EXPORT_DATA := export data version 5 is greater than maximum supported version 4
staticcheck:
	@out=$$(go run $(STATICCHECK) ./... 2>&1); status=$$?; \
	if [ $$status -ne 0 ] && echo "$$out" | grep -qF "$(STATICCHECK_EXPORT_DATA)" && \
	   ! echo "$$out" | grep -vF -e "$(STATICCHECK_EXPORT_DATA)" -e "exit status" -e "go: downloading " | grep -q .; then \
		msg="staticcheck skipped: $(STATICCHECK) cannot read this Go version's export data (dominikh/go-tools#1832)"; \
		if [ -n "$$GITHUB_ACTIONS" ]; then echo "::warning::$$msg"; else echo "WARNING: $$msg"; fi; \
		exit 0; \
	fi; \
	[ -z "$$out" ] || echo "$$out"; exit $$status

vulncheck:
	go run $(GOVULNCHECK) ./...

## manifest: rewrite conformance/manifest.json after changing schemas, examples or cases
manifest:
	go run ./tools/vectors manifest

## fuzz: each target for FUZZTIME, e.g. make fuzz FUZZTIME=30s
fuzz:
	@for spec in $(FUZZ_TARGETS); do \
		pkg=$${spec%%:*}; target=$${spec#*:}; \
		go test ./$$pkg/ -run '^$$' -fuzz "^$$target\$$" -fuzztime $(FUZZTIME) || exit 1; \
	done

## mutation: mutation tests; target ≥ 90 % killed mutants (required before a release).
## Gremlins does not reliably enforce the threshold via its exit code, so awk checks it.
## Without a higher timeout coefficient, mutants time out when the build cache is warm.
mutation:
	@for pkg in $(MUTATION_PKGS); do \
		GOFLAGS=-count=1 go run $(GREMLINS) unleash -S lt --timeout-coefficient 20 $$pkg | tee mutation.out; \
		awk -v min=$(EFFICACY_MIN) -v pkg=$$pkg '/^Test efficacy:/ { sub("%", "", $$3); found = 1; \
			if ($$3 + 0 < min) { print pkg ": mutation score " $$3 "% < " min "%"; exit 1 } else print pkg ": mutation score " $$3 "%" } \
			END { if (!found) { print pkg ": mutation score not found"; exit 1 } }' mutation.out || exit 1; \
	done

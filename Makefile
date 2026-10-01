# SPDX-License-Identifier: Apache-2.0

# Eine go.work in einem übergeordneten Verzeichnis darf dieses Modul nicht beeinflussen.
export GOWORK := off

STATICCHECK := honnef.co/go/tools/cmd/staticcheck@v0.8.1
GOVULNCHECK := golang.org/x/vuln/cmd/govulncheck@v1.8.0
GREMLINS    := github.com/go-gremlins/gremlins/cmd/gremlins@v0.6.0

COVER_MIN      := 95
EFFICACY_MIN   := 90
FUZZTIME       ?= 10m
FUZZ_TARGETS   := FuzzParse FuzzEvaluate

.PHONY: check test cover vet staticcheck vulncheck fuzz mutation

## check: alles, was vor einem Commit grün sein muss
check: vet staticcheck cover vulncheck

test:
	go test -race ./...

cover:
	go test -race -coverprofile=cover.out ./...
	@go tool cover -func=cover.out | awk -v min=$(COVER_MIN) '/^total:/ { sub("%", "", $$3); \
		if ($$3 + 0 < min) { print "Abdeckung " $$3 "% < " min "%"; exit 1 } else print "Abdeckung " $$3 "%" }'

vet:
	go vet ./...

staticcheck:
	go run $(STATICCHECK) ./...

vulncheck:
	go run $(GOVULNCHECK) ./...

## fuzz: jedes Ziel FUZZTIME lang, z. B. make fuzz FUZZTIME=30s
fuzz:
	@for target in $(FUZZ_TARGETS); do \
		go test ./evaluator/ -run '^$$' -fuzz "^$$target\$$" -fuzztime $(FUZZTIME) || exit 1; \
	done

## mutation: Mutationstests; Ziel ≥ 90 % getötete Mutanten (Pflicht vor dem Release).
## Gremlins setzt mit seinem Exit-Code die Schwelle nicht zuverlässig durch, deshalb prüft awk.
## Ohne höheren Zeitkoeffizienten laufen Mutanten bei warmem Build-Cache in Zeitüberschreitungen.
mutation:
	GOFLAGS=-count=1 go run $(GREMLINS) unleash -S lt --timeout-coefficient 20 ./evaluator | tee mutation.out
	@awk -v min=$(EFFICACY_MIN) '/^Test efficacy:/ { sub("%", "", $$3); found = 1; \
		if ($$3 + 0 < min) { print "Mutationswert " $$3 "% < " min "%"; exit 1 } else print "Mutationswert " $$3 "%" } \
		END { if (!found) { print "Mutationswert nicht gefunden"; exit 1 } }' mutation.out

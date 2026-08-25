# Developer-experience shortcuts for Tracefall. These wrap the existing
# `go` toolchain and internal/config flags/env vars directly -- no
# configuration logic is duplicated here. See internal/config for the
# full list of flags/env vars (TRACEFALL_HOST, TRACEFALL_PORT, etc.).

BINARY := ./bin/tracefall

.PHONY: run run-lan build test test-race clean

## Local development: binds to 127.0.0.1:8080 (internal/config's default).
run:
	go run ./cmd/tracefall

## LAN testing: binds to 0.0.0.0:8080, reachable from other machines on
## the same network. Reuses the existing -host flag; port stays default.
run-lan:
	go run ./cmd/tracefall -host 0.0.0.0

## Build the Tracefall binary to ./bin/tracefall.
build:
	mkdir -p $(dir $(BINARY))
	go build -o $(BINARY) ./cmd/tracefall

test:
	go test ./...

test-race:
	go test -race ./...

## Remove build artifacts only -- never the database, case data,
## uploads, or evidence (those live in the db file and data dir, both
## untouched here).
clean:
	rm -rf ./bin

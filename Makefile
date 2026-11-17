PATH := /opt/homebrew/bin:$(PATH)

.PHONY: build test race bench lint e2e verify-all

build:
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/tracescrub ./cmd/tracescrub

test:
	go test -v -cover ./...

race:
	go test -race -count=1 ./...

bench:
	go test -bench=. -benchmem ./internal/redact/... ./internal/proxy/...

lint:
	go vet ./...

e2e:
	go test -v -race ./test/e2e/...

verify-all: build race e2e bench
	@echo "ALL TRACESCRUB QA GATES PASSED"

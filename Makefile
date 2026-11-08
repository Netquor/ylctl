VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w -X github.com/Netquor/ylctl/internal/cli.Version=$(VERSION) -X github.com/Netquor/ylctl/internal/cli.Commit=$(COMMIT) -X github.com/Netquor/ylctl/internal/cli.Date=$(DATE)

.PHONY: build test lint fmt vet

# build writes dist/ylctl (dist/ is git-ignored).
build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/ylctl ./cmd/ylctl

test:
	go test -race -count=1 ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

# lint: gofmt must be clean, go vet must pass; golangci-lint runs too when it is installed.
lint: vet
	@test -z "$$(gofmt -l .)" || (echo "gofmt needed on:"; gofmt -l .; exit 1)
	@if command -v golangci-lint >/dev/null 2>&1; then golangci-lint run ./...; else echo "golangci-lint not installed, skipped"; fi

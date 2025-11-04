.PHONY: test test-coverage test-cover test-verbose build clean help

# Default port for coverage server
PORT ?= :3000

help:
	@echo "Available targets:"
	@echo "  make test              - Run all tests"
	@echo "  make test-verbose      - Run tests with verbose output"
	@echo "  make test-coverage     - Run tests and generate coverage report (HTML)"
	@echo "  make test-cover        - Run tests, serve coverage on PORT (default :3000)"
	@echo "                           Usage: make test-cover PORT=:8080"
	@echo "  make build             - Build the application"
	@echo "  make clean             - Remove build artifacts and test coverage files"

test:
	go test -v -race -coverprofile=coverage.out ./...
	@echo ""
	@echo "Coverage summary:"
	@go tool cover -func=coverage.out | tail -1

test-verbose:
	go test -v -race -coverprofile=coverage.out ./... -count=1

test-coverage: test
	go tool cover -html=coverage.out -o index.html
	@echo ""
	@echo "Coverage report generated: index.html"
	@echo "Open index.html in a browser to view the detailed report"

# Run tests and serve coverage report on a local HTTP server
test-cover: test
	@set -e; \
	TMPDIR=$$(mktemp -d); \
	trap "rm -rf $$TMPDIR" EXIT; \
	go tool cover -html=coverage.out -o $$TMPDIR/index.html; \
	echo ""; \
	echo "✓ Coverage report generated"; \
	echo "  Location: $$TMPDIR/index.html"; \
	echo ""; \
	echo "Starting HTTP server..."; \
	echo "  URL: http://localhost$(PORT)"; \
	echo "  Press Ctrl+C to stop"; \
	echo ""; \
	if command -v python3 >/dev/null 2>&1; then \
		cd $$TMPDIR && python3 -m http.server $(subst :,,$(PORT)); \
	elif command -v python >/dev/null 2>&1; then \
		cd $$TMPDIR && python -m SimpleHTTPServer $(subst :,,$(PORT)); \
	else \
		echo "ERROR: python3 or python not found"; \
		exit 1; \
	fi

build: bin/
	CGO_ENABLED=0 go build -o bin/turnkey-client .

bin/:
	mkdir -p bin

clean:
	rm -rf bin/ coverage.out index.html
	go clean

# Run tests with strict race detection and fail on coverage below threshold
test-strict:
	go test -v -race -coverprofile=coverage.out -covermode=atomic ./...
	@COVERAGE=$$(go tool cover -func=coverage.out | tail -1 | awk '{print $$3}' | sed 's/%//'); \
	if [ "$$(echo "$$COVERAGE < 60" | bc)" -eq 1 ]; then \
		echo "ERROR: Code coverage $$COVERAGE% is below minimum 60%"; \
		exit 1; \
	fi; \
	echo "✓ Code coverage: $$COVERAGE%"

# Run tests related to manifest processing
test-manifest:
	go test -v -race -run TestManifest ./...

# Run tests related to cryptography
test-crypto:
	go test -v -race -run TestCrypto ./...

# Run tests related to API key handling
test-apikey:
	go test -v -race -run TestAPIKey ./...

# Run tests related to client functionality
test-client:
	go test -v -race -run TestClient ./...

# Run benchmarks
bench:
	go test -bench=. -benchmem ./...

# Run benchmarks with verbose output
bench-verbose:
	go test -bench=. -benchmem -v ./...

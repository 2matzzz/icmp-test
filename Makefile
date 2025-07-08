# Makefile for building and testing Go project

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build -ldflags="-s -w"
GOTEST=$(GOCMD) test
GOFMT=$(GOCMD) fmt
GOMOD=$(GOCMD) mod tidy
BINARY_NAME=icmp-test

# OS (can be overridden: e.g. make build GOOS=linux)
GOOS ?= linux
# Architecture (can be overridden: e.g. make build GOARCH=arm64)
GOARCH ?= arm64

# Directories
SRC_DIR=./...
CONFIG_DIR=tests/configs

# Build the project
build: tidy
	GOOS=$(GOOS) GOARCH=$(GOARCH) $(GOBUILD) -o $(BINARY_NAME) $(SRC_DIR)

# Run unit tests
test:
	$(GOTEST) -v ./...

# Run integration tests (requires root privileges)
test-integration:
	$(GOTEST) -v -run TestICMPIntegration ./...

# Run YAML-based integration tests
test-yaml: build
	@echo "Running YAML-based ICMP tests..."
	@for config in $(CONFIG_DIR)/*.yaml; do \
		echo "Running test with config: $$config"; \
		sudo ./$(BINARY_NAME) -config $$config || echo "Test failed: $$config"; \
		echo ""; \
	done

# Run specific test config
test-config: build
	@if [ -z "$(CONFIG)" ]; then \
		echo "Usage: make test-config CONFIG=tests/configs/test_basic.yaml"; \
		exit 1; \
	fi
	sudo ./$(BINARY_NAME) -config $(CONFIG)

# Test comprehensive functionality (basic + payload sizes)
test-comprehensive: build
	sudo ./$(BINARY_NAME) -config $(CONFIG_DIR)/comprehensive.yaml

# Test DF bit functionality
test-df: build
	sudo ./$(BINARY_NAME) -config $(CONFIG_DIR)/df_bit.yaml

# Test localhost functionality
test-localhost: build
	sudo ./$(BINARY_NAME) -config $(CONFIG_DIR)/localhost.yaml

# Run all YAML tests with summary
test-all-yaml: build
	@echo "=== Running All YAML Test Configurations ==="
	@passed=0; failed=0; \
	for config in $(CONFIG_DIR)/*.yaml; do \
		echo "Running: $$config"; \
		if sudo ./$(BINARY_NAME) -config $$config >/dev/null 2>&1; then \
			echo "✓ PASSED: $$config"; \
			passed=$$((passed + 1)); \
		else \
			echo "✗ FAILED: $$config"; \
			failed=$$((failed + 1)); \
		fi; \
	done; \
	echo ""; \
	echo "=== Test Summary ==="; \
	echo "Passed: $$passed"; \
	echo "Failed: $$failed"; \
	echo "Total:  $$((passed + failed))"

# Format the code
fmt:
	$(GOFMT) ./...

# Tidy up go.mod and go.sum
tidy:
	$(GOMOD)

# Clean build artifacts
clean:
	rm -f $(BINARY_NAME)

# Show available test configs
list-configs:
	@echo "Available test configurations:"
	@ls -1 $(CONFIG_DIR)/*.yaml | sed 's|$(CONFIG_DIR)/||'

# Default target
all: fmt tidy build test

# Help target
help:
	@echo "Available targets:"
	@echo "  build            - Build the binary"
	@echo "  test             - Run unit tests"
	@echo "  test-integration - Run Go integration tests (requires root)"
	@echo "  test-yaml        - Run all YAML-based tests (requires root)"
	@echo "  test-config      - Run specific config: make test-config CONFIG=path/to/config.yaml"
	@echo "  test-comprehensive - Run comprehensive functionality tests"
	@echo "  test-df          - Run DF bit tests"
	@echo "  test-localhost   - Run localhost tests"
	@echo "  test-all-yaml    - Run all YAML tests with summary"
	@echo "  list-configs     - List available test configurations"
	@echo "  fmt              - Format code"
	@echo "  clean            - Clean build artifacts"
	@echo "  help             - Show this help"

.PHONY: build test test-integration test-yaml test-config test-comprehensive test-df test-localhost test-all-yaml fmt tidy clean list-configs help all
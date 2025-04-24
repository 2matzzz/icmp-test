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

# Build the project
build: tidy
	GOOS=$(GOOS) GOARCH=$(GOARCH) $(GOBUILD) -o $(BINARY_NAME) $(SRC_DIR)

# Run tests
test:
	$(GOTEST) -v ./...

# Format the code
fmt:
	$(GOFMT) ./...

# Tidy up go.mod and go.sum
tidy:
	$(GOMOD)

# Clean build artifacts
clean:
	rm -f $(BINARY_NAME)

# Default target
all: fmt tidy build test
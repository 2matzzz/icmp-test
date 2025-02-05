# Makefile for building and testing Go project

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build -ldflags="-s -w"
GOTEST=$(GOCMD) test
GOFMT=$(GOCMD) fmt
GOMOD=$(GOCMD) mod tidy
BINARY_NAME=icmp-test

# Directories
SRC_DIR=./...

# Build the project
build: tidy
	$(GOBUILD) -o $(BINARY_NAME) $(SRC_DIR)

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
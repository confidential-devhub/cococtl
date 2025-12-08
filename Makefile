.PHONY: build install clean test help release release-all lint

# Binary name
BINARY_NAME=kubectl-coco

# Installation path
INSTALL_PATH=/usr/local/bin

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod

# Test parameters
TEST?=.

# Version from git
VERSION?=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")

# Build flags
LDFLAGS=-ldflags "-s -w -X github.com/confidential-devhub/cococtl/cmd.version=$(VERSION)"

# Release parameters
GOOS?=$(shell go env GOOS)
GOARCH?=$(shell go env GOARCH)
RELEASE_DIR=release
RELEASE_BINARY=$(BINARY_NAME)-$(GOOS)-$(GOARCH)

# Default target
all: build

## build: Build the kubectl-coco binary
build:
	@echo "Building $(BINARY_NAME) (version: $(VERSION))..."
	$(GOBUILD) $(LDFLAGS) -o $(BINARY_NAME) .
	@echo "Build complete: $(BINARY_NAME)"

## install: Install kubectl-coco to $(INSTALL_PATH)
install: build
	@echo "Installing $(BINARY_NAME) to $(INSTALL_PATH)..."
	@mkdir -p $(INSTALL_PATH)
	@cp $(BINARY_NAME) $(INSTALL_PATH)/
	@chmod +x $(INSTALL_PATH)/$(BINARY_NAME)
	@echo "Installation complete. You can now use: kubectl coco"

## uninstall: Remove kubectl-coco from $(INSTALL_PATH)
uninstall:
	@echo "Uninstalling $(BINARY_NAME)..."
	@rm -f $(INSTALL_PATH)/$(BINARY_NAME)
	@echo "Uninstall complete"

## clean: Remove build artifacts
clean:
	@echo "Cleaning..."
	$(GOCLEAN)
	@rm -f $(BINARY_NAME)
	@rm -f coverage.out coverage.html
	@rm -rf $(RELEASE_DIR)
	@echo "Clean complete"

## test: Run integration tests (use TEST=<regex> to filter, e.g., make test TEST=TestConfig)
test:
	@echo "Running tests (filter: $(TEST))..."
	$(GOTEST) -v -run $(TEST) ./integration_test/...

## tidy: Tidy go modules
tidy:
	@echo "Tidying go modules..."
	$(GOMOD) tidy

## fmt: Format Go code
fmt:
	@echo "Formatting code..."
	$(GOCMD) fmt ./...

## vet: Run go vet
vet:
	@echo "Running go vet..."
	$(GOCMD) vet ./...

## lint: Run golangci-lint
lint:
	@echo "Running golangci-lint..."
	@which golangci-lint > /dev/null || (echo "golangci-lint not found. Install it from https://golangci-lint.run/usage/install/" && exit 1)
	golangci-lint run ./...

## deps: Download dependencies
deps:
	@echo "Downloading dependencies..."
	$(GOGET) -v ./...
	$(GOMOD) download

## help: Show this help message
help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@sed -n 's/^##//p' $(MAKEFILE_LIST) | column -t -s ':' | sed -e 's/^/ /'

## release: Build static binary for specific OS/ARCH (use GOOS and GOARCH env vars)
release:
	@echo "Building release binary for $(GOOS)/$(GOARCH) (version: $(VERSION))..."
	@mkdir -p $(RELEASE_DIR)
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) $(GOBUILD) -ldflags "-s -w -extldflags=-static -X github.com/confidential-devhub/cococtl/cmd.version=$(VERSION)" -o $(RELEASE_DIR)/$(RELEASE_BINARY) .
	@chmod +x $(RELEASE_DIR)/$(RELEASE_BINARY)
	@cd $(RELEASE_DIR) && sha256sum $(RELEASE_BINARY) > $(RELEASE_BINARY).sha256
	@echo "Release binary created: $(RELEASE_DIR)/$(RELEASE_BINARY)"
	@echo "Checksum: $(RELEASE_DIR)/$(RELEASE_BINARY).sha256"

## release-all: Build release binaries for all supported platforms
release-all: clean
	@echo "Building release binaries for all platforms..."
	@$(MAKE) release GOOS=linux GOARCH=amd64
	@$(MAKE) release GOOS=linux GOARCH=ppc64le
	@$(MAKE) release GOOS=linux GOARCH=s390x
	@$(MAKE) release GOOS=darwin GOARCH=amd64
	@$(MAKE) release GOOS=darwin GOARCH=arm64
	@echo "All release binaries created in $(RELEASE_DIR)/"
	@ls -lh $(RELEASE_DIR)/

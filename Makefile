PKG := github.com/lightninglabs/lseed
BINARY := lseed
BUILD_DIR := build

GOBUILD := go build -v
GOINSTALL := go install -v
GOTEST := go test -v
GOMOD := go mod

COMMIT := $(shell git describe --always --dirty --abbrev=40)
COMMIT_HASH := $(shell git rev-parse HEAD)
GOVERSION := $(shell go version | awk '{print $$3}')

LDFLAGS := -ldflags "-X '$(PKG)/version.Commit=$(COMMIT)' -X '$(PKG)/version.CommitHash=$(COMMIT_HASH)' -X '$(PKG)/version.GoVersion=$(GOVERSION)'"

# Default target.
all: build

## Build lseed binary into ./build.
build:
	@echo "Building $(BINARY)..."
	$(GOBUILD) -o $(BUILD_DIR)/$(BINARY) $(LDFLAGS) ./lseed.go

## Install binary to $GOBIN.
install:
	@echo "📦 Installing $(BINARY) to $$GOBIN..."
	$(GOINSTALL) $(LDFLAGS) ./lseed.go

## Clean build artifacts.
clean:
	rm -rf $(BUILD_DIR)

## Run tests.
test:
	$(GOTEST) ./...

## Run go mod tidy.
mod-tidy:
	@echo "Tidying Go modules..."
	$(GOMOD) tidy

## Lint source.
lint:
	golangci-lint run

.PHONY: all build install clean test mod-tidy lint

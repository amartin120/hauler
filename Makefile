# Makefile for hauler

# set shell
SHELL=/bin/bash

# set go variables
GO_FILES=$(shell go list ./... | grep -v /vendor/)
GO_COVERPROFILE=coverage.out

# set cosign variables
COSIGN_VERSION=v2.2.3+carbide.3

# set build variables
BIN_DIRECTORY=bin
DIST_DIRECTORY=dist
BINARIES_DIRECTORY=cmd/hauler/binaries

# builds hauler for current platform
# references other targets
build: install fmt vet test
	goreleaser build --clean --snapshot --parallelism 1 --single-target

# builds hauler for all platforms
# references other targets
build-all: install fmt vet test
	goreleaser build --clean --snapshot --parallelism 1

# install depedencies
install:
	rm -rf $(BINARIES_DIRECTORY)
	mkdir -p $(BINARIES_DIRECTORY)
	date > $(BINARIES_DIRECTORY)/date.txt
	go mod tidy
	go mod download
	CGO_ENABLED=0 go install ./cmd/...

# format go code
fmt:
	go fmt $(GO_FILES)

# vet go code
vet:
	go vet $(GO_FILES)

# test go code
test:
	go test $(GO_FILES) -cover -race -covermode=atomic -coverprofile=$(GO_COVERPROFILE)

# cleanup artifacts
clean:
	rm -rf $(BIN_DIRECTORY) $(BINARIES_DIRECTORY) $(DIST_DIRECTORY) $(GO_COVERPROFILE)

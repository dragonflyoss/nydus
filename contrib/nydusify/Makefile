GIT_COMMIT := $(shell git rev-list -1 HEAD)
BUILD_TIME := $(shell date -u +%Y%m%d.%H%M)
CURRENT_DIR := $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
PACKAGES ?= $(shell go list ./... | grep -v /vendor/)
#GOPROXY ?= https://goproxy.io

ifdef GOPROXY
PROXY := GOPROXY=${GOPROXY}
endif

.PHONY: build
build:
	@CGO_ENABLED=0 ${PROXY} GOOS=linux go build -ldflags '-X main.versionGitCommit=${GIT_COMMIT} -X main.versionBuildTime=${BUILD_TIME}' -gcflags=all="-N -l" -o ./cmd ./cmd/nydusify.go

.PHONY: static-release
static-release:
	@CGO_ENABLED=0 ${PROXY} GOOS=linux go build -ldflags '-X main.versionGitCommit=${GIT_COMMIT} -X main.versionBuildTime=${BUILD_TIME}' -o ./cmd ./cmd/nydusify.go

.PHONY: test
test: build build-smoke
	@go vet $(PACKAGES)
	@go test -count=1 -v -timeout 20m -race ./pkg/...

build-smoke:
	${PROXY} GOOS=linux go test -race -v -c -o ./nydusify-smoke ./tests

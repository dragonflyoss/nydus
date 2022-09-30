GIT_COMMIT := $(shell git rev-list -1 HEAD)
BUILD_TIME := $(shell date -u +%Y%m%d.%H%M)
PACKAGES ?= $(shell go list ./... | grep -v /vendor/)
GOARCH ?= amd64
GOPROXY ?= https://goproxy.io

ifdef GOPROXY
PROXY := GOPROXY=${GOPROXY}
endif

.PHONY: all build release plugin test clean build-smoke

all: build

build:
	@CGO_ENABLED=0 ${PROXY} GOOS=linux GOARCH=${GOARCH} go build -ldflags '-X main.versionGitCommit=${GIT_COMMIT} -X main.versionBuildTime=${BUILD_TIME}' -gcflags=all="-N -l" -o ./cmd ./cmd/nydusify.go

release:
	@CGO_ENABLED=0 ${PROXY} GOOS=linux GOARCH=${GOARCH} go build -ldflags '-X main.versionGitCommit=${GIT_COMMIT} -X main.versionBuildTime=${BUILD_TIME} -s -w -extldflags "-static"' -o ./cmd ./cmd/nydusify.go

plugin:
	@CGO_ENABLED=0 ${PROXY} GOOS=linux GOARCH=${GOARCH} go build -ldflags '-s -w -extldflags "-static"' -o nydus-hook-plugin ./plugin

test: build build-smoke
	@go vet $(PACKAGES)
	golangci-lint run
	@go test -count=1 -v -timeout 20m -race ./pkg/...

clean:
	rm -f cmd/nydusify

build-smoke:
	${PROXY} go test -race -v -c -o ./nydusify-smoke ./tests

PACKAGES ?= $(shell go list ./... | grep -v /vendor/)
GOARCH ?= $(shell go env GOARCH)
GOPROXY ?= https://goproxy.io

ifdef GOPROXY
PROXY := GOPROXY=${GOPROXY}
endif

# Used to populate variables in version package.
BUILD_TIMESTAMP=$(shell date '+%Y-%m-%dT%H:%M:%S')
VERSION=$(shell git describe --match 'v[0-9]*' --dirty='.m' --always --tags)
REVISION=$(shell git rev-parse HEAD)$(shell if ! git diff --no-ext-diff --quiet --exit-code; then echo .m; fi)

RELEASE_INFO = -X main.revision=${REVISION} -X main.gitVersion=${VERSION} -X main.buildTime=${BUILD_TIMESTAMP}

.PHONY: all build release plugin test clean build-smoke

all: build

build:
	@CGO_ENABLED=0 ${PROXY} GOOS=linux GOARCH=${GOARCH} go build -ldflags '${RELEASE_INFO}' -gcflags=all="-N -l" -o ./cmd ./cmd/nydusify.go

release:
	@CGO_ENABLED=0 ${PROXY} GOOS=linux GOARCH=${GOARCH} go build -ldflags '${RELEASE_INFO} -s -w -extldflags "-static"' -o ./cmd ./cmd/nydusify.go

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

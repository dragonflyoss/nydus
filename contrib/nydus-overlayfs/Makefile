GIT_COMMIT := $(shell git rev-parse --verify HEAD --short=7)
BUILD_TIME := $(shell date -u +%Y%m%d.%H%M)
PACKAGES ?= $(shell go list ./... | grep -v /vendor/)
GOARCH ?= $(shell go env GOARCH)
GOPROXY ?= https://goproxy.io

ifdef GOPROXY
PROXY := GOPROXY=${GOPROXY}
endif

.PHONY: all build release test clean

all: build

build:
	@CGO_ENABLED=0 ${PROXY} GOOS=linux GOARCH=${GOARCH} go build -ldflags="-s -w -X 'main.Version=${GIT_COMMIT}' -X 'main.BuildTime=${BUILD_TIME}'" -v -o bin/nydus-overlayfs ./cmd/main.go

release:
	@CGO_ENABLED=0 ${PROXY} GOOS=linux GOARCH=${GOARCH} go build -ldflags '-s -w -extldflags "-static"' -v -o bin/nydus-overlayfs ./cmd/main.go

test: build
	go vet $(PACKAGES)
	go test -v -cover ${PACKAGES}

lint: 
	golangci-lint run

clean:
	rm -f bin/*

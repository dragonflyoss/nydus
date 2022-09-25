GIT_COMMIT := $(shell git rev-list -1 HEAD)
BUILD_TIME := $(shell date -u +%Y%m%d.%H%M)
PACKAGES ?= $(shell go list ./... | grep -v /vendor/)
GOARCH ?= amd64
GOPROXY ?= https://goproxy.io

ifdef GOPROXY
PROXY := GOPROXY=${GOPROXY}
endif

.PHONY: all build release test clean

all: build

build:
	@CGO_ENABLED=0 ${PROXY} GOOS=linux GOARCH=${GOARCH} go build -v -o bin/nydus_graphdriver .

release:
	@CGO_ENABLED=0 ${PROXY} GOOS=linux GOARCH=${GOARCH} go build -ldflags '-s -w -extldflags "-static"' -v -o bin/nydus_graphdriver .

test: build
	go vet $(PACKAGES)
	golangci-lint run
	go test -v -cover ${PACKAGES}

clean:
	rm -f bin/*

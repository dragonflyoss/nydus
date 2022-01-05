all:clear build

VERSION=$(shell git rev-parse --verify HEAD --short=7)
BRANCH=$(shell git rev-parse --abbrev-ref HEAD)
PACKAGES ?= $(shell go list ./... | grep -v /vendor/)
#GOPROXY ?= https://goproxy.io

ifdef GOPROXY
PROXY := GOPROXY="${GOPROXY}"
endif

.PHONY: build
build:
	GOOS=linux ${PROXY} go build -ldflags="-s -w -X 'main.Version=${VERSION}'" -v -o bin/containerd-nydus-grpc ./cmd/containerd-nydus-grpc

static-release:
	CGO_ENABLED=0 ${PROXY} GOOS=linux go build -ldflags '-s -w -X "main.Version=${VERSION}" -extldflags "-static"' -v -o bin/containerd-nydus-grpc ./cmd/containerd-nydus-grpc

.PHONY: clear
clear:
	rm -f bin/*
	rm -rf _out

.PHONY: test
test: build
	go vet $(PACKAGES)
	golangci-lint run
	go test -v -cover ${PACKAGES}

.PHONY: cover
cover:
	@go test -coverprofile=_out/cover.out ${PACKAGES}
	@go tool cover -func=_out/cover.out
	@rm -f cover.out

build-image:
	docker build --build-arg VERSION=${VERSION} -t nydus-snapshotter:${VERSION} -f build/Dockerfile.release .

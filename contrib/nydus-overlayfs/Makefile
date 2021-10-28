all:clear build

GIT_COMMIT := $(shell git rev-parse --verify HEAD --short=7)
BUILD_TIME := $(shell date -u +%Y%m%d.%H%M)

.PHONY: build
build:
	GOOS=linux go build  -ldflags="-s -w -X 'main.Version=${GIT_COMMIT}' -X 'main.BuildTime=${BUILD_TIME}'" -v -o bin/nydus-overlayfs ./cmd/main.go

.PHONY: clear
clear:
	rm -f bin/*

.PHONY: static-release
static-release:
	GOOS=linux go build -ldflags '-s -w -extldflags "-static"' -v -o bin/nydus-overlayfs ./cmd/main.go

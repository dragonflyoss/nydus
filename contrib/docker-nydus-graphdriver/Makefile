PACKAGES ?= $(shell go list ./... | grep -v /vendor/)
GOARCH ?= amd64

all:clear build

.PHONY: build
build:
	GOOS=linux GOARCH=${GOARCH} go build -v -o bin/nydus_graphdriver .

.PHONY: clear
clear:
	rm -f bin/*

.PHONY: static-release
static-release:
	GOOS=linux GOARCH=${GOARCH} go build -ldflags '-s -w -extldflags "-static"' -v -o bin/nydus_graphdriver .

.PHONY: test
test: build
	go vet $(PACKAGES)
	golangci-lint run
	go test -v -cover ${PACKAGES}

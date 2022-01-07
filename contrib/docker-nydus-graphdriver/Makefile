PACKAGES ?= $(shell go list ./... | grep -v /vendor/)

all:clear build

.PHONY: build
build:
	GOOS=linux go build -v -o bin/nydus_graphdriver .

.PHONY: clear
clear:
	rm -f bin/*

.PHONY: static-release
static-release:
	GOOS=linux go build -ldflags '-s -w -extldflags "-static"' -v -o bin/nydus_graphdriver .

.PHONY: test
test: build
	go vet $(PACKAGES)
	golangci-lint run
	go test -v -cover ${PACKAGES}

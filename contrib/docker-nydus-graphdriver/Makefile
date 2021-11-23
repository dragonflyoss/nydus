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

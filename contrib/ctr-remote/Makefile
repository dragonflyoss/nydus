all:clear build

.PHONY: build
build:
	GOOS=linux go build -v -o bin/ctr-remote ./cmd/main.go

.PHONY: clear
clear:
	rm -f bin/*


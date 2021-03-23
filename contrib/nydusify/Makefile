GIT_COMMIT := $(shell git rev-list -1 HEAD)
BUILD_TIME := $(shell date -u +%Y%m%d.%H%M)
CURRENT_DIR := $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))

build:
	@CGO_ENABLED=0 GOOS=linux go build -ldflags '-X main.versionGitCommit=${GIT_COMMIT} -X main.versionBuildTime=${BUILD_TIME}' -gcflags=all="-N -l" -o ./cmd ./cmd/nydusify.go

static-release:
	@CGO_ENABLED=0 GOOS=linux go build -ldflags '-X main.versionGitCommit=${GIT_COMMIT} -X main.versionBuildTime=${BUILD_TIME}' -o ./cmd ./cmd/nydusify.go

build-smoke:
	@CGO_ENABLED=0 GOOS=linux go test -v -c -o ./nydusify-smoke ./tests

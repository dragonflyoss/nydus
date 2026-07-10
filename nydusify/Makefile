VERSION_TAG=$(shell git describe --match 'v[0-9]*' --dirty='.m' --always --tags)
GIT_COMMIT := $(shell git rev-list -1 HEAD)
BUILD_TIME := $(shell date -u +%Y%m%d.%H%M)

default: build

# Build binary to ./
build:
	go build -ldflags '-X main.versionTag=${VERSION_TAG} -X main.versionGitCommit=${GIT_COMMIT} -X main.versionBuildTime=${BUILD_TIME}' -gcflags=all="-N -l" ./

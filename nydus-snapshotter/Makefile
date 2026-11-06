PKG := github.com/dragonflyoss/nydus/nydus-snapshotter
VERSION ?= $(shell git describe --match 'v[0-9]*' --dirty='.m' --always --tags)
GIT_COMMIT ?= $(shell git rev-parse --short HEAD)
BUILD_TIME ?= $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
LDFLAGS := -s -w -X $(PKG)/internal/version.GitVersion=$(VERSION) -X $(PKG)/internal/version.GitCommit=$(GIT_COMMIT) -X $(PKG)/internal/version.BuildTime=$(BUILD_TIME)
IMAGE ?= ghcr.io/dragonflyoss/nydus-snapshotter
# Extra docker buildx flags, e.g. --platform linux/amd64,linux/arm64 --push.
IMAGE_FLAGS ?=

all: build

# Build the static binary to bin/.
build:
	CGO_ENABLED=0 go build -trimpath $(GO_BUILD_FLAGS) -ldflags '$(LDFLAGS)' -o bin/nydus-snapshotter ./cmd/nydus-snapshotter
.PHONY: build

# Run unit tests.
test:
	go test -race $(GO_TEST_FLAGS) ./...
.PHONY: test

# Format code with the formatters of .golangci.yml.
fmt:
	golangci-lint fmt
.PHONY: fmt

# Run go vet.
vet:
	go vet ./...
.PHONY: vet

# Run code lint.
lint:
	golangci-lint run
.PHONY: lint

# Regenerate mocks.
generate:
	go generate ./...
.PHONY: generate

# Build the installer image from the repository root, which also builds nydus.
image:
	docker buildx build -f Dockerfile $(IMAGE_FLAGS) \
		--build-arg VERSION=$(VERSION) --build-arg GIT_COMMIT=$(GIT_COMMIT) --build-arg BUILD_TIME=$(BUILD_TIME) \
		-t $(IMAGE):$(VERSION) ..
.PHONY: image

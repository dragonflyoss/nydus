PACKAGES ?= $(shell go list ./... | grep -v /vendor/)
GOPROXY ?= https://goproxy.io
TESTS ?= .*

ifdef GOPROXY
PROXY := GOPROXY=${GOPROXY}
endif

build:
	go test -o smoke.test -c -race -v -cover ./tests

lint:
	@go vet $(PACKAGES)
	golangci-lint run

# WORK_DIR=/tmp \
# NYDUS_BUILDER=/path/to/latest/nydus-image \
# NYDUS_NYDUSD=/path/to/latest/nydusd \
# NYDUS_NYDUSIFY=/path/to/latest/nydusify \
# make test
test: build lint
	sudo -E ./smoke.test -test.v -test.timeout 10m -test.parallel=8 -test.run=$(TESTS)

# WORK_DIR=/tmp \
# NYDUS_BUILDER=/path/to/latest/nydus-image \
# NYDUS_NYDUSD=/path/to/latest/nydusd \
# NYDUS_NYDUSIFY=/path/to/latest/nydusify \
# NYDUS_BUILDER_v0_1_0=/path/to/v0.1.0/nydus-image \
# NYDUS_NYDUSD_v0_1_0=/path/to/v0.1.0/nydusd \
# NYDUS_NYDUSIFY_v0_1_0=/path/to/v0.1.0/nydusify \
# NYDUS_BUILDER_v2_1_4=/path/to/v2.1.4/nydus-image \
# NYDUS_NYDUSD_v2_1_4=/path/to/v2.1.4/nydusd \
# NYDUS_NYDUSIFY_v2_1_4=/path/to/v2.1.4/nydusify \
# make test TESTS=TestCompatibility
test-compatibility: build lint
	make test TESTS=TestCompatibility

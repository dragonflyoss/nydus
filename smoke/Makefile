PACKAGES ?= $(shell go list ./... | grep -v /vendor/)
GOPROXY ?= https://goproxy.io
TESTS ?= .*

ifdef GOPROXY
PROXY := GOPROXY=${GOPROXY}
endif

build:
	go test -o smoke.test -c -race -v -cover ./tests

# WORK_DIR=/tmp \
# NYDUS_BUILDER=/path/to/latest/nydus-image \
# NYDUS_NYDUSD=/path/to/latest/nydusd \
# NYDUS_NYDUSIFY=/path/to/latest/nydusify \
# make test
test: build
	sudo -E ./smoke.test -test.v -test.timeout 10m -test.parallel=16 -test.run=$(TESTS)

# WORK_DIR=/tmp \
# NYDUS_STABLE_VERSION=v2.2.3 \
# NYDUS_STABLE_VERSION_EXPORT=v2_2_3 \
# NYDUS_BUILDER=/path/to/latest/nydus-image \
# NYDUS_NYDUSD=/path/to/latest/nydusd \
# NYDUS_NYDUSIFY=/path/to/latest/nydusify \
# NYDUS_BUILDER_v0_1_0=/path/to/v0.1.0/nydus-image \
# NYDUS_NYDUSD_v0_1_0=/path/to/v0.1.0/nydusd \
# NYDUS_NYDUSIFY_v0_1_0=/path/to/v0.1.0/nydusify \
# NYDUS_BUILDER_$NYDUS_STABLE_VERSION_EXPORT=/path/to/$NYDUS_STABLE_VERSION/nydus-image \
# NYDUS_NYDUSD_$NYDUS_STABLE_VERSION_EXPORT=/path/to/$NYDUS_STABLE_VERSION/nydusd \
# NYDUS_NYDUSIFY_$NYDUS_STABLE_VERSION_EXPORT=/path/to/$NYDUS_STABLE_VERSION/nydusify \
# make test TESTS=TestCompatibility
test-compatibility: build
	make test TESTS=TestCompatibility

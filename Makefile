CARGO ?= cargo
GO    ?= go
GO_BIN ?= $(or $(shell command -v $(GO) 2>/dev/null),$(shell command -v go 2>/dev/null))
SUDO ?= sudo
FEATURES ?= cli

.PHONY: build release crate nydusify test test-nydusify clean
.PHONY: ci-build e2e e2e-run e2e-ga e2e-dragonfly e2e-experimental test-bench test-top-images e2e-soak

build:
	$(CARGO) build -p nydus --features "$(FEATURES)"

release:
	$(CARGO) build -p nydus --release --features "$(FEATURES)"

# Validate that the nydus-core crate can be packaged and published
# to crates.io. Run `cargo publish -p nydus-core --registry crates-io`
# manually to publish.
crate:
	$(CARGO) publish -p nydus-core --registry crates-io --dry-run

nydusify:
	cd nydusify && $(GO_BIN) build -o nydusify .

test:
	$(CARGO) test --workspace

# nydusify's own Go tests, against a nydus builder (NYDUS_TEST_BUILDER,
# default: a debug build).
NYDUS_TEST_BUILDER ?=
test-nydusify:
	$(if $(NYDUS_TEST_BUILDER),,$(CARGO) build -p nydus --features cli)
	cd nydusify && NYDUS_TEST_BUILDER="$(or $(NYDUS_TEST_BUILDER),$(abspath $(or $(CARGO_TARGET_DIR),target))/debug/nydus)" \
		$(GO_BIN) test -race -count=1 ./...

# --- e2e suites --------------------------------------------------------
# Each directory under tests/e2e is one suite package; see
# tests/e2e/README.md. The test binaries are compiled as the invoking user
# and run as root through -exec, against the binaries named by NYDUS_BIN and
# NYDUSIFY_BIN, so a stale binary on PATH is never picked up.
#   make e2e PKG=./contract/...
#   make e2e PKG='./build/... ./export/...' E2E_RUN=TestBuild
#   make e2e-ga E2E_REQUIRE=1
#   make e2e-run PKG=./tar/...        # no build: reuse target/ci/nydus
# Features of the GA binary: the GA mount modes and the Dragonfly backend.
E2E_FEATURES ?= cli,fuse,fileio,dragonfly
E2E_EXPERIMENTAL_FEATURES ?= $(E2E_FEATURES),nbd,fanotify,ublk,uffd
PKG ?= ./...
E2E_RUN ?=
E2E_TAGS ?=
E2E_PARALLEL ?= 8
E2E_COUNT ?= 1
E2E_TIMEOUT ?= 15m
E2E_GO_TEST_ARGS ?=
# 1 turns every missing precondition (root, kernel feature, tool) into a
# failure instead of a skip; CI sets it.
E2E_REQUIRE ?=
# Cache for corpora and built images shared by the suites and across runs.
E2E_CACHE ?= $(CURDIR)/.test-tmp/e2e-cache
E2E_TARGET_DIR = $(abspath $(or $(CARGO_TARGET_DIR),target))
NYDUS_BIN ?= $(E2E_TARGET_DIR)/ci/nydus
NYDUSIFY_BIN ?= $(CURDIR)/nydusify/nydusify
NYDUS_WRITER_BIN ?= $(E2E_TARGET_DIR)/ci/examples/writer-fixture
# Every GA suite but dragonfly, which needs a running Dragonfly cluster
# (misc/dragonfly/cluster.sh) and runs through e2e-dragonfly.
E2E_GA_PKGS = ./internal/... ./contract/... ./api/... ./build/... ./tar/... ./export/... ./nydusify/... ./registry/... \
	./golden/... ./cache/... ./fault/... ./soak/... ./kernel/...
E2E_EXPERIMENTAL_PKGS = ./experimental/...
E2E_ENV = NYDUS_BIN="$(NYDUS_BIN)" NYDUSIFY_BIN="$(NYDUSIFY_BIN)" \
	NYDUS_WRITER_BIN="$(NYDUS_WRITER_BIN)" \
	NYDUS_E2E_REQUIRE="$(E2E_REQUIRE)" NYDUS_E2E_CACHE="$(E2E_CACHE)" TMPDIR="$(CURDIR)/.test-tmp"

# The nydus binary the e2e suites run: see [profile.ci] in Cargo.toml.
ci-build:
	$(CARGO) build -p nydus --profile ci --features "$(FEATURES)"
	$(CARGO) build -p nydus-core --profile ci --example writer-fixture

e2e-run:
	@test -n "$(GO_BIN)" || { echo "go not found; set GO=/abs/path/to/go or GO_BIN=/abs/path/to/go"; exit 1; }
	mkdir -p $(CURDIR)/.test-tmp
	# sudo's secure_path would drop the caller's PATH (and the Go toolchain on it).
	cd tests/e2e && $(E2E_ENV) $(GO_BIN) test -exec "$(SUDO) -E env PATH=$$PATH" -count $(E2E_COUNT) \
		-timeout $(E2E_TIMEOUT) -parallel $(E2E_PARALLEL) $(if $(strip $(E2E_TAGS)),-tags '$(E2E_TAGS)',) \
		$(if $(strip $(E2E_RUN)),-run '$(E2E_RUN)',) $(E2E_GO_TEST_ARGS) $(PKG)

e2e: FEATURES=$(E2E_FEATURES)
e2e: ci-build nydusify
	$(MAKE) e2e-run PKG='$(PKG)'

e2e-ga: PKG=$(E2E_GA_PKGS)
e2e-ga: e2e

# Needs a running cluster: sudo misc/dragonfly/cluster.sh up
e2e-dragonfly: PKG=./dragonfly/...
e2e-dragonfly: e2e

e2e-experimental: FEATURES=$(E2E_EXPERIMENTAL_FEATURES)
e2e-experimental: ci-build nydusify
	$(MAKE) e2e-run PKG='$(E2E_EXPERIMENTAL_PKGS)'

# Soak tiers are explicit; ordinary e2e-ga keeps the 30-second smoke.
SOAK_DURATION ?= 1h
SOAK_CYCLES ?= 120
SOAK_RSS_MIB ?=
SOAK_TIMEOUT ?= 80m
e2e-soak:
	NYDUS_E2E_SOAK_DURATION="$(SOAK_DURATION)" NYDUS_E2E_SOAK_CYCLES="$(SOAK_CYCLES)" \
	NYDUS_E2E_SOAK_RSS_MIB="$(SOAK_RSS_MIB)" \
	$(MAKE) e2e-run PKG=./soak/... E2E_TIMEOUT=$(SOAK_TIMEOUT) E2E_GO_TEST_ARGS='-v $(E2E_GO_TEST_ARGS)'

# Cold-start benchmark across every mount mode (tests/e2e/manual/bench).
# Needs root and fio; nbd/ublk/fanotify columns need their kernel support.
test-bench: FEATURES=$(E2E_FEATURES)
test-bench: ci-build
	$(MAKE) e2e-run PKG=./manual/bench/ E2E_TAGS=manual E2E_TIMEOUT=30m E2E_GO_TEST_ARGS='-v $(E2E_GO_TEST_ARGS)'

# Convert and validate the top Docker Hub images, pushing the converted nydus
# images to $(TOP_IMAGES_REGISTRY) (e.g. a GHCR namespace or a local
# registry). Needs root and credentials for the target registry.
TOP_IMAGES_TIMEOUT ?= 3600s
TOP_IMAGES_CONCURRENCY ?= 5
TOP_IMAGES_RETRIES ?= 5
TOP_IMAGES_RETRY_INTERVAL ?= 30s
TOP_IMAGES_REGISTRY ?= localhost:5000
TOP_IMAGES_PLAIN_HTTP ?=
TOP_IMAGES_PLATFORM ?= linux/amd64
TOP_IMAGES_WORKDIR ?=
# nydusify only uses nydus as its builder here.
test-top-images: FEATURES=cli,fuse
test-top-images: ci-build nydusify
	NYDUSFS_TOP_IMAGES_REGISTRY="$(TOP_IMAGES_REGISTRY)" \
	NYDUSFS_TOP_IMAGES_PLAIN_HTTP="$(TOP_IMAGES_PLAIN_HTTP)" \
	NYDUSFS_TOP_IMAGES_PLATFORM="$(TOP_IMAGES_PLATFORM)" \
	NYDUSFS_TOP_IMAGES_CONCURRENCY="$(TOP_IMAGES_CONCURRENCY)" \
	NYDUSFS_TOP_IMAGES_RETRIES="$(TOP_IMAGES_RETRIES)" \
	NYDUSFS_TOP_IMAGES_RETRY_INTERVAL="$(TOP_IMAGES_RETRY_INTERVAL)" \
	NYDUSFS_TOP_IMAGES_WORKDIR="$(TOP_IMAGES_WORKDIR)" \
	$(MAKE) e2e-run PKG=./manual/topimages/ E2E_TAGS=manual E2E_TIMEOUT=$(TOP_IMAGES_TIMEOUT) E2E_GO_TEST_ARGS='-v $(E2E_GO_TEST_ARGS)'

clean:
	$(CARGO) clean

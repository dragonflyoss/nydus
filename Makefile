CARGO ?= cargo
GO ?= go
SUDO ?= sudo
FEATURES ?= cli

COVERAGE_DIR ?= $(CURDIR)/coverage
COVERAGE_TOOLS_DIR ?= $(CURDIR)/coverage-tools
COVERAGE ?= $(if $(wildcard $(COVERAGE_TOOLS_DIR)/binaries.sha256),1,0)
COVERAGE_BUILD_ENV = $(if $(filter 1,$(COVERAGE)),RUSTC_WORKSPACE_WRAPPER="$(CURDIR)/tests/scripts/coverage_rustc.sh" CARGO_PROFILE_CI_STRIP=none LLVM_PROFILE_FILE="$(TARGET_DIR)/coverage-build/%8m.profraw")
COVERAGE_GO_BUILD = $(if $(filter 1,$(COVERAGE)),-cover -covermode=atomic -coverpkg=./...)
COVERAGE_GO_TEST = $(if $(filter 1,$(COVERAGE)),-coverpkg=./... -coverprofile="$(COVERAGE_DIR)/go-unit-integration.out")
COVERAGE_RUN_ENV = $(if $(filter 1,$(COVERAGE)),LLVM_PROFILE_FILE="$(COVERAGE_DIR)/raw/rust/nydus-%8m.profraw" GOCOVERDIR="$(COVERAGE_DIR)/raw/go")

E2E_FEATURES ?= cli,fuse,fileio,dragonfly
PKG ?= ./...
E2E_RUN ?=
E2E_TAGS ?=
E2E_PARALLEL ?= 8
E2E_COUNT ?= 1
E2E_TIMEOUT ?= 15m
E2E_GO_TEST_ARGS ?=
TARGET_DIR = $(abspath $(or $(CARGO_TARGET_DIR),target))
NYDUS_BIN ?= $(TARGET_DIR)/ci/nydus
NYDUSIFY_BIN ?= $(CURDIR)/nydusify/nydusify
NYDUS_WRITER_BIN ?= $(TARGET_DIR)/ci/examples/writer-fixture
NYDUS_E2E_CACHE ?= $(CURDIR)/.test-tmp/e2e-cache
BASELINE_VERSION ?= v3.0.0-beta.3
BASELINE_ARCH ?= $(shell uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')
BASELINE_DIR = $(CURDIR)/.test-tmp/baseline/$(BASELINE_VERSION)
BASELINE_NYDUS = $(BASELINE_DIR)/nydus-static/nydus
GOLDEN_DIR = $(CURDIR)/.test-tmp/golden
E2E_ENV = NYDUS_BIN="$(NYDUS_BIN)" NYDUSIFY_BIN="$(NYDUSIFY_BIN)" NYDUS_WRITER_BIN="$(NYDUS_WRITER_BIN)" \
	NYDUS_E2E_CACHE="$(NYDUS_E2E_CACHE)" TMPDIR="$(CURDIR)/.test-tmp" $(COVERAGE_RUN_ENV)

build:
	$(CARGO) build -p nydus --features "$(FEATURES)"
.PHONY: build

release:
	$(CARGO) build -p nydus --release --features "$(FEATURES)"
.PHONY: release

build-nydusify:
	cd nydusify && $(GO) build $(COVERAGE_GO_BUILD) -o nydusify .
.PHONY: build-nydusify

build-ci:
	$(COVERAGE_BUILD_ENV) $(CARGO) build -p nydus --profile ci --features "$(FEATURES)"
	$(CARGO) build -p nydus-core --profile ci --example writer-fixture
.PHONY: build-ci

build-coverage: COVERAGE = 1
build-coverage: FEATURES = $(E2E_FEATURES)
build-coverage: build-ci build-nydusify
	bash tests/scripts/e2e_coverage.sh bundle
.PHONY: build-coverage

crate:
	$(CARGO) publish -p nydus-core --registry crates-io --dry-run
.PHONY: crate

test:
	$(CARGO) test --workspace
.PHONY: test

test-nydusify: build-ci
	$(if $(filter 1,$(COVERAGE)),mkdir -p "$(COVERAGE_DIR)/raw/rust" "$(COVERAGE_DIR)/raw/go",)
	cd nydusify && $(COVERAGE_RUN_ENV) NYDUS_TEST_BUILDER="$(NYDUS_BIN)" $(GO) test -race -count=1 $(COVERAGE_GO_TEST) ./...
.PHONY: test-nydusify

e2e-run:
	mkdir -p $(CURDIR)/.test-tmp
	$(if $(filter 1,$(COVERAGE)),mkdir -p "$(COVERAGE_DIR)/raw/rust" "$(COVERAGE_DIR)/raw/go",)
	cd tests/e2e && $(E2E_ENV) $(GO) test -exec "$(SUDO) -E env PATH=$$PATH" -v -count $(E2E_COUNT) \
		-timeout $(E2E_TIMEOUT) -parallel $(E2E_PARALLEL) $(if $(strip $(E2E_TAGS)),-tags '$(E2E_TAGS)',) \
		$(if $(strip $(E2E_RUN)),-run '$(E2E_RUN)',) $(E2E_GO_TEST_ARGS) $(PKG)
.PHONY: e2e-run

e2e: FEATURES = $(E2E_FEATURES)
e2e: build-ci build-nydusify
	$(MAKE) e2e-run PKG='$(PKG)'
.PHONY: e2e

e2e-ga: PKG = ./internal/... ./contract/... ./api/... ./continuity/... ./build/... ./tar/... ./export/... ./nydusify/... ./registry/... ./golden/... ./cache/... ./fault/... ./soak/... ./kernel/...
e2e-ga: e2e
.PHONY: e2e-ga

e2e-continuity: PKG = ./continuity/...
e2e-continuity: e2e
.PHONY: e2e-continuity

e2e-dragonfly: PKG = ./dragonfly/...
e2e-dragonfly: e2e
.PHONY: e2e-dragonfly

e2e-compatibility: FEATURES = $(E2E_FEATURES)
e2e-compatibility: build-ci build-nydusify
	mkdir -p $(BASELINE_DIR)
	cd $(BASELINE_DIR) && curl -fsSL --retry 2 -O https://github.com/dragonflyoss/nydus/releases/download/$(BASELINE_VERSION)/nydus-static-$(BASELINE_VERSION)-linux-$(BASELINE_ARCH).tgz{,.sha256sum} \
		&& sha256sum -c nydus-static-$(BASELINE_VERSION)-linux-$(BASELINE_ARCH).tgz.sha256sum && tar -xzf nydus-static-$(BASELINE_VERSION)-linux-$(BASELINE_ARCH).tgz
	cd tests/e2e && $(GO) build -o $(CURDIR)/.test-tmp/golden-gen ./cmd/golden-gen
	$(SUDO) $(CURDIR)/.test-tmp/golden-gen -force -nydus $(BASELINE_NYDUS) -out $(GOLDEN_DIR)/historical
	$(SUDO) $(CURDIR)/.test-tmp/golden-gen -force -nydus $(NYDUS_BIN) -out $(GOLDEN_DIR)/current
	NYDUS_E2E_GOLDEN_DIR=$(GOLDEN_DIR)/historical NYDUS_E2E_GOLDEN_VERSIONS=$(BASELINE_VERSION) $(MAKE) e2e-run PKG=./golden/... E2E_TIMEOUT=2m
	NYDUS_E2E_GOLDEN_DIR=$(GOLDEN_DIR)/current $(MAKE) e2e-run PKG='./golden/... ./build/...' E2E_RUN='^(TestRead|TestGAFeatures)$$$$' E2E_TIMEOUT=2m
	NYDUS_E2E_GOLDEN_DIR=$(GOLDEN_DIR)/current $(MAKE) e2e-run PKG=./golden/... E2E_RUN='^TestRead$$$$/[^/]+/[^/]+/^(Check|FUSE|Export)$$$$' E2E_TIMEOUT=2m NYDUS_BIN=$(BASELINE_NYDUS)
.PHONY: e2e-compatibility

e2e-experimental: FEATURES = $(E2E_FEATURES),nbd,fanotify,ublk,uffd
e2e-experimental: build-ci build-nydusify
	$(MAKE) e2e-run PKG=./experimental/...
.PHONY: e2e-experimental

e2e-soak: export NYDUS_E2E_SOAK_DURATION ?= 1h
e2e-soak: export NYDUS_E2E_SOAK_CYCLES ?= 120
e2e-soak: FEATURES = cli,fuse,fileio
e2e-soak: build-ci build-nydusify
	$(MAKE) e2e-run PKG=./soak/... E2E_TIMEOUT=80m
.PHONY: e2e-soak

e2e-hugetar: FEATURES = cli,fuse,fileio
e2e-hugetar: build-ci build-nydusify
	$(MAKE) e2e-run PKG=./manual/hugetar/ E2E_TAGS=manual E2E_TIMEOUT=80m
.PHONY: e2e-hugetar

e2e-convert: FEATURES = cli,fuse
e2e-convert: build-ci build-nydusify
	$(MAKE) e2e-run PKG=./manual/topimages/ E2E_TAGS=manual E2E_TIMEOUT=140m
.PHONY: e2e-convert

benchmark: FEATURES = cli,fuse,fileio
benchmark: build-ci
	$(MAKE) e2e-run PKG=./manual/bench/ E2E_TAGS=manual E2E_TIMEOUT=60m
.PHONY: benchmark

clean:
	$(CARGO) clean
	rm -rf nydusify/nydusify coverage coverage-tools .test-tmp
.PHONY: clean

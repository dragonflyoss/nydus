CARGO ?= cargo
GO    ?= go
GO_BIN ?= $(or $(shell command -v $(GO) 2>/dev/null),$(shell command -v go 2>/dev/null))
SUDO ?= sudo

E2E_TEST ?=
E2E_TIMEOUT ?= 600s
E2E_COUNT ?= 1
E2E_GO_TEST_ARGS ?=
LEPTONFS_MERGE_PAUSE_SECS ?= 0
EROFS_C_FUSE ?=
EROFS_MKFS ?=

XFSTESTS_TIMEOUT ?= 600s
XFSTESTS_COUNT ?= 1
XFSTESTS_GO_TEST_ARGS ?=

PERF_TIMEOUT ?= 300s
PERF_COUNT ?= 1
PERF_GO_TEST_ARGS ?=

TOP_IMAGES_TIMEOUT ?= 3600s
TOP_IMAGES_COUNT ?= 1
TOP_IMAGES_CONCURRENCY ?= 5
TOP_IMAGES_REGISTRY ?= localhost:5000
TOP_IMAGES_GO_TEST_ARGS ?=

GO_TEST_ENV = $(SUDO) env "PATH=$(dir $(GO_BIN)):$(PATH)" "HOME=$(HOME)" \
	"GOCACHE=$$($(GO_BIN) env GOCACHE)" \
	"GOMODCACHE=$$($(GO_BIN) env GOMODCACHE)" \
	"EROFS_C_FUSE=$(EROFS_C_FUSE)" \
	"EROFS_MKFS=$(EROFS_MKFS)"
TEST_SUPPORT_FILES = util.go optimize_util.go
E2E_TEST_FILES = e2e_test.go $(TEST_SUPPORT_FILES)
XFSTESTS_TEST_FILES = xfstests_test.go $(TEST_SUPPORT_FILES)
PERF_TEST_FILES = perf_test.go $(TEST_SUPPORT_FILES)
TOP_IMAGES_TEST_FILES = top_image_test.go $(TEST_SUPPORT_FILES)

.PHONY: build release leptonify test test-e2e test-xfstests test-perf test-top-images clean

build:
	$(CARGO) build

release:
	$(CARGO) build --release

leptonify:
	cd leptonify && $(GO_BIN) build -o leptonify .

test:
	$(CARGO) test --workspace

# Run end-to-end integration tests (requires root, builds release first).
# Only runs tests/integration/e2e_test.go.
test-e2e: release leptonify
	@test -n "$(GO_BIN)" || { echo "go not found; set GO=/abs/path/to/go or GO_BIN=/abs/path/to/go"; exit 1; }
	cd tests/integration && \
		$(GO_TEST_ENV) \
		LEPTONFS_MERGE_PAUSE_SECS="$(LEPTONFS_MERGE_PAUSE_SECS)" \
		LEPTONFS_RUN_EROFS_COMPAT="$(LEPTONFS_RUN_EROFS_COMPAT)" \
		$(GO_BIN) test -v $(if $(strip $(E2E_TEST)),-run '^$(E2E_TEST)$$',) -count $(E2E_COUNT) -timeout $(E2E_TIMEOUT) $(E2E_GO_TEST_ARGS) $(E2E_TEST_FILES)

# Run xfstests regression separately (requires root, builds release first).
# First run will install xfstests dependencies via tests/scripts/setup_xfstests.sh.
test-xfstests: release
	@test -n "$(GO_BIN)" || { echo "go not found; set GO=/abs/path/to/go or GO_BIN=/abs/path/to/go"; exit 1; }
	cd tests/integration && \
		$(GO_TEST_ENV) \
		LEPTONFS_RUN_XFSTESTS=1 \
		$(GO_BIN) test -v -run '^TestXfstests$$' -count $(XFSTESTS_COUNT) -timeout $(XFSTESTS_TIMEOUT) $(XFSTESTS_GO_TEST_ARGS) $(XFSTESTS_TEST_FILES)

# Run performance benchmark (requires root, fio, ~5min).
# Compares Lepton vs C erofsfuse.
test-perf: release
	@test -n "$(GO_BIN)" || { echo "go not found; set GO=/abs/path/to/go or GO_BIN=/abs/path/to/go"; exit 1; }
	cd tests/integration && \
		$(GO_TEST_ENV) \
		LEPTONFS_RUN_PERF=1 \
		$(GO_BIN) test -v -run '^TestPerf$$' -count $(PERF_COUNT) -timeout $(PERF_TIMEOUT) $(PERF_GO_TEST_ARGS) $(PERF_TEST_FILES)

# Convert and validate the top Docker Hub images against a local registry
# (requires root and a registry at $(TOP_IMAGES_REGISTRY)). Builds leptonify on demand.
test-top-images: release
	@test -n "$(GO_BIN)" || { echo "go not found; set GO=/abs/path/to/go or GO_BIN=/abs/path/to/go"; exit 1; }
	cd tests/integration && \
		$(GO_TEST_ENV) \
		LEPTONFS_RUN_TOP_IMAGES=1 \
		LEPTONFS_TOP_IMAGES_REGISTRY=$(TOP_IMAGES_REGISTRY) \
		LEPTONFS_TOP_IMAGES_CONCURRENCY=$(TOP_IMAGES_CONCURRENCY) \
		$(GO_BIN) test -v -run '^TestTopImages$$' -count $(TOP_IMAGES_COUNT) -timeout $(TOP_IMAGES_TIMEOUT) $(TOP_IMAGES_GO_TEST_ARGS) $(TOP_IMAGES_TEST_FILES)

clean:
	$(CARGO) clean

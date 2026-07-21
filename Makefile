CARGO ?= cargo
GO    ?= go
GO_BIN ?= $(or $(shell command -v $(GO) 2>/dev/null),$(shell command -v go 2>/dev/null))
SUDO ?= sudo
FEATURES ?= cli

E2E_TEST ?=
E2E_TIMEOUT ?= 600s
E2E_COUNT ?= 1
E2E_GO_TEST_ARGS ?=
NYDUSFS_MERGE_PAUSE_SECS ?= 0
EROFS_C_FUSE ?=
EROFS_MKFS ?=

UFFD_TIMEOUT ?= 300s
UFFD_COUNT ?= 1
UFFD_GO_TEST_ARGS ?=

FANOTIFY_TIMEOUT ?= 600s
FANOTIFY_COUNT ?= 1
FANOTIFY_GO_TEST_ARGS ?=
# Set to 1 to also run the optional C11 fail-closed case (needs the local
# registry container started by the test).
FANOTIFY_RUN_FAIL_CLOSED ?=
# Set to 0 to skip C12 strace ground-truth case (runs by default if strace
# is installed).
FANOTIFY_RUN_STRACE ?=

FANOTIFY_PERF_TIMEOUT ?= 1800s
FANOTIFY_PERF_COUNT ?= 1
FANOTIFY_PERF_GO_TEST_ARGS ?=
FANOTIFY_PERF_SOURCE_IMAGE ?=

XFSTESTS_TIMEOUT ?= 600s
XFSTESTS_COUNT ?= 1
XFSTESTS_GO_TEST_ARGS ?=

PERF_TIMEOUT ?= 300s
PERF_COUNT ?= 1
PERF_GO_TEST_ARGS ?=

TOP_IMAGES_TIMEOUT ?= 3600s
TOP_IMAGES_COUNT ?= 1
TOP_IMAGES_CONCURRENCY ?= 5
TOP_IMAGES_RETRIES ?= 5
TOP_IMAGES_RETRY_INTERVAL ?= 30s
TOP_IMAGES_REGISTRY ?= localhost:5000
TOP_IMAGES_PLAIN_HTTP ?=
TOP_IMAGES_PLATFORM ?= linux/amd64
TOP_IMAGES_WORKDIR ?=
TOP_IMAGES_GO_TEST_ARGS ?=

GO_TEST_ENV = $(SUDO) env "PATH=$(CURDIR)/target/release:$(dir $(GO_BIN)):$(PATH)" "HOME=$(HOME)" \
	"GOCACHE=$$($(GO_BIN) env GOCACHE)" \
	"GOMODCACHE=$$($(GO_BIN) env GOMODCACHE)" \
	"EROFS_C_FUSE=$(EROFS_C_FUSE)" \
	"EROFS_MKFS=$(EROFS_MKFS)"
TEST_SUPPORT_FILES = util.go optimize_util.go
E2E_TEST_FILES = e2e_test.go $(TEST_SUPPORT_FILES)
UFFD_TEST_FILES = uffd_test.go $(TEST_SUPPORT_FILES)
XFSTESTS_TEST_FILES = xfstests_test.go $(TEST_SUPPORT_FILES)
PERF_TEST_FILES = perf_test.go $(TEST_SUPPORT_FILES)
TOP_IMAGES_TEST_FILES = top_image_test.go $(TEST_SUPPORT_FILES)
FANOTIFY_TEST_FILES = fanotify_test.go $(TEST_SUPPORT_FILES)
# Package-based compilation (not file list) because fanotify_perf_test.go
# depends on symbols from perf_test.go which itself depends on many other
# files (mount helpers, c-erofsfuse helpers, etc.).
FANOTIFY_PERF_TEST_PKG = .

.PHONY: build release nydusify test test-e2e test-uffd test-fanotify test-xfstests test-perf test-top-images crate clean

build:
	$(CARGO) build -p nydus --features "$(FEATURES)"

release:
	$(CARGO) build -p nydus --release --features "$(FEATURES)"

# Validate that the nydus-accessor crate can be packaged and published
# to crates.io. Run `cargo publish -p nydus-accessor --registry crates-io`
# manually to publish.
crate:
	$(CARGO) publish -p nydus-accessor --registry crates-io --dry-run

nydusify:
	cd nydusify && $(GO_BIN) build -o nydusify .

test:
	$(CARGO) test --workspace

# Run end-to-end integration tests (requires root, builds release first).
# Only runs tests/integration/e2e_test.go.
test-e2e: release nydusify
	@test -n "$(GO_BIN)" || { echo "go not found; set GO=/abs/path/to/go or GO_BIN=/abs/path/to/go"; exit 1; }
	cd tests/integration && \
		$(GO_TEST_ENV) \
		NYDUSFS_MERGE_PAUSE_SECS="$(NYDUSFS_MERGE_PAUSE_SECS)" \
		NYDUSFS_RUN_EROFS_COMPAT="$(NYDUSFS_RUN_EROFS_COMPAT)" \
		$(GO_BIN) test -v $(if $(strip $(E2E_TEST)),-run '^$(E2E_TEST)$$',) -count $(E2E_COUNT) -timeout $(E2E_TIMEOUT) $(E2E_GO_TEST_ARGS) $(E2E_TEST_FILES)

# Run the UFFD service smoke test. This builds nydus with the optional uffd
# feature and does not require root because it exercises stateless socket
# requests rather than real userfaultfd faults.
test-uffd: FEATURES=cli,uffd
test-uffd: release
	@test -n "$(GO_BIN)" || { echo "go not found; set GO=/abs/path/to/go or GO_BIN=/abs/path/to/go"; exit 1; }
	cd tests/integration && \
		$(GO_TEST_ENV) \
		$(GO_BIN) test -v -run '^TestUffdServiceSmoke$$' -count $(UFFD_COUNT) -timeout $(UFFD_TIMEOUT) $(UFFD_GO_TEST_ARGS) $(UFFD_TEST_FILES)

# Run the fanotify pre-content E2E test (requires root, Linux >= 6.15, docker
# for the throwaway local registry). Builds nydus with the fanotify feature.
# It boots the real daemon against a real OCI registry backend and asserts
# byte-exact on-demand reads through the FAN_PRE_ACCESS path. Set
# FANOTIFY_RUN_FAIL_CLOSED=1 to also run the optional C11 fail-closed case.
test-fanotify: FEATURES=cli,fanotify
test-fanotify: release nydusify
	@test -n "$(GO_BIN)" || { echo "go not found; set GO=/abs/path/to/go or GO_BIN=/abs/path/to/go"; exit 1; }
	mkdir -p $(CURDIR)/.test-tmp
	cd tests/integration && \
		$(GO_TEST_ENV) "TMPDIR=$(CURDIR)/.test-tmp" \
		FANOTIFY_RUN_FAIL_CLOSED="$(FANOTIFY_RUN_FAIL_CLOSED)" \
		FANOTIFY_RUN_STRACE="$(FANOTIFY_RUN_STRACE)" \
		$(GO_BIN) test -v -run '^TestFanotifyE2E$$' -count $(FANOTIFY_COUNT) -timeout $(FANOTIFY_TIMEOUT) $(FANOTIFY_GO_TEST_ARGS) $(FANOTIFY_TEST_FILES)

# Run xfstests regression separately (requires root, builds release first).
# First run will install xfstests dependencies via tests/scripts/setup_xfstests.sh.
test-xfstests: release
	@test -n "$(GO_BIN)" || { echo "go not found; set GO=/abs/path/to/go or GO_BIN=/abs/path/to/go"; exit 1; }
	cd tests/integration && \
		$(GO_TEST_ENV) \
		NYDUSFS_RUN_XFSTESTS=1 \
		$(GO_BIN) test -v -run '^TestXfstests$$' -count $(XFSTESTS_COUNT) -timeout $(XFSTESTS_TIMEOUT) $(XFSTESTS_GO_TEST_ARGS) $(XFSTESTS_TEST_FILES)

# Run performance benchmark (requires root, fio, ~5min).
# Compares Nydus vs C erofsfuse.
test-perf: release
	@test -n "$(GO_BIN)" || { echo "go not found; set GO=/abs/path/to/go or GO_BIN=/abs/path/to/go"; exit 1; }
	cd tests/integration && \
		$(GO_TEST_ENV) \
		NYDUSFS_RUN_PERF=1 \
		$(GO_BIN) test -v -run '^TestPerf$$' -count $(PERF_COUNT) -timeout $(PERF_TIMEOUT) $(PERF_GO_TEST_ARGS) $(PERF_TEST_FILES)

# Fanotify vs FUSE performance comparison (requires root, Linux >= 6.15, fio,
# docker for the local registry). Both modes mount the same registry-backed
# nydus image; after prewarming the nydus cache, the comparison isolates the
# read path: fanotify (FAN_PRE_ACCESS event + kernel ext4 read) vs FUSE
# (request + pread + reply). Two columns: warm (fully warm, steady-state)
# and cold-page (warm nydus cache, cold page cache). Set
# FANOTIFY_PERF_SOURCE_IMAGE to the OCI ref to pull and convert
# (e.g. docker.io/library/openclaw:latest).
# Cache dir must be on ext4 (not tmpfs) for FAN_PRE_ACCESS — TMPDIR is set
# to the repo root's .test-tmp/ on the same filesystem as the working tree.
test-fanotify-perf: FEATURES=cli,fanotify
test-fanotify-perf: release nydusify
	@test -n "$(GO_BIN)" || { echo "go not found; set GO=/abs/path/to/go or GO_BIN=/abs/path/to/go"; exit 1; }
	mkdir -p $(CURDIR)/.test-tmp
	cd tests/integration && \
		$(GO_TEST_ENV) "TMPDIR=$(CURDIR)/.test-tmp" \
		FANOTIFY_RUN_PERF=1 \
		FANOTIFY_PERF_SOURCE_IMAGE="$(FANOTIFY_PERF_SOURCE_IMAGE)" \
		$(GO_BIN) test -v -run '^TestFanotifyPerf$$' -count $(FANOTIFY_PERF_COUNT) -timeout $(FANOTIFY_PERF_TIMEOUT) $(FANOTIFY_PERF_GO_TEST_ARGS) $(FANOTIFY_PERF_TEST_PKG)

# Convert and validate the top Docker Hub images, pushing the converted nydus
# images to $(TOP_IMAGES_REGISTRY) (e.g. a GHCR namespace or a local registry).
# Requires root and credentials for the target registry. Builds nydusify on demand.
test-top-images: release
	@test -n "$(GO_BIN)" || { echo "go not found; set GO=/abs/path/to/go or GO_BIN=/abs/path/to/go"; exit 1; }
	cd tests/integration && \
		$(GO_TEST_ENV) \
		NYDUSFS_RUN_TOP_IMAGES=1 \
		NYDUSFS_TOP_IMAGES_REGISTRY=$(TOP_IMAGES_REGISTRY) \
		NYDUSFS_TOP_IMAGES_PLAIN_HTTP=$(TOP_IMAGES_PLAIN_HTTP) \
		NYDUSFS_TOP_IMAGES_PLATFORM=$(TOP_IMAGES_PLATFORM) \
		NYDUSFS_TOP_IMAGES_CONCURRENCY=$(TOP_IMAGES_CONCURRENCY) \
		NYDUSFS_TOP_IMAGES_RETRIES=$(TOP_IMAGES_RETRIES) \
		NYDUSFS_TOP_IMAGES_RETRY_INTERVAL=$(TOP_IMAGES_RETRY_INTERVAL) \
		NYDUSFS_TOP_IMAGES_WORKDIR=$(TOP_IMAGES_WORKDIR) \
		$(GO_BIN) test -v -run '^TestTopImages$$' -count $(TOP_IMAGES_COUNT) -timeout $(TOP_IMAGES_TIMEOUT) $(TOP_IMAGES_GO_TEST_ARGS) $(TOP_IMAGES_TEST_FILES)

clean:
	$(CARGO) clean

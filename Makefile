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

UFFD_TIMEOUT ?= 600s
UFFD_COUNT ?= 1
UFFD_GO_TEST_ARGS ?=
# Set to 1 (CI does) to make missing userfaultfd runner capability a hard
# failure instead of a skip, so the UFFD gate can never be silently skipped.
UFFD_REQUIRE ?=
# Directory for structured failure evidence (service logs, runner metadata);
# empty disables evidence collection.
UFFD_EVIDENCE_DIR ?=
# Scheduled stability run parameters: UFFD_STABILITY_COUNT repetitions of the
# three real-fault cases (3 * count core fault iterations per run).
UFFD_STABILITY_COUNT ?= 34
UFFD_STABILITY_TIMEOUT ?= 1500s

UBLK_TIMEOUT ?= 300s
UBLK_COUNT ?= 1
UBLK_GO_TEST_ARGS ?=

CACHE_SHARING_TIMEOUT ?= 900s
CACHE_SHARING_COUNT ?= 1
CACHE_SHARING_GO_TEST_ARGS ?=

FANOTIFY_TIMEOUT ?= 600s
FANOTIFY_COUNT ?= 1
FANOTIFY_GO_TEST_ARGS ?=
# Set to 1 to also run the optional C11 fail-closed case (needs the local
# registry container started by the test).
FANOTIFY_RUN_FAIL_CLOSED ?=
# Set to 0 to skip C12 strace ground-truth case (runs by default if strace
# is installed).
FANOTIFY_RUN_STRACE ?=

NBD_TIMEOUT ?= 600s
NBD_COUNT ?= 1
NBD_GO_TEST_ARGS ?=

FS_TIMEOUT ?= 1800s
FS_COUNT ?= 1
FS_GO_TEST_ARGS ?=

BENCH_TIMEOUT ?= 1800s
BENCH_COUNT ?= 1
BENCH_GO_TEST_ARGS ?=

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
TEST_SUPPORT_FILES = harness.go optimize.go diff.go
E2E_TEST_FILES = roundtrip_test.go $(TEST_SUPPORT_FILES)
TOOCI_TEST_FILES = tooci_test.go $(TEST_SUPPORT_FILES)
UFFD_TEST_FILES = uffd_test.go uffd_fault_test.go $(TEST_SUPPORT_FILES)
UBLK_TEST_FILES = ublk_test.go $(TEST_SUPPORT_FILES)
CACHE_SHARING_TEST_FILES = cache_sharing_test.go $(TEST_SUPPORT_FILES)
FS_TEST_FILES = fs_test.go $(TEST_SUPPORT_FILES)
TOP_IMAGES_TEST_FILES = top_image_test.go $(TEST_SUPPORT_FILES)
FANOTIFY_TEST_FILES = fanotify_test.go $(TEST_SUPPORT_FILES)
# NBD and bench use whole-package compilation: nbd_test.go and bench_test.go
# reuse helpers (shaFile, usedBytes, kernelVersion, erofsSupported, etc.)
# defined in fanotify_test.go and nbd_test.go, so the entire package must be
# compiled together.
NBD_TEST_PKG = .
BENCH_TEST_PKG = .

.PHONY: build release nydusify test test-e2e test-tooci test-uffd test-uffd-stability test-cache-sharing test-fanotify test-nbd test-bench test-fs test-top-images crate clean

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

# Run end-to-end integration tests (requires root, builds release first).
# Only runs tests/e2e/roundtrip_test.go.
test-e2e: release nydusify
	@test -n "$(GO_BIN)" || { echo "go not found; set GO=/abs/path/to/go or GO_BIN=/abs/path/to/go"; exit 1; }
	cd tests/e2e && \
		$(GO_TEST_ENV) \
		NYDUSFS_MERGE_PAUSE_SECS="$(NYDUSFS_MERGE_PAUSE_SECS)" \
		NYDUSFS_RUN_EROFS_COMPAT="$(NYDUSFS_RUN_EROFS_COMPAT)" \
		$(GO_BIN) test -v $(if $(strip $(E2E_TEST)),-run '^$(E2E_TEST)$$',) -count $(E2E_COUNT) -timeout $(E2E_TIMEOUT) $(E2E_GO_TEST_ARGS) $(E2E_TEST_FILES)

# Run the nydus-to-OCI round trip. Requires a local registry and root, since
# the round trip has to reproduce ownership and device nodes.
test-tooci: release nydusify
	@test -n "$(GO_BIN)" || { echo "go not found; set GO=/abs/path/to/go or GO_BIN=/abs/path/to/go"; exit 1; }
	cd tests/e2e && \
		$(GO_TEST_ENV) \
		$(GO_BIN) test -v -run '^TestNydusifyToOCI$$' -count $(E2E_COUNT) -timeout $(E2E_TIMEOUT) $(E2E_GO_TEST_ARGS) $(TOOCI_TEST_FILES)

# Run the UFFD test suite: capability preflight, the stateless socket smoke,
# real userfaultfd fault-completion integration (managed copy/zeropage and
# zerocopy), protocol negative corpus, backend failure and lifecycle cases.
# Builds nydus with the optional uffd feature. Real-fault cases need root (or
# vm.unprivileged_userfaultfd=1); set UFFD_REQUIRE=1 to fail instead of skip
# on runners without userfaultfd support.
test-uffd: FEATURES=cli,uffd
test-uffd: release
	@test -n "$(GO_BIN)" || { echo "go not found; set GO=/abs/path/to/go or GO_BIN=/abs/path/to/go"; exit 1; }
	cd tests/e2e && \
		$(GO_TEST_ENV) \
		NYDUSFS_UFFD_REQUIRE="$(UFFD_REQUIRE)" \
		NYDUSFS_UFFD_EVIDENCE_DIR="$(UFFD_EVIDENCE_DIR)" \
		$(GO_BIN) test -v -run '^TestUffd' -count $(UFFD_COUNT) -timeout $(UFFD_TIMEOUT) $(UFFD_GO_TEST_ARGS) $(UFFD_TEST_FILES)

# Scheduled UFFD stability run: repeats the three real-fault integration
# cases (managed copy, managed zeropage, zerocopy) UFFD_STABILITY_COUNT times
# each, yielding 3*count core fault iterations per invocation. Any iteration
# failure fails the target; there is no retry, so the first attempt is the
# recorded result.
test-uffd-stability: FEATURES=cli,uffd
test-uffd-stability: release
	@test -n "$(GO_BIN)" || { echo "go not found; set GO=/abs/path/to/go or GO_BIN=/abs/path/to/go"; exit 1; }
	cd tests/e2e && \
		$(GO_TEST_ENV) \
		NYDUSFS_UFFD_REQUIRE="$(UFFD_REQUIRE)" \
		NYDUSFS_UFFD_EVIDENCE_DIR="$(UFFD_EVIDENCE_DIR)" \
		$(GO_BIN) test -v -run '^TestUffdRealFault' -count $(UFFD_STABILITY_COUNT) -timeout $(UFFD_STABILITY_TIMEOUT) $(UFFD_GO_TEST_ARGS) $(UFFD_TEST_FILES)

# Run the ublk block device test. Requires root and Linux 6.0+ with ublk_drv;
# the test skips itself when either is missing.
test-ublk: FEATURES=cli,ublk
test-ublk: release
	@test -n "$(GO_BIN)" || { echo "go not found; set GO=/abs/path/to/go or GO_BIN=/abs/path/to/go"; exit 1; }
	cd tests/e2e && \
		$(GO_TEST_ENV) \
		$(GO_BIN) test -v -run '^TestUblkService$$' -count $(UBLK_COUNT) -timeout $(UBLK_TIMEOUT) $(UBLK_GO_TEST_ARGS) $(UBLK_TEST_FILES)

# Run the cross-process blob cache tests. Requires root because they mount
# several nydus FUSE instances against one shared --cache-dir and assert on the
# cache directory plus each instance's /metrics endpoint.
test-cache-sharing: release
	@test -n "$(GO_BIN)" || { echo "go not found; set GO=/abs/path/to/go or GO_BIN=/abs/path/to/go"; exit 1; }
	cd tests/e2e && \
		$(GO_TEST_ENV) \
		$(GO_BIN) test -v -run '^TestCacheSharing' -count $(CACHE_SHARING_COUNT) -timeout $(CACHE_SHARING_TIMEOUT) $(CACHE_SHARING_GO_TEST_ARGS) $(CACHE_SHARING_TEST_FILES)

# Run the fanotify pre-content E2E test (requires root, Linux >= 6.15, docker
# for the throwaway local registry). Builds nydus with the fanotify feature.
# It boots the real daemon against a real OCI registry backend and asserts
# byte-exact on-demand reads through the FAN_PRE_ACCESS path. Set
# FANOTIFY_RUN_FAIL_CLOSED=1 to also run the optional C11 fail-closed case.
test-fanotify: FEATURES=cli,fanotify
test-fanotify: release nydusify
	@test -n "$(GO_BIN)" || { echo "go not found; set GO=/abs/path/to/go or GO_BIN=/abs/path/to/go"; exit 1; }
	mkdir -p $(CURDIR)/.test-tmp
	cd tests/e2e && \
		$(GO_TEST_ENV) "TMPDIR=$(CURDIR)/.test-tmp" \
		FANOTIFY_RUN_FAIL_CLOSED="$(FANOTIFY_RUN_FAIL_CLOSED)" \
		FANOTIFY_RUN_STRACE="$(FANOTIFY_RUN_STRACE)" \
		$(GO_BIN) test -v -run '^TestFanotify$$' -count $(FANOTIFY_COUNT) -timeout $(FANOTIFY_TIMEOUT) $(FANOTIFY_GO_TEST_ARGS) $(FANOTIFY_TEST_FILES)

# Run the NBD E2E test (requires root, the nbd kernel module, EROFS support).
# Builds nydus with the nbd feature. Uses a LOCAL backend (nydus build
# --blob-dir, no docker/registry) so the test is hermetic. The daemon attaches
# a free /dev/nbdX, mounts it as EROFS on demand, and serves cold reads
# through the NBD socket protocol. Whole-package compilation (NBD_TEST_PKG=.)
# because nbd_test.go reuses helpers defined in fanotify_test.go.
test-nbd: FEATURES=cli,nbd
test-nbd: release
	@test -n "$(GO_BIN)" || { echo "go not found; set GO=/abs/path/to/go or GO_BIN=/abs/path/to/go"; exit 1; }
	mkdir -p $(CURDIR)/.test-tmp
	cd tests/e2e && \
		$(GO_TEST_ENV) "TMPDIR=$(CURDIR)/.test-tmp" \
		$(GO_BIN) test -v -run '^TestNbd$$' -count $(NBD_COUNT) -timeout $(NBD_TIMEOUT) $(NBD_GO_TEST_ARGS) $(NBD_TEST_PKG)

# Unified cold-start performance benchmark: FUSE vs NBD vs ublk vs fanotify
# (plus an optional C erofsfuse column when the binary is available), all
# serving the same local-backend image with prefetch disabled. Per mode:
# cold start (mount-ready, first-1MiB read, full-file prewarm fetch), then
# every fio job and metadata benchmark with the page cache dropped before
# each job (warm nydus cache, cold page cache). Modes whose kernel support
# is missing (nbd/ublk modules, Linux < 6.15 for fanotify) are skipped
# individually. Requires root and fio; fanotify needs an ext4 cache dir —
# TMPDIR is set to the repo's .test-tmp/ on the working tree filesystem.
test-bench: FEATURES=cli,fuse,nbd,ublk,fanotify,fileio
test-bench: release
	@test -n "$(GO_BIN)" || { echo "go not found; set GO=/abs/path/to/go or GO_BIN=/abs/path/to/go"; exit 1; }
	mkdir -p $(CURDIR)/.test-tmp
	cd tests/e2e && \
		$(GO_TEST_ENV) "TMPDIR=$(CURDIR)/.test-tmp" \
		NYDUSFS_RUN_BENCH=1 \
		$(GO_BIN) test -v -run '^TestBench$$' -count $(BENCH_COUNT) -timeout $(BENCH_TIMEOUT) $(BENCH_GO_TEST_ARGS) $(BENCH_TEST_PKG)

# Filesystem conformance suite. Pure Go, one mount per build config and corpus,
# all cases in parallel; covers write rejection, dirent encoding, inode
# identity, mmap, splice and xattr behaviour against the mounted image.
test-fs: release
	@test -n "$(GO_BIN)" || { echo "go not found; set GO=/abs/path/to/go or GO_BIN=/abs/path/to/go"; exit 1; }
	cd tests/e2e && \
		$(GO_TEST_ENV) \
		$(GO_BIN) test -v -run '^TestFilesystem' -parallel 32 -count $(FS_COUNT) -timeout $(FS_TIMEOUT) $(FS_GO_TEST_ARGS) $(FS_TEST_FILES)

# Convert and validate the top Docker Hub images, pushing the converted nydus
# images to $(TOP_IMAGES_REGISTRY) (e.g. a GHCR namespace or a local registry).
# Requires root and credentials for the target registry. Builds nydusify on demand.
test-top-images: release
	@test -n "$(GO_BIN)" || { echo "go not found; set GO=/abs/path/to/go or GO_BIN=/abs/path/to/go"; exit 1; }
	cd tests/e2e && \
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

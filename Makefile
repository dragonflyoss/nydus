all: release

all-build: build contrib-build

all-release: release contrib-release

all-static-release: static-release docker-static contrib-release

all-install: install contrib-install

all-clean: clean contrib-clean

TEST_WORKDIR_PREFIX ?= "/tmp"
INSTALL_DIR_PREFIX ?= "/usr/local/bin"
DOCKER ?= "true"

CARGO ?= $(shell which cargo)
RUSTUP ?= $(shell which rustup)
CARGO_BUILD_GEARS = -v ~/.ssh/id_rsa:/root/.ssh/id_rsa -v ~/.cargo/git:/root/.cargo/git -v ~/.cargo/registry:/root/.cargo/registry
SUDO = $(shell which sudo)
CARGO_COMMON ?=

EXCLUDE_PACKAGES =
UNAME_M := $(shell uname -m)
UNAME_S := $(shell uname -s)
STATIC_TARGET = $(UNAME_M)-unknown-linux-musl
ifeq ($(UNAME_S),Linux)
	CARGO_COMMON += --features=virtiofs
ifeq ($(UNAME_M),ppc64le)
	STATIC_TARGET = powerpc64le-unknown-linux-gnu
endif
ifeq ($(UNAME_M),riscv64)
	STATIC_TARGET = riscv64gc-unknown-linux-gnu
endif
endif
ifeq ($(UNAME_S),Darwin)
	EXCLUDE_PACKAGES += --exclude nydus-blobfs
ifeq ($(UNAME_M),amd64)
	STATIC_TARGET = x86_64-apple-darwin
endif
ifeq ($(UNAME_M),arm64)
	STATIC_TARGET = aarch64-apple-darwin
endif
endif
RUST_TARGET_STATIC ?= $(STATIC_TARGET)

NYDUSIFY_PATH = contrib/nydusify
NYDUS-OVERLAYFS_PATH = contrib/nydus-overlayfs

current_dir := $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
env_go_path := $(shell go env GOPATH 2> /dev/null)
go_path := $(if $(env_go_path),$(env_go_path),"$(HOME)/go")

# Functions

# Func: build golang target in docker
# Args:
#   $(1): The path where go build a golang project
#   $(2): How to build the golang project
define build_golang
	echo "Building target $@ by invoking: $(2)"
	if [ $(DOCKER) = "true" ]; then \
		docker run --rm -v ${go_path}:/go -v ${current_dir}:/nydus-rs --workdir /nydus-rs/$(1) golang:1.21 $(2) ;\
	else \
		$(2) -C $(1); \
	fi
endef

.PHONY: .release_version .format .musl_target .clean_libz_sys \
	all all-build all-release all-static-release build release static-release

.release_version:
	$(eval CARGO_BUILD_FLAGS += --release)

.format:
	${CARGO} fmt -- --check

.musl_target:
	$(eval CARGO_BUILD_FLAGS += --target ${RUST_TARGET_STATIC})

# Workaround to clean up stale cache for libz-sys
.clean_libz_sys:
	@${CARGO} clean --target ${RUST_TARGET_STATIC} -p libz-sys
	@${CARGO} clean --target ${RUST_TARGET_STATIC} --release -p libz-sys

# Targets that are exposed to developers and users.
build: .format
	${CARGO} build $(CARGO_COMMON) $(CARGO_BUILD_FLAGS)
	# Cargo will skip checking if it is already checked
	${CARGO} clippy --workspace $(EXCLUDE_PACKAGES) $(CARGO_COMMON) $(CARGO_BUILD_FLAGS) --bins --tests -- -Dwarnings --allow clippy::unnecessary_cast --allow clippy::needless_borrow

release: .format .release_version build

static-release: .clean_libz_sys .musl_target .format .release_version build

clean:
	${CARGO} clean

install: release
	@sudo mkdir -m 755 -p $(INSTALL_DIR_PREFIX)
	@sudo install -m 755 target/release/nydusd $(INSTALL_DIR_PREFIX)/nydusd
	@sudo install -m 755 target/release/nydus-image $(INSTALL_DIR_PREFIX)/nydus-image
	@sudo install -m 755 target/release/nydusctl $(INSTALL_DIR_PREFIX)/nydusctl

# unit test
ut: .release_version
	TEST_WORKDIR_PREFIX=$(TEST_WORKDIR_PREFIX) RUST_BACKTRACE=1 ${CARGO} test --no-fail-fast --workspace $(EXCLUDE_PACKAGES) $(CARGO_COMMON) $(CARGO_BUILD_FLAGS) -- --skip integration --nocapture --test-threads=8

# you need install cargo nextest first from: https://nexte.st/book/pre-built-binaries.html
ut-nextest: .release_version
	TEST_WORKDIR_PREFIX=$(TEST_WORKDIR_PREFIX) RUST_BACKTRACE=1 ${RUSTUP} run stable cargo nextest run --no-fail-fast --filter-expr 'test(test) - test(integration)' --workspace $(EXCLUDE_PACKAGES) $(CARGO_COMMON) $(CARGO_BUILD_FLAGS)

# install miri first from https://github.com/rust-lang/miri/
miri-ut-nextest: .release_version
	MIRIFLAGS=-Zmiri-disable-isolation TEST_WORKDIR_PREFIX=$(TEST_WORKDIR_PREFIX) RUST_BACKTRACE=1 ${RUSTUP} run nightly cargo miri nextest run --no-fail-fast --filter-expr 'test(test) - test(integration) - test(deduplicate::tests) - test(inode_bitmap::tests::test_inode_bitmap)' --workspace $(EXCLUDE_PACKAGES) $(CARGO_COMMON) $(CARGO_BUILD_FLAGS)

# install test dependencies
pre-coverage:
	${CARGO} +stable install cargo-llvm-cov --locked
	${RUSTUP} component add llvm-tools-preview

# print unit test coverage to console
coverage: pre-coverage
	TEST_WORKDIR_PREFIX=$(TEST_WORKDIR_PREFIX) ${CARGO} llvm-cov --workspace $(EXCLUDE_PACKAGES) $(CARGO_COMMON) $(CARGO_BUILD_FLAGS) -- --skip integration --nocapture  --test-threads=8

# write unit teset coverage to codecov.json, used for Github CI
coverage-codecov:
	TEST_WORKDIR_PREFIX=$(TEST_WORKDIR_PREFIX) ${RUSTUP} run stable cargo llvm-cov --codecov --output-path codecov.json --workspace $(EXCLUDE_PACKAGES) $(CARGO_COMMON) $(CARGO_BUILD_FLAGS) -- --skip integration --nocapture --test-threads=8

smoke-only:
	make -C smoke test

smoke-performance:
	make -C smoke test-performance

smoke-benchmark:
	make -C smoke test-benchmark

smoke-takeover:
	make -C smoke test-takeover

smoke: release smoke-only

contrib-build: nydusify nydus-overlayfs

contrib-release: nydusify-release nydus-overlayfs-release

contrib-test: nydusify-test nydus-overlayfs-test

contrib-lint: nydusify-lint nydus-overlayfs-lint

contrib-clean: nydusify-clean nydus-overlayfs-clean

contrib-install:
	@sudo mkdir -m 755 -p $(INSTALL_DIR_PREFIX)
	@sudo install -m 755 contrib/nydus-overlayfs/bin/nydus-overlayfs $(INSTALL_DIR_PREFIX)/nydus-overlayfs
	@sudo install -m 755 contrib/nydusify/cmd/nydusify $(INSTALL_DIR_PREFIX)/nydusify

nydusify:
	$(call build_golang,${NYDUSIFY_PATH},make)

nydusify-release:
	$(call build_golang,${NYDUSIFY_PATH},make release)

nydusify-test:
	$(call build_golang,${NYDUSIFY_PATH},make test)

nydusify-clean:
	$(call build_golang,${NYDUSIFY_PATH},make clean)

nydusify-lint:
	$(call build_golang,${NYDUSIFY_PATH},make lint)

nydus-overlayfs:
	$(call build_golang,${NYDUS-OVERLAYFS_PATH},make)

nydus-overlayfs-release:
	$(call build_golang,${NYDUS-OVERLAYFS_PATH},make release)

nydus-overlayfs-test:
	$(call build_golang,${NYDUS-OVERLAYFS_PATH},make test)

nydus-overlayfs-clean:
	$(call build_golang,${NYDUS-OVERLAYFS_PATH},make clean)

nydus-overlayfs-lint:
	$(call build_golang,${NYDUS-OVERLAYFS_PATH},make lint)

docker-static:
	docker build -t nydus-rs-static --build-arg RUST_TARGET=${RUST_TARGET_STATIC} misc/musl-static
	docker run --rm ${CARGO_BUILD_GEARS} -e RUST_TARGET=${RUST_TARGET_STATIC} --workdir /nydus-rs -v ${current_dir}:/nydus-rs nydus-rs-static

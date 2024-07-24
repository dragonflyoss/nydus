all:.format build

current_dir := $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
rust_arch := $(shell uname -p)

.musl_target:
	$(eval CARGO_BUILD_FLAGS += --target ${rust_arch}-unknown-linux-musl)

.release_version:
	$(eval CARGO_BUILD_FLAGS += --release)

.format:
	cargo fmt -- --check

build:
	cargo build $(CARGO_BUILD_FLAGS)

release: .format .release_version build

static-release: .musl_target .format .release_version build

clean:
	cargo clean

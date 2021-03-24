TEST_WORKDIR_PREFIX ?= "/tmp"

current_dir := $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))

build: build-virtiofs build-fusedev
	cargo fmt -- --check

release: build-virtiofs-release build-fusedev-release
	cargo fmt -- --check

build-virtiofs:
	# TODO: switch to --out-dir when it moves to stable
	# For now we build with separate target directories
	cargo build --features=virtiofs --target-dir target-virtiofs
	cargo clippy --features=virtiofs --tests --bins --workspace --target-dir target-virtiofs -- -Dclippy::all

build-fusedev:
	cargo build --features=fusedev --target-dir target-fusedev
	cargo clippy --features=fusedev --tests --bins --workspace --target-dir target-fusedev -- -Dclippy::all

build-virtiofs-release:
	cargo build --features=virtiofs --release --target-dir target-virtiofs

build-fusedev-release:
	cargo build --features=fusedev --release --target-dir target-fusedev

static-release:
	cargo build --target x86_64-unknown-linux-musl --features=fusedev --release --target-dir target-fusedev
	cargo build --target x86_64-unknown-linux-musl --features=virtiofs --release --target-dir target-virtiofs

ut:
	RUST_BACKTRACE=1 cargo test --features=fusedev --target-dir target-fusedev --workspace -- --nocapture --test-threads=15 --skip integration
	RUST_BACKTRACE=1 cargo test --features=virtiofs --target-dir target-virtiofs --workspace -- --nocapture --test-threads=15 --skip integration

# Run smoke test including general integration tests and unit tests in container.
# Nydus binaries should already be prepared.
static-test:
	# No clippy for virtiofs for now since it has much less updates.
	cargo clippy --features=fusedev --tests --bins --workspace --target-dir target-fusedev  -- -Dclippy::all
	# For virtiofs target UT
	cargo test --target x86_64-unknown-linux-musl --features=virtiofs --release --target-dir target-virtiofs --workspace -- --nocapture --test-threads=15 --skip integration
	# For fusedev target UT & integration
	cargo test --target x86_64-unknown-linux-musl --features=fusedev --release --target-dir target-fusedev --workspace -- --nocapture --test-threads=15

docker-static:
	docker build -t nydus-rs-static misc/musl-static
	docker run --rm \
		-v ${current_dir}:/nydus-rs \
		-v ~/.cargo/git:/root/.cargo/git \
		-v ~/.cargo/registry:/root/.cargo/registry \
		nydus-rs-static

docker-nydus-smoke: docker-static
	docker build -t nydus-smoke misc/nydus-smoke
	docker run --rm --privileged \
		-e TEST_WORKDIR_PREFIX=$(TEST_WORKDIR_PREFIX) \
		-v $(TEST_WORKDIR_PREFIX) \
		-v ${current_dir}:/nydus-rs \
		-v ~/.cargo/git:/root/.cargo/git \
		-v ~/.cargo/registry:/root/.cargo/registry \
		nydus-smoke

docker-nydusify-smoke: docker-static
	docker run --rm -v ~/go:/go -v ${current_dir}:/nydus-rs --workdir /nydus-rs golang:1.14 make -C contrib/nydusify build-smoke
	docker build -t nydusify-smoke misc/nydusify-smoke
	docker run --rm -v $(current_dir):/nydus-rs --privileged nydusify-smoke TestSmoke

docker-nydusify-image-test: docker-static
	docker run --rm -v ~/go:/go -v ${current_dir}:/nydus-rs --workdir /nydus-rs golang:1.14 make -C contrib/nydusify build-smoke
	docker build -t nydusify-smoke misc/nydusify-smoke
	docker run --rm -v $(current_dir):/nydus-rs --privileged nydusify-smoke TestDockerHubImage

docker-smoke: docker-nydus-smoke docker-nydusify-smoke

nydusify:
	make -C contrib/nydusify

nydusify-static:
	make -C contrib/nydusify static-release

nydus-snapshotter:
	make -C contrib/nydus-snapshotter

nydus-snapshotter-static:
	make -C contrib/nydus-snapshotter static-release

all-static-release: static-release nydusify-static nydus-snapshotter-static

docker-example: all-static-release
	cp target-fusedev/x86_64-unknown-linux-musl/release/nydusd misc/example
	cp target-fusedev/x86_64-unknown-linux-musl/release/nydus-image misc/example
	cp contrib/nydusify/cmd/nydusify misc/example
	cp contrib/nydus-snapshotter/bin/containerd-nydus-grpc misc/example
	docker build -t nydus-rs-example misc/example

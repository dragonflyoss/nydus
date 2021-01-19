current_dir := $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))

build: build-virtiofs build-fusedev
	cargo fmt -- --check

release: build-virtiofs-release build-fusedev-release
	cargo fmt -- --check

build-virtiofs:
	# TODO: switch to --out-dir when it moves to stable
	# For now we build with separate target directories
	cargo build --features=virtiofs --target-dir target-virtiofs
	cargo clippy --features=virtiofs --target-dir target-virtiofs -- -Dclippy::all

build-fusedev:
	cargo build --features=fusedev --target-dir target-fusedev
	cargo clippy --features=fusedev --target-dir target-fusedev -- -Dclippy::all

build-virtiofs-release:
	cargo build --features=virtiofs --release --target-dir target-virtiofs

build-fusedev-release:
	cargo build --features=fusedev --release --target-dir target-fusedev

static-release:
	cargo build --target x86_64-unknown-linux-musl --features=fusedev --release --target-dir target-fusedev
	cargo build --target x86_64-unknown-linux-musl --features=virtiofs --release --target-dir target-virtiofs

ut:
	RUST_BACKTRACE=1 cargo test --features=virtiofs --target-dir target-virtiofs --workspace -- --nocapture --test-threads=15 --skip integration
test: build ut
	# Run smoke test and unit tests
	RUST_BACKTRACE=1 cargo test --features=fusedev --target-dir target-fusedev --workspace -- --nocapture --test-threads=15

docker-smoke:
	docker build -t nydus-rs-smoke misc/smoke
	docker run -it --rm --privileged -v /tmp -e TEST_WORKDIR_PREFIX=/tmp -v ${current_dir}:/nydus-rs -v ~/.ssh/id_rsa:/root/.ssh/id_rsa -v ~/.cargo:/usr/local/cargo -v fuse-targets:/nydus-rs/target-fusedev -v virtiofs-targets:/nydus-rs/target-virtiofs nydus-rs-smoke

docker-static:
	# For static build with musl
	docker build -t nydus-rs-static misc/musl-static
	docker run -it --rm -v ${current_dir}:/nydus-rs -v ~/.ssh/id_rsa:/root/.ssh/id_rsa -v ~/.cargo:/root/.cargo nydus-rs-static

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

current_dir := $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))

build: build-virtiofsd build-fusedev
	cargo fmt -- --check

release: build-virtiofsd-release build-fusedev-release
	cargo fmt -- --check

build-virtiofsd:
	# TODO: switch to --out-dir when it moves to stable
	# For now we build with separate target directories
	cargo build --features=virtiofsd --target-dir target-virtiofsd
	cargo clippy --features=virtiofsd --target-dir target-virtiofsd -- -Dclippy::all

build-fusedev:
	cargo build --features=fusedev --target-dir target-fusedev
	cargo clippy --features=fusedev --target-dir target-fusedev -- -Dclippy::all

build-virtiofsd-release:
	cargo build --features=virtiofsd --release --target-dir target-virtiofsd

build-fusedev-release:
	cargo build --features=fusedev --release --target-dir target-fusedev

static-release:
	cargo build --target x86_64-unknown-linux-musl --features=fusedev --release --target-dir target-fusedev
	cargo build --target x86_64-unknown-linux-musl --features=virtiofsd --release --target-dir target-virtiofsd

test: release
	# Run smoke test and unit tests
	RUST_BACKTRACE=1 cargo test --features=virtiofsd --target-dir target-virtiofsd --workspace -- --nocapture --test-threads=15 --skip integration
	RUST_BACKTRACE=1 cargo test --features=fusedev --target-dir target-fusedev --workspace -- --nocapture --test-threads=15

docker-smoke:
	docker build -t nydus-rs-smoke misc/smoke
	docker run --rm --privileged -v ${current_dir}:/nydus-rs nydus-rs-smoke make test

docker-static:
	# For static build with musl
	docker build -t nydus-rs-static misc/musl-static
	docker run -it --rm --privileged -v ${current_dir}:/nydus-rs nydus-rs-static make static-release

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

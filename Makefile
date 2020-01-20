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

test: build
	# Run smoke test and unit tests
	RUST_BACKTRACE=1 cargo test --features=virtiofsd --target-dir target-virtiofsd --workspace -- --nocapture --skip integration
	RUST_BACKTRACE=1 cargo test --features=fusedev --target-dir target-fusedev --workspace -- --nocapture

docker-smoke:
	docker build -t nydus-rs-smoke misc/smoke
	docker run -it --rm --privileged -v ${current_dir}:/nydus-rs -v ~/.ssh/id_rsa:/root/.ssh/id_rsa -v ~/.cargo:/usr/local/cargo -v fuse-targets:/nydus-rs/target-fusedev -v virtiofsd-targets:/nydus-rs/target-virtiofsd nydus-rs-smoke

docker-static:
	# For static build with musl
	docker build -t nydus-rs-static misc/musl-static
	docker run -it --rm --privileged -v ${current_dir}:/nydus-rs -v ~/.ssh/id_rsa:/root/.ssh/id_rsa -v ~/.cargo:/root/.cargo nydus-rs-static

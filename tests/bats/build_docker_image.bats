#!/usr/bin/bats

load "${BATS_TEST_DIRNAME}/common_tests.sh"

setup() {
	dockerfile="/tmp/rust_golang_dockerfile"
	cat > $dockerfile <<EOF
FROM rust:${rust_toolchain}

RUN apt-get update -y \
    && apt-get install -y cmake g++ pkg-config jq libcurl4-openssl-dev libelf-dev libdw-dev binutils-dev libiberty-dev musl-tools \
    && rustup component add rustfmt clippy \
    && rm -rf /var/lib/apt/lists/*

# install golang env
Run wget https://go.dev/dl/go1.19.linux-amd64.tar.gz \
    && tar -C /usr/local -xzf go1.19.linux-amd64.tar.gz \
    && rm -rf go1.19.linux-amd64.tar.gz

ENV PATH \$PATH:/usr/local/go/bin
RUN go env -w GO111MODULE=on
RUN go env -w GOPROXY=https://goproxy.io,direct
EOF
}

@test "build rust golang image" {
	yum install -y docker
        docker build -f $dockerfile -t $compile_image .
}

teardown() {
	rm -f $dockerfile
}


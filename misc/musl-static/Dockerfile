FROM clux/muslrust:1.72.1

ARG RUST_TARGET=x86_64-unknown-linux-musl

RUN apt update && apt install -y cmake

WORKDIR /nydus-rs

CMD rustup component add clippy && \
  rustup component add rustfmt && \
  rustup target add $RUST_TARGET && \
  make static-release

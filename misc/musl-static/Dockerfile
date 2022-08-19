FROM clux/muslrust:1.61.0

ARG ARCH=x86_64

RUN rustup component add clippy && rustup component add rustfmt && \
  rustup target add $ARCH-unknown-linux-musl

WORKDIR /nydus-rs

CMD make static-release

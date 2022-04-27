FROM clux/muslrust:1.52.1

ARG ARCH=x86_64

WORKDIR /nydus-rs

CMD rustup component add clippy && \
  rustup component add rustfmt && \
  rustup target add $ARCH-unknown-linux-musl && \
  make static-release

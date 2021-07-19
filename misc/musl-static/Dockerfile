FROM clux/muslrust:1.50.0

WORKDIR /nydus-rs

CMD rustup component add clippy && \
  rustup component add rustfmt && \
  rustup target add x86_64-unknown-linux-musl && \
  make static-release

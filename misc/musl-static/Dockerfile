FROM clux/muslrust:1.47.0

WORKDIR /nydus-rs

CMD rustup target add x86_64-unknown-linux-musl && make static-release

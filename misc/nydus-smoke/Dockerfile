FROM rust:1.61.0
ARG RUST_TARGET=x86_64-unknown-linux-musl

RUN mkdir /root/.cargo/
RUN rustup component add rustfmt && rustup component add clippy

ENV CARGO_HOME=/root/.cargo
RUN apt update && apt install -y cmake tree

WORKDIR /nydus-rs

VOLUME /tmp

CMD make release smoke

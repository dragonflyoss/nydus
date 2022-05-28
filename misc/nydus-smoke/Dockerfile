FROM rust:1.61.0
ARG ARCH=x86_64

RUN mkdir /root/.cargo/
RUN rustup component add rustfmt && rustup component add clippy

ENV CARGO_HOME=/root/.cargo
RUN apt update && apt install -y tree

WORKDIR /nydus-rs

CMD make fusedev-release smoke

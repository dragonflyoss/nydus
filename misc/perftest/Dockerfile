# syntax=docker/dockerfile:1.6
#
# Nydus performance test image for Dragonfly proxy SDK mode.
#
# This image bundles a statically-linked nydusd (musl) plus a small benchmark
# harness that mounts a Nydus image via FUSE and reads every regular file
# in parallel, exercising the Dragonfly SDK proxy path. Bind-mount a local
# nydusd over /usr/local/bin/nydusd to test a new daemon without rebuilding
# this image. Dragonfly (dfdaemon + scheduler) is expected to be deployed
# OUTSIDE the container; the proxy and scheduler endpoints are passed via
# environment variables.
#
# See README.md in this directory for usage.

# -----------------------------------------------------------------------------
# Stage 1: build a static nydusd (and nydusctl) on musl.
#
# `make static-release` honours the workspace defaults plus virtiofs on Linux.
# The `backend-dragonfly-proxy` feature is target-gated for x86_64/aarch64 in
# the root Cargo.toml, so it is automatically enabled on supported arches.
# -----------------------------------------------------------------------------
ARG RUST_TARGET=x86_64-unknown-linux-musl
FROM clux/muslrust:1.84.0-stable AS builder

ARG RUST_TARGET
ENV RUST_TARGET=${RUST_TARGET}

# protoc is required by tonic / dragonfly-api build scripts.
RUN apt-get update \
    && apt-get install -y --no-install-recommends cmake protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /nydus-rs
COPY . /nydus-rs

RUN rustup target add "${RUST_TARGET}"

# Lean build: directly invoke cargo for the nydus binaries we ship, skipping
# fmt/clippy and contrib targets that `make static-release` would also run.
# The `backend-dragonfly-proxy` storage feature is target-gated for x86_64 /
# aarch64 in the workspace root Cargo.toml, so it is automatically enabled on
# the supported architectures.
RUN cargo build --release --target "${RUST_TARGET}" \
        --bin nydusd --bin nydusctl --features=virtiofs \
    && cp target/${RUST_TARGET}/release/nydusd  /out-nydusd \
    && cp target/${RUST_TARGET}/release/nydusctl /out-nydusctl \
    && /out-nydusd --version

# -----------------------------------------------------------------------------
# Stage 2: Go builder. Produces a static `crane` for portable image manifest /
# blob access AND the static `workload` benchmark binary used by the harness.
# -----------------------------------------------------------------------------
FROM golang:1.22-alpine AS go-builder
RUN apk add --no-cache git ca-certificates \
    && go install github.com/google/go-containerregistry/cmd/crane@v0.20.2 \
    && cp /go/bin/crane /out-crane

WORKDIR /workload
COPY misc/perftest/workload/ /workload/
RUN CGO_ENABLED=0 go build -trimpath -ldflags '-s -w' -o /out-workload ./...

# -----------------------------------------------------------------------------
# Stage 3: minimal runtime image.
#
# Ubuntu keeps the bundled static musl binaries working while also allowing
# /usr/local/bin/nydusd to be replaced by a normal glibc-linked nydusd
# bind-mounted from a local host build. The only runtime tooling we need beyond
# bash is fuse3 (for the FUSE mount), jq (for JSON munging), gettext-base
# (envsubst), curl + tar + ca-certificates (used by crane via TLS), and tini.
# -----------------------------------------------------------------------------
FROM ubuntu:24.04

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        bash \
        ca-certificates \
        coreutils \
        curl \
        file \
        fuse3 \
        gettext-base \
        jq \
        libgcc-s1 \
        tar \
        tini \
        util-linux \
        zlib1g \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /etc/nydus /mnt/nydus /results /var/lib/nydus/cache /tmp/nydus

COPY --from=builder    /out-nydusd   /usr/local/bin/nydusd
COPY --from=builder    /out-nydusctl /usr/local/bin/nydusctl
COPY --from=go-builder /out-crane    /usr/local/bin/crane
COPY --from=go-builder /out-workload /usr/local/bin/workload

COPY misc/perftest/entrypoint.sh        /usr/local/bin/perftest-entrypoint
COPY misc/perftest/fetch-bootstrap.sh   /usr/local/bin/fetch-bootstrap
COPY misc/perftest/config.template.json /etc/nydus/config.template.json

RUN chmod +x /usr/local/bin/perftest-entrypoint \
             /usr/local/bin/fetch-bootstrap

# Sensible defaults; all are overridable at `docker run` time.
ENV NYDUS_IMAGE="ghcr.io/dragonflyoss/image-service/nginx:nydus-latest" \
    DRAGONFLY_PROXY_URL="http://host.docker.internal:4001" \
    DRAGONFLY_SCHEDULER_ENDPOINT="http://host.docker.internal:8002" \
    REGISTRY_SCHEME="https" \
    MOUNT_POINT="/mnt/nydus" \
    RESULTS_DIR="/results" \
    WORK_DIR="/tmp/nydus" \
    BLOB_CACHE_DIR="/var/lib/nydus/cache" \
    READ_PARALLELISM="16" \
    READ_CHUNK_SIZE="1048576" \
    MAX_FILES="0" \
    MOUNT_READY_TIMEOUT="60" \
    NYDUSD_LOG_LEVEL="info" \
    PLATFORM="linux/amd64"

VOLUME ["/results"]
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/perftest-entrypoint"]
CMD []

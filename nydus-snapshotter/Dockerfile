# syntax=docker/dockerfile:1

# Build from the repository root, so the image carries the nydus binary of the
# same commit:
#
#   docker buildx build -f nydus-snapshotter/Dockerfile \
#     --platform linux/amd64,linux/arm64 -t <image> .
#
# The release workflow (.github/workflows/release.yml) builds both binaries
# once for its tarball and replaces the binaries stage with them, so the image
# holds exactly the released binaries:
#
#   docker buildx build -f nydus-snapshotter/Dockerfile \
#     --build-context binaries=<dir holding nydus and nydus-snapshotter> -t <image> .
#
# The image holds the payload the installer copies onto the host:
#
#   /opt/nydus-snapshotter/payload/bin/{nydus-snapshotter,nydus}
#   /opt/nydus-snapshotter/payload/systemd/nydus-snapshotter.{service,socket}
#   /opt/nydus-snapshotter/payload/config/  defaults, shadowed by the ConfigMap

# nydus runs on the host, so it is a static musl build with the release
# workflow's features and environment. It builds on the target platform, as
# dragonflyoss/client's image does, instead of cross-compiling C dependencies.
FROM rust:1.88.0-bookworm@sha256:af306cfa71d987911a781c37b59d7d67d934f49684058f96cf72079c3626bfe0 AS nydus

RUN apt-get update && apt-get install -y --no-install-recommends cmake libprotobuf-dev musl-tools protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY nydus nydus
COPY nydus-backend nydus-backend
COPY nydus-config nydus-config
COPY nydus-core nydus-core
COPY nydus-error nydus-error
COPY nydus-format nydus-format
COPY nydus-storage nydus-storage
COPY nydus-telemetry nydus-telemetry
COPY nydus-test-utils nydus-test-utils

ARG FEATURES=cli,uffd,fanotify,fileio,dragonfly
ENV RUSTFLAGS="-C target-feature=+crt-static" \
    CC_x86_64_unknown_linux_musl=musl-gcc \
    CC_aarch64_unknown_linux_musl=musl-gcc
# Cache mounts keep the cargo registry and the target dir across builds, refer
# to https://docs.docker.com/build/cache/optimize/#use-cache-mounts. The target
# dir also holds the host's build scripts, so each platform gets its own.
ARG TARGETARCH
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git/db \
    --mount=type=cache,target=/src/target,id=nydus-target-${TARGETARCH} \
    target="$(uname -m)-unknown-linux-musl" \
    && rustup target add "${target}" \
    && cargo build --locked -p nydus --release --target "${target}" --features "${FEATURES}" \
    && cp "target/${target}/release/nydus" /nydus

# The Go binary cross-compiles on the build platform.
FROM --platform=$BUILDPLATFORM golang:1.25.5-bookworm@sha256:d9132cce84391efab786495288756d60e1da215b1f94e87860aeefc3d4c45b6d AS snapshotter

WORKDIR /src/nydus-snapshotter

COPY nydus-snapshotter/ ./

ARG TARGETOS TARGETARCH
ARG VERSION=unknown
ARG GIT_COMMIT=unknown
ARG BUILD_TIME=unknown
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    make build VERSION=${VERSION} GIT_COMMIT=${GIT_COMMIT} BUILD_TIME=${BUILD_TIME}

# The binaries the image ships. --build-context binaries=<dir> replaces this
# stage, refer to
# https://docs.docker.com/reference/cli/docker/buildx/build/#build-context.
FROM scratch AS binaries

COPY --from=nydus /nydus /nydus
COPY --from=snapshotter /src/nydus-snapshotter/bin/nydus-snapshotter /nydus-snapshotter

# Both binaries run on the host, so they must be static, as the release
# workflow checks for its tarball.
FROM debian:bookworm-slim@sha256:99c0b25c46d0214d5a2091092e7908907dcaecd6a962cde0ac700acee222b6f3 AS verify

RUN apt-get update && apt-get install -y --no-install-recommends file \
    && rm -rf /var/lib/apt/lists/*

COPY --from=binaries /nydus /nydus-snapshotter /opt/nydus-snapshotter/payload/bin/

RUN set -e; for bin in /opt/nydus-snapshotter/payload/bin/*; do \
        file "${bin}" | grep -Eq 'statically linked|static-pie linked'; \
        "${bin}" --version; \
    done

# Nothing else runs in the Pod.
FROM gcr.io/distroless/static-debian12:latest@sha256:d75cdd72874d4790092fcb1b058493ecf6bb5bf2b2b897045b00ff01d91843f2

COPY --from=verify /opt/nydus-snapshotter/payload/bin/ /opt/nydus-snapshotter/payload/bin/
COPY nydus-snapshotter/deploy/systemd/ /opt/nydus-snapshotter/payload/systemd/
COPY nydus-snapshotter/deploy/nydus-snapshotter/ /opt/nydus-snapshotter/payload/config/

ENTRYPOINT ["/opt/nydus-snapshotter/payload/bin/nydus-snapshotter", "install"]

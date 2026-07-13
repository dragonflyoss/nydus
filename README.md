# Nydus

Nydus is an EROFS-native container image format and runtime, implemented in
Rust. It converts container image layers into chunk-based EROFS filesystems
that support on-demand loading: a container can start after fetching only a
small metadata bootstrap, while file data is pulled from the registry lazily,
in compressed groups, exactly when it is read.

This repository is the Nydus image format v3 implementation. Compared with
earlier Nydus versions it uses native EROFS metadata end to end — the same
bootstrap mounts through FUSE on the host, or directly as EROFS inside a
microVM guest via virtio-pmem.

## Features

- **Single-artifact layers** — each layer is one full blob file
  (`data + bootstrap + blob meta + footer`) named by its SHA256, with an
  optional standalone metadata-only bootstrap.
- **On-demand loading** — file reads map to compressed groups through an O(1)
  logical-address lookup; only the touched groups are fetched, CRC-validated,
  decoded, and cached.
- **Compression and dedup** — zstd-compressed groups independent of chunk
  boundaries; chunk-level BLAKE3 digests deduplicate data within a build.
- **Multiple mount paths** — host FUSE mount (`nydus fuse`), a device-level
  userfaultfd service for microVM virtio-pmem (`nydus uffd`), and an embeddable
  accessor library (`NydusAccessor`) for hypervisors.
- **Registry backend with P2P** — blobs are range-read directly from any OCI
  registry, optionally through a Dragonfly forward proxy or client SDK.
- **Access-trace optimization** — `nydus optimize` records the group access
  order of a real workload and builds an "ondemand" blob that prefetch streams
  first, so cold starts hit warm cache instead of scattered registry reads.
- **Cross-process cache sharing** — concurrent instances on one node share a
  decoded cache directory; a shared readiness bitmap and per-blob prefetch lock
  make N cold starts cost one warmup.
- **Observability** — Prometheus metrics and the on-demand access trace are
  exposed over a Unix-socket apiserver (`/metrics`, `/trace`).

## Components

| Component | Path | Description |
| --- | --- | --- |
| `nydus` | `src/bin/nydus/` | CLI: `build`, `merge`, `check`, `optimize`, `fuse`, and optional `uffd` |
| `nydusify` | `nydusify/` | Go orchestrator that converts, checks, and optimizes whole OCI images against a registry |
| `NydusAccessor` | `src/accessor.rs` | Library API for embedding the image read path (e.g. hypervisor virtio-pmem wiring) without FUSE |

## Quick Start

Build a directory into a nydus layer and mount it:

```bash
# Build: emits ./layer.blob (data + bootstrap + blob meta + footer).
nydus build --blob ./layer.blob /path/to/source-dir

# Mount the blob directly.
nydus fuse --blob ./layer.blob --mountpoint /mnt/nydus

# Inspect it without mounting.
nydus check --blob ./layer.blob
```

Convert a whole OCI image and validate the result (requires root):

```bash
sudo nydusify convert \
  --source docker.io/library/mariadb:latest \
  --target localhost:5000/mariadb-nydus \
  --plain-http

sudo nydusify check \
  --source docker.io/library/mariadb:latest \
  --target localhost:5000/mariadb-nydus \
  --plain-http
```

Mount a converted image lazily from the registry with a YAML storage config
(see [docs/nydus.md](docs/nydus.md#storage-config) and the example
[`config.yaml`](config.yaml)):

```bash
nydus fuse --bootstrap image.boot --config config.yaml --mountpoint /mnt/nydus
```

## Documentation

| Document | Contents |
| --- | --- |
| [docs/nydus.md](docs/nydus.md) | Design document: CLI contract, artifact model, blob meta format, read path, prefetch, optimize pipeline, metrics, accessor API, and `nydusify` |
| [docs/uffd.md](docs/uffd.md) | UFFD service design: flattened device layout, Unix-socket wire protocol, SCM_RIGHTS FD rules, and fault-handling policies for microVM virtio-pmem |
| [docs/erofs.md](docs/erofs.md) | EROFS internals: on-disk format, superblock, inode/NID system, chunk indexes, directory format, and the metadata build pipeline |

## Building from Source

Prerequisites: a Rust toolchain with `cargo`; Go for `nydusify` and the
integration tests.

```bash
# Debug / release CLI binary (written to target/{debug,release}/nydus).
make build
make release

# With the optional UFFD service.
cargo build --release --features cli,uffd

# The nydusify binary.
make nydusify
```

Library embedders can build a minimal surface without FUSE, CLI, or server
dependencies:

```bash
cargo build --no-default-features --features backend-registry
```

## Testing

```bash
# Rust unit tests.
make test

# End-to-end integration tests (requires root and FUSE).
make test-e2e

# UFFD service smoke test.
make test-uffd

# xfstests regression (requires root); fio performance benchmark (requires root and fio).
make test-xfstests
make test-perf
```

Integration tests live under `tests/integration/`. See the `Makefile` for
per-target knobs such as `E2E_TEST=<regex>` to select a single e2e test.

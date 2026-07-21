# Nydus

> [!WARNING]
> This project is under active development. On-disk formats, CLI interfaces
> and APIs may still change without compatibility guarantees — it is not yet
> ready for production use.

Nydus is an EROFS-native container image format and runtime, implemented in
Rust. It converts container image layers into chunk-based EROFS filesystems
that support on-demand loading: a container can start after fetching only a
small metadata bootstrap, while file data is pulled from the registry lazily,
in compressed groups, exactly when it is read.

This repository is the Nydus image format v3 implementation — a ground-up
redesign in Rust. Compared with Nydus v2 (RAFS), v3 brings:

## Features

- **CLI-friendly** — non-core capabilities are removed and binary components
  reduced: one `nydus` binary (`build` / `merge` / `check` / `optimize` /
  `fuse` / `uffd` / `fanotify`) plus the `nydusify` image orchestrator. Each layer is one
  self-contained blob artifact (`data + bootstrap + blob meta + footer`)
  named by its SHA256, with an optional standalone metadata-only bootstrap.
- **Native EROFS format** — a fully standard EROFS layout compatible with
  erofs-utils and kernel mounting; filesystem and chunk metadata are fetched
  in bulk up front via the compact bootstrap, then file data loads on demand.
- **Decoupled dedup and compression units** — `--chunk-size` sets the
  deduplication granularity (BLAKE3) while `--compress-size` sets the
  compression and read unit (zstd, default 4 MiB), no longer tied to file
  chunks: better compression efficiency and less read amplification, with
  CRC32C validation enforced on every read path.
- **On-demand loading** — file reads map to compressed groups through an O(1)
  logical-address lookup; only the touched groups are fetched, validated,
  decoded, and cached.
- **Trace-driven prefetching** — `nydus optimize` turns a workload access
  trace into a compact hot-data "ondemand" blob, converting scattered
  cold-start range reads into a streaming prefetch. Concurrent instances on
  one node share the warmup through a shared cache readiness bitmap and a
  per-blob prefetch lock, so N cold starts cost one warmup.
- **Native Dragonfly P2P support** — registry blobs are range-read directly,
  optionally through a Dragonfly forward proxy or the higher-performance
  client SDK mode talking straight to a scheduler, improving large-scale
  distribution performance.
- **Multiple mount paths, Kata pmem UFFD support** — host FUSE mount
  (`nydus fuse`), a device-level userfaultfd service (`nydus uffd`), a
  fanotify pre-content service (`nydus fanotify`, Linux >= 6.15), and an
  embeddable accessor library (`NydusAccessor`) that serve the image to
  microVM guests as EROFS over virtio-pmem — the target end-state for Kata
  image acceleration in agent sandbox image and snapshot scenarios.
- **Build and FUSE performance** — targets over 3× overall improvement in
  layer build time, memory efficiency, and FUSE performance compared with v2.
- **Observability** — Prometheus metrics and the on-demand access trace are
  exposed over a Unix-socket apiserver (`/metrics`, `/trace`).
- **Ecosystem improvements** — simplified snapshotter capabilities,
  addressing containerd-related issues, and strengthened integration with
  nerdctl, BuildKit, Docker, and related tooling.

## Performance

Cold-start comparison on a real-world 4.04 GB, 52-layer **openclaw** agent container image
(cold registry, cold local cache, single container). **E2E = Pull + Create +
Ready**: image pull, container creation, and the in-container application
reaching its ready log line. For OCI the pull downloads and unpacks every
layer up front; for Nydus it fetches only the metadata bootstrap and file data
is loaded on demand at runtime (that cost shows up inside Ready).

| # | Image format                    | Runtime | Pull size | Pull   | Create | Ready  | E2E       |
| --- | ------------------------------- | ------- | --------- | ------ | ------ | ------ | --------- |
| 1 | OCI                             | runc    | 4.04 GB   | 14.76s | 0.19s  | 5.45s  | 20.40s    |
| 2 | OCI                             | rund    | 4.04 GB   | 14.76s | 1.37s  | 6.49s  | 22.62s    |
| 3 | Nydus v2 (RAFS)                 | runc    | 11.36 MiB | 2.09s  | 0.16s  | 13.46s | 15.71s    |
| 4 | Nydus v2 (RAFS)                 | rund    | 11.36 MiB | 2.09s  | 1.38s  | 14.28s | 17.75s    |
| 5 | Nydus v3                        | rund    | 6.44 MiB  | 1.75s  | 1.53s  | 7.50s  | 10.78s    |
| 6 | Nydus v3 optimized              | rund    | 6.44 MiB  | 1.75s  | 1.47s  | 5.72s  | **8.94s** |
| 7 | Nydus v3 optimized (warm cache) | rund    | —         | —      | 0.79s  | 5.42s  | **6.21s** |

- `runc` is the standard host container runtime; `rund` is a Kata-style
  microVM runtime mounting the image as EROFS over virtio-pmem.
- "Nydus v3 optimized" is the same image after `nydus optimize` rewrote it
  with an access-trace-ordered ondemand blob (see
  [docs/nydus.md](docs/nydus.md#optimize)).
- Row 7 keeps the image and the decoded chunk cache on the node, so no pull
  is needed.
- Against OCI on the same microVM runtime (row 2 vs 6), Nydus v3 optimized
  cuts cold-start E2E from 22.62s to 8.94s (~2.5×), and against Nydus v2
  (row 4 vs 6) from 17.75s to 8.94s (~2×).

### Fanotify vs FUSE

`nydus fanotify` (Linux ≥ 6.15) serves the same registry-backed image through
a kernel EROFS mount instead of a userspace FUSE daemon. Same image, backend,
and cache for both modes; **warm** = page cache hot, **cold-page** = page
cache dropped before every job. All metrics represent the statistically 
aggregated median derived from the standard test-fanotify-perf benchmark suite.

**Conclusion:** Fanotify wins everywhere the kernel read path matters —
metadata ops (stat +23%, readdir 3.4×, xattr ~6×) run on pure kernel EROFS
with no userspace round trip, and sequential reads are 1.9–3.5× faster because
data never copies through userspace. 4K random reads are a wash; the one loss
is concurrent 128K random reads (~18% behind FUSE), where the Fanotify
pre-content mark disables kernel readahead.

| Benchmark | Unit | Fanotify warm | FUSE warm | Fanotify cold-page | FUSE cold-page |
| --- | --- | ---: | ---: | ---: | ---: |
| Sequential read 128K | MiB/s | 6,285 | 1,818 | 5,856 | 1,728 |
| Sequential read 4-job 128K | MiB/s | 10,155 | 5,386 | 9,046 | 5,305 |
| Random read 128K | MiB/s | 1,541 | 1,335 | 1,330 | 1,203 |
| Random read 4-job 128K | MiB/s | 4,280 | 5,206 | 3,802 | 4,720 |
| Random read 4K | IOPS | 60,529 | 61,455 | 12,040 | 12,461 |
| Random read 4K latency | µs | 15.7 | 15.4 | 82.3 | 79.5 |
| Stat | IOPS | 548,389 | 445,512 | 537,990 | 435,645 |
| Stat latency | µs | 1.8 | 2.3 | 1.9 | 2.3 |
| Readdir | IOPS | 159,184 | 46,935 | 154,748 | 46,710 |
| Readdir latency | µs | 6.3 | 21.3 | 6.5 | 21.4 |
| Listxattr | IOPS | 437,168 | 71,446 | 346,836 | 70,597 |
| Listxattr latency | µs | 2.3 | 14.0 | 2.9 | 14.2 |
| Getxattr | IOPS | 401,411 | 70,006 | 400,065 | 70,363 |
| Getxattr latency | µs | 2.5 | 14.3 | 2.5 | 14.2 |
| Readdir + stat (`ls -l`) | IOPS | 99.7 | 84.0 | 99.2 | 83.3 |
| Readdir + stat (`ls -l`) latency | ms/op | 10.0 | 11.9 | 10.1 | 12.0 |
| First 1 MiB cold read | s | — | — | 0.02 | 0.08 |

## Components

| Component        | Path                     | Description                                                                                              |
| ---------------- | ------------------------ | -------------------------------------------------------------------------------------------------------- |
| `nydus`          | `nydus/src/bin/nydus/`         | CLI: `build`, `merge`, `check`, `optimize`, `fuse`, and optional `uffd` / `fanotify`                      |
| `nydusify`       | `nydusify/`              | Go orchestrator that converts, checks, and optimizes whole OCI images against a registry                 |
| `nydus-accessor` | `nydus-accessor/` | Library crate (`NydusAccessor`) for embedding the image read path (e.g. hypervisor virtio-pmem wiring) without FUSE |

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

| Document                       | Contents                                                                                                                                          |
| ------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| [docs/nydus.md](docs/nydus.md) | Design document: CLI contract, artifact model, blob meta format, read path, prefetch, optimize pipeline, metrics, accessor API, and `nydusify`    |
| [docs/uffd.md](docs/uffd.md)   | UFFD service design: flattened device layout, Unix-socket wire protocol, SCM_RIGHTS FD rules, and fault-handling policies for microVM virtio-pmem |
| [docs/erofs.md](docs/erofs.md) | EROFS internals: on-disk format, superblock, inode/NID system, chunk indexes, directory format, and the metadata build pipeline                   |
| [docs/fanotify.md](docs/fanotify.md) | Fanotify pre-content service: multi-device EROFS model, event ABI, event processing, response protocol, service lifecycle, and fail-open behavior on crash |

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

Library embedders should depend on the `nydus-accessor` crate
(`nydus-accessor/`, re-exported by the root `nydus` crate), which
carries the accessor read path without FUSE, CLI, or server dependencies:

```bash
cargo build -p nydus-accessor --features backend-registry

# Validate crates.io packaging (cargo publish dry run).
make crate
```

## Testing

```bash
# Rust unit tests.
make test

# End-to-end integration tests (requires root and FUSE).
make test-e2e

# UFFD service smoke test.
make test-uffd

# Fanotify service smoke test.
make test-fanotify

# xfstests regression (requires root); fio performance benchmark (requires root and fio).
make test-xfstests
make test-perf
```

Integration tests live under `tests/integration/`. See the `Makefile` for
per-target knobs such as `E2E_TEST=<regex>` to select a single e2e test.

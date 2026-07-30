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
  `fuse` / `ublk` / `uffd` / `fanotify`) plus the `nydusify` image orchestrator. Each layer is one
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
  (`nydus fuse`), a read-only ublk block device (`nydus ublk`, Linux >= 6.0)
  that the kernel EROFS driver mounts directly, a device-level userfaultfd
  service (`nydus uffd`), a fanotify pre-content service (`nydus fanotify`,
  Linux >= 6.15), and an embeddable accessor library (`NydusAccessor`) that
  serve the image to microVM guests as EROFS over virtio-pmem — the target
  end-state for Kata image acceleration in agent sandbox image and snapshot
  scenarios.
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

### Block device vs FUSE

`nydus nbd` and `nydus ublk` each serve the same image as a single
read-only block device — NBD through the kernel NBD driver, ublk through
`ublk_drv` (Linux 6.0+) — both mounted as native EROFS. `make test-block-perf`
runs all three modes (FUSE, NBD, ublk) against the same local-backend image
with prefetch off and separate caches: **warm** = page cache hot,
**cold-page** = page cache dropped before every job, **O_DIRECT** = page
cache bypassed on every request (the pure per-request round trip).

**Conclusion:** both block-device modes beat FUSE on warm steady state and
metadata — warm large-block reads run ~2× FUSE (Seq 128K: NBD 26,715 / ublk
26,361 vs FUSE 13,466 MiB/s) with the daemons fully out of the data path
(0.0 s CPU over the warm suite vs 2.2 s for FUSE); readdir is ~1.5× faster
and stat ~15% faster, served by the kernel EROFS driver. NBD and ublk are
within ~2% of each other whenever the page cache is hot — the transport
difference only shows up on cold requests. There ublk is the thinnest: with
O_DIRECT, 4K random costs 11.7 µs (ublk) vs 13.4 µs (FUSE) vs 24.0 µs (NBD),
and sequential 128K direct goes 4,320 / 3,330 / 2,235 MiB/s — io_uring
shared-memory SQE/CQE undercuts both the NBD kernel socket and FUSE's
request/reply, so ublk now wins the cold per-request round trip too. The fill
path is identical by construction (shared accessor and cache format): prewarm
972 / 1,060 / 1,069 MiB/s, 71.1 MiB fetched for the block modes vs 64.0 for
FUSE (readahead policy). FUSE's only remaining win is mount-ready latency:
0.21 s vs ublk 6.42 s, because `nydus ublk` eagerly prepares every blob in
`UblkDevice::new` so the EROFS `mount` never stalls — that same ~6 s of blob
prep shows up in FUSE/NBD's first 1 MiB read (6.18–6.36 s) instead of
mount-ready, so the total cold-start cost is roughly constant across modes.

| Benchmark | Unit | FUSE warm | FUSE cold-page | NBD warm | NBD cold-page | ublk warm | ublk cold-page |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Sequential read 128K | MiB/s | 13,466 | 14,947 | 26,715 | 27,791 | 26,361 | 28,140 |
| Sequential read 4-job 128K | MiB/s | 19,967 | 21,722 | 34,167 | 22,189 | 33,695 | 27,233 |
| Sequential read 4K | MiB/s | 4,980 | 5,158 | 5,831 | 5,702 | 5,757 | 5,943 |
| Sequential read 4-job 4K | MiB/s | 7,771 | 7,783 | 7,410 | 7,573 | 7,380 | 7,548 |
| Random read 128K | MiB/s | 12,841 | 15,368 | 25,752 | 14,748 | 24,982 | 14,222 |
| Random read 4-job 128K | MiB/s | 18,371 | 21,210 | 32,056 | 19,742 | 31,667 | 20,598 |
| Random read 4K | IOPS | 1,059,692 | 862,411 | 1,073,705 | 843,477 | 1,057,331 | 1,022,064 |
| Random read 4K latency | µs | 0.8 | 1.0 | 0.8 | 1.1 | 0.8 | 0.9 |
| Random read 4-job 4K | MiB/s | 6,210 | 5,081 | 6,353 | 4,792 | 6,367 | 5,871 |
| Stat | IOPS | 379,835 | 380,165 | 441,985 | 441,879 | 442,925 | 438,224 |
| Stat latency | µs | 2.6 | 2.6 | 2.3 | 2.3 | 2.3 | 2.3 |
| Readdir | IOPS | 16,850 | 16,826 | 26,125 | 25,187 | 25,051 | 24,718 |
| Readdir latency | µs | 59.3 | 59.4 | 38.3 | 39.7 | 39.9 | 40.5 |
| Sequential read 128K O_DIRECT | MiB/s | — | 3,330 | — | 2,235 | — | 4,320 |
| Random read 4K O_DIRECT | IOPS | — | 72,906 | — | 41,363 | — | 84,229 |
| Random read 4K O_DIRECT latency | µs | — | 13.4 | — | 24.0 | — | 11.7 |
| Daemon CPU over the suite | s | 2.2 | 2.9 | 0.0 | 0.7 | 0.0 | 0.3 |
| Mount ready | s | — | 0.21 | — | 0.21 | — | 6.42 |
| First 1 MiB cold read | s | — | 6.36 | — | 6.18 | — | 0.007 |
| Prewarm (full-file cold fetch) | MiB/s | — | 972 | — | 1,060 | — | 1,069 |
| Data fetched (prewarm) | MiB | — | 64.0 | — | 71.1 | — | 71.1 |

- The First 1 MiB cold read is not a transport cost. FUSE and NBD pay
  ~6.2–6.4 s here because both prepare the blob lazily on first touch (meta
  download + cache-file sizing + digest verification); ublk pays 6.42 s in
  *mount-ready* instead, because `nydus ublk` calls
  `accessor.blob.flat_layout()` in `UblkDevice::new` so EROFS `mount` never
  stalls. The total cold-start cost (mount-ready + first read) is roughly
  constant across modes.
- Cold-page `direct=0` rows largely re-warm during each 20 s job (the target
  file is 64 MiB), so they mostly reflect the same page-cache path difference
  as the warm columns; the O_DIRECT rows are the clean cold-path comparison.

## Components

| Component        | Path                     | Description                                                                                              |
| ---------------- | ------------------------ | -------------------------------------------------------------------------------------------------------- |
| `nydus`          | `nydus/src/bin/nydus/`         | CLI: `build`, `merge`, `check`, `optimize`, `fuse`, and optional `uffd` / `fanotify` / `nbd`              |
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
| [docs/ublk.md](docs/ublk.md)   | ublk block device target: flattened device layout, device parameters, queue model, mmap-based read path, and comparison with the other mount paths |
| [docs/erofs.md](docs/erofs.md) | EROFS internals: on-disk format, superblock, inode/NID system, chunk indexes, directory format, and the metadata build pipeline                   |
| [docs/fanotify.md](docs/fanotify.md) | Fanotify pre-content service: multi-device EROFS model, event ABI, event processing, response protocol, service lifecycle, and fail-open behavior on crash |
| [docs/nbd.md](docs/nbd.md)     | NBD service: flattened block device, kernel socket protocol framing, ioctl session setup, request validation, and mount lifecycle                 |

## Building from Source

Prerequisites: a Rust toolchain with `cargo`; Go for `nydusify` and the
integration tests.

```bash
# Debug / release CLI binary (written to target/{debug,release}/nydus).
make build
make release

# With the optional UFFD service.
cargo build --release --features cli,uffd

# With the optional ublk block device target (needs Linux 6.0+ to run).
cargo build --release --features cli,ublk

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

# ublk block device test (requires root and Linux 6.0+ with ublk_drv).
make test-ublk

# Fanotify service smoke test.
make test-fanotify

# NBD service E2E (requires root and the nbd module);
make test-nbd

# FUSE vs NBD vs ublk benchmark.
make test-block-perf

# xfstests regression (requires root); fio performance benchmark (requires root and fio).
make test-xfstests
make test-perf
```

Integration tests live under `tests/integration/`. See the `Makefile` for
per-target knobs such as `E2E_TEST=<regex>` to select a single e2e test.

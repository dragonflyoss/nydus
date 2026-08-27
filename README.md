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
  self-contained blob artifact (`data + zstd-compressed bootstrap + blob
  meta + footer`) named by its SHA256, with an optional standalone
  metadata-only bootstrap.
- **Native EROFS format** — a fully standard EROFS layout compatible with
  erofs-utils and kernel mounting; filesystem and chunk metadata are fetched
  in bulk up front via the compact bootstrap, then file data loads on demand.
- **Decoupled chunking and compression units** — `--chunk-size` sets the
  file chunk granularity while `--compress-size` sets the compression and
  read unit (zstd, default 4 MiB), no longer tied to file chunks: better
  compression efficiency and less read amplification, with CRC32C
  validation enforced on every read path.
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
  Linux >= 6.15), and an embeddable core library (`NydusCore`) that
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

### Read-path transport comparison (FUSE / NBD / ublk / fileio / fanotify)

The table below compares every serving mode on a REAL application cold
start: all modes mount the SAME locally built image (separate caches), so
the comparison isolates the read transport:

- **OCI (full pull)** — baseline: download the gzip layer from the same
  registry and fully extract it before starting the container (pipelined
  `curl | gunzip | tar -x`, as containerd does), no lazy loading.
- **v2 FUSE** — optional column: the nydus v2 `nydusd` daemon serving the
  same rootfs as a RAFS v6 (zstd) image, enabled by pointing
  `NYDUSFS_BENCH_V2_NYDUSD` and `NYDUSFS_BENCH_V2_IMAGE_BIN` at v2 binaries.
- **FUSE** — every read and metadata call is a userspace round trip through
  the `nydus fuse` daemon.
- **NBD** — kernel EROFS over `/dev/nbdX`; cache misses reach the daemon
  through the NBD socket, metadata is served by the kernel EROFS driver.
- **ublk** — like NBD, but block requests travel through `ublk_drv`'s
  io_uring SQE/CQE shared memory instead of a kernel socket (Linux 6.0+).
- **fileio** — kernel EROFS mounted file-backed over a FUSE export of the
  flattened image; metadata is served by the kernel EROFS driver and only
  backing-file reads reach the daemon (Linux 6.12+).
- **fanotify** — kernel EROFS mount over the cache files; a `FAN_PRE_ACCESS`
  event fills missing ranges, warm reads never leave the kernel
  (Linux ≥ 6.15).

Methodology: this is a REAL Next.js application end-to-end test, not a
synthetic fio run. The image is a production `next build` of
`create-next-app` on `node:20` (1.6 GiB rootfs, ~35k files), served from a
local OCI registry (`registry:2`); extra network latency is injected on the
registry traffic with `tc netem` to emulate remote registries. Per run the
nydus cache and the page cache are wiped, the image is mounted (nydus +
overlayfs), and the container is started with `runc` running `npm start`.
The reported time is mount start until the FIRST successful HTTP 200 from
the Next.js server — the moment the service is actually usable. Values are
the mean of 2 runs; run-to-run spread is < 5%.

<!-- Next.js cold-start e2e, 2-run means. Rebuild the harness per
     docs: local registry:2 + tc netem on port 5000; v2 column needs the
     v2 nydusd/nydus-image binaries. -->

| Serving mode | Image size | RTT ≈ 0 | RTT +30 ms | RTT +50 ms | Data fetched |
| --- | ---: | ---: | ---: | ---: | ---: |
| v2 FUSE | 500 MiB | 1.72 s | 5.51 s | 8.64 s | 197 MiB |
| FUSE | 465 MiB | 1.44 s | 3.48 s | 4.90 s | 230 MiB |
| NBD | 465 MiB | 1.15 s | 3.28 s | 4.77 s | 231 MiB |
| ublk | 465 MiB | 1.04 s | 3.09 s | 4.62 s | 231 MiB |
| fileio | 465 MiB | 1.17 s | 3.21 s | 4.83 s | 230 MiB |
| fanotify | 465 MiB | 1.10 s | 3.20 s | 4.60 s | 230 MiB |
| FUSE + optimize | 521 MiB | 0.92 s | 1.56 s | 1.75 s | 230 MiB |
| NBD + optimize | 521 MiB | 0.72 s | 1.25 s | 1.67 s | 230 MiB |
| ublk + optimize | 521 MiB | 0.86 s | 1.14 s | 1.45 s | 230 MiB |
| fileio + optimize | 521 MiB | 0.72 s | 1.18 s | 1.51 s | 230 MiB |
| fanotify + optimize | 521 MiB | **0.59 s** | **1.08 s** | **1.38 s** | 230 MiB |

- Measured on Ubuntu 24.04 (arm64), Linux 7.0.0; image built with 1 MiB
  chunks, 4 MiB block groups, zstd. The v2 row is the same rootfs as a
  RAFS v6 zstd image served by the v2 `nydusd` from the same registry.
  All rows are 2-run means from one session.
- The "+ optimize" rows mount the same image after `nydus optimize` rewrote
  it from a recorded boot trace: mounts stream the 56 MiB hot-data
  "ondemand" blob over ONE connection (prefetch scope `ondemand`) instead
  of paying a round trip per cache miss, which makes ready time nearly
  RTT-independent. The stored image grows by that ondemand blob; the rest
  of the working set still loads on demand.
- Image size counts what a registry transfer needs: the OCI row is the
  gzip tar layer; the nydus rows are the full blob (zstd data plus the
  zstd-compressed embedded bootstrap) and the gzipped merged bootstrap
  (v2 bootstrap 7.5 MiB → 2.6 MiB gzipped, v3 bootstrap 21.7 MiB →
  0.8 MiB gzipped). The v3 image is 10% below the OCI layer and 7%
  below v2 for the same rootfs.
- Every v3 mode beats v2 at every latency point: 1.6× at zero RTT and
  1.8× at +50 ms RTT even without optimize. With optimize, v3 reaches
  ready 6× faster than v2 and the OCI full pull at +50 ms (1.4 s vs
  8.6 s) and 14× faster than OCI at zero RTT.
- The OCI row barely moves with RTT because a full pull is a single
  bandwidth-bound stream dominated by gunzip + untar of the whole layer;
  it boots fast once extracted but pays all 517 MiB on every cold start.
  Notably, v2 FUSE at +50 ms (8.64 s) is already no faster than the full
  pull — its per-chunk round trips eat the entire lazy-loading win, while
  v3's grouped fetches (and the optimize stream) keep it well ahead.
- The gap grows with registry latency because v3 fetches data in 4 MiB
  block groups — roughly a third of the HTTP round trips v2 needs — even
  though it transfers more bytes (230 vs 197 MiB); on latency-bound paths
  request count dominates bytes.
- The kernel-EROFS modes (NBD/ublk/fileio/fanotify) serve all metadata
  in-kernel; on metadata-heavy workloads (full-tree scans) they extend the
  lead over v2 FUSE to 2–3×.

### Image build performance (v2 vs v3)

Building the Linux kernel source tree (1.8 GiB, ~95.8k files, warm page
cache) into an image, measured with `/usr/bin/time -v`, 3 runs each:

| Builder | Wall time | Peak RSS | Data blob | Bootstrap (gzip) | Total transfer |
| --- | ---: | ---: | ---: | ---: | ---: |
| v2 `nydus-image create` (RAFS v6, zstd) | 5.6–6.1 s | 170 MiB | 298 MiB | 7.5 MiB | 306 MiB |
| v3 `nydus build` (zstd) | **1.7–1.8 s** | **82 MiB** | **236 MiB** | **1.9 MiB** | **238 MiB** |

- v3 builds 3.3× faster than v2: source reads stay on the produce thread
  while per-block-group crc32 + zstd run on a small background pipeline
  drained in submission order, so the output remains byte-for-byte
  deterministic.
- v3 output is 22% smaller end to end — the full blob stores its embedded
  bootstrap as one zstd frame — and the metadata bootstrap compresses 4×
  smaller than v2's (1.9 vs 7.5 MiB gzipped).
- Peak memory is 52% lower than v2. The build is streaming end to end:
  read buffers are recycled, the encode pipeline is bounded to a couple of
  in-flight block groups, the bootstrap is rendered in place inside the
  layout buffer (no assembly copy), the standalone bootstrap is patched
  from the embedded one instead of re-rendered, and the inode tree is
  freed as soon as rendering finishes.

### Whole-image conversion (`nydusify convert`, v2 vs v3)

Converting `gitlab/gitlab-ce` (5.38 GB docker size, 9 layers, ~440k
files) between two local registries (pull from one, push to the other,
the push registry recreated before every run), cold page cache. Memory is
the peak of the summed RSS of the whole process tree:

| Converter | Wall time | Peak memory (tree) | Output image |
| --- | ---: | ---: | ---: |
| v2 nydusify (RAFS v6, zstd) | 34.1–34.3 s | ~330 MiB | 1319 MiB |
| v3 nydusify (zstd) | **29.7–34.6 s** | **~130 MiB** | **1275 MiB** |

- The source OCI image is 1333 MiB of gzip layers; v3's output is 4%
  smaller than the source and 3% smaller than v2's. Each layer is a
  self-contained full blob whose embedded bootstrap is stored as one
  zstd frame — only merge, `check`, and single-blob mounts decode it,
  so the runtime read path (merged bootstrap + blob meta sidecar) is
  untouched.
- v3 converts layers with a bounded worker pool and one shared builder,
  so its memory stays flat as images grow layers; v2 spawns one
  `nydus-image` per layer in parallel, so its peak scales with the layer
  count. Layer blobs are uploaded as soon as each is built, overlapping
  the remaining conversions.
- `nydus merge` (the bootstrap-merging step) never materialises the
  merged tree: each directory's entries are k-way merged across the
  layer bootstraps on demand while flattening, and the bootstrap is
  stream-rendered; merging the 440k-inode gitlab tree peaks at ~107 MiB
  in 0.1 s.

Output image size across payload shapes (manifest layer totals):

| Image | Source (OCI gzip) | v2 output | v3 output |
| --- | ---: | ---: | ---: |
| `continuumio/anaconda3` (2 layers, Python distro) | 1067 MiB | 1123 MiB | **965 MiB** (-10% / -14%) |
| `n8nio/n8n` (12 layers, node_modules-dense) | 359 MiB | 419 MiB | **320 MiB** (-11% / -24%) |

- The gap widens on small-file-heavy payloads: v3's 4 MiB block groups
  compress the small-file stream far better than v2's 1 MiB chunks, and
  the per-layer embedded bootstraps (108 MiB of raw EROFS metadata on
  n8n's largest layer) shrink ~20× as zstd frames. v2 comes out larger
  than the OCI source on both images; v3 beats the source on both. v3
  also converts with a fraction of v2's peak process-tree memory
  (anaconda3: 199 vs 449 MiB, n8n: 227 vs 523 MiB).

## Components

| Component         | Path               | Description                                                                                               |
| ----------------- | ------------------ | --------------------------------------------------------------------------------------------------------- |
| `nydus`           | `nydus/`           | Mount services (`fuse`, `fanotify`, `nbd`, `ublk`, `uffd`), the build/merge/check/optimize pipelines, and the CLI binary |
| `nydus-core`      | `nydus-core/`      | Image runtime library (`NydusCore`, `ErofsReader`) for embedding the read path (e.g. hypervisor virtio-pmem wiring) without FUSE |
| `nydus-config`    | `nydus-config/`    | YAML config loading                                                                                        |
| `nydus-storage`   | `nydus-storage/`   | Local blob cache, prefetch, and access tracing (data plane, `io::Result` only)                             |
| `nydus-backend`   | `nydus-backend/`   | Blob sources: OCI registry, local directory, Dragonfly P2P (data plane, `io::Result` only)                 |
| `nydus-format`    | `nydus-format/`    | On-disk format definitions: EROFS structures and the nydus blob format                                     |
| `nydus-error`     | `nydus-error/`     | Control-plane error contract (`Error`, `report()`, `Context`)                                              |
| `nydus-telemetry` | `nydus-telemetry/` | Metrics and logging setup                                                                                  |
| `nydusify`        | `nydusify/`        | Go orchestrator that converts, checks, and optimizes whole OCI images against a registry                   |

See [docs/nydus.md](docs/nydus.md#crate-architecture) for the dependency
graph and the data-plane/control-plane split the crate boundaries enforce.

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
[`config/registry.example.yaml`](config/registry.example.yaml)):

```bash
nydus fuse --bootstrap image.boot --config config/registry.example.yaml --mountpoint /mnt/nydus
```

## Documentation

| Document                       | Contents                                                                                                                                          |
| ------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| [docs/nydus.md](docs/nydus.md) | Design document: CLI contract, artifact model, blob meta format, read path, prefetch, optimize pipeline, metrics, core API, and `nydusify`    |
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

Library embedders should depend on the `nydus-core` crate
(`nydus-core/`), which carries the core read path without FUSE, CLI, or
server dependencies:

```bash
cargo build -p nydus-core

# With the OCI registry backend enabled.
cargo build -p nydus-core --features nydus-backend/backend-registry

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

# Unified cold-start performance benchmark: FUSE / NBD / ublk / fanotify
# (requires root and fio; unavailable modes are skipped individually).
make test-bench

# xfstests regression (requires root).
make test-xfstests
```

Integration tests live under `tests/integration/`. See the `Makefile` for
per-target knobs such as `E2E_TEST=<regex>` to select a single e2e test.

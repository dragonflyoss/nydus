# Nydus

> [!NOTE]
> Looking for Nydus v2 (RAFS, `nydusd` / `nydus-image`)? It lives on the
> [`master`](https://github.com/dragonflyoss/nydus/tree/master) branch.
> This branch is Nydus v3, a different image format: v3 does not read v2
> (RAFS v5/v6) images.

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
- **Content-defined chunk groups, runtime fetch size** — `--chunk-size`
  (default 2 MiB) sets the file chunk granularity; chunk groups are
  compressed and verified as a unit (zstd or LZ4, CRC32C on each decode,
  optional BLAKE3 verification per chunk group). `--chunk-group-minimum-size` (default 2 MiB,
  independent of the file chunk size) is the least any group but a blob's last spans:
  a chunk at or above it is a group of its own, so its compressed bytes
  are one frame a content-addressed cache can serve by digest, while
  smaller chunks, including full chunks below that minimum, are packed
  together into groups of one to four times it (the final group may be smaller).
  Content-defined boundaries help near-identical images share packs,
  without guaranteeing resynchronisation; how much one on-demand read
  covers is the daemon's `storage.fetch_size` (default 2 MiB of compressed
  bytes), tuned per deployment without rebuilding the image.
- **On-demand loading** — file reads map to compressed groups through an O(1)
  logical-address lookup; missing groups and optional fetch-window neighbors
  are fetched, validated, decoded, and cached.
- **Extensible blob metadata** — a 24-byte header followed by ChunkGroupTable,
  ChunkLengthTable, ChunkGroupIndexTable, and optional ChunkGroupDigestTable and
  ChunkGroupRedirectTable, each with its own header; compat and incompat feature bits
  replace a version field, so newer tables and fields stay readable by older
  readers. Every chunk has a four-byte length; a mapped direct lookup table
  needs no auxiliary runtime index. Images from older experimental layouts
  must be rebuilt.
- **Ondemand blob prefetching** — `nydus optimize` turns a workload's ondemand
  record into a compact hot-data "ondemand" blob of byte-exact chunk group
  copies, converting scattered cold-start range reads into one streaming
  prefetch that lands in the source blobs' caches. Concurrent instances on
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
- **Observability** — Prometheus metrics and the ondemand record are
  exposed over a Unix-socket apiserver (`/metrics`, `/trace`).
- **Ecosystem improvements** — simplified snapshotter capabilities,
  addressing containerd-related issues, and strengthened integration with
  nerdctl, BuildKit, Docker, and related tooling.

## Performance

### Global cache deduplication with content-defined chunk groups

Data to store for the **SWE-rebench-v2** image set, 120k+ images:

| Method                                               | Data size   | Deduplication rate |
| ---------------------------------------------------- | ----------- | ------------------ |
| Image total, no deduplication                        | 71.7 TiB    | —                  |
| OCI, deduplication by layer                          | 20.8 TiB    | 71%                |
| Nydus v3 with a cache cluster deduplicating globally | about 3 TiB | 96%                |

OCI and Nydus v2 deduplicate whole layers only (Nydus v2 chunks are too small
to deduplicate at an affordable cost): one changed file makes the whole layer
different. Nydus v3 cuts layer data into chunk groups with content-defined
boundaries (2 MiB and up by default). A cache such as Dragonfly can cache by
chunk group digest, so identical data across layers and images is stored
once. This helps most on a huge image set like SWE Bench: it saves cache
storage and raises the cache hit rate considerably.

### End-to-end startup of training and inference images

Nydus starts a container after fetching only a small metadata bootstrap from
the network; file data is loaded on demand at runtime. In the Dragonfly
columns data comes from the P2P cache and never goes back to the registry.
The ondemand blob is the hot-data layer `nydus optimize` builds from the
access record of a container start. It is prefetched in one stream at
startup, which avoids most scattered on-demand requests and speeds up the
cold start: the end-to-end time comes close to that of an OCI image already
cached locally.

| Metric             | Image                                        | Nydus v2 | Nydus v3 | Nydus v2 + Dragonfly | Nydus v3 + Dragonfly | Nydus v3 + Dragonfly (ondemand blob) |
| ------------------ | -------------------------------------------- | -------- | -------- | -------------------- | -------------------- | ------------------------------------ |
| End-to-end startup | PyTorch (`nvcr.io/nvidia/pytorch:24.10-py3`) | 41.2s    | 24.6s    | 18.7s                | 14.9s                | 9.4s                                 |

### Image build performance

Time, memory and output size of converting an OCI image into a Nydus image
(`nydusify convert`) and of building one layer (`nydus build`). Nydus v3
builds as a stream end to end, reads source files in parallel with
compression and checksumming, and is tuned for memory and CPU cost. Small
files are packed into shared chunk groups and compressed together, and the
bootstrap is stored as one zstd frame, so both data and metadata are smaller.

| Metric                              | Image                                        | Nydus v2  | Nydus v3  | Improvement |
| ----------------------------------- | -------------------------------------------- | --------- | --------- | ----------- |
| Conversion time                     | PyTorch (`nvcr.io/nvidia/pytorch:24.10-py3`) | 102s      | 61s       | 40%         |
| Conversion time P99                 | SWE-rebench-v2 (120k+ images)                | 25.03s    | 15.09s    | 39%         |
| Raw bootstrap size P99              | SWE-rebench-v2 (120k+ images)                | 26.40 MiB | 19.18 MiB | 27%         |
| Compressed bootstrap layer size P99 | SWE-rebench-v2 (120k+ images)                | 10.01 MiB | 3.46 MiB  | 65%         |
| Peak conversion memory              | `gitlab/gitlab-ce` (5.38 GB, 9 layers)       | 330 MiB   | 130 MiB   | 61%         |
| Converted image size                | `n8nio/n8n` (OCI 359 MiB)                    | 419 MiB   | 320 MiB   | 24%         |
| Single-layer build time             | Linux kernel source (1.8 GiB, 96k files)     | 5.6–6.1s  | 1.7–1.8s  | 70%         |
| Peak single-layer build memory      | Linux kernel source (1.8 GiB, 96k files)     | 170 MiB   | 82 MiB    | 52%         |

### Images on a block-device cache disk

When images are kept on a block device such as an EBS volume, data is
distributed by the EBS storage network instead of lazy loading from a
registry. Inside the containerd snapshotter, OCI layers are converted
concurrently, as streams, into Nydus (EROFS LZ4) blobs written straight to
the disk. This replaces the containerd pull + unpack into an image directory,
and at runtime the kernel EROFS driver mounts the blobs directly.

Pulling the wordpress image onto an EBS volume: containerd writes each OCI
layer twice, the compressed layer and the unpacked file tree, and downloads
and unpacks a layer serially. Nydus converts the layers concurrently while
they download and stores one LZ4-compressed copy. It writes less, so the
filesystem sync is faster too:

| Metric                                                | OCI pull + unpack | Nydus LZ4 streamed to disk | Gain     |
| ----------------------------------------------------- | ----------------- | -------------------------- | -------- |
| Unpack / convert time                                 | 12s               | 2.0s                       | 6×       |
| Ready (the container can serve)                       | 13.0s             | 2.0s                       | 6.5×     |
| Settle (synced to disk, an EBS snapshot can be taken) | 31.0s             | 9.0s                       | 3.4×     |
| EBS usage                                             | 1171 MB           | 436 MB                     | 63% less |

EBS deduplication of 2 MiB blocks: some EBS storage backends deduplicate
fixed 2 MiB blocks, so identical data must land on the same block boundaries
to hit. Nydus aligns the files of 2 MiB and more to 2 MiB inside the blob,
and XFS (su=2m + extsize) keeps the blob aligned to 2 MiB on the disk too:

| Scenario                                             | OCI deduplication rate | Nydus deduplication rate |
| ---------------------------------------------------- | ---------------------- | ------------------------ |
| wordpress incremental build (24 of 25 layers reused) | 46.6%                  | 95.6%                    |
| node adjacent patch versions (0 of 8 layers reused)  | 32.9%                  | 78.1%                    |

- Each new wordpress version takes 24 MB of new space instead of 404 MB. On a
  full rebuild both formats deduplicate less than 3%.
- The alignment costs 42 MB more per version (504 → 546 MB). The writable
  layer is not aligned and takes no extra space, and performance matches
  ext4.

Runtime: a 9-layer image with 2080 MiB of file content, a 2c4g Pod, one
process reading every file of the image sequentially. To read the whole
image, Nydus v3 reads 37% of the bytes OCI reads from EBS, in 15% of the read
IOs, and the cache disk usage drops from 2.8 GiB for OCI to 1.4 GiB (850 MiB
with further optimization):

| Metric                                               | OCI                                              | Nydus                                       | Gain     |
| ---------------------------------------------------- | ------------------------------------------------ | ------------------------------------------- | -------- |
| End-to-end time (Pod creation to the last file read) | 75.4s                                            | 25.1s                                       | 3.0×     |
| Of which: startup                                    | 3.44s                                            | 3.68s                                       | —        |
| Of which: reading all files                          | 71.9s                                            | 21.5s                                       | 3.3×     |
| EBS read IOs                                         | 69,487                                           | 10,607                                      | 6.6×     |
| EBS read IO bytes                                    | 2265 MiB                                         | 846 MiB                                     | 2.7×     |
| Average time per read                                | 1.35 ms                                          | 2.35 ms                                     | —        |
| Average size per read                                | 33.4 KiB                                         | 81.7 KiB                                    | —        |
| Cache disk usage                                     | 2851 MiB (gzip layers 594 + unpacked files 2256) | 1444 MiB (gzip layers 594 + Nydus data 849) | 49% less |

- A Nydus read is larger and slower, but there are 85% fewer of them, so the
  total time is shorter. Startup is about 0.2s slower, spent mounting EROFS.
- The test enabled neither XFS, 2 MiB alignment nor stream conversion, and
  both formats kept the 594 MiB of original gzip layers. With stream
  conversion the Nydus cache disk usage drops to about 850 MiB.
- The gap is smaller for a workload that starts an application, where the
  CPU time of the application itself weighs more: openclaw (a 31-layer image,
  runc on the local host with a simulated warm EBS volume at 1 ms per IO)
  starts end to end in 4.43s instead of 8.98s (2.0×), with 2182 read IOs
  instead of 10844 (5.0×).

### OCI vs Nydus v2 FUSE + VirtioFS vs Nydus v3 + PMEM + UFFD

Cold start of three image solutions under a secure container. OCI downloads
and unpacks every layer before the start. Nydus pulls only the metadata
bootstrap and loads file data on demand at runtime, a cost counted in Ready.
v2 serves the filesystem to the guest through FUSE + VirtioFS; v3 serves the
image to the guest as an EROFS device over virtio-pmem, which `nydus uffd`
fills on demand at page faults. "optimize" means building the hot-data layer
from the access record of a start and prefetching it as a stream.

The openclaw image (4.04 GB, 52 layers), cold start of a Kata secure
container, E2E = Pull + Create + Ready:

| Solution                                           | Pull size | Pull   | Create | Ready  | E2E    |
| -------------------------------------------------- | --------- | ------ | ------ | ------ | ------ |
| OCI                                                | 4.04 GB   | 14.76s | 1.37s  | 6.49s  | 22.62s |
| Nydus v2 FUSE + VirtioFS                           | 11.36 MiB | 2.09s  | 1.38s  | 14.28s | 17.75s |
| Nydus v3 + PMEM + UFFD                             | 6.44 MiB  | 1.75s  | 1.53s  | 7.50s  | 10.78s |
| Nydus v3 + PMEM + UFFD (optimize)                  | 6.44 MiB  | 1.75s  | 1.47s  | 5.72s  | 8.94s  |
| Nydus v3 + PMEM + UFFD (optimize, local cache hit) | —         | —      | 0.79s  | 5.42s  | 6.21s  |

- The cold-start E2E of Nydus v3 (optimize) is 1/2.5 of the OCI one and 1/2
  of the Nydus v2 one.

### FUSE / NBD / ublk / fileio / fanotify

Comparison of the Nydus v3 read paths: the same image, only the mount mode
differs. With FUSE every read and metadata operation goes through the
userspace daemon. In the other four the kernel EROFS driver mounts the image
and serves the metadata, and only the data requests that miss the cache reach
the daemon. They differ in the request channel:

- NBD: a kernel socket.
- ublk: io_uring shared memory (Linux 6.0+).
- fileio: an EROFS file-backed mount over the image file a FUSE export serves
  (Linux 6.12+).
- fanotify: EROFS mounts the cache files directly, a pre-content event fills
  the missing data, and cached reads never leave the kernel (Linux 6.15+).

Time from cold start to the first HTTP 200 of a Next.js application (image
`node:20`, 1.6 GiB rootfs, 35k files), by extra RTT to the registry. The last
three columns are after `nydus optimize`:

| Mode          | RTT ≈ 0 | +30ms | +50ms | optimize RTT ≈ 0 | optimize +30ms | optimize +50ms |
| ------------- | ------- | ----- | ----- | ---------------- | -------------- | -------------- |
| Nydus v2 FUSE | 1.72s   | 5.51s | 8.64s | —                | —              | —              |
| FUSE          | 1.44s   | 3.48s | 4.90s | 0.92s            | 1.56s          | 1.75s          |
| NBD           | 1.15s   | 3.28s | 4.77s | 0.72s            | 1.25s          | 1.67s          |
| ublk          | 1.04s   | 3.09s | 4.62s | 0.86s            | 1.14s          | 1.45s          |
| fileio        | 1.17s   | 3.21s | 4.83s | 0.72s            | 1.18s          | 1.51s          |
| fanotify      | 1.10s   | 3.20s | 4.60s | 0.59s            | 1.08s          | 1.38s          |

- Every v3 mode is faster than v2 FUSE: up to 1.6× at RTT ≈ 0 and about 1.8×
  at +50ms, and up to 6× at +50ms after optimize.
- The four kernel EROFS modes are faster than FUSE at every point; fanotify
  with optimize is the fastest.

## Components

| Component         | Path               | Description                                                                                                                      |
| ----------------- | ------------------ | -------------------------------------------------------------------------------------------------------------------------------- |
| `nydus`           | `nydus/`           | Mount services (`fuse`, `fanotify`, `nbd`, `ublk`, `uffd`), the build/merge/check/optimize pipelines, and the CLI binary         |
| `nydus-core`      | `nydus-core/`      | Image runtime library (`NydusCore`, `ErofsReader`) for embedding the read path (e.g. hypervisor virtio-pmem wiring) without FUSE |
| `nydus-config`    | `nydus-config/`    | YAML config loading                                                                                                              |
| `nydus-storage`   | `nydus-storage/`   | Local blob cache, prefetch, and access tracing (data plane, `io::Result` only)                                                   |
| `nydus-backend`   | `nydus-backend/`   | Blob sources: OCI registry, local directory, Dragonfly P2P (data plane, `io::Result` only)                                       |
| `nydus-format`    | `nydus-format/`    | On-disk format definitions: EROFS structures and the nydus blob format                                                           |
| `nydus-error`     | `nydus-error/`     | Control-plane error contract (`Error`, `report()`, `Context`)                                                                    |
| `nydus-telemetry` | `nydus-telemetry/` | Metrics and logging setup                                                                                                        |
| `nydusify`        | `nydusify/`        | Go orchestrator that converts, checks, and optimizes whole OCI images against a registry                                         |

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

Optional `--apiserver unix:///run/nydus/api.sock` enables metrics, tracing, and
hot upgrade; independent `--supervisor-socket unix:///run/nydus/supervisor/image.sock` enables
crash failover. See [FUSE hot upgrade and crash failover](docs/upgrade.md).

## Documentation

| Document                             | Contents                                                                                                                                                   |
| ------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [docs/nydus.md](docs/nydus.md)       | Design document: CLI contract, artifact model, blob meta format, read path, prefetch, optimize pipeline, metrics, core API, and `nydusify`                 |
| [docs/upgrade.md](docs/upgrade.md) | FUSE hot upgrade and crash failover: usage, startup selection, ownership, and the holder protocol |
| [docs/uffd.md](docs/uffd.md)         | UFFD service design: flattened device layout, Unix-socket wire protocol, SCM_RIGHTS FD rules, and fault-handling policies for microVM virtio-pmem          |
| [docs/ublk.md](docs/ublk.md)         | ublk block device target: flattened device layout, device parameters, queue model, mmap-based read path, and comparison with the other mount paths         |
| [docs/erofs.md](docs/erofs.md)       | EROFS internals: on-disk format, superblock, inode/NID system, chunk indexes, directory format, and the metadata build pipeline                            |
| [docs/fanotify.md](docs/fanotify.md) | Fanotify pre-content service: multi-device EROFS model, event ABI, event processing, response protocol, service lifecycle, and fail-open behavior on crash |
| [docs/nbd.md](docs/nbd.md)           | NBD service: flattened block device, kernel socket protocol framing, ioctl session setup, request validation, and mount lifecycle                          |

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
make build-nydusify
```

Library embedders should depend on the `nydus-core` crate
(`nydus-core/`), which carries the core read path without FUSE, CLI, or
server dependencies:

```bash
cargo build -p nydus-core

# With the OCI registry backend enabled.
cargo build -p nydus-core --features nydus-backend/registry

# Validate crates.io packaging.
make crate
```

## Testing

```bash
# Rust unit tests.
make test

# End-to-end suites (root via sudo, FUSE; see tests/e2e/README.md). Each
# directory under tests/e2e is a suite; CI=1 turns missing preconditions
# into failures, as GitHub Actions does.
make e2e PKG=./conformance/...
make e2e-ga                      # every GA suite but dragonfly
make e2e-dragonfly               # needs upstream Kind/Helm setup; see tests/e2e/README.md
make e2e-experimental            # nbd, fanotify, ublk, uffd

# FUSE hot upgrade, rollback, crash failover, no-API operation and live-owner exclusion.
make e2e-continuity
# Optional separate, hot-upgrade-capable predecessor binary:
NYDUS_E2E_FUSE_PREDECESSOR=/abs/path/to/nydus make e2e-continuity

# Unified cold-start performance benchmark: FUSE / fileio / NBD / ublk /
# fanotify (requires root and fio; unavailable modes are left out).
make benchmark
```

End-to-end suites live under `tests/e2e/`. See the `Makefile` for
per-target knobs such as `E2E_RUN=<regex>` to select tests.

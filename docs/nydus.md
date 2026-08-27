# Nydus Design

## Status

This document describes the current nydus artifact model, blob meta format and
runtime read path.

The user-facing commands are:

- `nydus build`
- `nydus check`
- `nydus merge`
- `nydus optimize`
- `nydus fuse`
- `nydus ublk` (with the optional `ublk` feature)
- `nydus uffd` (with the optional `uffd` feature)
- `nydus fanotify` (with the optional `fanotify` feature)
- `nydus nbd` (with the optional `nbd` feature)

The merge implementation focuses on metadata overlay, blob-id preservation and
OCI whiteout handling. The build and runtime paths use the embedded blob meta
region as the canonical map from logical EROFS external-device addresses to
encoded ranges in the stored data region.

## Goals

- Use one user-visible `blob` artifact as the primary layer output.
- Allow an optional standalone `bootstrap` artifact for remote metadata-only use.
- Make `fuse` support either a direct blob path or a bootstrap plus blob-dir.
- Persist a stable blob identifier inside bootstrap metadata.
- Keep EROFS file chunk indexes logical and map a block to its compression block group
	in O(1) via constant-sized block groups.
- Support compressed blob data while preserving a plain decoded cache artifact
	for EROFS compatibility and repeated reads.

## Non-goals

- Preserve on-disk compatibility with earlier Nydus image formats (RAFS v5/v6).
- Introduce cross-layer global deduplication beyond the current single-build dedup.
- Rework the full EROFS on-disk layout to match every upstream variant.

## Crate Architecture

The Rust side is a workspace of eight crates. The split exists to encode
one distinction in the crate graph itself: the **data plane** (moving and
caching blob bytes) versus the **control plane** (assembly, configuration,
services). Data-plane crates return `io::Result` end-to-end so the original
`errno` survives all the way to the kernel; control-plane crates use the
structured `nydus_error::Error`. Because `nydus-backend` and `nydus-storage`
do not depend on `nydus-error`, reaching for the wrong error type on the
data plane is a compile error, not a review comment.

```
                        ┌───────────┐
                        │   nydus   │  services + CLI (binary)
                        └─────┬─────┘
                              │
                        ┌─────▼─────┐
                        │nydus-core │  image runtime facade
                        └─┬───┬───┬─┘
              ┌───────────┘   │   └───────────┐
        ┌─────▼──────┐ ┌──────▼──────┐        │
        │nydus-config│ │nydus-storage│        │
        └──┬──────┬──┘ └──┬───────┬──┘        │
           │      │       │       │           │
           │  ┌───▼───────▼───┐   │           │
           │  │ nydus-backend │   │           │
           │  └───┬───────┬───┘   │           │
     ┌─────▼───┐  │   ┌───▼───────▼───┐       │
     │  nydus- │  │   │nydus-telemetry│       │
     │  error  │  │   └───────────────┘       │
     └────┬────┘  │                           │
          │  ┌────▼─────────────────────────┐ │
          └─▶│         nydus-format         │◀┘
             └──────────────────────────────┘
```

Dependencies point strictly downward; the arrows above are the complete
inter-crate dependency set, enforced by each `Cargo.toml`.

| Crate | Plane | Role | Errors |
| ----- | ----- | ---- | ------ |
| `nydus` | boundary | The five mount services (`fuse/`, `fanotify/`, `nbd/`, `ublk/`, `uffd/`), the build/optimize/check/export pipelines, and the CLI binary | each service's `core.rs` converts `Error` ↔ `errno` explicitly |
| `nydus-core` | both | Image runtime facade: `NydusCore`, `ErofsReader`, path walk (`entry`), flattened device view (`extent`), blob table (`blob`) | `Error` for assembly/queries, `io::Result` on the read path |
| `nydus-config` | control | Loads the YAML config file and converts it into the plain config structs owned by the crates below | `Error` |
| `nydus-storage` | data | Local cache and reuse: `LocalBlobCache` (block group decode, CRC, on-demand fill), `BlobCaches`, block group ready-bitmaps, prefetch, access tracing | `io::Result` only |
| `nydus-backend` | data | Where bytes come from: `Registry` (OCI distribution), `Local` (directory), Dragonfly P2P via SDK or HTTP proxy | `io::Result` only |
| `nydus-format` | neutral | Single source of truth for on-disk layouts: `erofs/` structures, the nydus blob format (`blob/`), byte-level utils | own `FormatError`, wrapped by each plane |
| `nydus-error` | control | The error contract: `Error`, chain-printing `report()`, `Context` | — |
| `nydus-telemetry` | leaf | Metrics (including `ReadKind`) and feature-gated logging setup; a leaf so every layer can record without cycles | — |

`nydus-format` stays neutral by mirroring the error shape: its `FormatError`
carries the same context-chain design, the data plane wraps it into
`io::Error`, and the control plane converts it via
`From<FormatError> for Error` with the message text preserved verbatim.

Naming follows a gradient that tells the reader which layer a type belongs
to: `Erofs*` / `Blob*` names (in `nydus-format`) are zero-copy on-disk
views, `Raw*` names are minimally parsed lifetime-free forms, and bare
names (`BlobInfo`, `DirEntry`) are the owned user-facing API.

Each mount service in the `nydus` crate follows the same file pattern:
`core.rs` (kernel-independent logic and the `Error` ↔ `errno` boundary),
`proto.rs` (wire/ABI encoding), `service.rs` (event loop), and `mount.rs`.

`nydusify` (Go, outside the workspace) converts, checks, and optimizes
whole OCI images against a registry. It shares no code with the Rust side;
the image format and the registry protocol are the only contracts between
them.

## CLI Contract

### Image layouts

A nydus image exists in exactly two on-disk layouts, and the `--blob`,
`--blob-dir` and `--bootstrap` flags map onto them across every subcommand:

- **Single-file image (`--blob`)** — one self-contained full blob:
	`[data | bootstrap | blob meta | footer]`. Path-addressed: the consumer
	opens the file you name. Used for transport, piping (the path may be a
	FIFO), inspection (`nydus check --blob`) and export (`nydus export`).
- **Store layout (`--bootstrap` + `--blob-dir`)** — a standalone bootstrap
	file plus a content-addressed store directory. Each blob in the store is a
	full blob named by its own SHA256; the bootstrap is the entry point whose
	EROFS device table records those SHA256s. Mounts resolve blobs as
	`bootstrap device slot -> digest -> <store>/<digest>`. Because names are
	digests, writes are atomic (temp file + rename), identical blobs
	deduplicate, and many images can share one store. A store can be populated
	before its bootstrap exists: per-layer builds write blobs first and
	`nydus merge` derives the merged bootstrap afterwards.

### Build

`nydus build <--blob <BLOB>|--blob-dir <BLOB_DIR>> [OPTIONS] <SOURCE>`

The `nydus build` command builds a source directory into the nydus EROFS
format, in either image layout: `--blob` writes the single-file image,
`--blob-dir` deposits the full blob into a store (see Image layouts above),
and `--bootstrap` additionally emits the standalone metadata-only entry point.
The reverse direction — turning a nydus full blob back into an OCI layer tar
stream — is `nydus export` (see below).

Current CLI help:

```bash
nydus build -h
Build a nydus filesystem image

Usage: nydus build [OPTIONS] <--blob <BLOB>|--blob-dir <BLOB_DIR>> <SOURCE>

Arguments:
	<SOURCE>  Specify the source directory to build the nydus image from

Options:
	--blob <BLOB>
		Specify the file path to save the image as a single self-contained full blob; if the path is an existing FIFO the blob is streamed into it [env: NYDUS_BUILD_BLOB=]
	--blob-dir <BLOB_DIR>
		Specify the content-addressed store directory to save the full blob into, named by its SHA256, so mounts resolve it through the bootstrap and images share the store [env: NYDUS_BUILD_BLOB_DIR=]
	--bootstrap <BOOTSTRAP>
		Specify the file path to save the standalone bootstrap: the store layout's entry point, whose device table records each blob's SHA256 [env: NYDUS_BUILD_BOOTSTRAP=]
	--chunk-size <CHUNK_SIZE>
		Specify the file chunk size (must be a power of two, >= 4KiB, and 4KiB-aligned). The value needs to be set with human readable format, for example: 4kib, 1mib [env: NYDUS_BUILD_CHUNK_SIZE=] [default: 1MiB]
	--block-group-size <BLOCK_GROUP_SIZE>
		Specify the uncompressed size of each block group, the unit of compression and of a single backend read (must be a power of two, >= 1MiB, and >= the chunk size). The value needs to be set with human readable format, for example: 4mib, 16mib [env: NYDUS_BUILD_BLOCK_GROUP_SIZE=] [default: 4MiB]
	--compressor <COMPRESSOR>
		Specify the algorithm to compress data chunks [env: NYDUS_BUILD_COMPRESSOR=] [default: zstd] [possible values: none, zstd]
	--exclude <EXCLUDE>
		Specify the absolute or current-working-directory-relative paths to exclude. May be specified multiple times. Entries inside the source tree are omitted from the blob and the resulting filesystem tree entirely
	-l, --log-level <LOG_LEVEL>
		Specify the logging level [trace, debug, info, warn, error] [env: NYDUS_BUILD_LOG_LEVEL=] [default: info]
```

Current implementation notes:

- Exactly one of `--blob` or `--blob-dir` is required (enforced at parse time).
- `--bootstrap` is optional and emits a standalone metadata-only artifact.
- `--chunk-size` defaults to `1MiB`, accepts human readable sizes (e.g. `4kib`,
	`1mib`) or plain byte counts, and controls EROFS file chunk
	indexes (the unit of file splitting and per-chunk BLAKE3 digests). Chunks are
	independent of compression block groups and may straddle block group boundaries, so a
	smaller chunk size does not fragment blob_meta into tiny compression units.
- `--block-group-size` defaults to `4MiB` (same size formats) and sets the uncompressed size
	of each blob_meta block group (the unit of compression and of a single backend
	read). Block groups are formed by packing whole decoded blocks up to this size
	regardless of chunk boundaries, so every block group but the last is exactly this
	many blocks. Like `--chunk-size` it must be a power of two (the blob meta
	header stores both sizes as log2 exponents); it must also be at least 1 MiB
	and at least `--chunk-size`. Raising `--chunk-size` above 1 MiB requires
	raising `--block-group-size` to match or exceed it.
- `--blob <path>` stores the full blob at `<path>` and a standalone blob meta
	copy at `<path>.blob.meta`. If `<path>` already exists and is a FIFO, build
	writes the full blob stream to that FIFO instead of creating a regular file.
- `--blob-dir` stores the full blob under `<blob-dir>/<full_blob_sha256>` and a
	standalone blob meta copy under `<blob-dir>/<full_blob_sha256>.blob.meta`.
- `--compressor zstd` attempts to compress each blob_meta block group as one
	unit. If the compressed bytes are larger than 70% of the uncompressed block group,
	the block group is stored plain and its blob_meta block group entry has
	`compressed_size == uncompressed_block_count * 4096`.
- `--compressor none` writes every block group plain.
- `--exclude <path>` omits paths inside the source tree from the blob and the
	resulting filesystem tree entirely. It accepts absolute or
	current-working-directory-relative paths and may be repeated.
- Build prints one `Blobs` section grouped by `Blob N` with `blob_index`,
	`data_blob_digest`, `full_blob_digest`, `chunk_size`, `chunk_count`,
	`block_group_count`, `chunk_digester`, `chunk_compressor`,
	compressed/uncompressed totals, and full blob region offsets and block counts.

### Export

`nydus export <BLOB> [-o <path>]`

A nydus full blob is self-describing: it carries the filesystem tree, the chunk
data and the footer of exactly one layer. Exporting it back into an OCI layer
tar stream therefore needs nothing but that one file — no merged bootstrap, no
lower layer, no storage backend, and no on-demand fetching.

Current CLI help:

```bash
nydus export -h
Export a nydus image as an OCI layer tar stream

Usage: nydus export [OPTIONS] <SOURCE>

Arguments:
	<SOURCE>  Specify the nydus full blob to export the OCI layer tar stream from

Options:
	-o, --output <OUTPUT>
		Specify the file path to save the exported tar stream (defaults to stdout) [env: NYDUS_EXPORT_OUTPUT=]
	-l, --log-level <LOG_LEVEL>
		Specify the logging level [trace, debug, info, warn, error] [env: NYDUS_EXPORT_LOG_LEVEL=] [default: info]
```

The exporter walks the embedded EROFS tree from the root inode and emits one
tar entry per inode, streaming file data straight out of the blob:

- Mode, uid, gid, size, rdev and mtime come from the inode. A non-zero
	sub-second mtime is emitted as a PAX `mtime` record.
- Extended attributes become PAX `SCHILY.xattr.*` records. The internal
	`trusted.nydus.*` attributes are dropped: they only drive the nydus runtime.
- Hard links reuse the first path visited. That entry is a regular file and
	every later path for the same inode becomes a tar hard link pointing at it.
- Sockets cannot be represented in tar and are skipped with a warning.
- OCI whiteouts need no special handling. `nydusify` extracts `.wh.*` markers
	verbatim when it builds a layer, so they are ordinary inodes in the blob and
	round-trip as ordinary tar entries.

Current implementation notes:

- `<SOURCE>` must be a regular file, because the blob is memory-mapped.
- Without `--output` the tar goes to stdout; logging always goes to stderr,
	so the stream stays clean for piping.
- Entries follow EROFS directory order, which is sorted by name, so the output
	is deterministic for a given blob.
- The rebuilt tar is not a byte-for-byte copy of the layer the blob was built
	from: framing details such as the tar flavor and entry ordering are not
	recorded in the image. Content and metadata round-trip, the layer digest does
	not.

```bash
# Inspect a layer without mounting it.
nydus export layer.blob --output - | tar -tvf -

# Materialize the layer as an OCI layer tar.
nydus export layer.blob --output layer.tar
```

### Merge

`nydus merge [OPTIONS] <SOURCE>...`

The `nydus merge` command merges multiple layer blobs in order into a single
overlaid bootstrap in EROFS metadata format. Each source path must be a full
blob file whose file name is its SHA256. Merge validates that invariant before
loading metadata. The emitted merged bootstrap preserves each source layer's
blob id from the source bootstrap device table and applies OCI whiteout
semantics so the final bootstrap reflects the merged filesystem view after
deletions and opaque-directory masking.

Current CLI help:

```bash
nydus merge -h
Merge multiple nydus layers into an overlaid bootstrap

Usage: nydus merge [OPTIONS] --bootstrap <BOOTSTRAP> <SOURCES>...

Arguments:
	<SOURCES>...  Specify the nydus layer blob paths named by their SHA256

Options:
	--bootstrap <BOOTSTRAP>
		Specify the file path to save the generated overlaid nydus bootstrap [env: NYDUS_MERGE_BOOTSTRAP=]
	--whiteout-spec <WHITEOUT_SPEC>
		Specify the whiteout specification to apply while merging layers [env: NYDUS_MERGE_WHITEOUT_SPEC=] [default: oci] [possible values: oci]
	-l, --log-level <LOG_LEVEL>
		Specify the logging level [trace, debug, info, warn, error] [env: NYDUS_MERGE_LOG_LEVEL=] [default: info]
```

Current implementation notes:

- Merge requires source blob file names to be 64-character SHA256 hex strings.
- Merge verifies each source file's content SHA256 against its file name.
- Merge rebuilds an overlaid bootstrap by loading each source into an in-memory
	metadata tree, applying OCI whiteout rules, and emitting a new device table.
- Merge preserves the blob id already stored in each source device slot. For
	single-layer outputs from `nydus build`, that blob id is currently the SHA256
	of the data region.
- Merge currently assumes source regular files use the nydus chunk-based data
	layout and preserves each file's original chunkbits.

### Optimize

`nydus optimize [OPTIONS]`

The `nydus optimize` command builds a compact "ondemand" blob from a recorded
block group access pattern and rewrites the bootstrap so the runtime prefetches that
blob first. The ondemand blob carries copies of the hot block groups (in first-access
order); at mount time the phase-0 prefetch streams it and redirects each decoded
block group into the source blob's cache, so early on-demand reads hit warm cache
instead of issuing scattered registry range reads.

Supported forms:

```bash
# Fetch the trace live from a running mount's apiserver.
nydus optimize \
  --apiserver unix:///path/to/api.sock \
  --parent-bootstrap /path/to/parent-bootstrap \
  --bootstrap /path/to/bootstrap \
  --blob-dir /path/to/blobs \
  --config /path/to/config.yaml

# Or load the trace from a previously saved JSON file.
nydus optimize \
  --trace-file /path/to/trace.json \
  --parent-bootstrap /path/to/parent-bootstrap \
  --bootstrap /path/to/bootstrap \
  --blob-dir /path/to/blobs \
  --config /path/to/config.yaml
```

Current implementation notes:

- `--apiserver` is the apiserver address of a **running** `nydus fuse` mount
	(the same `unix:///path` form as `nydus fuse --apiserver`). Optimize fetches
	the access patterns live from its `GET /trace` endpoint
	(`{"version":1,"patterns":[{"blob_index":1,"block_group_index":4},...]}`);
	entries are deduplicated preserving first-access order. Run the workload
	against the mount before invoking optimize so the trace is populated.
- `--trace-file` is the offline alternative to `--apiserver` (the two are
	mutually exclusive; one of them is required). It accepts the same versioned
	trace document as produced by the `/trace` endpoint, so a trace captured
	from a pmem/core mount can be replayed without a live apiserver.
- `--parent-bootstrap` is the merged bootstrap to optimize; it is read-only, so
	optimize can be re-run against the same parent with new patterns.
- `--bootstrap` is the rewritten bootstrap output: the parent's inode tree with
	an appended ondemand device slot and the root `trusted.nydus.prefetch.blobs`
	xattr updated to list the ondemand device id first.
- `--blob-dir` receives the ondemand blob (named by its full SHA256) and its
	`<digest>.blob.meta` sidecar; the digest is printed in the summary table as
	`ONDEMAND BLOB DIGEST`.
- `--config` is the same storage config as `nydus fuse --config`: source block group
	bytes are pulled through the regular blob cache, so block groups already decoded in
	`storage.dir` are served from disk and cold block groups are fetched from the
	backend (with CRC validation on every path).
- The ondemand artifact layout is `[block group data][blob meta][footer]` with
	`bootstrap_blocks = 0` (no embedded bootstrap) and an empty chunk table. Each
	block group entry is a redirect: it stores the source device id and source block group
	index, and its `crc32c` equals the source block group's decoded CRC.

### Check

`nydus check [OPTIONS]`

The `nydus check` command performs static inspection of a nydus / EROFS image
without mounting it. It prints image sizing, a full superblock dump, filesystem
summary data, and one grouped `Blobs` entry per external device.

Supported forms:

- `nydus check --blob <blob>`
- `nydus check --bootstrap <bootstrap>`
- `nydus check --bootstrap <bootstrap> --blob-dir <blob-dir>`
- `nydus check --bootstrap <bootstrap> --config <config.yaml>`

Current implementation notes:

- `--blob` inspects the full nydus blob, locates the bootstrap through the
	footer, and verifies the data-region SHA256 against the device-table blob id.
- `--bootstrap` inspects metadata only and reports blob sizes from device-table
	block counts.
- `--blob-dir` is optional for static inspection and is used only to resolve
	referenced blob files and verify their digests.
- `--config` supplies the blob directory through the storage config's
	`backend.config.dir`; an explicit `--blob-dir` takes precedence when both are
	given. See [Storage config](#storage-config).
- Blob entries report `data_blob_digest`, `full_blob_digest`, blob_meta
	`chunk_size`, `chunk_count`, `block_group_count`, `chunk_digester`,
	`chunk_compressor`, and compressed/uncompressed totals when the referenced
	blob can be resolved.
- `--blob-dir` resolves by scanning full blob candidates. Device slots normally
	store the data-region SHA256, while blob files are named by full blob SHA256
	when produced by `--blob-dir`.

### Fuse

`nydus fuse [OPTIONS]`

The `nydus fuse` command mounts nydus metadata as a filesystem at the target
mountpoint. It is the host filesystem mount entrypoint; microVM integrations
can instead use [`nydus uffd`](#uffd), and block-device consumers
[`nydus nbd`](#nbd) or [`nydus ublk`](#ublk). During read path resolution, runtime
uses the blob id recorded in bootstrap metadata to locate the corresponding
blob under `--blob-dir` and then serves chunk data from that blob.

Current implementation notes:

- `SIGINT`/`SIGTERM`/`SIGQUIT` trigger a best-effort unmount before process exit,
	so interactive `Ctrl+C` tears down the mountpoint instead of leaving it behind.
- After mounting, runtime starts background blob prefetch unless it is disabled
	through the storage config. See [Blob prefetch](#blob-prefetch).
- Pass `--apiserver unix:///path/to/api.sock` to expose Prometheus metrics over a
	Unix socket. See [Metrics](#metrics).

Current CLI help:

```bash
nydus fuse -h
Mount a nydus image through FUSE

Usage: nydus fuse [OPTIONS] --mountpoint <MOUNTPOINT>

Options:
	--blob-dir <BLOB_DIR>
		Specify the content-addressed store directory holding the blobs recorded in the bootstrap, named by their SHA256 [env: NYDUS_FUSE_BLOB_DIR=]
	--cache-dir <CACHE_DIR>
		Specify the directory path for persistent chunk cache files [env: NYDUS_FUSE_CACHE_DIR=]
	--config <CONFIG>
		Specify the file path to a YAML storage config providing backend/cache directories and prefetch options. When set, --blob-dir and --cache-dir can be omitted [env: NYDUS_FUSE_CONFIG=]
	--prefetch
		Specify whether to enable background blob prefetch after mounting. Off by default; when --config is provided, the config's `prefetch.scope` also turns it on [env: NYDUS_FUSE_PREFETCH=]
	--bootstrap <BOOTSTRAP>
		Specify the file path to nydus bootstrap [env: NYDUS_FUSE_BOOTSTRAP=]
	--blob <BLOB>
		Specify the file path to nydus blob [env: NYDUS_FUSE_BLOB=]
	--mountpoint <MOUNTPOINT>
		Specify the directory path to mount nydus filesystem [env: NYDUS_FUSE_MOUNTPOINT=]
	--apiserver <APISERVER>
		Specify the address to serve Prometheus metrics over a Unix socket, e.g. `unix:///run/nydus/api.sock`. The metrics are exposed at `/metrics` [env: NYDUS_FUSE_APISERVER=]
	-l, --log-level <LOG_LEVEL>
		Specify the logging level [trace, debug, info, warn, error] [env: NYDUS_FUSE_LOG_LEVEL=] [default: info]
	--log-dir <LOG_DIR>
		Specify the log directory [env: NYDUS_FUSE_LOG_DIR=] [default: /var/log/nydus/]
	--log-max-files <LOG_MAX_FILES>
		Specify the max number of log files [env: NYDUS_FUSE_LOG_MAX_FILES=] [default: 6]
```

Supported forms:

- `nydus fuse --blob <blob> --mountpoint <mountpoint>`
- `nydus fuse --bootstrap <bootstrap> --blob-dir <blob-dir> --mountpoint <mountpoint>`
- `nydus fuse --bootstrap <bootstrap> --config <config.yaml> --mountpoint <mountpoint>`

The fuse command rejects mixed or partial combinations outside these forms.
`--cache-dir` is optional; without it (and without a cache directory from
`--config`), runtime fetches and validates requested blob_meta block groups using a
temporary cache directory that is removed on exit. When `--config` is provided,
`backend.config.dir` supplies the blob directory and `storage.dir` supplies
the cache directory, so `--blob-dir` and `--cache-dir` can be omitted. Explicit
`--blob-dir`/`--cache-dir` flags take precedence over the config. See
[Storage config](#storage-config).

### Ublk

`nydus ublk [OPTIONS]`

The `nydus ublk` command serves a flattened nydus image as a read-only
`/dev/ublkbN` block device through the kernel's userspace block driver
(`ublk_drv`). The bootstrap sits at device offset `0` and every blob at the
`mapped_offset` recorded in its EROFS device slot, which is exactly the layout
the kernel EROFS driver expects from a single device — so the device can be
mounted with `mount -t erofs` and every filesystem operation above it runs in
the kernel, with no userspace round trip per file.

The ublk command is available only when Nydus is built with both the `cli` and
`ublk` features. It requires Linux 6.0 or newer with the `ublk_drv` module
loaded.

```bash
cargo build --release --features cli,ublk --bin nydus

sudo modprobe ublk_drv

sudo nydus ublk \
  --bootstrap /var/lib/nydus/image/image.boot \
  --config /etc/nydus/config.yaml
# prints e.g. /dev/ublkb0

sudo mount -t erofs -o ro /dev/ublkb0 /mnt/nydus
```

Options:

- `--bootstrap` selects the EROFS bootstrap used as device metadata. Its blob
  table drives the flattened layout, so multi-blob images need no extra flags.
- `--config` selects the regular Nydus backend, cache, and prefetch
  configuration. See [Storage config](#storage-config).
- `--dev-id` requests a specific device id; `-1` (the default) lets the driver
  allocate one.
- `--queues` sets the queue count. Each queue is one thread serving its I/O
  synchronously, so a single queue serializes the whole device. The default is
  one queue per host CPU, capped at 4.
- `--depth` sets the per-queue depth (default 128).
- `--io-buf-bytes` sets the per-request buffer size (default 512 KiB).
- `--unprivileged` creates the device with `UBLK_F_UNPRIVILEGED_DEV`.
- `--log-level`, `--log-dir`, and `--log-max-files` control service logging.

Blobs are prepared before the device path is printed, so a backend that cannot
serve a blob meta fails the daemon at startup rather than surfacing later as an
opaque `mount` failure. The device path is printed to stdout as its own line;
callers should match the `/dev/ublkb` prefix rather than assume it is the first
line, because structured logs may also go to stdout.

Unmount before stopping the daemon: the kernel cannot delete a mounted device,
so killing the daemon first leaks it. The daemon must also not share a mount
namespace with the mounter, or shutdown and unmount deadlock on each other.

See [Nydus ublk Block Device Target](ublk.md) for the flattened device layout,
device parameters, read path, queue model, and a comparison with the other
mount paths.

### UFFD

`nydus uffd [OPTIONS]`

The `nydus uffd` command serves a flattened nydus image to microVM processes
over a Unix stream socket. A microVM can expose an anonymous virtio-pmem VMA to
its guest, register the VMA with userfaultfd, and let Nydus resolve faults from
the bootstrap and decoded blob cache files. The guest mounts the resulting
device as EROFS.

The UFFD command is available only when Nydus is built with both the `cli` and
`uffd` features. The `uffd` feature gates the service and its FD-passing
dependency, so other Nydus library and builtin-core users do not include
the UFFD service path.

```bash
cargo build --release --features cli,uffd --bin nydus

nydus uffd \
  --bootstrap /var/lib/nydus/image/image.boot \
  --config /etc/nydus/config.yaml \
  --socket /run/nydus/uffd.sock
```

Options:

- `--bootstrap` selects the EROFS bootstrap used as device metadata.
- `--config` selects the regular Nydus backend, cache, and prefetch
  configuration.
- `--socket` is the Unix socket used by microVM clients.
- `--threads` optionally sets the Tokio runtime worker count; when omitted,
  Tokio chooses its default from available host CPUs.
- `--log-level`, `--log-dir`, and `--log-max-files` control service logging.

The service supports multiple connections, Zerocopy and Copy page-fault
policies, optional prefaulting of locally ready ranges, and stateless
`STAT`/`FETCH`/`PROBE` requests for clients that monitor userfaultfd themselves.
Termination signals stop the listener, drain connection tasks, remove the Unix
socket, and then exit the runtime.

See [Nydus UFFD Service and Wire Protocol](uffd.md) for the flattened device
layout, binary framing, SCM_RIGHTS FD rules, request/response formats, and
fault-handling responsibilities.

### Fanotify

`nydus fanotify [OPTIONS]`

The `nydus fanotify` command serves a Nydus image to the kernel EROFS driver as
an on-demand, **multi-device** mount. The bootstrap is a real local EROFS image
mounted directly, so mount and metadata reads (`ls`, `stat`) work off the local
bootstrap; each blob is a separate EROFS device backed by the core's sparse
cache file, marked for fanotify `FAN_PRE_ACCESS`. A cold blob-data read faults;
the daemon identifies the blob, fetches the range into its cache file, and
answers the event. This is the native-EROFS counterpart to `nydus uffd` (which
serves microVMs) and the successor to the deprecated EROFS-over-fscache path.

The fanotify command is available only when Nydus is built with both the `cli`
and `fanotify` features.

```bash
cargo build --release --features cli,fanotify --bin nydus

sudo nydus fanotify \
  --bootstrap /var/lib/nydus/image/image.boot \
  --config /etc/nydus/config.yaml \
  --mountpoint /mnt/erofs
```

Options:

- `--bootstrap` is the local mount source and metadata device.
- `--config` selects the regular Nydus backend, cache, and prefetch
  configuration; the blob cache files under the cache directory are the blob
  devices.
- `--mountpoint` is the EROFS mount target. When provided, the daemon mounts
  after the fanotify group is ready and unmounts on shutdown.
- `--fetch-concurrency` bounds how many blob fetches run concurrently
  (default `max(ncpu, 64)`). A busy pool queues tasks — backpressure —
  rather than denying reads. Admission is unbounded; there is no per-event
  byte cap or timeout (bounded fetch time comes from the backend's HTTP
  timeout + retries; a registry `timeout: 0s` is rejected for this mode).
- `--log-level`, `--log-dir`, and `--log-max-files` control service logging.

The service marks every blob device and runs an event coordinator whose fetch
concurrency is bounded by the fetch pool; there is no per-event deadline
(bounded fetch time comes from the backend's HTTP timeout + retries). On
shutdown it denies outstanding events and unmounts **before** dropping the
fanotify group fd, whose release would fail-open residual events. Requires
`CAP_SYS_ADMIN` and Linux 6.15+.

See [Nydus Fanotify Pre-Content Service](fanotify.md) for the multi-device layout,
event ABI, event processing, service lifecycle, and constraints.

### NBD

`nydus nbd [OPTIONS]`

The `nydus nbd` command exposes the flattened nydus image (bootstrap plus all
data blobs) as a single read-only block device through the Linux NBD driver.
The kernel reads `/dev/nbdX`; each cold read fetches the covering blob ranges
into the local cache files on demand. The bootstrap keeps its device table, so
mounting the device as EROFS without `device=` options enables the kernel's
flatdev mode and every chunk resolves on the one device. This is the
block-device counterpart to `nydus fanotify`: it works on kernels without
`FAN_PRE_ACCESS` (Linux < 6.15) and needs only the `nbd` module and EROFS
support.

The NBD command is available only when Nydus is built with both the `cli` and
`nbd` features.

```bash
cargo build --release --features cli,nbd --bin nydus

sudo nydus nbd \
  --bootstrap /var/lib/nydus/image/image.boot \
  --config /etc/nydus/config.yaml \
  --device /dev/nbd0 \
  --mountpoint /mnt/erofs
```

Options:

- `--bootstrap` is the EROFS bootstrap served at the head of the device.
- `--config` selects the regular Nydus backend, cache, and prefetch
  configuration.
- `--device` is the NBD device node to attach. A device already serving
  another client (nonzero capacity) is refused.
- `--mountpoint` optionally mounts the device as EROFS once the session is
  live and unmounts it on shutdown; when omitted, only the device is attached
  and the caller mounts it.
- `--threads` sets the worker count (default: available CPU count, capped at
  16). Each worker is an independent kernel NBD connection, so backend
  fetches for concurrent reads overlap.
- `--timeout` (seconds, default 60, nonzero) is how long the kernel waits for
  one reply before failing the request; size it above the worst-case cold
  fetch from the backend.
- `--log-level`, `--log-dir`, and `--log-max-files` control service logging.

On shutdown, the first termination signal unmounts **before** tearing down
the NBD session — the unmount's own reads still need a live device — and a
second signal forces immediate exit. Requires root (NBD ioctls plus mount)
and the `nbd` kernel module.

See [Nydus NBD Service](nbd.md) for the wire framing, ioctl session setup,
request validation, and lifecycle details.

### Storage config

`nydus fuse`, `nydus uffd`, `nydus fanotify`, `nydus nbd`, `nydus ublk`, and
`nydus check` accept a shared YAML storage config through `--config <path>`. It centralizes the backend
directory, cache directory, and prefetch behavior so command-specific directory
flags can be
omitted.

```yaml
backend:
  type: local
  config:
    dir: /var/lib/nydus/blobs
storage:
  dir: /var/lib/nydus/cache
prefetch:
  concurrent_blob_count: 10
  scope: ondemand
```

Fields:

- `backend.type` selects the blob backend, either `local` or `registry`.
	- `local`: `config.dir` is the directory holding nydus blob files
		(equivalent to `--blob-dir`).
	- `registry`: serves blobs on demand from an OCI registry. See
		[Registry backend](#registry-backend) for the full field list. `nydus
		check` only supports the `local` backend.
- `storage.dir` is the persistent directory storing each blob's decoded chunk
	cache file (equivalent to `--cache-dir`). When unset (or the whole
	`storage` section is omitted), reads run diskless: every read fetches,
	decodes, and validates its block groups from the backend directly, and nothing is
	written to disk — the kernel page cache above the mount is the only reuse
	layer. Diskless mode applies to `nydus fuse` and `nydus check`; the modes
	that hand the cache file to the kernel (`fanotify`, `nbd`, `ublk`, `uffd`)
	and `nydus optimize` require a directory and reject its absence at startup.
- `storage.skip_verify_checksums` (default `true`) skips verifying decoded
	block groups against their stored checksums before they are served. Set it
	to `false` to verify every decoded block group when the transport is not
	trusted end to end.
- `prefetch.concurrent_blob_count` (default `10`) caps how many blobs are
	prefetched concurrently.
- `prefetch.timeout` (default `1h`) bounds how long prefetching one whole
	blob may take, while `http.timeout` bounds each block group request within it;
	`0s` disables the bound. A blob that exceeds it is aborted with a warning
	and prefetch moves on.
- `prefetch.retry_delay_min` / `prefetch.retry_delay_max` (defaults `6h` /
	`12h`) bound the random delay before a blob prefetch that the backend
	throttled (a Dragonfly proxy `429`) is re-attempted; each throttled blob is
	rescheduled with a fresh random deadline inside the window so retry load
	spreads out instead of stampeding. `retry_delay_min` must not exceed
	`retry_delay_max`. Only throttled failures are rescheduled; other prefetch
	failures are logged and skipped.
- `prefetch.scope` (default `ondemand`) selects which blobs to pull. `none`
	disables prefetch; `ondemand` prefetches only the "ondemand" redirect blob
	(if any), warming the access-ordered hot set while leaving backend
	bandwidth to on-demand reads; `all` prefetches every blob — priority blobs
	first, then the rest. See [Blob prefetch](#blob-prefetch).

The whole `prefetch` block is optional and falls back to the defaults above;
individual fields may also be omitted independently. CLI directory flags
override the corresponding config directories. Runtime prefetch applies to
`nydus fuse`, `nydus uffd`, `nydus nbd`, and `nydus ublk`; static `nydus check`
does not start it.
Unknown `backend.type` values and unknown fields are rejected at load time.

Example invocations:

```bash
nydus fuse --bootstrap layer.bootstrap --config storage.yaml --mountpoint /mnt/nydus
nydus uffd --bootstrap layer.bootstrap --config storage.yaml --socket /run/nydus/uffd.sock
nydus check --bootstrap layer.bootstrap --config storage.yaml
```

### Registry backend

The `registry` backend serves blobs on demand from an OCI registry instead of a
local directory. A blob id is the full-blob SHA256 digest, fetched via
`GET /v2/<repository>/blobs/sha256:<hex>` with HTTP range requests. A ready-to-edit
example lives at [`config/registry.example.yaml`](../config/registry.example.yaml).

```yaml
backend:
  type: registry
  config:
    addr: http://127.0.0.1:5000
    repository: library/nydus-demo
    # base64-encoded `username:password`
    auth: dGVzdHVzZXI6dGVzdHBhc3N3b3Jk
    http:
      timeout: 5s
      max_retries: 3
      tls:
        skip_verify: false
        ca_cert: /etc/nydus/certs/registry-ca.pem
    # dragonfly:
    #   scheduler_endpoint: http://127.0.0.1:65000
```

Fields under `backend.config`:

- `addr` (required): registry address including the scheme, e.g.
	`https://registry-1.docker.io` or `http://127.0.0.1:5000`. The scheme
	selects between TLS and plain HTTP.
- `repository` (required): image repository without tag/digest, e.g.
	`library/ubuntu`.
- `auth` (optional): base64-encoded `username:password` string for basic auth.
	Omit for anonymous / token-only registries.
- `http` (optional): the HTTP client settings — timeouts, retries, and TLS
	trust. The timeout also applies to Dragonfly SDK requests; retry counts
	for Dragonfly reads are governed by the `dragonfly` policy knobs below.
	- `timeout` (default `5s`): per-request timeout in humantime format (e.g.
		`5s`, `1m`); `0s` disables it. Kept short because a read holds the
		block group's cross-process fetch claim for its whole duration, and what
		queues up behind that claim are reader threads in the other instances
		sharing the cache directory.
	- `max_retries` (default `3`): maximum number of retry attempts per
		request, applied with exponential backoff by the HTTP client's retry
		middleware on direct origin requests. Origin requests issued as
		Dragonfly fallbacks share the same budget but pace each retry through
		the fallback throttle instead of the middleware's backoff, so this
		default is what bounds "origin failing 3 retries" before a fallback
		read errors out.
	- `proxy` (optional): routes every registry request through an HTTP
		forward proxy. Requests keep their original upstream URL, so a proxy
		like a Dragonfly `dfdaemon` knows what to back-source. Omit to connect
		directly to the origin.
		- `addr` (required): the proxy address including the scheme, e.g.
			`http://127.0.0.1:65001`.
	- `tls` (optional): the TLS settings for connections to the registry.
		- `skip_verify` (default `false`): skip TLS certificate verification.
		- `ca_cert` (optional): a CA certificate path with PEM format to trust
			in addition to the system roots; the file may bundle multiple
			certificates.
- `dragonfly` (optional): routes blob `GET`s through the Dragonfly client SDK
	(crate `dragonfly-client-request`) for P2P distribution, carrying a
	priority hint (`6` for on-demand reads, `3` for prefetch) plus the
	configured `timeout`; every other request (`HEAD`, auth token fetches)
	goes directly to the origin registry. Only available when the binary is
	built with the `backend-dragonfly-proxy` feature. Omit to talk to the
	origin directly. Metrics attribute each read to the origin or proxy side
	(see [Metrics](#metrics)).

	Failed Dragonfly reads are handled by a load-shedding policy keyed on the
	failure class and the read kind. The SDK's internal retries are disabled;
	the retry counts below are exact and observable:

	| Failure class | Prefetch | On-demand |
	|---|---|---|
	| Proxy `429` | No retry, no origin fallback; the blob's prefetch fails and is rescheduled after a random `prefetch.retry_delay_min`–`prefetch.retry_delay_max` delay | No Dragonfly retry; fall back to the origin through the fallback throttle; the origin failing `http.max_retries` attempts → IO error |
	| Proxy `403` | Fail immediately, no retry, no fallback | Fail immediately, no retry, no fallback |
	| Timeout | `prefetch_max_retries` Dragonfly retries (each after a random 100ms–1s delay), then fail (no fallback) | `ondemand_max_retries` Dragonfly retries, then throttled origin fallback |
	| Connect / `5xx` / other | `prefetch_max_retries` Dragonfly retries (each after a random 100ms–1s delay), then fail (no fallback) | `ondemand_max_retries` Dragonfly retries, then throttled origin fallback |

	Prefetch reads never fall back to the origin, so a Dragonfly outage
	degrades prefetch instead of flooding the registry, while on-demand reads
	stay served through the shaped fallback path.

	- `scheduler_endpoint` (required): the Dragonfly scheduler endpoint (gRPC),
		e.g. `http://127.0.0.1:65000`.
	- `ondemand_max_retries` (default `3`): Dragonfly retries for a retryable
		(timeout / connect / `5xx`) on-demand read failure before falling back
		to the origin.
	- `prefetch_max_retries` (default `10`): Dragonfly retries for a retryable
		prefetch read failure before the read fails. Each prefetch retry waits
		a random 100ms–1s delay first so failing prefetch reads do not hammer
		a struggling Dragonfly proxy in lockstep; on-demand retries are never
		delayed.
	- `fallback_interval` (default `1s`, i.e. 1 QPS per process): the minimum
		interval between origin requests issued as Dragonfly fallbacks; `0s`
		disables the throttle. Every fallback attempt — including each retry
		of a transient origin failure — waits for its own throttle slot, so
		actual origin requests never exceed one per interval. Only fallback
		reads are shaped — the normal direct path and auth fetches are never
		throttled. On-demand group singleflight already dedupes concurrent
		readers per group, so the throttle queues at most one leader per cold
		group.


## Metrics

When `nydus fuse` is started with `--apiserver unix:///path/to/api.sock`, a
small HTTP server is bound to that Unix socket and serves the Prometheus text
exposition at `GET /metrics` and the recorded on-demand block group access order at
`GET /trace` (any other path returns `404`). The server is torn down and the
socket unlinked when the mount exits. Scrape it with, e.g.:

```bash
curl --unix-socket /run/nydus/api.sock http://localhost/metrics
curl --unix-socket /run/nydus/api.sock http://localhost/trace
```

`GET /trace` returns JSON like
`{"patterns":[{"blob_index":1,"block_group_index":4},...]}` listing each `(blob,
block group)` pair in first-access order, deduplicated. The blob index is the device
id from the bootstrap device table. The trace feeds `nydus optimize` /
`nydusify optimize`.

Each completed backend request is also logged at `debug` level after it returns,
carrying the request source, transport, method, URL, request headers, response
status and headers (or an error), and the wall-clock duration.

For library embedders (no apiserver socket), `nydus_telemetry::metrics::snapshot()`
returns a serializable `Snapshot` capturing every registered metric from the same
registry. It serializes to a flat JSON map: counters as unsigned integers,
gauges as signed integers, histograms expanded to `<name>_sum` / `<name>_count`,
and labeled series keyed as `<name>{label="value",...}`. Embedders (e.g. a
hypervisor's stats endpoint) include it to reason about runtime behavior — in
particular `backend_ondemand_read_count > 0` means the prefetch did not cover
the access pattern and the workload fell back to the network.

Exported metrics:

Backend:

- `backend_origin_read_count`, `backend_origin_read_errors`,
	`backend_proxy_read_count`, `backend_proxy_read_errors` — read and error counts
	split by whether the origin registry or a proxy served the read.
- `backend_origin_read_latency`, `backend_proxy_read_latency` — read latency
	histograms (seconds, exponential buckets from 1ms to ~8s).
- `backend_origin_read_bytes`, `backend_proxy_read_bytes` — bytes read per side.
- `backend_ondemand_read_count`, `backend_ondemand_read_bytes`,
	`backend_ondemand_read_errors`, `backend_ondemand_read_high_latency_count` and
	the `backend_prefetch_*` equivalents — reads split by on-demand vs prefetch
	source. A read is "high latency" when it takes 250ms or more.
- `backend_origin_crc_check_errors`, `backend_proxy_crc_check_errors` — CRC
	validation failures on fetched data, attributed to the serving side.
- `backend_dragonfly_read_errors{class,kind}` — Dragonfly read failures by
	failure class (`rate_limited`, `forbidden`, `timeout`, `connect`,
	`server_error`, `other`) and read kind (`ondemand`, `prefetch`).
- `backend_fallback_read_count`, `backend_fallback_read_errors` — origin
	requests issued as Dragonfly fallbacks and how many of them failed; these
	reads also count into the `backend_origin_*` split above. Each logical
	fallback read counts once, however many throttled retry attempts it made.
	The error counter covers only HTTP transport errors (connect failures,
	timeouts) surfaced once the retry budget is spent — an HTTP error status
	from the origin or a failure while streaming the response body is not
	counted here. Watch this rate to confirm origin load stays shaped by
	`fallback_interval`.
- `backend_fallback_throttle_wait` — histogram of how long fallback reads
	waited in the throttle queue (seconds).
- `prefetch_reschedule_count`, `prefetch_reschedule_run_count` — throttled
	blob prefetches queued for a delayed retry, and delayed retries executed.

Filesystem:

- `fs_op_count{op}`, `fs_op_errors{op}` — successful and failed FUSE operations
	by op (`read`, `lookup`, `getattr`, ...).
- `fs_read_latency` — FUSE read latency histogram (seconds).

Cache:

- `cache_opened_files` — open blob data cache files (excludes the `.blob.meta`,
	`.group.map` and `.lock` sidecars).
- `cache_hit_block_group` — block groups served from cache without a backend read.
- `cache_total_block_group` — total block groups across loaded blob metas, counted once per
	blob however many caches are open on it.
- `cache_fill_block_group` — block groups written into a blob's own cache by regular blob
	prefetch.
- `cache_ondemand_fill_block_group` — block groups written into a blob's own cache to
	satisfy an on-demand read. Summing it across the instances sharing a cache
	directory shows how much duplicate fetching they do.
- `cache_redirect_fill_block_group` — block groups written into a **source** blob's cache
	from a redirect (ondemand) blob during phase-0 prefetch.
- `cache_redirect_skip_block_group` — redirect block groups skipped during ondemand
	prefetch (decode/CRC failures, unknown source device, or failed fills);
	normally zero.

Redirect (ondemand blob) backend traffic:

- `backend_redirect_read_count`, `backend_redirect_read_bytes` — backend reads
	that fetched ondemand (redirect) blob data, a subset of the
	`backend_prefetch_*` counters. Together with `cache_redirect_fill_block_group`
	these attribute cache warmup to the optimize pipeline: after an optimized
	mount's prefetch quiesces, `backend_redirect_read_count > 0` proves the
	ondemand blob was fetched and `cache_redirect_fill_block_group` equals the number
	of traced block groups written into the source caches.


## Artifact Model

### Build outputs

`nydus build` can materialize up to two distinct artifacts:

1. Full blob.
2. Optional standalone bootstrap.

Current output shapes:

- `--blob <path>` writes one full blob exactly at `<path>`.
- `--blob-dir <dir>` writes one full blob at `<dir>/<full_blob_sha256>`.
- `--bootstrap <path>` additionally writes a standalone metadata-only bootstrap.

### Full blob byte layout

The full blob is the primary layer artifact. Its byte layout is:

1. Encoded data region.
2. Optional zero padding to the next 4 KiB boundary.
3. Bootstrap region.
4. Optional zero padding to the next 4 KiB boundary.
5. Blob meta region.
6. Footer.

The order matters: the file is `data + bootstrap + blob_meta + footer`, not
`bootstrap + data`. The data region is first so build can append encoded chunk
block groups directly into the final artifact without copying them behind metadata
later.

```text
full blob file: <full_blob_sha256>

+-------------------------------+  byte 0
| encoded data region           |
| zstd or stored plain block_groups   |
+-------------------------------+  byte = footer.compressed_data_offset + footer.compressed_data_size
| padding to 4 KiB alignment    |
+-------------------------------+  byte = footer.bootstrap_offset
| bootstrap (zstd frame)        |
|  decodes to the EROFS image:  |
|  block 0                      |
|  +-------------------------+  |
|  | 0x0000..0x03ff zeros    |  |
|  | 0x0400..0x047f sb       |  |
|  | 0x0480.. device slots   |  |
|  | rest of block 0 = zeros |  |
|  +-------------------------+  |
|                               |
|  block 1..N-1                 |
|  +-------------------------+  |
|  | inode slots             |  |
|  | inode xattr bodies      |  |
|  | chunk index arrays      |  |
|  | directory data blocks   |  |
|  +-------------------------+  |
+-------------------------------+  byte = footer.bootstrap_offset + footer.bootstrap_blocks * 4096
| padding to 4 KiB alignment    |
+-------------------------------+  byte = footer.blob_meta_offset
| blob meta                     |
| 4 KiB header + chunk table    |
| block_group table                   |
| zero padding to 4 KiB         |
+-------------------------------+  byte = footer.blob_meta_offset + footer.blob_meta_blocks * 4096
| blob footer                   |
+-------------------------------+  EOF
```

The footer is fixed at 4096 bytes and is always located at EOF. The current
fields occupy the first 64 bytes; the remaining bytes are reserved for future
compat fields — writers zero them, readers ignore them (EROFS-style, so a
compat extension does not break old readers), and corruption is caught by the
footer crc32c.

```text
BlobFooter

u8  magic[8]           "LPFOOTER", raw ASCII bytes written as-is
u32 version            informational format generation (currently 1)
u32 flags              low 16 bits incompat (unknown bits reject),
                       high 16 bits compat (unknown bits ignored)
u32 crc32              crc32c over footer bytes with this field zeroed
u32 reserved0          future compat-field slot; writers zero, readers ignore
u64 compressed_data_offset
u64 bootstrap_offset
u64 blob_meta_offset
u64 compressed_data_size
u32 bootstrap_blocks
u32 blob_meta_blocks
u64 bootstrap_compressed_size   exact zstd frame bytes when the
                                BOOTSTRAP_ZSTD flag is set, else 0
u8  reserved1[4024]    compat area: writers zero, readers ignore
```

The `magic + version + flags` header prefix matches the blob meta
(`LPBLMETA`) and block_block_group_map (`LPGRPMAP`) sidecars.

Reader validation requires:

```text
compressed_data_offset + compressed_data_size <= bootstrap_offset
bootstrap_offset + bootstrap_blocks * 4096 <= blob_meta_offset
blob_meta_offset + blob_meta_blocks * 4096 == footer_offset
```

The inequalities allow alignment padding between regions. Offsets and the footer
offset must be 4 KiB aligned. The bootstrap and blob meta region lengths are
stored as 4 KiB block counts in the footer.

The bootstrap region stores the metadata-only EROFS image as a single zstd
frame (footer incompat flag `BOOTSTRAP_ZSTD = 1 << 0`), padded with zeros to
the 4 KiB region boundary; `bootstrap_compressed_size` carries the exact frame
length so readers decode without trusting the zero tail. An empty bootstrap
(ondemand blobs) keeps the flag clear and the size zero. When `--bootstrap` is
specified, the standalone bootstrap file is byte-for-byte identical to the
decoded region.

### Bootstrap region details

Within the bootstrap region:

- `superblock.blocks` counts only bootstrap blocks, not the entire full blob.
- the device table starts in block 0 immediately after the superblock.
- the metadata area starts at block 1 and contains inode bodies, xattrs, chunk
	index arrays and directory data.

## On-disk Metadata Design

### Superblock

The superblock continues to provide:

- `extra_devices`
- `devt_slotoff`
- primary image block count
- native EROFS `sb_checksum` verification for the bootstrap image

It does not carry the blob identity itself. It only points to the device table.
Both per-layer bootstraps generated by `nydus build` and merged bootstraps
generated by `nydus merge` pass through the same bootstrap writer, so both set
`EROFS_FEATURE_COMPAT_SB_CHKSUM` and write the EROFS superblock crc32c.

### Device table and chunk address semantics

Each external blob device is represented by one `ErofsDeviceSlot` entry.

For current single-layer build output:

- `tag[0..32]` stores the SHA256 of the encoded data region only.
- `tag[32..64]` is zero-filled.
- `blocks_lo/blocks_hi` store the logical uncompressed external-device size in
	4 KiB blocks.

For current merge output:

- merge preserves the blob id already stored in each source device slot;
- for source layers produced by current `nydus build`, that preserved blob id
	is also the data-region SHA256.

Regular file chunk indexes continue to use `blkaddr` and `device_id`, where:

- `device_id` is only a device-table index;
- `blkaddr` for external data is a logical uncompressed external-device block
	address and is not rebased by the bootstrap size.

Example:

```text
first logical external data block starts at offset 0
	blkaddr = 0
	logical byte offset = 0 * 4096

blob_meta then maps that logical byte offset to a compressed range in the full
blob's data region. The block is mapped to its block_group by
`block_group_index = blkaddr >> block_group_block_count_bits`, and the block_group entry gives the
encoded `compressed_offset` (for example 0 for the first encoded block_group).
```

Blob identity is therefore attached to the device slot, not to the chunk index
and not to the superblock directly.

### Blob ID semantics

The current implementation stores the SHA256 of the encoded data region in the
device slot rather than the SHA256 of the whole full blob file.

This avoids a self-reference problem:

- the full blob contains bootstrap metadata;
- bootstrap metadata contains the blob identifier;
- hashing the full file while embedding that hash into the file would be circular.

At the same time:

- the full blob file name written by `--blob-dir` is the SHA256 of the whole
	full blob artifact;
- the device slot blob id still refers to the data region SHA256.

### Blob meta region layout

Whenever build emits a full blob, it writes one blob meta region before the
footer. Blob meta is the canonical catalog for the external data blob. A blob
meta chunk is a content-addressed entry (BLAKE3 digest + absolute block range)
used for inspection and future deduplication; chunks are independent of block groups.
A blob meta block group is the compression unit and cache population unit. EROFS inode
chunk indexes point into the logical uncompressed external-device address space;
blob meta maps a block offset to its block group by a single division and the cache
file mirrors that decoded address space directly.

Current blob_meta on-disk shape:

```text
embedded blob meta region

+-------------------------------+
| 4096-byte header (one block)  |
| magic (8 bytes, "LPBLMETA")   |
| version                       |
| flags                         |
| crc32c                        |
| reserved0                     |
| chunks_offset                 |
| block_groups_offset                 |
| chunk_count                   |
| block_group_count                   |
| chunk_block_count_bits (u8)         |
| block_group_block_count_bits (u8 + pad)   |
| reserved tail (compat area)   |
+-------------------------------+
| chunk entries                 |
| 48 bytes each                 |
|                               |
| digest (BLAKE3)               |
| uncompressed_block_offset     |
| uncompressed_block_count      |
| reserved                      |
+-------------------------------+
| block_group entries                 |
| 40 bytes each                 |
|                               |
| uncompressed_block_offset     |
| compressed_offset             |
| uncompressed_block_count      |
| compressed_size               |
| crc32c                        |
| source_block_group_index            |
| source_blob_index               |
| reserved (6 bytes)            |
+-------------------------------+
| zero padding to 4 KiB         |
+-------------------------------+
```

Header details:

- `magic` is the 8 raw ASCII bytes `LPBLMETA`, written as-is (a hexdump of the
	file starts with the readable string). Same magic style as the block_block_group_map
	sidecar (`LPGRPMAP`).
- `version` is an informational format generation (currently 1). Readers do
	not gate on it: compatibility is governed EROFS-style by the magic (a new
	format family gets a new magic) and by the flag bits below.
- `flags` is split EROFS-style: the low 16 bits are incompatible features — a
	reader that does not know a set bit must reject the file (like
	`feature_incompat`); the high 16 bits are compatible features — unknown
	bits are ignored (like `feature_compat`). `COMPRESSOR_ZSTD` (`1 << 0`)
	means zstd is the blob's default compressor; no compressor bit means
	stored plain. `DIGESTER_BLAKE3` (`1 << 1`) is mandatory for chunk digests.
	Entry-layout evolution (wider chunk/block group entries, new entry kinds) is
	expressed as a new incompat bit — the same way EROFS gates compact vs
	extended inodes — while header growth uses the reserved tail plus a compat
	bit. The `magic + version + flags` header prefix is shared with the
	block_block_group_map sidecar.
- `crc32c` covers the full blob meta region with this field zeroed: the fixed
	header, all chunk entries, all block group entries, and trailing zero padding. The cache layer
	verifies this crc32c before mmaping a cached blob meta file for chunk lookup.
- `chunks_offset` is fixed at the header size. `block_groups_offset` follows the dense
	chunk table.
- `chunk_count` is the number of chunk entries.
- `block_group_count` is the number of compressed block group entries.
- `chunk_block_count_bits` is log2 of the EROFS chunk size in 4 KiB blocks:
	`chunk_size = 4096 << chunk_block_count_bits`, so the default 1 MiB chunk stores
	8. Storing the exponent EROFS-style (the same quantity as `chunk_format &
	EROFS_CHUNK_FORMAT_BLKBITS_MASK`) makes non-power-of-two chunk sizes
	unrepresentable and feeds the shift-based offset math directly.
- `block_group_block_count_bits` is log2 of the per-block group block count, same
	representation as `chunk_block_count_bits` (the default 4 MiB block group stores 10).
	Every block group except the last is exactly `1 << block_group_block_count_bits` blocks, so
	the read path maps a block to its block group with
	`block_group_index = block_id >> block_group_block_count_bits` in O(1). The two exponents
	are adjacent `u8`s at offset 48; the six bytes after them are reserved.
- The header is one EROFS block (4096 bytes): the chunk table starts block
	aligned by construction, and everything between the last field and the end
	of the header block is reserved for future compat fields — writers zero it,
	readers ignore it (so a compat extension does not break old readers), and
	corruption is caught by the region crc32c. Layout changes that old readers
	cannot safely ignore (wider entries, new tables, moved offsets) must use an
	incompat flag bit instead. The header intentionally does not
	store total compressed size or total uncompressed size — totals are computed
	from the block group entries — and the blob meta region is padded to a 4 KiB block
	boundary.

Chunk details:

- Chunks are decoupled from block groups: a chunk may straddle a block group boundary, and a
	block group may contain parts of several chunks. The chunk table is a digest index,
	not a per-block group map.
- `digest` is the BLAKE3 hash of the chunk's decoded, block-aligned bytes — the
	deduplication key.
- `uncompressed_block_offset` is the chunk's absolute 4 KiB block offset in the
	dense decoded address space (chunks are stored back-to-back).
- `uncompressed_block_count` is the chunk span in 4 KiB blocks. Only the chunk's
	final block carries zero padding; full chunks are already block-aligned, so the
	dense layout packs real blocks instead of large zero runs.

Block group details:

- Block groups are formed by packing whole decoded blocks up to `--block-group-size`
	regardless of chunk boundaries, then compressing the batch as one unit. So
	every block group but the last is exactly `1 << block_group_block_count_bits` blocks.
- `uncompressed_block_offset` is the decoded cache 4 KiB block offset for the
	block group. Block groups are dense and contiguous in the decoded address space.
- `compressed_offset` is the encoded payload's byte offset within the data
	region (not inside the whole full blob file). Encoded block groups are packed
	back-to-back with no inter-block group padding, so this is a plain byte position and
	is not block-aligned for compressed block groups. Runtime backends add the
	data-region base offset before issuing range reads.
- `uncompressed_block_count` describes the decoded block group size in 4 KiB blocks.
- `compressed_size` is the actual encoded byte length. The next block group starts at
	exactly the previous block group's `compressed_offset + compressed_size`.
- `crc32c` is computed over the decoded block group. If `compressed_size` equals
	`uncompressed_block_count * 4096`, runtime treats the block group as stored plain and
	skips decompression even when the header compressor is zstd.
- `source_blob_index` and `source_block_group_index` mark a redirect block group. They are
	zero for normal block groups. A non-zero `source_blob_index` means the block group's data
	belongs to that source blob (1-based device-table index) at
	`source_block_group_index`; phase-0 prefetch writes the decoded bytes into the
	source blob's cache instead of this blob's own cache. A blob containing any
	redirect block group is an "ondemand" blob: its block groups may be non-uniform in size
	(the uniformity invariant is relaxed) and `block_group_index_for_offset` is
	never used on it. The redirect block group's `crc32c` equals the source block group's
	decoded CRC so the fill is cross-checked before touching the source cache.

The writer does not bias `compressed_offset` by the bootstrap size, and
does not bias `uncompressed_block_offset`. Only the data region as a whole is
padded to a 4 KiB boundary (so the embedded bootstrap that follows starts on a
block); block groups themselves are not individually padded.

### Blocks, chunks and block groups

The three units live in two address spaces: blocks, chunks and block groups are
defined on the **decoded** (uncompressed) external-device address space that
EROFS chunk indexes point into, while only block groups exist in the **encoded**
data region stored in the full blob. The figures below use the defaults
(`--chunk-size` 1 MiB = 256 blocks, `--block-group-size` 4 MiB = 1024 blocks),
so one block group spans four chunks.

Chunks are the deduplication unit and are split **per file**: every regular
file is cut independently into `--chunk-size` pieces, and a file's final chunk
keeps only its real block-aligned size instead of being padded to a full
chunk:

```text
           file A (448 blocks)     file B (512 blocks)      file C ..
           +--------+------+    +--------+--------+    +--------
           | A ch 0 |A ch 1|    | B ch 0 | B ch 1 |    | C ch 0
           |256 blk |192blk|    |256 blk |256 blk |    | 256 blk
           | BLAKE3 |BLAKE3|    | BLAKE3 | BLAKE3 |    | BLAKE3
           +--------+------+    +--------+--------+    +--------
```

A fully-zero chunk — a real filesystem hole reads back as zeros, and so does
zero-filled data — is never stored: the builder emits the standard EROFS null
chunk index (all 48 address bits set on disk) instead. Hole chunks occupy no
bytes in the data region, get no blob meta chunk entry, and never touch the
blob cache at runtime: the core read paths satisfy them with zeros
directly, and native EROFS mounts decode the null address in-kernel the same
way.

The per-file chunks are then packed densely, back-to-back, into the decoded
external-device address space that EROFS chunk indexes point into; each
chunk's BLAKE3 digest and absolute block range are recorded in the blob meta
chunk table:

```text
blkaddr    0        256    448      704      960
           |        |      |        |        |
           +--------+------+--------+--------+--------+--
           | A ch 0 |A ch 1| B ch 0 | B ch 1 | C ch 0 | ..
           +--------+------+--------+--------+--------+--
```

Block groups aggregate **blocks**, not files or chunks: the block group builder packs
whole decoded blocks up to `--block-group-size` and flushes, regardless of where
files or chunks start and end — here the block group 0 boundary at block 1024 falls
in the middle of `C ch 0`, so that chunk straddles two block groups:

```text
blkaddr    0                                   1024
           |                                   |
           +--------+------+--------+--------+--------+--
same space | A ch 0 |A ch 1| B ch 0 | B ch 1 | C ch 0 | ..
           +--------+------+--------+--------+--------+--
           |<------------ block_group 0 ------------>|<- block_group 1 ..
           |       CRC32C(decoded bytes)       |   CRC32C ..
           +-----------------------------------+-----------
```

Each block group is the compression, backend-read and cache-fill unit, with a
CRC32C computed over its decoded bytes.

Block groups are then compressed independently and packed back-to-back into the
encoded data region of the full blob:

```text
           block_group 0                      block_group 1
              | zstd                       | zstd (stored plain when
              v                            v  saving is less than 30%)
+---------------------------+------------------+---
| block_group 0 compressed bytes  | block_group 1 bytes    | ...
+---------------------------+------------------+---
^ compressed_offset(g0) = 0
                            ^ compressed_offset(g1)
                              = offset(g0) + compressed_size(g0)
```

Hash and validation summary:

- **BLAKE3 per chunk** (blob meta chunk table) — the deduplication key over
	the chunk's decoded, block-aligned bytes.
- **CRC32C per block group** (blob meta block group entry) — validated after every fetch
	and decode, on both the on-demand and prefetch paths.
- **SHA256 over the data region** — written into the bootstrap device slot as
	the blob id.
- **SHA256 over the whole full blob** — the artifact file name (`--blob-dir`)
	and the OCI layer digest.
- **CRC32C in the blob meta header and blob footer** — checked before either
	structure is trusted; the bootstrap has its own EROFS superblock checksum.

### Ondemand (redirect) blob layout

`nydus optimize` emits one extra "ondemand" blob and appends it to the image
as a new layer. It reuses the full blob container format, but degenerates two
regions: there is no embedded bootstrap (`bootstrap_blocks = 0`) and the blob
meta chunk table is empty — the ondemand blob introduces no new filesystem
data, it only re-hosts copies of hot block groups from the source blobs:

```text
ondemand blob — named by SHA256(full blob), one new nydus layer

+--------------------------------+  byte 0
| block_group data                     |
|  encoded copies of the traced  |
|  source block_groups, packed in      |
|  first-access order            |
+--------------------------------+
| blob meta                      |
|  header (crc32c)               |
|  chunk table: empty            |
|  block_group table: redirect entries |
+--------------------------------+
| footer (bootstrap_blocks = 0)  |
+--------------------------------+
```

Every block group entry in the ondemand blob is a **redirect**: instead of
describing this blob's own decoded address space, it names the source block group
it is a copy of. Block group sizes follow the source block groups, so the uniform-size
invariant is relaxed and the O(1) `block >> block_group_block_count_bits` lookup is never
used on an ondemand blob:

```text
redirect block_group entry (in the ondemand block_group table)

  source_blob_index  = 2 --+
  source_block_group_index = 7   +--> names source blob 2, block_group 7;
  crc32c ------------------+    crc32c equals that block_group's decoded CRC

  compressed_offset -------+
  compressed_size ---------+--> locates the encoded copy inside
                                the ondemand data region
```

At mount time the rewritten bootstrap lists the ondemand device first in the
root inode's `trusted.nydus.prefetch.blobs` xattr, so phase-0 prefetch streams
it and fans the decoded block groups out into the **source** blobs' caches:

```text
phase-0 prefetch of the ondemand blob

fetch block_group copy -> zstd decode -> CRC32C check (must equal the
        |                          source block_group's decoded CRC)
        v
<source digest>.blob.data  at the source block_group's uncompressed offset
+ source block_block_group_map bit set
```

The ondemand blob never builds a cache file of its own; a failed redirect
(unknown source device, CRC mismatch, cache write error) is logged and
skipped, so a bad block group can only lose warmup, never poison a source cache.
See [Optimize](#optimize) for the CLI and [Blob prefetch](#blob-prefetch) for
the scheduling details.

### Merge output

The merge command emits an overlaid standalone bootstrap that references one or
more previously built full blobs.

## Build Pipeline

The build pipeline now follows this sequence:

1. Walk the source directory and build the in-memory inode tree.
2. Assign file chunk indexes into a logical uncompressed external-device address
	space. Chunks are packed densely: each chunk advances by its real
	block-aligned size, so only a chunk's final block carries zero padding (no
	full-chunk zero runs).
3. Record one blob_meta chunk entry per chunk (BLAKE3 digest + absolute block
	range) and feed the decoded data stream into a block-oriented block group builder
	that flushes a compression block group whenever it fills to `--block-group-size`,
	regardless of chunk boundaries. A chunk may therefore span two block groups.
4. Compute BLAKE3 digest over each uncompressed chunk and CRC32C over each
	uncompressed block group.
5. Compress each block group according to the blob_meta header compressor and append
	the encoded bytes directly to the data region. Encoded block groups are packed
	back-to-back with no inter-block group padding. For zstd, block groups that do not shrink
	to at most 70% of their uncompressed size are stored plain and marked by
	`compressed_size == uncompressed_block_count * 4096`.
6. Compute SHA256 over the encoded data region as those bytes are written and
	write it into the bootstrap device slot tag.
7. Serialize the bootstrap bytes in memory. External chunk `blkaddr` values stay
	logical and are not rebased by the bootstrap size. The bootstrap includes the
	native EROFS superblock checksum.
8. Optionally persist the standalone bootstrap.
9. Append `aligned bootstrap + aligned blob_meta + footer` after the data
	region. Blob meta carries its own header crc32c. The full blob SHA256 continues
	from the data-region hash state while these bytes are appended, so the final
	artifact digest is computed without re-reading the file.
10. Move or keep the full blob at the requested output path, then write the
	standalone `.blob.meta` copy beside that full blob.

Full blob output is sequential. This allows `--blob` to target a FIFO: data
bytes are written first, then the bootstrap bytes, then one serialized blob meta
buffer, then the fixed footer. The build path does not seek within the full blob
output.

This layout is intentionally footer-based. A header-based variant would need to
reserve a header at byte 0 and backpatch it after bootstrap/blob_meta offsets are
known. That is possible with `pwrite`, but a normal SHA256 stream cannot revise
bytes that were already fed into the hasher. A header design would therefore
need a second pass over the completed file, a precomputed header, a digest that
excludes mutable header bytes, or a different tree-hash construction. The footer
keeps the artifact append-friendly and permits one-pass full-blob digesting.

## Reader and Mount Design

### Direct blob mount

When mounting with `--blob`:

1. Read the fixed footer from EOF.
2. Map the embedded bootstrap region as the primary EROFS image.
3. Read device slots and resolve the full blob through the local backend.
4. Use a temporary local cache for the mount lifetime. The cache downloads the
	standalone blob meta into that cache, verifies its header crc32c, mmaps it for
	chunk lookup, fetches encoded block groups from the data region, and validates each
	decoded block group.

### Bootstrap plus blob-dir mount

When mounting with `--bootstrap + --blob-dir`:

1. Open the bootstrap.
2. Read every external device slot.
3. Extract the raw 32-byte blob id from each slot tag.
4. Resolve the full blob from `blob-dir` by scanning footer-bearing candidates
	and matching the SHA256 of each data region.
5. `--cache-dir` selects the persistent local cache; otherwise runtime creates a
	temporary local cache for the mount lifetime.
6. Before chunk lookup, check the cache directory for `<full_blob_digest>.blob.meta`.
	If it is absent, download the standalone blob meta from the local backend into
	the cache directory. The cache verifies the blob meta header crc32c before
	mmaping the cached file and using its chunk entries.
7. Reads use logical uncompressed offsets from inode chunk indexes. The cache
	layer maps an offset to its block group in O(1) with `block >> block_group_block_count_bits`,
	ensures every block group covering the requested range is fetched and decoded from
	the data region (validating block group CRC32C), and then reads the bytes straight
	out of the cache file. The cache file mirrors the dense decoded address space,
	so once the covering block groups are ready the absolute offset indexes directly into
	it for a single contiguous read — no chunk-level lookup is needed on the read
	path.

The runtime no longer reads external blob data by direct mmap offsets. External
blob reads always go through the blob_meta-aware cache abstraction.

The local backend opens source blob files lazily when read IO is first issued and
caches the file descriptor for later `pread` calls. The persistent local cache
also opens `<full_blob_digest>.blob.data` lazily, then serves repeated reads via
cached `pread`/`pwrite` file descriptors. Cache artifacts are named by the full
blob digest:

- `<full_blob_digest>.blob.data` stores decoded uncompressed data.
- `<full_blob_digest>.blob.meta` stores the verified blob meta copy cached from
	the local backend.
- `<full_blob_digest>.group.map` records which blob_meta block groups have been decoded
	(a shared readiness bitmap, see
	[Cross-process cache sharing](#cross-process-cache-sharing-and-prefetch-dedup)).
- `<full_blob_digest>.prefetch.lock` is the cross-process prefetch lock file
	(empty; only its `flock` state matters).
- `<full_blob_digest>.flight.lock` is the cross-process fetch lock file for
	single block groups (empty; only its byte-range lock state matters, see
	[Cross-process cache sharing](#cross-process-cache-sharing-and-prefetch-dedup)).

The cache data file mirrors the decoded address space one-to-one, so a block group's
bytes land at `uncompressed_block_offset * 4096` and EROFS chunk `blkaddr`
offsets index into it directly:

```text
cache directory, artifacts named by SHA256(full blob) = <hex>

<hex>.blob.data — decoded data, sparse; filled block_group by block_group
+-----------+-----------+-----------+-----------+---
|  block_group 0  |  (hole)   |  block_group 2  |  (hole)   | ...
|  decoded  |           |  decoded  |           |
+-----------+-----------+-----------+-----------+---
^ byte offset = uncompressed_block_offset * 4096; a block_group is written
  only after zstd decode + CRC32C validation succeeds

<hex>.blob.meta — verified blob meta copy (mmap'd for chunk/block_group lookup)
+--------+-------------------+-------------------+
| header | chunk table       | block_group table       |
| crc32c | BLAKE3 digests    | offsets + CRC32C  |
+--------+-------------------+-------------------+

<hex>.group.map — shared readiness bitmap, MAP_SHARED + atomic bit ops
+---------------------------------+----------------------+
| 4 KiB header (LPGRPMAP, version,| 1 bit per block_group ...  |
| flags, count, ready count)      |                      |
+---------------------------------+----------------------+
  bit set only after the block_group's bytes are resident in .blob.data;
  the ALL_READY header flag latches once every bit is set

<hex>.prefetch.lock — empty; exclusive flock serializes prefetch owners

<hex>.flight.lock — empty; byte N carries an OFD lock claiming block_group N,
  so exactly one process fetches a cold block_group and the rest wait for it
```

### Blob prefetch

After a successful mount, `nydus fuse` spawns a background prefetcher that warms
the local cache so later on-demand reads hit decoded data instead of fetching and
decoding block groups synchronously. Prefetch is **off by default**: enable it with the
`--prefetch` flag, or through the storage config `prefetch.scope` (either one
turns it on); the config's `prefetch` block also sizes the worker pool. See
[Storage config](#storage-config).

Per-blob prefetch streams block groups into the cache:

- The blob meta block groups are the compression/cache unit. Prefetch reads the data
	region in windows that accumulate consecutive block groups up to the default block group
	uncompressed size (4 MiB), so each window decode covers one or more block groups.
- For each window it issues a single contiguous backend range read, then decodes
	each contained block group (plain copy or zstd), validates length and CRC32C, writes
	the decoded bytes to the cache file at the block group's uncompressed offset, and
	marks the block group ready in the block_block_group_map.
- Prefetch uses its own decode buffer and does not take the on-demand read
	`fetch_lock`. The block_block_group_map bits are updated atomically and `set_ready` is
	idempotent, so racing with a FUSE read at worst decodes the same block group twice
	into identical bytes at the same offset. This keeps prefetch fully decoupled
	from, and non-blocking to, the on-demand read path.
- Block groups already marked ready (for example, fetched on demand or from a previous
	run's persistent cache) are skipped.

Prefetch scheduling across blobs has two phases:

1. Priority blobs are prefetched first, sequentially, in the order listed by the
	root inode's `trusted.nydus.prefetch.blobs` xattr (a comma-separated list of
	device ids). The list is deduplicated and filtered to existing devices. When
	`prefetch.scope` is `ondemand` (the default), only redirect ("ondemand") priority
	blobs are warmed; non-redirect priority blobs are skipped so backend
	bandwidth is not spent pulling whole source blobs.
2. Only when `prefetch.scope` is `all`, the remaining blob devices are then
	prefetched concurrently by a worker pool sized to
	`min(prefetch.concurrent_blob_count, remaining)` (default `10`).

When a priority blob is an "ondemand" redirect blob (produced by `nydus
optimize`, listed first in the xattr), its prefetch is dispatched differently:
the block groups are streamed and decoded as usual, but each decoded block group is written
into its **source** device's cache (validated against the source block group's length
and CRC) and marked ready there. The ondemand blob never builds a cache file of
its own. Per-block group failures — unknown source device, CRC mismatch, source cache
errors — are logged and skipped, so a bad redirect can only lose warmup, never
poison a source cache or abort the mount. Blob device caches are opened lazily
on first read or prefetch, so a device fully covered by the ondemand warmup
pays no extra metadata fetch at mount time.

Redirect prefetch is itself parallelized when the ondemand blob is larger than
one segment and more than one worker thread is configured. The block group list is
split into segments of up to 16 MiB uncompressed each and fetched concurrently
by the prefetch worker pool, with one twist: the earliest block groups are emitted as
single-block group segments (a "ramp") so they land in the first wave of workers
within a single round trip — ahead of the workload's first page faults — while
the rest are bundled into full-size segments for throughput. A small ondemand
blob (fitting in one segment) or a single-thread pool streams sequentially,
since segmentation and extra registry connections would add overhead without
overlapping any work. In a cold-registry container start benchmark this
parallel ramped prefetch cut end-to-end start time from 32.6s to 25.0s.

### Cross-process cache sharing and prefetch dedup

Many identical instances cold-starting on one node (for example, dozens of
hypervisor-embedded cores mounting the same optimized image) all target the
same cache directory, the same blobs, and the same access-ordered hot set.
Without coordination each instance would stream the whole ondemand blob and
decode every block group independently — N× the backend traffic, decode CPU, and
cache writes for identical bytes. Two mechanisms make the warmup effectively
single-instance while leaving the on-demand read path untouched.

**Shared block_block_group_map bitmap.** The `<digest>.group.map` file is a 4096-byte header
followed by one readiness bit per blob_meta block group. The header carries the
8-byte ASCII magic `LPGRPMAP` (same raw-bytes style as the blob meta's
`LPBLMETA`), an informational little-endian `u32` format generation (not gated
on, like the other formats), a mutable `flags` word (the same
`magic + version + flags` prefix as the blob meta header — but here the flags
are runtime state bits, not format features, and unknown bits are ignored),
the block group count, and a mutable ready-block group counter; the rest of the header
page is reserved and zero. The whole file is mapped `MAP_SHARED`
and every bit access goes through atomic operations (`Acquire` loads,
`fetch_or` with `AcqRel` to set), so `set_ready` updates made by one process
are immediately observed by every other process sharing the cache directory
through the shared page cache — no reopen, no polling, no IPC. Modeled on the
nydus chunk-state `PersistMap`. Two details matter for concurrent creation and
crash safety:

- Racing creators run the same idempotent sequence (`set_len` to the expected
	size, then write the identical header bytes). The window where one process
	maps a fully sized but still all-zero header is detected at open and healed
	by rewriting the header; a non-zero header with a wrong magic is rejected as
	corrupt instead of silently reinitialized.
- Bits are set only after the decoded, CRC-validated block group bytes have been
	written to the cache data file, and persistence rides on regular kernel
	writeback of the dirty mapping — there is no per-bit write syscall on the hot
	path.

`is_all_ready()` is the O(1) fast path: the process that flips the last
missing bit (tracked by the shared ready counter) latches the sticky
`ALL_READY` flag in the header, and from then on a single atomic load answers
"is this blob fully cached?" for every process. Per-event handlers — uffd page
faults, FUSE reads — consult it before any
per-block group bookkeeping (`ensure_range` and `ready_ranges` short-circuit on it),
so a fully warmed blob costs one load per request instead of a bitmap walk.
`check_all_ready()` falls back to scanning the shared bitmap (masking the partial
final byte) when the flag is not yet set, and latches the flag when the scan
proves completion — this also heals the rare counter skew left by a process
that died between setting the last bit and bumping the counter, as does the
same reconciliation at every `open`. A successful `prefetch_all` additionally
runs this authoritative scan before returning, so once a full prefetch
completes, `is_all_ready` is guaranteed to answer true even in the presence of
historical counter skew.

**Per-blob prefetch flock.** Blob-level prefetch — and only prefetch — is
serialized across processes with an exclusive `flock` on
`<digest>.prefetch.lock`, taken at the top of the per-blob prefetch entry point
(modeled on the nydus blob prefetcher):

- The lock is polled non-blocking with a 1s sleep between attempts, so a waiter
	can observe progress while it waits: a waiter on a regular blob gives up on
	the lock as soon as the shared block_block_group_map reports every block group ready (its own
	prefetch then reduces to a cheap all-ready scan).
- Locking failures (unopenable lock file, unexpected errno) degrade to
	prefetching without the lock — correctness never depends on it, only the
	cross-process dedup guarantee does.
- The guard is the open file descriptor: dropping it — including by process
	death — releases the lock, so a crashed owner is taken over by a waiter, and
	the ready-skip logic resumes the warmup exactly where the crashed owner left
	off.
- **On-demand reads never touch the prefetch lock.** A cold block group hit by a page
	fault is never queued behind a whole-blob warmup; it coordinates at block group
	granularity instead, on its own lock file (below).

**Per-block group fetch claim.** On-demand reads coordinate at block group granularity on
`<digest>.flight.lock`, where byte `N` stands for block group `N` — one descriptor per
blob however many block groups it has. A reader that finds a block group cold claims its
byte, and readers in the other instances block until the claim is released,
which the fetcher does immediately after publishing the block group in the shared
block_block_group_map. Waiters therefore re-check readiness and almost always find the block group
already there, so a cold block group costs one backend fetch per node rather than one
per instance.

- The claims are **open file description locks**, so the kernel releases them
	when the descriptor closes, including on process death. A fetcher that crashes
	mid-flight hands the block group to a waiter instead of wedging it.
- Waiting blocks in the kernel rather than polling, so the handover follows the
	release immediately. What bounds the wait is the fetcher, not the waiter:
	every backend read carries a timeout (hence the short registry `timeout`
	default), so a claim is always released. **A claim must never be held across
	an operation that cannot time out** — what queues up behind it are reader
	threads. The wait is interruptible, so shutdown still works.
- The in-process fetch flight elects a single fetcher per block group before any of
	this, which is what makes a descriptor-owned lock meaningful: two threads
	locking the same byte through one descriptor would both succeed and neither
	would wait.
- A filesystem that cannot provide the lock degrades to fetching without
	coordination, exactly as before this existed — a missing optimisation must
	never fail a read.

**Redirect segment skipping.** A waiter that eventually acquires the lock (or a
restart replaying the warmup) must not re-download the ondemand blob just to
discover every fill is a no-op: the parallel redirect stream accepts a `skip`
predicate that consults the **source** blobs' shared block_block_group_maps, and any segment
whose block groups are all already resident is not fetched at all. Partially-done
segments are still fetched whole to keep backend reads contiguous.

Measured on one node with the shared cache directory (cold registry, optimized
image): with 10 concurrent cold starts exactly one instance acquired the lock
and streamed the ondemand blob (≈230 MB, 222 block groups filled) while the other
nine did zero prefetch backend reads (only 0–5 MB of early on-demand faults
each, thousands of shared-cache hits); with 50 concurrent cold starts the
cache grew to the same ≈900 MB a single instance produces and end-to-end
application readiness stayed at the single-instance baseline (24–27s across
all 50, vs ≈25s for one).

## Core (virtio-pmem integration)

`nydus_core::NydusCore` is
the library entry point for hypervisors
that mount the nydus image inside the guest as a plain EROFS
filesystem over virtio-pmem, instead of using `nydus fuse` on the host. The
`nydus uffd` service builds its flattened device and on-demand fetch path on
the same core; see [Nydus UFFD Service and Wire Protocol](uffd.md). The
`nydus nbd` service serves the same flattened view through the kernel NBD
driver; see [Nydus NBD Service](nbd.md). The `nydus ublk` service serves it
through `ublk_drv` over `io_uring`; see
[Nydus ublk Block Device Target](ublk.md).

- The bootstrap is the EROFS primary device; each data blob is an external
	device backed by its host cache data file (`{cache_dir}/{hex}.blob.data`),
	which mirrors the dense decoded block address space — a guest read of block
	`N` lands at byte `N * 4096` of the backing file.
- `NydusCore::new(bootstrap, Config)` parses the bootstrap and an already
	loaded `nydus_config::Config` (same structure as `nydus fuse --config`) lazily;
	per-blob work (blob meta download/validation, sparse cache file creation)
	happens on first touch through `blobs.prepare_all()` or `blobs.fetch`.
- Unless `config.prefetch.scope` is `none`, `new` spawns a background prefetch
	worker before returning — the same two-phase workflow as `nydus fuse`
	(redirect blob first, then the rest only under `prefetch.scope: all`). The worker
	thread inherits the network namespace active at construction time, so
	callers that construct the core for a guest-facing backend must do so
	while the desired netns is active.
- Access traces are recorded on actual backend fetches (not cache hits), and
	`nydus_telemetry::metrics::snapshot()` exposes runtime counters for embedding
	into hypervisor stats endpoints; a saved trace JSON can be replayed offline
	via `nydus optimize --trace-file`. See [Metrics](#metrics).
- `BlobId` is the public blob digest type. It converts to/from 64-character
	SHA256 hex strings and `[u8; 32]` bytes.
- `blobs.prepare_all()` lists the device table in order as `BlobInfo` entries:
	blob index, `BlobId`, block count, cache path, cache size, and whether the
	blob is an ondemand redirect blob. Calling it prepares the sparse cache data
	files, so `BlobInfo.cache_path` is immediately suitable as a virtio-pmem
	backing file and `BlobInfo.cache_size` is `blocks * 4096`.
- `blobs.fetch(id, offset, len)` guarantees the 4 KiB-aligned range is decoded,
	CRC-validated, and resident in the cache data file. It maps the range to
	blob meta block groups with the O(1) division lookup and reuses the regular cache
	chain (`ensure_block_group`), so it is idempotent, concurrency-safe, and shares
	trace/metrics recording with the FUSE path. Redirect blobs are rejected.
- `fs.open(path)` resolves a path once and returns a `Node`; use
	`node.metadata()`, `node.read_dir()`, `node.read()`,
	`node.read_at(...)`, `node.read_link()`, and `node.xattrs()` for
	metadata/data access without FUSE. Holding the node avoids repeated path
	resolution and is the only filesystem API surface.

Complete example:

```rust
use std::path::Path;

use nydus_config::Config;
use nydus_core::NydusCore;

fn wire_nydus_image(bootstrap: &Path, config_path: &Path) -> nydus_error::Result<()> {
	// Load the same YAML schema accepted by `nydus fuse --config`.
	let config = Config::from_file(config_path)?;
	let core = NydusCore::new(bootstrap, config)?;

	// Materialize every blob cache file before creating guest pmem devices.
	// The vector is in bootstrap device-table order; `index` is the 1-based
	// EROFS external-device index used by chunk indexes.
	let blobs = core.blobs.prepare_all()?;
	for blob in &blobs {
		println!(
			"blob index={} id={} blocks={} cache={} bytes={} redirect={}",
			blob.index,
			blob.id,
			blob.blocks,
			blob.cache_path.display(),
			blob.cache_size,
			blob.is_redirect,
		);

		// Hypervisor wiring point:
		//   - map `bootstrap` as the EROFS primary device;
		//   - map `blob.cache_path` as the virtio-pmem backing file for
		//     external device `blob.index`, sized to `blob.cache_size`.
	}

	// Prepare a range before the guest touches it. The range must be 4 KiB
	// aligned; fetch expands to whole blob-meta block_groups internally and is
	// safe to call repeatedly or concurrently.
	if let Some(blob) = blobs.iter().find(|blob| !blob.is_redirect) {
		core.blobs.fetch(&blob.id, 0, 4096 * 16)?;
	}

	// Static filesystem inspection without FUSE. Resolve a path once and
	// reuse the Node for hot loops.
	let file = core.fs.open("path/to/file")?;
	let meta = file.metadata()?;
	println!("ino={} size={} mode={:o}", meta.ino, meta.size, meta.mode);

	let mut buf = vec![0u8; 128 * 1024];
	let n = file.read_at(0, &mut buf)?;
	println!("read {n} bytes");

	let root = core.fs.open("/")?;
	for entry in root.read_dir()? {
		println!("{} {:?} ino={}", entry.name, entry.file_type, entry.ino);
	}

	Ok(())
}
```

The core needs neither FUSE nor the CLI stack: it lives in the
standalone `nydus-core` crate (`nydus-core/`). Depending on `nydus-core`
produces a minimal library surface (no fuser/hyper/tokio-server/clap)
suitable for embedding; enable the registry backend with
`--features nydus-backend/backend-registry` when blobs are served from an
OCI registry. See [Crate Architecture](#crate-architecture) for how the
library crates layer.

## Merge Design

The current merge pipeline is:

1. Normalize each source into a metadata view.
2. Overlay layer trees in order.
3. Apply OCI whiteout rules.
4. Reassign merged NIDs.
5. Emit an overlaid bootstrap referencing the merged blob set.

## OCI Whiteout Rules

The merge implementation will follow OCI whiteout semantics:

- `.wh.<name>` removes an entry from lower layers.
- opaque directory markers hide all lower-layer children of that directory.

These rules belong in the merge metadata layer, not in build and not in mount.

## Compatibility Notes

The nydus v3 format described here is self-consistent and does not preserve
on-disk compatibility with earlier Nydus image formats (RAFS v5/v6): bootstraps
are native EROFS images rather than RAFS metadata.

EROFS compatibility is handled by exposing decoded cache data when running
compatibility checks against C erofsfuse. Compressed full blobs are Nydus runtime
artifacts and are not directly consumable as plain EROFS external devices.

## Image Conversion (nydusify)

`nydus` operates on local directories, blobs and bootstraps. `nydusify` is the
Go orchestrator that wraps `nydus` to operate on whole OCI images in a registry:
it pulls one or more sources (OCI images and/or local directories), converts
them into a nydus image, pushes the result, and can validate that the converted
image is faithful to its source. It also runs the conversion in reverse,
turning a nydus image back into a plain OCI image.

`nydusify` lives in `nydusify/` as its own Go module
(`github.com/dragonflyoss/nydus/nydusify`) and shells out to the `nydus`
binary for the actual filesystem work (`nydus build`, `nydus merge`,
`nydus check`, `nydus fuse`).

```text
        nydusify convert                         nydusify check
        -----------------                         ---------------
  registry --pull--> content store          registry --pull--> content store
  and/or local directory sources                         |
              |                              manifest / bootstrap / filesystem
   per layer / per dir: nydus build                      rules
              |                                          |
   all blobs: nydus merge                            pass / fail
              |
  registry <--push-- nydus image

        nydusify convert --compressor oci-gzip|oci-zstd|oci-tar
        --------------------------------------------------------
  registry --pull--> content store
              |
   per blob layer: nydus export, then recompress
              |
  registry <--push-- OCI image
```

### Image format

A converted nydus image reuses the nydus on-wire manifest layout so existing
nydus-aware snapshotters and tooling can consume it (see
`pkg/nydus/constants.go`):

- Each OCI data layer becomes one nydus **blob** layer with media type
  `application/vnd.oci.image.layer.nydus.blob.v1`, annotated with
  `containerd.io/snapshot/nydus-blob`. A nydus full blob is uncompressed at the
  layer level, so its diff id equals the blob digest.
- One extra **bootstrap** layer is appended last as a gzip tarball containing
  `image/image.boot`, annotated with `containerd.io/snapshot/nydus-bootstrap`.
- The ondemand blob appended by `nydusify optimize` is a nydus blob layer that
  additionally carries `containerd.io/snapshot/nydus-blob-optimized`. It holds a
  rearranged copy of data already present in the other blobs and describes no
  filesystem tree of its own, so consumers that walk the layers (such as the
  reverse conversion) can tell it apart without parsing the blob.
- The platform manifest is marked with the
  `nydus.remoteimage.v1` OS feature to flag it as a lazy-loadable remote image.
- Only `RootFS.DiffIDs` and `History` are rewritten in the image config; all
  runtime-relevant config fields (env, cmd, entrypoint, working dir, os,
  architecture) are preserved verbatim.

Putting the pieces together, a converted nydus image looks like:

```text
nydus image (OCI manifest, os.features: ["nydus.remoteimage.v1"])
+--------------------------------------------------------------------+
| config      diff_ids / history rewritten; runtime fields verbatim  |
|--------------------------------------------------------------------|
| layer 0     nydus blob layer   ...nydus.blob.v1   <- OCI layer 0   |
| layer 1     nydus blob layer   ...nydus.blob.v1   <- OCI layer 1   |
|  ...        (one full blob per source OCI layer                    |
|             or per local directory source)                         |
| layer N     bootstrap layer    gzip tar { image/image.boot }       |
|             = merged overlaid bootstrap referencing layers 0..N-1  |
+--------------------------------------------------------------------+
           |
           |  each blob layer is one full blob; layer digest =
           |  SHA256(full blob) (uncompressed layer, diff id = digest)
           v
+--------------------+-------------+-----------+--------+
| encoded data       | bootstrap   | blob meta | footer |  full blob
| (zstd block_groups,      | (embedded   | (chunk +  | 4 KiB  |
|  CRC32C each)      |  EROFS)     |  block_group)   |        |
+--------------------+-------------+-----------+--------+
  SHA256(data region) -> device slot blob id in the bootstrap
```

The merged `image.boot` in the bootstrap layer carries one device slot per
blob layer, so mounting needs only that bootstrap plus on-demand range reads
into the blob layers.

### Subcommand mapping

`nydusify` does not reimplement any filesystem logic; each high-level image
operation is composed from the lower-level `nydus` subcommands plus registry
pull/push:

| `nydusify` | Underlying `nydus` subcommands | Registry |
| --- | --- | --- |
| `convert` | `nydus build` (per OCI layer / per directory source) + `nydus merge` (all blobs) | pull sources, push target |
| `convert --compressor oci-*` | `nydus export` (per blob layer) | pull source, push target |
| `check` | `nydus check` (bootstrap rule) + `nydus fuse` (filesystem rule) | pull source and/or target |

The `--builder` flag selects which `nydus` binary is invoked for all of the
above, so `nydusify` and `nydus` versions can be pinned together.

### convert

`nydusify convert --source <oci-ref|dir> [--source <oci-ref|dir> ...] --target <ref> [OPTIONS]`

Converts an image between OCI and nydus format and pushes it to the target
reference. `--compressor` picks the direction: `none` and `zstd` are nydus chunk
compressors and run the OCI to nydus conversion, while the `oci-` prefixed
values run the reverse and select the layer compression of the rebuilt OCI
image. An unknown value is rejected up front rather than silently running the
wrong direction.

#### OCI to nydus

A source is either an OCI image reference (pulled into a local content store) or
a local directory path (built directly with `nydus build`).

With a single image source, the classic whole-image conversion runs (all
platforms by default). With a single directory source, a one-layer nydus image
is built from the directory tree. When `--source` is repeated, the sources are
stacked in order (first is lowest) into **one** nydus image: every directory
contributes one blob layer, every image contributes its layers as blob layers
(existing nydus blob layers are reused as-is and a pre-merged bootstrap is
dropped), and a single `nydus merge` over all blobs produces the one bootstrap
layer covering the whole stack.

Pipeline (single image source):

1. Pull `--source` into a scratch content store
   (`internal/remote`, backed by containerd's local content store).
2. For each OCI layer, extract its rootfs (decompressing gzip/zstd, resolving
   whiteouts) and run `nydus build` with the configured `--chunk-size`,
   `--block-group-size` and `--compressor`. The build output is streamed straight
   into the content store through a FIFO, so the full blob is never staged on
   disk twice (`internal/pipeline/layer.go`).
3. A post-convert index hook runs `nydus merge` over the per-layer blobs to
   produce the overlaid bootstrap, which is written back as the final bootstrap
   layer (`internal/pipeline/hook.go`).
4. Push the rewritten manifest and all new layers to `--target`
   (`internal/remote`).

Pipeline (multiple and/or directory sources, `internal/pipeline/multi.go`):

1. Pull each image source; directory sources are used in place.
2. Per source, produce nydus blob layers: `nydus build` on each directory,
   per-layer conversion for OCI image layers, pass-through for layers that are
   already nydus blobs.
3. Stage all blobs (in stacking order) and run a single `nydus merge` to
   produce one bootstrap layer for the whole stack.
4. Assemble the manifest (`[blobs..., bootstrap]`) and config. The runtime
   config (env, cmd, entrypoint, ...) is inherited from the uppermost image
   source when present; otherwise a minimal config is synthesized. Push to
   `--target`.

#### nydus to OCI

`nydusify convert --compressor oci-gzip|oci-zstd|oci-tar --source <nydus-ref> --target <oci-ref>`

Rebuilds a plain OCI image from a nydus image. Exactly one image source is
expected; directory sources and stacking do not apply.

Every nydus data layer is a self-contained full blob covering exactly one OCI
layer, so each one is unpacked on its own and the merged bootstrap is simply
dropped (`internal/pipeline/tooci.go`):

1. Pull `--source` and classify its layers by annotation. Layers carrying
   `nydus-bootstrap` or `nydus-blob-optimized` describe no filesystem tree and
   are dropped; the remaining nydus blob layers are the data layers. A manifest
   that is not a nydus image is rejected.
2. For each data layer, materialize the blob (the exporter memory-maps it), run
   `nydus export` and pipe the tar into the configured
   compressor and into the content store, hashing the uncompressed stream on the
   way through to get the diff id. Layers are independent, so they are unpacked
   concurrently up to `GOMAXPROCS`; each concurrent layer stages a full blob
   copy in `--work-dir`.
3. Rebuild the config and manifest: fresh diff ids, the `nydus.remoteimage.v1`
   OS feature cleared, the bootstrap layer removed, and the history entries of
   the removed layers trimmed. Runtime config fields are preserved verbatim.
4. Push to `--target`.

Layer media types follow the compressor: `oci-gzip` produces
`application/vnd.oci.image.layer.v1.tar+gzip`, `oci-zstd` produces
`...tar+zstd`, and `oci-tar` produces the uncompressed `...tar`.

Two properties do not survive the round trip:

- **Layer digests change.** The rebuilt tar is not a byte-for-byte copy of the
  original layer, so its diff id (and therefore the config and manifest digest)
  differs from the image the nydus one was converted from. Content and file
  metadata do round-trip.
- **Files bundled with `--append-in-bootstrap` are lost.** They only ever
  existed in the bootstrap layer, which the reverse conversion drops.

Flags:

| Flag | Default | Description |
| --- | --- | --- |
| `--source`, `-s` | required | Source OCI image reference or local directory path. Repeatable; multiple sources are stacked in order (lower to upper) into one image. Converting back to OCI takes exactly one image source. |
| `--target`, `-t` | required | Target image reference to push. |
| `--builder` | `nydus` | Path to the `nydus` binary (PATH-resolvable). |
| `--work-dir` | temp dir | Scratch directory; a temp dir is created and removed when omitted. |
| `--chunk-size` | `1048576` | Nydus file chunk size in bytes (1 MiB). Ignored when converting back to OCI. |
| `--block-group-size` | `4194304` | Blob meta block group uncompressed size in bytes; a power of two, at least 1 MiB and at least `--chunk-size`. Ignored when converting back to OCI. |
| `--compressor` | `zstd` | Direction and compression. `none`/`zstd`: chunk data compressor for OCI to nydus. `oci-gzip`/`oci-zstd`/`oci-tar`: layer compression of the rebuilt OCI image for nydus to OCI. |
| `--platform` | all | Convert only the given platform (e.g. `linux/amd64`). |
| `--append-in-bootstrap` | empty | Local file paths to bundle into the bootstrap layer tar alongside `image.boot`; files inside a directory source are excluded from that source's blob data region. |
| `--insecure` | `false` | Skip TLS verification for the registry. |
| `--plain-http` | `false` | Use plain HTTP to talk to the registry. |
| `--log-level` | `info` | `trace`, `debug`, `info`, `warn`, `error`. Forwarded to the `nydus build`/`merge` subprocesses. |

Notes:

- Converting an **OCI image** source requires **root privileges**. Layer
  extraction must preserve original uid/gid, setuid/setgid/sticky bits, xattrs
  and device/fifo nodes; these operations fail without root, and `nydusify`
  treats such failures as fatal rather than silently producing a corrupted
  image. Directory sources and already-nydus image sources do not need root.
- Multiple sources are merged into one single-platform manifest, so image
  sources are resolved against exactly one platform: `--platform`, or the host
  platform when omitted.
- Converting back to OCI needs no root: it only reads blobs and writes tar
  streams, it never materializes a rootfs.
- Image references are normalized like a container runtime: a bare name such as
  `mariadb` expands to `docker.io/library/mariadb:latest`, and a tagless
  reference defaults to `:latest`.

Examples:

```bash
# Whole-image conversion (requires root).
sudo nydusify convert \
  --source docker.io/library/mariadb:latest \
  --target localhost:5000/mariadb-nydus \
  --plain-http

# One-layer image from a local directory.
nydusify convert \
  --source ./models/llama \
  --target localhost:5000/llama-nydus \
  --plain-http

# Stack a nydus base image and two directories into one image:
# three blob layers plus one merged bootstrap layer.
nydusify convert \
  --source localhost:5000/base-nydus \
  --source ./layer-data \
  --source ./layer-config \
  --target localhost:5000/app-nydus \
  --plain-http

# Convert a nydus image back to a plain OCI image with gzip layers.
nydusify convert \
  --compressor oci-gzip \
  --source localhost:5000/mariadb-nydus \
  --target localhost:5000/mariadb-oci \
  --plain-http
```

### check

`nydusify check [--source <ref>] [--target <ref>] [OPTIONS]`

Validates the consistency of an OCI and/or nydus image. At least one of
`--source`/`--target` must be provided; the typical use is to pass both the
original OCI image and its converted nydus image to prove the conversion is
faithful.

`check` pulls each provided image into a content store, parses it (detecting OCI
vs nydus from the layer annotations), and runs the following rules in order
(`internal/checker`):

1. **manifest** — validates each manifest's structure (layer count equals diff-id
   count; for nydus images the last layer is the bootstrap and all preceding
   layers are blobs). When both images are present, it asserts their runtime
   configs are equivalent (env/cmd/entrypoint/working dir/os/architecture).
2. **bootstrap** — for each nydus image, materializes its blobs and bootstrap
   and runs `nydus check --bootstrap <b> --blob-dir <d>` to statically validate
   the metadata and verify blob digests.
3. **filesystem** — materializes both images into real root filesystems and
   compares them entry by entry. The OCI side is produced by applying its layers
   (preserving ownership); the nydus side is mounted via `nydus fuse`. The
   comparison covers, for every path:
   - file type (regular, dir, symlink, device, fifo, …),
   - permission bits **and** setuid/setgid/sticky special bits,
   - uid and gid,
   - symlink target,
   - device major/minor (`rdev`) for device nodes,
   - extended attributes (names and values, skipping the `system.*` namespace),
   - content (size + sha256) for regular files.

   Missing, extra or mismatching entries fail the check.

The filesystem rule requires **root privileges** (both the FUSE mount and the
OCI layer ownership replay need root) and is skipped automatically when only one
of `--source`/`--target` is given. Running non-root fails fast with a clear
message instead of silently timing out on the mount.

Flags:

| Flag | Default | Description |
| --- | --- | --- |
| `--source`, `-s` | empty | Source image reference (OCI or nydus). |
| `--target`, `-t` | empty | Target image reference (OCI or nydus). |
| `--builder` | `nydus` | Path to the `nydus` binary. |
| `--work-dir` | temp dir | Scratch directory; created and removed when omitted. |
| `--platform` | host | Check only the given platform; defaults to the host platform. |
| `--insecure` | `false` | Skip TLS verification for the registry. |
| `--plain-http` | `false` | Use plain HTTP to talk to the registry. |
| `--log-level` | `info` | `trace`, `debug`, `info`, `warn`, `error`. Forwarded to the `nydus fuse` subprocess (use `debug` to see per-request backend reads). |

Example:

```bash
sudo nydusify check \
  --source docker.io/library/mariadb:latest \
  --target localhost:5000/mariadb-nydus \
  --plain-http
```

A passing run logs `check passed`; any rule failure returns a non-zero exit code
with the failing rule and offending path in the error.

### nydusify optimize

`nydusify optimize --pattern <path> --source <nydus-ref> --target <nydus-ref> [OPTIONS]`

Publishes an optimized copy of a nydus image from a recorded access pattern:

1. Pull `--source` (must be a nydus image) and extract its bootstrap layer
	(`image.boot` plus the per-layer blob metas, which seed the cache dir).
2. Run `nydus optimize` against the bootstrap with `--trace-file`, using a
	registry-backed storage config so source block group data is range-read from the
	source registry on demand.
3. Assemble the optimized manifest: the original data layers are reused as-is,
	the ondemand blob is appended as a new nydus data layer (annotated with
	`containerd.io/snapshot/nydus-blob-optimized` so it is recognizable without
	parsing it), and the bootstrap layer is rebuilt with the rewritten
	`image.boot` plus all blob metas (including the ondemand one). Config diff
	ids and history are updated.
4. Push the result to `--target`.

`--pattern` is a JSON access-pattern file in the same format served by a
mount's `GET /trace` endpoint
(`{"version":1,"patterns":[{"blob_index":1,"block_group_index":4},...]}`). It can be
saved from the `/trace` endpoint of a `nydusify mount` apiserver, or exported
offline from a pmem/core mount trace (e.g. a rund sandbox extendedstats
snapshot). Record the pattern from a mount **without** prefetch so it captures
the pure on-demand access pattern, exercise the workload, then save the trace.
Mount the optimized image **with** `--prefetch` to get the phase-0 redirect
warmup. Shared flags (`--builder`, `--work-dir`, `--platform`, `--insecure`,
`--plain-http`, `--log-level`) behave as in `nydusify convert`. No root is
required: optimize never extracts OCI layers, it only rewrites metadata and
appends the ondemand layer.

Example:

```bash
nydusify mount -t localhost:5000/app:nydus -m /mnt/app --work-dir /tmp/mnt &
# ... run the workload against /mnt/app ...
curl --unix-socket /tmp/mnt/apiserver.sock http://localhost/trace > /tmp/pattern.json
nydusify optimize \
  --pattern /tmp/pattern.json \
  --source localhost:5000/app:nydus \
  --target localhost:5000/app:nydus-optimized \
  --plain-http
```

## Validation Strategy

The current validation surface is:

1. Rust compile checks for CLI, build, metadata, storage and mount wiring.
2. Unit coverage for blob_meta parsing, blob-id/device-slot helpers, local backend
	lookup, cache validation, and build-time compression decisions.
3. Integration tests for build full blob, build standalone bootstrap, direct
	blob mount, bootstrap plus blob-dir mount, cache artifact naming, merge, OCI
	whiteouts, and optional erofs-utils compatibility.
4. Round-trip coverage for the reverse conversion: `nydus export`
	against a freshly built blob at the unit level, and an image-level
	test that pushes a multi-layer OCI image, converts it to nydus and back for
	every `oci-` compressor, and diffs the nydus mount against the rebuilt OCI
	rootfs with `nydusify check`.
5. xfstests and fio-backed performance checks for mount behavior.

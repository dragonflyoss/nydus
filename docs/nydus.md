# Nydus Design

Current contract for this branch. Start at the
[documentation index](../README.md#documentation) for the EROFS format and
transport guides.
The private `.blob.meta` and footer layouts carry no version: compatibility is
decided by feature bits, and older development layouts are unsupported.

## Status

This document describes the current nydus artifact model, blob meta format and
runtime read path.

The user-facing commands are:

- `nydus build`
- `nydus export`
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
- Keep EROFS file chunk indexes logical and map a block to its compression chunk
	group in O(1): groups tile the address space back to back, and a small
	ChunkGroupIndexTable names the group with a direct lookup and one compare,
	so no index is derived at open and no lookup scans.
- Support compressed blob data while preserving a plain decoded cache artifact
	for EROFS compatibility and repeated reads.

## Non-goals

- Preserve on-disk compatibility with earlier Nydus image formats (RAFS v5/v6).
- Introduce chunk-content or cross-layer global deduplication.
- Lazily load native `erofs-*` layers through the nydus daemons: they are
	block-device artifacts the kernel mounts directly.
- Rework the full EROFS on-disk layout to match every upstream variant.

## Kernel Compatibility and Format Limits

The generated FS version 7 bootstrap targets upstream Linux 5.16 EROFS
metadata with 4 KiB blocks, using CHUNKED_FILE and DEVICE_TABLE incompat
features. It does not use 48BIT addresses or compact-inode time deltas.
This is a metadata baseline, not a claim that every mount transport works on
Linux 5.16. Kernel configuration, vendor backports, architecture and page size
also matter; the minimum-version validation environment is x86_64 with 4 KiB
pages.

| Capability or path | Upstream requirement | Reason |
| --- | --- | --- |
| Extended 64-byte inode | 4.19 staging, supported in formal EROFS 5.4 | Stores full per-inode timestamps and wider ownership/size fields |
| Chunk-based regular files | 5.15 | Interprets chunk indexes rather than a contiguous file extent |
| Bootstrap with explicit extra block devices | 5.16 | DEVICE_TABLE and `device=` support resolve the referenced decoded data devices |
| Flattened NBD, ublk, or PMEM image | 6.4 | flatdev maps logical extra devices into the primary device using mapped block addresses; the ublk driver itself first appeared in 6.0 |
| Nydus FUSE | No kernel EROFS requirement | Nydus parses metadata in userspace; FUSE support is still required |
| Fanotify-backed EROFS | 6.15+ and the mode's kernel configuration/capabilities | Pre-content fanotify events service on-demand data before kernel reads |

For PMEM/RunD, the EROFS requirement applies to the guest mounting the device.
Host UFFD, PMEM and device prerequisites are separate. Linux 5.16 native tests
must use explicit decoded extra devices, not the flattened single-device path.
Compressed Nydus full blobs are not raw EROFS extra devices.

Each bootstrap or decoded external device has at most `u32::MAX` blocks:
`(2^32 - 1) * 4096 = 17,592,186,040,320` bytes, or **16 TiB minus 4 KiB**.
This is not a compressed-blob size limit or a global limit on the sum of layers.
Each device's mapped start is independently limited to `u32::MAX` blocks,
including after alignment. A representable mapped start plus device size may
exceed 32 bits; range calculations remain checked in 64 bits.

Ordinary chunk addresses range from `0` through `0xfffffffe`. The low-word
value `0xffffffff` denotes a hole; unused high fields are zero. Constructors,
writers and bootstrap layout reject unrepresentable values instead of
truncating them or enabling newer features. Readers reject 48BIT and
unsupported chunk formats. A failed build does not finalize its output or
write success sidecars; bytes already written to a direct file/FIFO may remain.

Compact inodes use exactly the superblock's shared timestamp. Build, merge and
optimize choose the most frequent mtime among distinct output inodes with zero
nanoseconds that otherwise fit compact size, ownership and link-count fields.
Ties choose the smallest seconds value; no candidates yields zero. Selection
uses the final flattened tree, so hidden lower-layer inodes do not vote.
With `fixed_nsec = 0`, any inode with different
seconds or nonzero nanoseconds uses the extended format before layout is
allocated. Build, merge, optimize and export preserve full timestamps, except
for the existing intentional normalization of the source root to zero. Reserved
compact time bytes are zero on output and are never decoded as a time delta.

A non-inline symlink does not require an extended inode by itself: both header
formats store its checked 32-bit data-block address. Header selection still
respects size, ownership, link count and timestamp constraints; inline capacity
uses the selected header size together with xattrs.

No compatibility with older development images is retained. Rebuild affected
images and derived caches when the format changes; there is no format guessing,
legacy decoder or migration fallback. Later upstream 48BIT and compact-time
extensions first appeared in 6.15 and are deliberately not used here. The later
extra-device high-field repair is likewise not a minimum-version dependency.

Version references:

- [Linux 4.19 staging inode layout](https://kernel.googlesource.com/pub/scm/linux/kernel/git/torvalds/linux/+/refs/tags/v4.19/drivers/staging/erofs/erofs_fs.h)
- [Linux 5.4 inode layout](https://kernel.googlesource.com/pub/scm/linux/kernel/git/torvalds/linux/+/refs/tags/v5.4/fs/erofs/erofs_fs.h)
- [Linux 5.15 chunk format](https://kernel.googlesource.com/pub/scm/linux/kernel/git/torvalds/linux/+/refs/tags/v5.15/fs/erofs/erofs_fs.h)
- [Linux 5.16 device table](https://kernel.googlesource.com/pub/scm/linux/kernel/git/torvalds/linux/+/refs/tags/v5.16/fs/erofs/super.c)
- [Linux 6.4 flatdev mapping](https://kernel.googlesource.com/pub/scm/linux/kernel/git/torvalds/linux/+/refs/tags/v6.4/fs/erofs/data.c)
- [Linux 6.15 compact time decoding](https://kernel.googlesource.com/pub/scm/linux/kernel/git/torvalds/linux/+/refs/tags/v6.15/fs/erofs/inode.c)
- [Extra-device high-field repair](https://github.com/torvalds/linux/commit/63c2f06198ca7513433f1c92f2c654869d72417e)

The native metadata gate is `make test-e2e E2E_TEST=TestErofsKernelCompatibility`,
with root, EROFS, loop devices, util-linux and erofs-utils available. It checks
fresh, merged and optimized images using decoded devices, fsck and native
content/timestamp comparisons. CI attempts `modprobe erofs` first. The test
skips when the running kernel is older than 5.16 or EROFS is absent from
`/proc/filesystems`; both built-in and loaded-module support are accepted.
Other prerequisites remain mandatory on supported kernels. A skipped test is
not native compatibility validation.

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
| `nydus-storage` | data | Local cache and reuse: `LocalBlobCache` (chunk group decode, CRC, on-demand fill), `BlobCaches`, chunk group ready-bitmaps, prefetch, access tracing | `io::Result` only |
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

## Runtime Thread Model

The data-plane APIs are synchronous. A thread that calls `ErofsReader`,
`NydusCore`, `Blobs`, or `BlobBackend` remains responsible for that operation
until it completes. The layers below may use helper threads for remote I/O or
explicit prefetch, but they do not turn an ordinary read into a detached task.
This means frontend concurrency is also read concurrency: for example, a FUSE
worker that misses the cache stays blocked until the chunk group has been
fetched, decoded, verified, and stored. Concurrent callers that miss the same
chunk group are coalesced by the cache's per-group claim/wait state rather than
downloading it more than once.

### Backend thread pools

`BlobBackend` itself does not own a general-purpose thread pool. The local
backend performs file I/O directly on the caller. Remote registry and
Dragonfly HTTP backends bridge their synchronous methods into one lazy,
process-wide Tokio multi-thread runtime:

| Pool | Default | Lifetime and work |
| ---- | ------- | ----------------- |
| Async workers | 2 threads | Created when the runtime is first needed (the first remote read, or the construction of a Dragonfly-backed registry) and retained for the process lifetime. Each request future is spawned onto them, so DNS and TCP connect happen on a runtime thread; they also drive HTTP sockets, timers, and connection-pool futures while the synchronous frontend caller waits for the result. |
| Blocking workers | Up to 8 threads | Created by Tokio on demand for blocking DNS resolution (`getaddrinfo`). Idle threads are released after 10 seconds. Blob reads, decompression, verification, and cache writes do not run in this pool. |

The registry `http.worker_threads` and `http.max_blocking_threads` settings
override these defaults. The runtime is shared by every registry backend in a
process, so configuration is first-writer-wins and must be applied before the
first registry backend is constructed. Repeating the same configuration is
harmless; a conflicting late configuration is rejected and logged. Embedders
may instead call `nydus_backend::configure_runtime` before constructing any
backend, including an optional network namespace that every runtime thread
enters; because requests run on those threads, registry sockets are created in
that namespace regardless of the caller's. A process using only local blobs
never creates this Tokio runtime.

### `nydus-core` API

`nydus-core` has no request executor or implicit read pool. Construction,
metadata lookup, path walking, range probing, and on-demand fetch all execute
synchronously on the calling thread. Callers choose the concurrency model by
calling the shared `NydusCore`/`ErofsReader` from their own FUSE, NBD, ublk,
fanotify, UFFD, or VMM workers. Internal locks protect shared lazy state and
serialize publication of a chunk group without serializing unrelated groups.

The exception is configured prefetch. `NydusCore::new` starts one detached
`nydus_prefetch` coordinator when `prefetch.scope` is not `none`. Depending on
the scope and image, that coordinator creates transient cache-open and fetch
worker pools, each bounded by `prefetch.concurrent_blob_count`. Under ondemand
prefetch the two pools can overlap, so this setting is a per-pool concurrency
bound rather than a total thread cap. These workers are joined by the
coordinator. The core keeps a stop flag rather than a join handle: dropping it
requests a cooperative stop, so teardown does not wait for an in-flight
backend request. The standalone FUSE path builds `ErofsReader` directly and
starts the same prefetch workflow after mounting; its prefetch threads are
independent of the FUSE request workers.

### Nydus FUSE

`nydus fuse` sets `fuser::Config::n_threads` from the hidden `--threads`
option (or `NYDUS_FUSE_THREADS`). The default is the host's available
parallelism clamped to 4 through 16. `fuser` then creates:

- one `fuser-bg` session thread, which owns the background session and waits
	for its event loops; and
- exactly `n_threads` `fuser-N` request threads. Each thread reads from its
	cloned FUSE file descriptor and executes the corresponding `ErofsFs`
	callback synchronously. There is no additional callback queue or I/O pool.

Consequently, at most `n_threads` FUSE callbacks can run at once, and a cold
read occupies one of those workers while the synchronous cache/backend path
completes. Metadata requests and cache hits use the same workers. The FUSE
service also creates two lifecycle threads which are not request workers:
`nydus_fuse_signal` waits synchronously for termination signals, while
`nydus_fuse_controller` owns unmount and session join. The command's main
thread waits for the controller result.

Optional facilities add their own independent threads: enabled prefetch uses
the model above, the metrics API server runs a current-thread Tokio runtime on
one dedicated OS thread, and non-blocking tracing writers have their own drain
workers. None of these increases FUSE callback concurrency. On non-Linux
platforms, `fuser` supports only one request thread and rejects a larger
`n_threads` value.

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

The `nydus build` command builds a source into the nydus EROFS format, in
either image layout: `--blob` writes the single-file image, `--blob-dir`
deposits the full blob into a store (see Image layouts above), and
`--bootstrap` additionally emits the standalone metadata-only entry point.
The source is a directory (`--source-type dir`, the default) or one OCI layer
tarball (`--source-type tar`), see [Sources](#sources) below. The reverse
direction — turning a nydus full blob back into an OCI layer tar stream — is
`nydus export` (see below).

Current CLI help:

```bash
nydus build -h
Build a nydus filesystem image

Usage: nydus build [OPTIONS] <--blob <BLOB>|--blob-dir <BLOB_DIR>> <SOURCE>

Arguments:
	<SOURCE>  Specify the source to build the nydus image from: a directory (--source-type dir) or one OCI layer tarball, gzip or plain (--source-type tar)

Options:
	--source-type <SOURCE_TYPE>
		Specify the source type. tar stream-converts one OCI layer tarball: file data is written to the blob as the tar is read, no rootfs is staged on disk, and whiteout entries are kept for the merge subcommand [env: NYDUS_BUILD_SOURCE_TYPE=] [default: dir] [possible values: dir, tar]
	--blob <BLOB>
		Specify the file path to save the image as a single self-contained full blob; if the path is an existing FIFO the blob is streamed into it [env: NYDUS_BUILD_BLOB=]
	--blob-dir <BLOB_DIR>
		Specify the content-addressed store directory to save the full blob into, named by its SHA256, so mounts resolve it through the bootstrap and images share the store [env: NYDUS_BUILD_BLOB_DIR=]
	--erofs-data-alignment <EROFS_DATA_ALIGNMENT>
		With an erofs-* compressor, start files of at least this size on this boundary of the layer data (a power of two multiple of 4KiB), so block-level dedup and snapshots of the volume see identical files at stable offsets, e.g. 2mib for cloud disks deduplicating at 2MiB; 0 (the default) packs files back to back [env: NYDUS_BUILD_EROFS_DATA_ALIGNMENT=] [default: 0]
	--bootstrap <BOOTSTRAP>
		Specify the file path to save the standalone bootstrap: the store layout's entry point, whose device table records each blob's SHA256 [env: NYDUS_BUILD_BOOTSTRAP=]
	--chunk-size <CHUNK_SIZE>
		Specify the file chunk size (a power of two, >= 4KiB, and 4KiB-aligned; default 2MiB) for the chunk-based layouts (none, zstd, lz4, erofs-none). Chunk groups are sized independently by --chunk-group-minimum-size: when the chunk size is smaller, full chunks are packed together. It does not apply to erofs-lz4 and erofs-zstd, whose files are pclusters. The value needs to be set with human readable format, for example: 256kib, 1mib, 2mib [env: NYDUS_BUILD_CHUNK_SIZE=]
	--chunk-group-minimum-size <CHUNK_GROUP_MIN_SIZE>
		Specify the chunk group minimum size (a power of two between 4KiB and 512MiB; default 2MiB, independent of the chunk size): every chunk group but the last of a blob spans at least this much, the granularity a content-addressed cache deduplicates at. A chunk of at least this size is a group of its own, so its compressed bytes are one frame the cache can serve by the chunk's digest alone; smaller chunks, including full chunks when the chunk size is below this minimum, are packed in order into shared groups spanning one to four times it, closed at content-defined boundaries so that near-identical images share their packs. Larger values mean fewer, larger objects and slightly better compression, smaller ones less retransmission when a few files change between image versions. It does not apply to the erofs-* compressors. The value needs to be set with human readable format, for example: 256kib, 1mib, 2mib [env: NYDUS_BUILD_CHUNK_GROUP_MINIMUM_SIZE=]
	--compressor <COMPRESSOR>
		Specify the data layout and compression. zstd, lz4 and none build chunk groups the nydus daemon fetches on demand and decodes, described by the blob meta. The erofs-* values instead build a native EROFS layer without blob meta: the full blob's data region is the raw layer device, so the store file serves as a device= of a kernel block-device mount and the nydus daemons never fetch it on demand. erofs-none stores the chunks uncompressed at their block addresses; erofs-lz4 and erofs-zstd compress file data into native LZ4 or zstd pclusters the kernel decompresses (64KiB pclusters, files up to 64KiB packed into the shared fragment inode; kernel mounts need 6.1+ for erofs-lz4 and 6.10+ for erofs-zstd). --digester does not apply to the erofs-* values [env: NYDUS_BUILD_COMPRESSOR=] [default: zstd] [possible values: none, zstd, lz4, erofs-none, erofs-lz4, erofs-zstd]
	--digester <DIGESTER>
		Specify the digest algorithm recorded in the blob meta, one digest per chunk group (a lone chunk's content digest, or a BLAKE3 derived from the member chunks' digests for a pack); "none" records no digests and skips hashing, for content already verified upstream [env: NYDUS_BUILD_DIGESTER=] [default: blake3] [possible values: blake3, none]
	--blob-id <BLOB_ID>
		Name the blob with this 64-hex id (e.g. the OCI layer digest) instead of its SHA256, skipping the data and full-blob hashing; with --blob-dir an existing entry of that name is replaced. Only local stores resolve such blobs (the id is the file name under --blob-dir); a registry serves blobs by their real digest [env: NYDUS_BUILD_BLOB_ID=]
	--exclude <EXCLUDE>
		Specify the absolute or current-working-directory-relative paths to exclude. May be specified multiple times. Entries inside the source tree are omitted from the blob and the resulting filesystem tree entirely
	-l, --log-level <LOG_LEVEL>
		Specify the logging level [trace, debug, info, warn, error] [env: NYDUS_BUILD_LOG_LEVEL=] [default: info]
	-h, --help
		Print help (see more with '--help')
```

Current implementation notes:

- Exactly one of `--blob` or `--blob-dir` is required (enforced at parse time).
- `--bootstrap` is optional and emits a standalone metadata-only artifact.
- `--chunk-size` defaults to `2MiB`, accepts human readable sizes (e.g. `4kib`,
	`1mib`) or plain byte counts, and sets the unit files are split into
	*chunks* at for the EROFS chunk indexes (a file of at most the chunk size
	is one chunk). A chunk is a blob meta *chunk group* of its own only
	when it reaches `--chunk-group-minimum-size`; smaller chunks are packed
	together, including full chunks when the chunk size is below the group
	minimum. Groups, not file chunks, are the unit of compression, on-demand
	fetch and cache readiness; see [Chunk groups](#chunk-groups).
	The chunk size must be a power of two of at least 4 KiB.
- `--chunk-group-minimum-size` is the one grouping knob: every chunk group
	but the last of a blob spans at least this much address space, so it is
	the granularity a content-addressed tier (a P2P cache deduplicating by
	digest) indexes at. A chunk of at least the minimum is a group of its
	own, so its compressed bytes are one frame the cache can locate and serve
	from the chunk's digest alone; smaller chunks are packed in order until
	the pack spans the minimum, at content-defined boundaries, and packs span
	at most four times it (~1.6× on average in the measured default sample). It defaults
	to `2MiB` independently of the chunk size: passing only
	`--chunk-size 256kib` packs full 256 KiB chunks into larger groups, and
	nothing but a blob's last group spans under 2 MiB. Lowering the minimum
	trades object count and compression ratio for
	retransmission: in a historical sweep of three swebench sibling images
	(order 4021, 3947, 4182; 20 unique layers built independently with zstd
	and 2 MiB chunks; additional compressed bytes keyed by group digest),
	what the 2nd / 3rd image add with a 2 MiB minimum is
	15.1 / 29.7 MiB of new groups from 1664 groups, 1 MiB 10.7 / 21.3 MiB
	from 2409, 512 KiB 9.1 / 19.9 MiB from 3583, and 64 KiB 5.4 / 10.8 MiB
	from 13945 (against ~200 MiB of new layers and a ~10 MiB floor for
	per-chunk dedup), while the blobs grow 1.7%, 3.1% and 6.0% over the
	2 MiB default, because compressing small files in small groups costs
	ratio. These are sample-specific results, not a guaranteed reduction
	for other images; the original temporary benchmark artifacts are not
	distributed with this repository. The minimum
	must be a power of two between 4 KiB and 512 MiB, and may exceed the
	chunk size. Build records it as the index span; the file format does
	not store the writer's lone-chunk threshold. Readers validate group spans
	against the index span.
- `--blob <path>` stores the full blob at `<path>` and a standalone blob meta
	copy at `<path>.blob.meta`. If `<path>` already exists and is a FIFO, build
	writes the full blob stream to that FIFO instead of creating a regular file.
- `--blob-dir` stores the full blob under `<blob-dir>/<full_blob_sha256>` and a
	standalone blob meta copy under `<blob-dir>/<full_blob_sha256>.blob.meta`.
- `--compressor zstd` (or `lz4`) compresses each chunk group on its own. If
	the compressed group is larger than 70% of its payload, the group is
	stored plain and its blob_meta entry has `compressed_size == payload_size`
	(its chunks then sit at their dense offsets).
- `--compressor none` writes every chunk group plain.
- `--exclude <path>` omits paths inside the source tree from the blob and the
	resulting filesystem tree entirely. It accepts absolute or
	current-working-directory-relative paths and may be repeated.
- Build prints one `Blobs` section grouped by `Blob N` with `blob_index`,
	`data_blob_digest`, `full_blob_digest`, `group_span`,
	`index_span`, `chunk_group_count`,
	`chunk_count`, `digest_count`, `chunk_compressor`, payload/compressed/
	uncompressed totals, and full blob region offsets and block counts.

#### Sources

- `--source-type dir` (default) walks a directory tree. Whiteouts present in an
	unpacked layer directory (OCI `.wh.` files or overlayfs character devices)
	are stored as they are; `nydus merge` applies them.
- `--source-type tar` stream-converts exactly one OCI layer tarball. The source
	is sniffed for the gzip magic and may be plain tar or gzip, and it may be a
	FIFO: nothing is seeked, so a layer can be piped in as it downloads. File
	data is chunked into the blob the moment each tar entry is read and only the
	directory tree (names, attributes, chunk indexes) is kept in memory, so no
	rootfs is ever unpacked to disk. Hardlinks resolve to the already seen
	target, PAX `SCHILY.xattr.*` records become EROFS xattrs, and `.wh.`
	whiteout entries are kept as empty regular files for `merge`. The result is
	one single-layer image per tarball; stack the layers with `nydus merge`.
	Entry types nydus cannot represent (GNU sparse, volume headers) fail the
	build rather than being dropped silently.
- `--exclude` applies to directory sources only.

#### Build speed knobs

The default build hashes every chunk with BLAKE3 and the output with SHA256
(data region, full blob). Two flags trade those guarantees for speed when the
caller already trusts the content:

- `--digester none` records no digests and skips BLAKE3 (by default every
	chunk is hashed and every chunk group gets one digest). The blob meta
	header then carries no digester bit and an empty digest table; packs then
	close only when they span four times the chunk group minimum size, since
	no digest
	marks a boundary. No
	mount path verifies digests by default (`storage.skip_verify_checksums`);
	`nydus check` reports the digester and the digest count.
- `--blob-id <64-hex>` (optionally prefixed `sha256:`) names the blob up front,
	e.g. with the OCI layer digest, and skips both SHA256 passes. The id is
	written to the device slot tag, used as the file name under `--blob-dir`
	(replacing an existing entry) and reported as both digests. Because it is
	not a digest of the bytes, only local stores can resolve such a blob by
	name; a registry serves blobs under their real digest, so do not use
	`--blob-id` for images that will be pushed. `nydus check` reports these
	slots as `named` and unverified.
- `sha2` is built with its `asm` feature (SHA2 instructions on aarch64) and
	gzip layers are inflated by zlib-ng.

#### Chunk groups

Chunk groups do not store the padded address space byte for
byte. Every regular file is cut into *chunks* of at most `--chunk-size`
bytes, each chunk starts on its own 4KiB block of the address space the
EROFS chunk indexes point into (so the bootstrap, DAX and the 5.16+ kernel
requirement are exactly as before), but the encoded stream carries the
chunks' bytes back to back, without the tail-block padding after each file
(see [Blob meta region layout](#blob-meta-region-layout)):

- Chunk groups tile the address space back to back: group `i` starts at
	the block where group `i - 1` ends (`uncompressed_block_offset` in ChunkGroupTable) and
	spans exactly its chunks' blocks, each chunk whole and on its own 4 KiB
	block boundary, so the address space is as large as the block-padded
	data and nothing else. Tail-padding overhead depends on the file-size
	distribution; the layout introduces no fixed-size group slots. A
	chunk of at least the *chunk group minimum size*
	(`--chunk-group-minimum-size`: 2 MiB by default, independent of the chunk
	size) is a group of its own:
	its encoded bytes are one frame, addressable by the chunk's digest.
	Smaller chunks, including full chunks when the chunk size is below the
	minimum, are packed in order into shared
	groups built around the same minimum size. The builder keeps one pack open and closes it at
	content-defined boundaries: once the pack spans the minimum it closes
	after any chunk whose BLAKE3 digest ends in six zero bits (one chunk in
	64), once it spans twice the minimum after any chunk whose digest ends in
	five zero bits (one in 32), and a chunk that would take it past four
	times the minimum closes it regardless. Digest marks depend on the chunk
	content, but accepting a mark also depends on the accumulated pack span.
	Shared marks help near-identical inputs resynchronise after a change, so
	identical packs can share content-addressed cache entries. This is not
	guaranteed: the minimum, target and forced span boundaries can keep cuts
	misaligned. Packs span 1–4× the minimum, except the final pack may be smaller.
	With `--digester none`, a pack closes when full or before the next chunk
	would exceed four times the minimum. Groups are emitted in
	index order; a chunk's block address is only known once its group
	closes, so the builder resolves the inode chunk indexes when the data
	region is complete, before the bootstrap is rendered.
- Every group but the last spans at least the *index span* recorded in
	the blob meta (the chunk group minimum size, 2 MiB by default: a lone
	chunk is at least that, and so is a closed pack). ChunkGroupIndexTable
	has one four-byte entry per index span (four bytes per 2 MiB by default),
	and locates a group by direct indexing and at most one forward correction (see
	[Blob meta region layout](#blob-meta-region-layout)).
- The group is the unit of compression, of an on-demand read (see
	[Bootstrap plus blob-dir mount](#bootstrap-plus-blob-dir-mount)), of
	cache readiness and of the ondemand blob `nydus optimize` assembles: a
	reader decodes whole groups; `storage.fetch_size` can include neighboring
	groups in the same backend read.
- An all-zero chunk-sized chunk (a hole) is not stored at all and gets the
	EROFS null chunk index.
- On fill the daemon writes a decoded group back onto its blocks of the
	padded address space (gathering the chunks into `pwritev` runs), so the
	cache file, `read_at` and the pmem/DAX extents are a mirror of the address
	space; only the fetch side sees the dense stream.
- The blob meta records one 24-byte entry per group (compressed offset,
	start block, first chunk index, payload size, crc32c), one four-byte length
	per stored chunk (including a lone chunk)
	and one 32-byte BLAKE3 digest per group: a lone chunk's content digest,
	or for a pack a domain-separated BLAKE3 over the member chunks' digests
	(see [Chunk group digest](#chunk-group-digest); no digests with
	`--digester none`).

The chunk size therefore trades compression and table size against read
granularity: larger groups compress a run of small files better and need
fewer entries, smaller groups let a read of one small file fetch and decode
less and let the ondemand blob copy less around the traced chunks. The
on-demand fetch size (`storage.fetch_size`) is independent of it and is
the read-ahead knob. `nydus check` reports the group, chunk, digest and
redirect counts and the payload size per blob.

#### Native EROFS output

`--compressor erofs-none`, `erofs-lz4` or `erofs-zstd` switches the data
region from chunk groups to a native EROFS layer device: the
bytes the kernel reads at offset 0 of a `device=` of a block-device mount.
`erofs-none` writes the chunks uncompressed at their block addresses (the
padded address space itself, tail padding included); `erofs-lz4` and
`erofs-zstd` build a z_erofs layer, see [z_erofs Layers](#z_erofs-layers). All
three work with both source types and with both image layouts: the output is
still a full blob, `--blob-dir` deposits it under its SHA256 and `--bootstrap`
optionally emits the standalone bootstrap, exactly like a chunk-based build.

A native full blob is `[layer data][bootstrap][footer]`: it carries **no blob
meta** and no `.blob.meta` sidecar, and the footer sets the `RAW_DEVICE`
incompat flag with a zero blob meta block count. There is no lazy loading of
native layers: the nydus daemons never fetch them on demand from a registry
(the registry backend rejects them), `nydus optimize` refuses them, and a
mount reads them as-is from a local store or, through the kernel, from the
block device. `--chunk-size` cuts `erofs-none` files; `--erofs-data-alignment`
(default `0`) aligns large files inside the layer data for block-level dedup;
`--digester` describes the chunk-based blob and is ignored.

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
- OCI whiteouts need no special handling. The tar builder retains `.wh.*` markers
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
overlaid bootstrap in EROFS metadata format. Full-blob source paths are named
by their expected SHA256; nydusify may stage only their metadata tails in sparse
files. Merge validates the name and metadata layout, not the full data digest.
The content store or registry must have verified content identity before staging.
The emitted merged bootstrap records each source layer's
full-blob SHA256 in the device table and applies OCI whiteout
semantics so the final bootstrap reflects the merged filesystem view after
deletions and opaque-directory masking.

Current CLI help:

```bash
nydus merge -h
Merge multiple nydus layers into an overlaid bootstrap

Usage: nydus merge [OPTIONS] --bootstrap <BOOTSTRAP> <SOURCES>...

Arguments:
	<SOURCES>...  Specify the layers to stack, lower to upper: the layers' full blob paths named by their SHA256 (chunk-based or z_erofs, all of one kind); a z_erofs layer's standalone bootstrap from build --bootstrap is accepted too

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
- Merge trusts the parsed source ID; use `nydus check` with complete blobs to
	verify their data/full-blob digests. Sparse metadata staging cannot prove
	the full-blob hash.
- Merge rebuilds an overlaid bootstrap by loading each source into an in-memory
	metadata tree, applying OCI whiteout rules, and emitting a new device table.
- Merge records each source full-blob SHA256, rather than the data-region
	digest stored in its embedded bootstrap, so the store/backend can resolve it.
- Chunk-based merges preserve each file's original chunkbits. Native-z layers
	use the separate relocation path described below.
- When the first source is a z_erofs layer (`nydus build --compressor erofs-*`),
	every source must be one. Sources are the layers' full blobs named by their
	SHA256 like chunk-based layers (a standalone bootstrap written with
	`--bootstrap` is accepted too; its slot already carries that digest). The
	output is a multi-device bootstrap whose device `i + 1` is layer `i`'s blob;
	see [Merging z_erofs layers](#merging-z_erofs-layers).
- Mixed chunk-based/z_erofs inputs are rejected in either order. When z_erofs
	layers contain packed inodes, their packed compression algorithms must match;
	merging LZ4 and zstd packed streams requires reencoding and is not supported.

### Optimize

`nydus optimize [OPTIONS]`

The `nydus optimize` command builds a compact "ondemand" blob from a recorded
chunk group access pattern and rewrites the bootstrap so the runtime
prefetches it first. The ondemand blob is a **redirect** blob: the traced
chunk groups, in first-access order, copied byte for byte out of their
source blobs — encoded payload, chunk lengths and digests — with a redirect
table naming the source blob and chunk group of every copy. Nothing is
decoded or recompressed, and the bootstrap keeps every chunk index pointing
at the source blobs: the ondemand blob is never read through the filesystem.
At mount time the phase-0 prefetch streams it in one sequential pass,
decodes each copy and writes it into the *source* blob's cache at the
source group's blocks, so the workload's early reads hit warm cache instead of
issuing scattered registry range reads.

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
	(`{"version":1,"patterns":[{"blob_index":1,"chunk_group_index":4},...]}`,
	one entry per chunk group read); entries are deduplicated preserving
	first-access order. Run the workload against the mount before invoking
	optimize so the trace is populated.
- `--trace-file` is the offline alternative to `--apiserver` (the two are
	mutually exclusive; one of them is required). It accepts the same versioned
	trace document as produced by the `/trace` endpoint, so a trace captured
	from a pmem/core mount can be replayed without a live apiserver.
- `--parent-bootstrap` is the merged bootstrap to optimize; it is read-only, so
	optimize can be re-run against the same parent with new patterns.
- `--bootstrap` is the rewritten bootstrap output: the parent's inode tree
	and chunk indexes unchanged, an appended ondemand device slot, and the
	root `trusted.nydus.prefetch.blobs` xattr updated to list the ondemand
	device id first.
- `--blob-dir` receives the ondemand blob (named by its full SHA256) and its
	`<digest>.blob.meta` sidecar; the digest is printed in the summary table as
	`ONDEMAND BLOB DIGEST`, next to the `CHUNK GROUP COUNT` it copied.
- `--config` is the same storage config as `nydus fuse --config`: it names
	the backend the source blobs are read from. Consecutive traced groups of
	one blob are read in one range request, and every copy is decoded once to
	validate it (CRC32C and, when the source carries digests, BLAKE3) before
	it is appended.
- Sources may use different file chunk sizes and group minimums. The output
	uses the largest source group-span bound and derives its index span
	from the copied groups. Compressed sources must share one compressor
	(plain-stored groups fit under any compressor), because the copies are
	byte-exact; a source that is itself an ondemand blob is
	refused. Sources without digests (`--digester none`) make the ondemand
	blob digest-free too.
- The ondemand artifact layout is `[chunk groups][blob meta][footer]` with
	`bootstrap_size = 0` (no embedded bootstrap); its blob meta carries a
	ChunkGroupRedirectTable, see
	[Ondemand (redirect) blob layout](#ondemand-redirect-blob-layout). It is
	fetched and checked like any blob but never builds a cache of its own.

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
	`group_span`, `index_span`, `chunk_group_count`,
	`chunk_compressor`, the chunk, digest
	and redirect counts (`BLOB META REDIRECTS` is non-zero only for an ondemand
	blob), and payload/compressed/uncompressed totals when the referenced blob
	can be resolved.
- `--blob-dir` resolves by scanning full blob candidates. Device slots normally
	store the data-region SHA256, while blob files are named by full blob SHA256
	when produced by `--blob-dir`. A slot whose id matches no digest falls back
	to the store entry of that file name (a blob built with `--blob-id`); it is
	reported with `SLOT DIGEST KIND named` and counts as unverified.
- Every blob entry carries a `VERIFIED` row: `yes` when the resolved file
	reproduces the slot id, `no` when it was resolved by name only, and
	`<unresolved>` when no candidate matched.
- z_erofs images (superblock `COMPR OR DISTANCE` non-zero) are checked as
	such: the incompat dump names `zero_padding`, `big_pcluster+compr_cfgs` and
	`fragments`; the summary counts `Z_EROFS FILES`, `Z_EROFS FRAGMENT FILES`
	and `Z_EROFS PCLUSTERS OUT OF RANGE` (HEAD/PLAIN lcluster addresses that no
	device covers, always 0 for a sound image), and the packed inode is walked
	too. Each device resolves to `<blob-dir>/<slot id>`, the layer's full blob
	(`SLOT DIGEST KIND z_erofs_device`); it verifies when the footer's data
	region spans the declared block count and the file's SHA256 equals the slot
	id (a bare data file without a footer is accepted as well). `nydus check
	--blob` on one z full blob verifies its data region like a chunk-based one.
	`CHUNK REFS` / `UNIQUE CHUNKS` then count the pclusters addressing that
	device.

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
`--config`), runtime fetches and validates requested blob_meta chunk groups using a
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
  scope: auto
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
	decodes, and validates the chunk groups it touches from the backend directly,
	and nothing is written to disk — the kernel page cache above the mount is
	the only reuse layer. Diskless mode applies to `nydus fuse` and `nydus check`; the modes
	that hand the cache file to the kernel (`fanotify`, `nbd`, `ublk`, `uffd`)
	and `nydus optimize` require a directory and reject its absence at startup,
	except that the kernel modes accept an image whose every blob is a native
	layer in a `local` store: its store file is handed to the kernel directly.
- `storage.skip_verify_checksums` (default `true`) skips verifying decoded
	chunks against the blob meta's BLAKE3 digests before they are served.
	Every fetched chunk group is always checked against its `crc32c`; set this
	to `false` to also verify each chunk when the transport is not trusted end
	to end.
- `storage.fetch_size` (default `2097152`, 2 MiB) is how many compressed
	bytes one on-demand backend read covers: the chunk groups whose compressed
	ranges overlap the fetch-size-aligned cell holding the missed group,
	trimmed at groups already cached or in flight, so one read never refetches
	cached bytes. Larger fetches make fewer, larger requests and win over high
	per-request latency; smaller fetches transfer fewer unused bytes and win
	over limited bandwidth. `0` fetches the missed group alone. The fetch size
	is independent of the image's `--chunk-size`: the same image serves every
	fetch size. See [Bootstrap plus blob-dir mount](#bootstrap-plus-blob-dir-mount)
	for the trade-off.
- `prefetch.concurrent_blob_count` (default `10`) caps how many blobs are
	prefetched concurrently.
- `prefetch.timeout` (default `1h`) bounds how long prefetching one whole
	blob may take, while `http.timeout` bounds each backend request within it;
	`0s` disables the bound. A blob that exceeds it is aborted with a warning
	and prefetch moves on.
- `prefetch.retry_delay_min` / `prefetch.retry_delay_max` (defaults `6h` /
	`12h`) bound the random delay before a blob prefetch that the backend
	throttled (a Dragonfly proxy `429`) is re-attempted; each throttled blob is
	rescheduled with a fresh random deadline inside the window so retry load
	spreads out instead of stampeding. `retry_delay_min` must not exceed
	`retry_delay_max`. Only throttled failures are rescheduled; other prefetch
	failures are logged and skipped.
- `prefetch.scope` (default `auto`) selects which blobs to pull. `none`
        disables prefetch; `ondemand` prefetches only the "ondemand" redirect blob
        `nydus optimize` emits (if any), landing the access-ordered hot set in the
        source blobs' caches while leaving backend bandwidth to on-demand reads;
        `all` prefetches every blob — the ondemand blob first, then the other
        priority blobs, then the rest; `auto` behaves like `ondemand` when a
        priority blob is an ondemand blob and like `all` otherwise, so an
        unoptimized image is still streamed in the background.
        See [Blob prefetch](#blob-prefetch).

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
		chunk group's cross-process fetch claim for its whole duration, and what
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
	- `worker_threads` (default `0` = 2): async worker threads of the
		process-wide runtime that drives the registry client's sockets. They
		only move bytes for the connection pool (readers block on their own
		threads), so two suffice for a node's worth of blob traffic; raise it
		only if the backend metrics show the workers saturated.
	- `max_blocking_threads` (default `0` = 8): upper bound on the runtime's
		on-demand blocking threads, which serve DNS lookups and are released
		after 10 s idle.

		The runtime is shared by every registry backend in the process, so these
		two keys take effect only from the first backend constructed with a
		non-zero value; a later backend asking for different values logs a
		warning and keeps the running runtime. Programs that embed the backend
		(a VMM) may also fix the runtime's network namespace through the
		`nydus_backend::configure_runtime` API; the config file cannot.
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
exposition at `GET /metrics` and the recorded chunk access order at
`GET /trace` (any other path returns `404`). The server is torn down and the
socket unlinked when the mount exits. Scrape it with, e.g.:

```bash
curl --unix-socket /run/nydus/api.sock http://localhost/metrics
curl --unix-socket /run/nydus/api.sock http://localhost/trace
```

`GET /trace` returns JSON like
`{"version":1,"patterns":[{"blob_index":1,"chunk_group_index":4},...]}`
listing each chunk group the workload read as a `(blob, chunk group index)`
pair in first-access order, deduplicated. Every group a read touches is
recorded, hit or miss, so the trace names what was read rather than what a
fetch pulled. The blob index is the device id from the bootstrap device
table. The trace feeds `nydus optimize` / `nydusify optimize`.

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
	`.group.map` and `.prefetch.lock` sidecars).
- `cache_hit_chunk_group` — chunk groups served from cache without a backend
	read.
- `cache_total_chunk_group` — total chunk groups across loaded blob metas,
	counted once per blob however many caches are open on it.
- `cache_fill_chunk_group` — chunk groups written into a blob's own cache by
	regular blob prefetch (`prefetch.scope: all`).
- `cache_ondemand_fill_chunk_group` — chunk groups written into a blob's own
	cache to satisfy an on-demand read. Summing it across the instances
	sharing a cache directory shows how much duplicate fetching they do.
- `cache_redirect_fill_chunk_group` — chunk groups written into a **source**
	blob's cache from a redirect (ondemand) blob during phase-0 prefetch.
- `cache_redirect_skip_chunk_group` — redirect chunk groups skipped during
	ondemand prefetch (decode/CRC failures, unknown source blob, or failed
	fills); normally zero. Groups whose source was already cached are not
	fetched at all and count in neither.

After an optimized mount's prefetch quiesces, `backend_prefetch_read_count > 0`
with `cache_redirect_fill_chunk_group` equal to the number of traced groups
shows the ondemand blob was pulled into the source caches, and a
`backend_ondemand_read_count` that stays at zero through the workload shows
the trace covered it.


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
5. Blob meta region (absent for native `erofs-*` layers).
6. Footer.

The order matters: the file is `data + bootstrap + blob_meta + footer`, not
`bootstrap + data`. The data region is first so build can append encoded chunk
groups directly into the final artifact without copying them behind metadata
later.

```text
full blob file: <full_blob_sha256>

+-------------------------------+  byte 0
| encoded data region           |
| chunk groups, each one zstd   |
| frame or stored plain         |
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
|  device table may continue   |
|  through later head blocks   |
|  meta_blkaddr..N-1           |
|  +-------------------------+  |
|  | inode slots             |  |
|  | inode xattr bodies      |  |
|  | chunk index arrays      |  |
|  | directory data blocks   |  |
|  +-------------------------+  |
+-------------------------------+  byte = footer.bootstrap_offset + footer.bootstrap_size
| padding to 4 KiB alignment    |
+-------------------------------+  byte = footer.blob_metadata_offset
| blob meta                     |
| header, then tables           |
| groups, chunks, digests       |
| zero padding to 4 KiB         |
+-------------------------------+  byte = footer.blob_metadata_offset + footer.blob_metadata_size
| blob footer                   |
+-------------------------------+  EOF
```

The footer is fixed at 4096 bytes and is always located at EOF. The fields
occupy the first 80 bytes; the remaining bytes are reserved — writers zero
them, readers ignore them, and corruption is caught by the footer crc32c.
There is no version: unknown `feature_compat` bits are ignored and unknown
`feature_incompat` bits reject the blob, like the blob meta header. A new
field takes reserved bytes together with a feature bit announcing it.

```text
BlobFooter

u8  magic[8]           "NDFOOTER", raw ASCII bytes written as-is
u32 feature_compat     unknown bits ignored
u32 feature_incompat   unknown bits reject the blob
u32 crc32              crc32c over footer bytes with this field zeroed
u32 bootstrap_crc32    crc32c over the whole bootstrap region, padding
                       included; zero without a bootstrap
u64 compressed_data_offset
u64 compressed_data_size
u64 bootstrap_offset
u64 bootstrap_size              4 KiB multiple, zero for an ondemand blob
u64 bootstrap_compressed_size   exact zstd frame bytes when the
                                BOOTSTRAP_ZSTD feature is set, else 0
u64 blob_metadata_offset
u64 blob_metadata_size          4 KiB multiple, zero exactly when the
                                RAW_DEVICE feature is set
u8  reserved[4016]     writers zero, readers ignore
```

The `magic + feature_compat + feature_incompat + crc32` prefix matches the
blob meta (`NDBLMETA`).

Reader validation requires:

```text
compressed_data_offset + compressed_data_size <= bootstrap_offset
bootstrap_offset + bootstrap_size <= blob_metadata_offset
blob_metadata_offset + blob_metadata_size == footer_offset
```

The inequalities allow alignment padding between regions. Offsets, region
sizes except the compressed data size, and the footer offset must be 4 KiB
aligned. Every offset and size is a byte count. Opening the embedded
bootstrap (merge, check, single-blob mounts) verifies `bootstrap_crc32`
before decoding it.

The bootstrap region stores the metadata-only EROFS image as a single zstd
frame (footer incompat flag `BOOTSTRAP_ZSTD = 1 << 0`), padded with zeros to
the 4 KiB region boundary; `bootstrap_compressed_size` carries the exact frame
length so readers decode without trusting the zero tail. An empty bootstrap
(ondemand blobs) keeps the flag clear and the size zero. When `--bootstrap` is
specified, its inode metadata comes from the decoded region, but the device
table is retargeted to the full-blob digest and flattened mapped addresses, and
the superblock checksum is recomputed. The standalone file is therefore not
byte-for-byte identical to the embedded bootstrap.

A native `erofs-*` layer sets the incompat feature `RAW_DEVICE = 1 << 1`: its
data region is the raw EROFS device the kernel reads, there is no blob meta
region (`blob_metadata_size` is zero) and a bootstrap is mandatory. Readers that
do not know the feature reject the blob; readers that do never fetch it on
demand.

### Bootstrap region details

Within the bootstrap region:

- `superblock.blocks` counts only bootstrap blocks, not the entire full blob.
- the device table starts in block 0 immediately after the superblock.
- the metadata area starts at `superblock.meta_blkaddr` and contains inode
	bodies, xattrs, chunk index arrays and directory data. This is block 1 for
	up to 23 device slots; a larger device table occupies additional head blocks.
- directories are laid out like `mkfs.erofs` does: the full 4KiB blocks of
	dirent data go to the data area, and the partial last block is packed right
	behind the inode header (`EROFS_INODE_FLAT_INLINE`, `i_size` is the exact
	used length) whenever header + xattrs + tail fit in the inode's block. A
	directory whose data ends on a block boundary, or whose tail does not fit,
	stays `FLAT_PLAIN` with block-padded data. Looking a name up in a small
	directory therefore costs one metadata block instead of two.
- inodes are allocated breadth first: the root, then for each directory (in
	that order) all of its children back to back, hardlinked inodes once under
	their first parent, and inodes outside the tree (the z_erofs packed inode)
	last. A directory's inline dirents and its children's inodes thus share a
	few consecutive blocks, so listing or `stat`-ing siblings touches one or two
	metadata blocks rather than one per child. Both rules shrink the merged
	bootstrap several-fold and cut the metadata reads of a cold start; they apply
	to every image nydus builds or merges.

### Automatic FUSE xattr optimization

Build, merge, and optimize record `trusted.nydus.no_xattr` with the exact value
`1` on the bootstrap's root inode when the final tree contains no FUSE-visible
xattrs. This is an EROFS inode xattr inside the bootstrap bytes, not an xattr
on the host bootstrap file, an EROFS feature bit, or a blob footer flag.

The shared build/merge/optimize flattening traversal accumulates whether any
emitted inode has visible xattrs and finalizes the root marker before metadata
layout. No separate inode-list scan is needed. Inherited root markers are
replaced or removed, so an upper layer's marker
cannot hide attributes on surviving lower-layer inodes. Root `trusted.nydus.*`
attributes are internal and excluded from the decision; attributes on all
other inodes count, including empty values and internal-looking names, because
FUSE only hides that namespace on the root inode. Visible attributes are always
serialized, regardless of the optimization.

Bootstrap renderers preserve the finalized attributes and do not recompute
the marker. Code that constructs inode lists directly or changes visible xattrs
after flattening must finalize or invalidate the root marker before rendering.
Adding root internal prefetch attributes does not change the decision.

FUSE reads the root marker once during initialization. The exact name and value
enable `ENOSYS` replies for getxattr/listxattr, allowing Linux FUSE to stop
forwarding subsequent requests for each operation. Missing or unknown values
do not enable the optimization. There is no CLI or environment override and no
full-tree mount-time scan. Root metadata read errors fail initialization rather
than being mistaken for absence of xattrs.

The marker is present in embedded, standalone, merged, and optimized bootstraps
when their final tree qualifies. It is hidden by the existing root internal
xattr filter and omitted from exported OCI tar attributes. Non-FUSE readers
and native EROFS mounts do not use it to disable xattr support.

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

The entire `tag[0..64]` stores 64 lowercase SHA256 hex characters, not a raw
32-byte digest followed by zeros. The embedded single-layer bootstrap identifies
the encoded data region; the standalone bootstrap and merge output identify
the full blobs in the store. Optimize appends the full digest of its ondemand
artifact without changing the original source-blob identities.

`blocks_lo` stores the decoded external-device block count. `uniaddr_lo` stores
its mapped start for flattened layouts; `blocks_hi`, `uniaddr_hi` and reserved
bytes are zero. These are 32-bit fields with the bounds described above.

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
blob's data region. ChunkGroupIndexTable gives the group covering the index span
start; comparing with the next group start corrects the answer at most once.
The ChunkGroupTable entry gives
the encoded `compressed_offset` (for example 0 for the first encoded
chunk_group).
```

Blob identity is therefore attached to the device slot, not to the chunk index
and not to the superblock directly.

### Blob ID semantics

An embedded single-layer bootstrap stores the SHA256 of its encoded data
region. Standalone and merged bootstraps instead name the full blobs used by
the content store or registry.

This avoids a self-reference problem:

- the full blob contains bootstrap metadata;
- bootstrap metadata contains the blob identifier;
- hashing the full file while embedding that hash into the file would be circular.

At the same time:

- the full blob file name written by `--blob-dir` is the SHA256 of the whole
	full blob artifact;
- only the embedded bootstrap's self-reference uses the data-region SHA256;
	standalone and merged device slots use full-blob SHA256. An explicit
	`--blob-id` override is supported only for local filename-based resolution.

### Blob meta region layout

Chunk-based blobs contain this metadata both as a `.blob.meta` sidecar and
verbatim before the full blob's footer. Native `erofs-*` blobs omit it.
There is no format version: compatibility is decided EROFS-style by feature
bits in the header and in every table header, so a newer writer can add
tables, table header fields and entry fields that older readers skip.

The encoded payload contains tightly concatenated chunk bytes, while the
cache address space starts every chunk on a 4096-byte boundary. Groups tile
both spaces without additional group padding.

```text
Header (24 bytes)
table_count tables back to back, each at the next 8-byte boundary:
  ChunkGroupTable        type 1  24-byte header + (group_count + 1) * 24 bytes
  ChunkLengthTable        type 2  16-byte header + chunk_count * 4 bytes
  ChunkGroupIndexTable type 3  24-byte header + ceil(cache_bytes / index_span) * 4 bytes
  ChunkGroupDigestTable       type 4  24-byte header + group_count * 32 bytes, when enabled
  ChunkGroupRedirectTable     type 5  16-byte header + group_count * 8 bytes, redirect blobs only
Zero padding to a 4096-byte multiple
```

All integers are unsigned and little-endian. Writers zero every reserved
field, the alignment and the tail padding; readers ignore them, and
corruption there is caught by the crc32c. The file must end exactly at the
4096-byte boundary after the last table, so no byte is undescribed.

#### Header

| Offset | Field | Bytes | Meaning |
|---:|---|---:|---|
| 0 | `magic` | 8 | ASCII `NDBLMETA` |
| 8 | `feature_compat` | 4 | Compatible features; unknown bits are ignored |
| 12 | `feature_incompat` | 4 | Incompatible features; unknown bits reject the file. None is defined yet |
| 16 | `crc32` | 4 | CRC32C of all metadata including padding, with this field zeroed |
| 20 | `table_count` | 2 | Tables following the header |
| 22 | `reserved` | 2 | Writers zero it, readers ignore it |

The first 20 bytes (`magic`, both feature words, `crc32`) are frozen for
every nydus record format, including the footer: any reader can always tell
whether it supports a file. The header holds only what concerns the whole
file; parameters of a table live in that table's header extension.

#### Table header

Every table starts with a 16-byte header; a table type may define an
optional header extension behind it and then declares the larger
`header_size`; entries start at `header_size`. The first table
starts at offset 24, and each next one at the first 8-byte boundary after
the previous table, so the headers alone describe the layout.

| Offset | Field | Bytes | Meaning |
|---:|---|---:|---|
| 0 | `type` | 2 | Nonzero and unique; `0x8000` and above are private |
| 2 | `header_size` | 2 | At least 16 and the known size, a multiple of 8 |
| 4 | `feature_compat` | 2 | Compatible table features; unknown bits are ignored |
| 6 | `feature_incompat` | 2 | Incompatible table features; unknown bits reject the file. None is defined yet |
| 8 | `entry_size` | 4 | Bytes per entry, at least the known entry size |
| 12 | `entry_count` | 4 | Entries |

Types 1 through 5 are the core tables above; nydus allocates the next ones
from 6. ChunkGroupTable, ChunkLengthTable and ChunkGroupIndexTable are mandatory. To a
reader that does not know a table's type every incompat bit is unknown, so
it skips an unknown table whose `feature_incompat` is zero and rejects the
file otherwise: a new table that older readers must understand sets an
incompat bit.

A table is exactly `header_size + entry_size * entry_count` bytes. Readers
reach entry `i` at `header_size + i * entry_size`, so a newer writer may
append fields to a table header or to every entry; older readers read the
fields they know and skip the rest. A changed meaning needs a new table
type or an incompat feature instead.

Header extensions, optional per table type:

| Table | Offset | Field | Bytes | Meaning |
|---|---:|---|---:|---|
| ChunkGroupTable | 16 | `max_group_span_bits` | 1 | Maximum group span is `4096 << value` bytes; at most 19 (2 GiB) |
| ChunkGroupTable | 17 | `compressor` | 1 | 0 plain, 1 Zstandard, 2 LZ4; unknown values reject the file |
| ChunkGroupTable | 18 | `reserved` | 6 | Writers zero it, readers ignore it |
| ChunkGroupIndexTable | 16 | `index_span_bits` | 1 | Lookup span is `4096 << value` bytes; at most `max_group_span_bits` |
| ChunkGroupIndexTable | 17 | `reserved` | 7 | Writers zero it, readers ignore it |
| ChunkGroupDigestTable | 16 | `algorithm` | 1 | 1 BLAKE3 group digest; a reader that does not know the value treats the blob as undigested and fails reads that must verify digests |
| ChunkGroupDigestTable | 17 | `reserved` | 7 | Writers zero it, readers ignore it |

The default maximum span is 8 MiB (bits 11), and index span
2 MiB (bits 9). Setting the group minimum to 4, 8 or 16 MiB writes
index span bits 10, 11 or 12 respectively. File chunk size and
build-time grouping threshold are not recorded. Optimized blobs derive
their own index span from copied group spans, so their index span bits are not
necessarily 9.

#### ChunkGroupTable

Each entry is 24 bytes; offsets below are relative to its start.

| Offset | Field | Bytes | Meaning |
|---:|---|---:|---|
| 0 | `compressed_offset` | 8 | Encoded group start relative to the blob data region |
| 8 | `uncompressed_block_offset` | 4 | Group start in the uncompressed cache address space, in 4096-byte blocks |
| 12 | `first_chunk_index` | 4 | First entry of this group's run in ChunkLengthTable |
| 16 | `payload_size` | 4 | Sum of actual chunk lengths, excluding block padding; not the cache address span |
| 20 | `payload_crc32` | 4 | CRC32C of the decoded, tightly packed payload |

Subtract the current entry from the next to obtain encoded length, cache
block count and chunk count. All three starts increase strictly for real
groups, starting at zero. A chunk count of one is a lone chunk; any larger
count is a pack. There is no special zero-member representation.

The final entry is a terminator: its first three fields contain total data
bytes, total cache blocks and total chunks; payload size and CRC are zero.
The group count is therefore the entry count minus one; the header does not
store it. The terminator has no ChunkGroupDigestTable or ChunkGroupRedirectTable entry. An empty
blob has just this zero terminator and no other table entries.

Stored size equal to decoded payload size means plain data, even if the
ChunkGroupTable header declares a compressor. Otherwise the payload is compressed; the builder
stores it plain unless compression saves at least 30%. Runtime backends add
the data-region base offset before issuing the encoded range read.

#### ChunkLengthTable

Each entry is a nonzero `chunk_byte_length` stored as a four-byte integer.
Every stored chunk has an entry, including lone chunks. The table is ordered
by group, then by chunk within each group. Holes have no entry or payload.

Chunk lengths sum to the group's decoded payload size. Their individually
rounded block counts sum to the group's cache span. Thus the same lengths
split the tight payload and recover each chunk's block-aligned cache address.

#### ChunkGroupIndexTable

Each entry is a four-byte `group_index` naming the group covering the
corresponding index span's **first byte**. Every non-final group must span at
least one index span; the final group may be shorter. The table is mandatory
for every nonempty blob, including redirect blobs.

For a checked cache byte offset:

```text
span_index = cache_byte_offset / index_span
group_index = ChunkGroupIndexTable[span_index]
if cache_byte_offset >= ChunkGroupTable[group_index + 1].uncompressed_block_offset * 4096:
    group_index += 1
```

At most one group boundary lies inside a index span, so this is worst-case
O(1): direct indexing, one comparison and at most one increment. There is no
binary-search fallback, bitmap or popcount. At the default index span the index
costs four bytes per 2 MiB of cache address space.

The parser verifies the crc32c and the feature words, bounds every table of
the directory, resolves the known tables through their headers with checked
arithmetic, cross-checks their entry counts against the ChunkGroupTable
terminator, then validates every chunk, group and index entry. The mapped
reader verifies the index in place; it does not allocate or rebuild a second
lookup structure. File mappings still consume page-cache memory when
accessed. The bytes are kept verbatim, so saving or caching a loaded blob
meta preserves the tables the reader does not know.

#### Chunk group digest

- The digest table has one entry per chunk group: entry `i` names group
	`i`'s content. A group holding one chunk carries the BLAKE3 digest of that
	chunk's exact bytes (no padding), so every chunk of at least the chunk
	group minimum size is addressable by its plain content digest. A group of
	several chunks (a pack) carries a domain-separated BLAKE3 over its member
	chunks' digests in order: `blake3::derive_key("nydus blob meta chunk
	group digest v1", d_0 ‖ d_1 ‖ … ‖ d_n-1)`. The builder already hashes
	every chunk to decide the pack boundaries, so the group digest costs no
	second pass over the bytes. The context separates group hashing from plain
	content hashing; collision resistance still relies on BLAKE3. The table
	uses 32 bytes per group rather than per chunk, so its reduction depends
	on the number of chunks per group. These digests are the identities a
	content-addressed cache uses for groups.
- The runtime checks a decoded group against its entry when
	`storage.skip_verify_checksums` is `false`: it hashes each member chunk
	of the decoded payload and recombines them the same way.

Redirect details (redirect blobs only):

- Entry `i` is 8 bytes: a two-byte nonzero `source_blob_index`, the EROFS
	device index of a source blob, two reserved bytes, and a four-byte
	`source_chunk_group_index`, a group within it.
	Group `i`'s encoded bytes, payload size, chunk lengths,
	digest and `crc32c` are those of the source group, copied verbatim, so
	the redirect blob preserves each source's chunk lengths and compatible
	compressor and is decoded with the same code path. Its groups tile their own address space
	in access order (the redirect blob's `uncompressed_block_offset` values are its own), with
	a power-of-two index span no larger than any non-final copied group.
- The runtime never builds a cache for a redirect blob: each decoded group is
	written into the source blob's cache at the source group's blocks and
	marked ready there. See [Ondemand (redirect) blob layout](#ondemand-redirect-blob-layout).

Address-to-group lookups are O(1) and need no derived index: ChunkGroupIndexTable names the group
of an address (see above), the group row and its successor bound the backend
range, the address span and the chunk run, and a chunk within a pack is
found by walking the run's lengths (at most a group span of them). The
reader validates the tables once and then maps the region read-only;
no auxiliary lookup table is built in memory at open. Range reads spanning
several groups, fetch-window planning, decoding and validation still cost
time proportional to the groups or bytes processed. Cache hits read the
decoded cache directly; misses fetch, decode, validate and scatter chunks
before publishing readiness. The cache readiness bitmap is separate from
the immutable metadata's address index.

The writer does not bias `compressed_offset` by the bootstrap size. Only the
data region as a whole is padded to a 4 KiB boundary (so the embedded
bootstrap that follows starts on a block); chunk groups themselves are not
individually padded.

### Blocks, chunks and chunk groups

The units live in two address spaces: blocks and chunks are defined on the
**decoded** (uncompressed, padded) external-device address space that EROFS
chunk indexes point into, while chunk groups map consecutive spans of it onto the
**encoded** data region stored in the full blob. The figures below use
1 MiB chunks (256 blocks) and a 64 KiB chunk group minimum size
(`--chunk-size 1mib --chunk-group-minimum-size 64kib`), so that a medium
chunk shows up as a group of its own and a pack of small files stays
short; with the defaults (2 MiB chunks and a 2 MiB minimum) A p1 below
would join the pack instead.

Chunks are split **per file**: every regular file is cut independently into
`--chunk-size` chunks, and a file's final chunk keeps only its real size
instead of being padded to a full chunk:

```text
           file A (1 MiB + 700 KiB)   file B (2 MiB)           file C (300 B)
           +--------+------+    +--------+--------+    +---+
           | A p0   | A p1 |    | B p0   | B p1   |    | C |
           |1 MiB   |700KiB|    | 1 MiB  | 1 MiB  |    |300|
           | BLAKE3 |BLAKE3|    | BLAKE3 | BLAKE3 |    |   |
           +--------+------+    +--------+--------+    +---+
```

A fully-zero chunk — a real filesystem hole reads back as zeros, and so does
zero-filled data — is never stored: the builder emits the standard EROFS null
chunk index (`startblk_lo == 0xffffffff`, unused high fields zero) instead. Hole chunks occupy no
bytes in the data region, get no chunk entry, and never touch the blob cache
at runtime: the core read paths satisfy them with zeros directly, and native
EROFS mounts decode the null address in-kernel the same way.

The chunks are then placed into chunk **groups**, laid out back to back in
the decoded address space, each spanning exactly its chunks' blocks. A whole
chunk — A p0, B p0, B p1 — or one that reaches the chunk group minimum
size (64 KiB here) — A p1, 700 KiB — is a group of its own, its encoded
bytes one frame that a content-addressed cache can serve by the chunk's
digest. Smaller chunks are packed in order: C (300 bytes, one block) opens
a shared group and the small files after it join it, each starting on its
own 4 KiB block, until a chunk's digest marks a boundary once the pack
spans the chunk group minimum size (low six bits zero) or twice it (low
five bits
zero), or one would take the pack past four times the minimum, and the
pack closes there. A large chunk arriving in
between closes as its own group without disturbing the pack. Groups are
emitted in index order, and the chunk indexes take their block addresses
from the finished layout:

```text
blkaddr    0        256      512      768      943 944  ..
           |        |        |        |        |   |
           +--------+--------+--------+--------+---+-+-+---
           | A p0   | B p0   | B p1   | A p1   |C|D|..| ..
           +--------+--------+--------+--------+---+-+-+---
group      0        1        2        3        4
ChunkGroupTable: uncompressed_block_offset 0, 256, 512, 768, 943, ..;
			payload_size 1048576, 1048576, 1048576, 716800, |C|+|D|+..;
			first_chunk_index 0, 1, 2, 3, 4, 7 (group 4 holds three chunks)
ChunkLengthTable: 1048576, 1048576, 1048576, 716800, 300, |D|, ..
```

Within a group the chunks' **bytes** are the group's payload, back to back
with no tail padding (C's 300 bytes, then D, ...); the group is compressed
as one zstd or LZ4 stream and the groups are packed back to back as the
data region:

```text
           group 0   group 1   group 2   group 3   group 4        group 5
           | A p0    | B p0    | B p1    | A p1    | C, D, ..     |
           v         v         v         v         v              v
+-----------+---------+---------+---------+--------------+----------+---
| zstd(A p0)|zstd(Bp0)|zstd(Bp1)|zstd(Ap1)|zstd(C,D,..)  | group 5  |
+-----------+---------+---------+---------+--------------+----------+---
^ compressed_offset(0) = 0                               ^ compressed_offset(5)
```

A group that does not shrink below 70% of its payload is stored plain
instead, its chunks then sitting at their dense offsets. Every group carries
a CRC32C over its decoded payload.

The group is the compression, on-demand read and cache-fill unit: a read of C
fetches and decodes group 4 (with the groups of its fetch-size cell) and
nothing else of the blob, then writes the group's chunks onto their blocks,
leaving the tail of each block zero.

Hash and validation summary:

- **BLAKE3 per chunk group** (blob meta digest table, one entry per group)
	— the content identity of the group: a lone chunk's own digest, or a
	BLAKE3 derived from the member chunks' digests for a pack (see
	[Chunk group digest](#chunk-group-digest)); what a read checks a decoded
	group against when checksum verification is enabled.
- **CRC32C per chunk group** (blob meta chunk group entry) — validated after
	every fetch and decode, on demand and prefetch alike.
- **SHA256 over the data region** — written into the bootstrap device slot as
	the blob id.
- **SHA256 over the whole full blob** — the artifact file name (`--blob-dir`)
	and the OCI layer digest.
- **CRC32C in the blob meta header and blob footer** — checked before either
	structure is trusted; the footer's `bootstrap_crc32` covers the embedded
	bootstrap region, checked before it is decoded.

### Ondemand (redirect) blob layout

`nydus optimize` emits one extra "ondemand" blob and appends it to the image
as a new layer. It is a full blob without an embedded bootstrap
(`bootstrap_size = 0`) whose blob meta carries a ChunkGroupRedirectTable:
every chunk group is a byte-exact copy of a traced chunk group of a source
blob — encoded payload, payload size, chunk lengths, digest and CRC32C —
laid out in first-access order, and the redirect table names the source
blob and chunk group of each copy. Groups are decoded for validation but
their encoded bytes are copied without recompression, so the blob shares the sources' compressor
and introduces no new filesystem addresses.

```text
ondemand blob — named by SHA256(full blob), one new nydus layer

+--------------------------------+  byte 0
| chunk groups                   |
|  verbatim copies of the traced |
|  source groups, in first-access|
|  order                         |
+--------------------------------+
| blob meta (has ChunkGroupRedirectTable)  |
|  Header (24 bytes, crc32c)      |
|  ChunkGroupTable                    |
|  ChunkLengthTable                    |
|  ChunkGroupIndexTable             |
|  ChunkGroupDigestTable                   |
|  ChunkGroupRedirectTable                 |
|   (source blob, source group)  |
+--------------------------------+
| footer (bootstrap_size = 0)    |
+--------------------------------+
```

The rewritten bootstrap appends the ondemand blob as a new device slot and
leaves every chunk index untouched: the filesystem keeps reading the source
blobs, and the ondemand blob is never addressed through it. The root inode's
`trusted.nydus.prefetch.blobs` xattr lists the ondemand device first, so
phase-0 prefetch streams it in one sequential pass and writes each decoded
group into the *source* blob's cache at the source group's blocks, marking the
source group ready:

```text
phase-0 prefetch of the ondemand blob

fetch groups -> decode -> CRC32C check -> <source digest>.blob.data at the
                                          source group's blocks
                                          + source group map bit set
```

The workload's reads of the traced groups are then cache hits on the source
blobs; a source blob is only fetched for groups the trace did not cover.
Source groups another process already cached are skipped without being
fetched, so a node running several instances of the image streams each hot
group once. The ondemand blob never builds a cache file of its own, and an
ondemand blob is never itself a source for another `nydus optimize` run (the
command refuses it). See [Optimize](#optimize) for the CLI and
[Blob prefetch](#blob-prefetch) for the scheduling details.

### Merge output

The merge command emits an overlaid standalone bootstrap that references one or
more previously built full blobs.

## z_erofs Layers

The chunk-based format above keeps file data in nydus-defined chunk groups
that a nydus daemon fetches on demand and decodes. `nydus build --compressor
erofs-lz4` or `--compressor erofs-zstd` instead produces a native **z_erofs**
layer: the data region is an EROFS device the kernel decompresses itself
(`--compressor erofs-none` produces the uncompressed native counterpart, the
padded chunk address space as a device). Native layers are made for block
devices: a kernel mount reads the store file directly as a `device=` (a cloud
disk such as EBS, a local volume, a virtio-blk image: no daemon, per-request
charging, so the layout minimises read requests). They are never lazily
loaded by the nydus daemons — the registry backend rejects them and the
on-demand frontends have no cache file for them; `nydus fuse` and `nydus
export` read them whole from a local store, decompressing pclusters in
userspace, which is how `nydusify check` and the nydus-to-OCI conversion
handle them on any kernel.

### Layer layout

A native layer is a full blob without the blob meta region (`[layer
data][bootstrap][footer]`, see [Full blob byte layout](#full-blob-byte-layout)):

- **Layer data**: the raw EROFS data region at offset 0, nothing else. For
	z_erofs it is LZ4 or zstd pclusters of at most 64KiB plus the packed inode;
	for `erofs-none` it is the padded chunk address space. It is an EROFS
	*extra device*.
- **Bootstrap**: a complete single-layer EROFS image (`[head | metadata]`)
	whose device table has one slot mapping the layer data just past the
	bootstrap, on a 512KiB boundary. The embedded copy names the data region by
	its SHA256 (the file cannot contain its own digest); the standalone copy
	written by `--bootstrap` names the full blob, i.e. the store file. Either
	mounts on its own with `device=<layer data>`.
- **Footer**: `RAW_DEVICE` incompat feature, `blob_metadata_size = 0`. There
	is no blob meta and no `.blob.meta` sidecar: nothing describes fetch
	granularity because nothing fetches the layer on demand.

Inside the layer data:

- Regular files larger than 64KiB become `COMPRESSED_FULL` inodes: full
	lcluster indexes (8 bytes per 4KiB logical block) behind the inode header,
	HEAD1 pclusters spanning several lclusters with `CBLKCNT` carrying the
	physical size (`BIG_PCLUSTER`), compressed payload tail-aligned in its
	pcluster (`ZERO_PADDING`), and per-lcluster PLAIN blocks whenever a window
	does not shrink by a block (the `mkfs.erofs` layout). Pclusters are packed
	greedily with `LZ4_compress_destSize`: each consumes as much source as
	fits into 64KiB of output, rounded down to whole lclusters.
- Regular files of at most 64KiB are **fragments**: their bytes are appended
	to one packed stream, compressed as it fills into the **packed inode** (a
	regular compressed file outside the tree, referenced by the superblock's
	`packed_nid`, `FRAGMENTS` incompat, kernel 6.1+). The file's 8-byte map
	header has bit 63 set and holds its offset in the packed inode. Neighbouring
	small files thus share pclusters and one read serves many of them — this is
	what cuts the request count for `node_modules`-style trees.
- Empty files are `COMPRESSED_FULL` inodes with no lclusters.
- With `--erofs-data-alignment N`, a file of at least `N` bytes starts on an
	`N`-byte boundary **of the layer data** (zero-filled gap, no pcluster
	references it). Identical large files then occupy identical blocks
	regardless of their neighbours, so a volume that deduplicates or snapshots
	at a fixed granularity (2MiB on common cloud disks) sees stable blocks.
	Because the alignment is relative to the data file, not to the image
	address space, `merge` may map the device anywhere. Put the store on a
	filesystem that keeps file extents on that grid as well (e.g. XFS with
	`su=2m` / `extsize 2m`).
- The builder compresses on a worker pool: file data (and the packed
	stream) is cut into 4MiB segments handed to `min(CPUs, 8)` threads, and
	segments are committed to the blob strictly in submission order, so the
	output depends only on the source bytes (deterministic, reproducible
	digests), never on scheduling. A pcluster never spans a segment boundary
	(at most one under-filled pcluster per 4MiB, well under 1% of size).
	Inode metadata of a file is finalized when its last segment lands, so
	the builder still streams: the tar is read once, no rootfs is staged, and
	memory stays bounded regardless of layer size (16 segments in flight
	plus their outputs).

The superblock declares `ZERO_PADDING | BIG_PCLUSTER (= COMPR_CFGS) |
CHUNKED_FILE | DEVICE_TABLE` plus `FRAGMENTS` when a packed inode exists, the
algorithm bit in `available_compr_algs` (LZ4 = bit 0, zstd = bit 3), and the
matching `COMPR_CFGS` records right after the superblock — LZ4 `{max_distance
65535, max_pclusterblks 16}`, zstd `{format 0, windowlog 19 - 10}` (a 512KiB
window, what erofs-utils picks for 64KiB pclusters) — so the device table
starts at slot 10 (byte 1280) like `mkfs.erofs`. Each inode's map header
names its algorithm in `h_algorithmtype`; `merge` declares the union of its
layers' algorithms. Directory and symlink data blocks resolve through the
device table like file data, which is why the layer device must be mapped
past the bootstrap.

zstd pclusters are independent standard frames (level 3), found by the same
fitblk search erofs-utils uses (zstd has no `compress_destSize`), which costs
several times the LZ4 build CPU for a noticeably smaller store. Kernel mounts
need 6.10+ (`CONFIG_EROFS_FS_ZIP_ZSTD`); `nydus fuse` decodes either in
userspace.

The readers accept the `FRAGMENT_PCLUSTER` tail-fragment form `mkfs.erofs
-Efragments` emits (a file's last extent in the packed inode) but the builder
does not produce it: it did not reduce request count or start time on the
images measured and read slightly more bytes.

### Merging z_erofs layers

`nydus merge --bootstrap out.img /store/<l0> /store/<l1> ...` takes the
layers' full blobs (or their standalone bootstraps) and emits one multi-device
bootstrap:

- device `i + 1` is layer `i`'s blob, named by its SHA256 and placed back to
	back in the mapped block space on 512KiB boundaries past the merged
	bootstrap; every HEAD/PLAIN lcluster address in the copied inode tails is
	shifted by the difference between the layer's and the merged mapping;
- OCI whiteouts are applied and the k-way path merge is the same as for
	chunk-based layers;
- the layers' packed inodes are concatenated into one (each is block padded by
	the builder so the lcluster grids line up) and every fragment offset is
	shifted by the packed bytes of the layers below it.

The blobs are untouched, so a store shared by many images keeps one copy of
each layer, and the same merged bootstrap drives both mount paths below.

### Mounting

Kernel mounts read the store files as devices:

```bash
# One layer.
mount -t erofs -o device=/store/<sha256> layer.meta /mnt

# A merged image: one device= per slot, in device table order (nydus check
# prints them as "Blobs" entries).
mount -t erofs -o "device=/store/<l0>,device=/store/<l1>,..." out.img /mnt
```

The bootstrap and the devices can be block devices (kernel 6.1+ with
fragments, 5.16+ without) or regular files on a filesystem (file-backed EROFS,
kernel 6.12+; file-backed I/O is capped at 64KiB per request, one pcluster).
The kernel only reads the leading data region of each store file.

`nydus fuse` mounts a native image from a local store without any cache
(`--blob-dir /store`), decompressing pclusters per read in userspace; this
needs no z_erofs support from the kernel and is what `nydusify check` uses.
The on-demand frontends (`ublk`, `nbd`, `fanotify`, `uffd`) serve native
layers from a `local` store by handing the store file itself to the kernel:
it is already complete, so nothing is fetched, and no `storage.dir` is needed
when every blob is native. Registry backends do not serve native layers.

### Checking

`nydus check --bootstrap out.img --blob-dir /store` resolves every device by
its slot id, verifies size and SHA256 (see [Check](#check)), counts z inodes and
fragments, and reports any pcluster address outside the device table.

## Build Pipeline

The build pipeline follows this sequence:

1. Walk the source directory and build the in-memory inode tree.
2. Assign file chunk indexes into a logical uncompressed external-device address
	space. Every chunk (a file of at most the chunk size, or one chunk of a
	larger file) starts on its own block and advances by its real block-aligned
	size, so only a chunk's final block carries zero padding (no full-chunk zero
	runs).
3. Feed the chunks' bytes (without the tail padding) into the chunk group
	builder, which lays the groups out back to back: a chunk that
	reaches the chunk group minimum size is a group on its own, smaller chunks
	join the one open pack in order, which closes at a content-defined
	boundary (a digest with six low zero bits once the pack spans the pack
	minimum, five once it spans twice that) or when a chunk would take it
	past four times the minimum. Every chunk length, including lone chunks,
	is recorded in ChunkLengthTable. The chunk
	index handed back for each chunk is a placeholder until its group closes.
4. Compute BLAKE3 digests over every chunk and CRC32C over
	each chunk group payload.
5. Compress each chunk group according to the blob_meta header compressor and append
	the encoded bytes directly to the data region, in group index order. Encoded
	chunk groups are packed back-to-back with no inter-chunk group padding. For
	zstd and LZ4, chunk groups that do not shrink to at most 70% of their payload
	are stored plain and marked by `compressed_size == payload_size`.
6. Compute SHA256 over the encoded data region as those bytes are written and
	write it into the bootstrap device slot tag.
7. Close the remaining groups, resolve every placeholder chunk index to its
	group's start block plus its offset within the group, and serialize the
	bootstrap bytes in memory.
	External chunk `blkaddr` values stay logical and are not rebased by the
	bootstrap size. The bootstrap includes the native EROFS superblock
	checksum.
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
	chunk group lookup, fetches encoded chunk groups from the data region, and
	validates each decoded group.

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
	mmaping the cached file and using its tables.
7. Reads use logical uncompressed offsets from inode chunk indexes. The cache
	layer names the chunk groups covering the requested range with one cell
	table lookup per end, ensures each is fetched, decoded
	from the data region (checking the group's CRC32C, and the chunks' BLAKE3
	digests when checksum verification is on) and written onto its
	blocks, and then reads the bytes straight out of the cache file. The cache
	file mirrors the padded decoded address space, so once the covering groups
	are ready the absolute offset indexes directly into it for a single
	contiguous read — no chunk-level lookup is needed on the read path.

A miss does not fetch its group alone. The cache splits the **compressed**
data region into cells of `storage.fetch_size` bytes (default 2 MiB) and,
on a miss, issues one range read for every group whose compressed range
overlaps the missed group's cell — trimmed at groups that are already cached
or already being fetched — then decodes each group as it comes and publishes
it. The fetch size is a runtime choice, independent of the image's chunk
size; groups tile the data region back to back, so a fetch is always one
contiguous range, and because it is measured in compressed bytes it bounds
the transfer rather than the decoded span. The fetch size sets the
request/byte trade-off: the blobs compress several-fold, so a fetch of `W`
compressed bytes decodes to a multiple of `W` in the cache, and every extra
group a fetch pulls in is decoded onto the cache whether or not the workload
reads it. Larger fetches cut the request count and help on high-latency
links; smaller fetches transfer fewer unused bytes and help on
bandwidth-bound links and small disks. The 2 MiB default takes about a third
of the requests off the previous block-group format for a moderate byte and
cache cost, where 4 MiB roughly doubles the cache. Deployments that are short
on bandwidth or disk should lower `fetch_size`; latency-bound ones can
raise it. Optimized images (see [Optimize](#optimize)) sidestep the trade-off:
their ondemand blob is prefetched whole into the source caches, so the fetch
size only governs the residual misses.

Every chunk group a read touches is also recorded in the on-demand access
trace, whether it hit or missed, so `/trace` names the groups the workload
read and `nydus optimize` copies exactly those (see [Optimize](#optimize)).

External blob reads always go through the blob_meta-aware cache abstraction;
the runtime never reads external blob data by direct mmap offsets.

On-demand and diskless group reads own their temporary input/output buffers.
Buffers of at least 1 MiB use private anonymous mappings, which are unmapped
when the buffer owner is dropped instead of remaining in allocator arenas.
On Linux, mappings of at least 2 MiB also receive a best-effort transparent
huge-page hint to reduce page faults during decoding. This neither requires
reserved huge pages nor changes system-wide settings; allocation still works
if the kernel cannot provide huge pages. The mapping lifetime is unchanged.
Smaller buffers use ordinary vectors. Zstandard decodes directly into the
declared-size output slice, and an unexpected decoded length remains an error.
This changes temporary memory management, not the persistent data cache or
fetch concurrency. Prefetch workers continue to reuse their fetch buffers.

Three further measures keep the idle footprint of a mount service small. The
standalone bootstrap is mapped with a read-ahead hint (`MADV_WILLNEED`) rather
than pre-faulted, so the whole file is pulled into the page cache but only the
metadata actually touched counts toward RSS. The asynchronous log writers queue
at most 8192 lines each instead of the crate default of 128k, which alone
pinned about 4 MiB per appender. On glibc, the `nydus` binary caps malloc at
two arenas and fixes the mmap threshold at 512 KiB (trim threshold 1 MiB) for
the long-running services only; build, check, merge, export and optimize keep
the allocator defaults. Explicit `MALLOC_ARENA_MAX`, `MALLOC_MMAP_THRESHOLD_`,
`MALLOC_TRIM_THRESHOLD_` or `GLIBC_TUNABLES` in the environment disable this
built-in tuning.

The local backend opens source blob files lazily when read IO is first issued and
caches the file descriptor for later `pread` calls. The persistent local cache
also opens `<full_blob_digest>.blob.data` lazily, then serves repeated reads via
cached `pread`/`pwrite` file descriptors. Cache artifacts are named by the full
blob digest:

- `<full_blob_digest>.blob.data` stores decoded uncompressed data.
- `<full_blob_digest>.blob.meta` stores the verified blob meta copy cached from
	the local backend.
- `<full_blob_digest>.group.map` records which chunk groups have been decoded
	(a shared readiness bitmap, one bit per group, see
	[Cross-process cache sharing](#cross-process-cache-sharing-and-prefetch-dedup));
	byte `N` of the same file also carries the cross-process fetch claim for
	group `N` (an OFD byte-range lock spanning the groups of one fetch; the
	bytes' contents are unaffected).
- `<full_blob_digest>.prefetch.lock` is the cross-process prefetch lock file
	(empty; only its `flock` state matters).

The cache data file mirrors the decoded address space one-to-one, so a group's
chunks land at their `blkaddr * 4096` and EROFS chunk `blkaddr` offsets index
into it directly:

```text
cache directory, artifacts named by SHA256(full blob) = <hex>

<hex>.blob.data — decoded data, sparse; filled group by group
+-----------+-----------+-----------+-----------+---
|  group 0  |  (hole)   | groups 2-5|  (hole)   | ...
|  decoded  |           |  decoded  |           |
+-----------+-----------+-----------+-----------+---
^ byte offset = the group's uncompressed_block_offset * 4096; written only after
  decode + CRC32C (+ digest validation when enabled) succeeds

<hex>.blob.meta — verified blob meta copy (mmap'd for group/chunk lookup)
Header            CRC32C, counts and address geometry
ChunkGroupTable        data/block/chunk starts, payload sizes and CRC32C
ChunkLengthTable        u32 length for every stored chunk
ChunkGroupIndexTable u32 group index per index span
ChunkGroupDigestTable       BLAKE3 per group, when enabled
ChunkGroupRedirectTable     source blob and group, for ondemand blobs only

<hex>.group.map — shared readiness bitmap, MAP_SHARED + atomic bit ops
+---------------------------------+----------------------+
| 4 KiB header (NDGRPMAP, features| 1 bit per group ...  |
| count, ready count, state)      |                      |
+---------------------------------+----------------------+
  bits set only after the group's bytes are resident in .blob.data;
  the ALL_READY header state bit latches once every bit is set;
  byte N also carries the OFD lock claiming group N's fetch

<hex>.prefetch.lock — empty; exclusive flock serializes prefetch owners
```

### Blob prefetch

After a successful mount, `nydus fuse` spawns a background prefetcher that warms
the local cache so later on-demand reads hit decoded data instead of fetching and
decoding chunk groups synchronously. Prefetch is **off by default**: enable it with the
`--prefetch` flag, or through the storage config `prefetch.scope` (either one
turns it on); the config's `prefetch` block also sizes the worker pool. See
[Storage config](#storage-config).

Per-blob prefetch streams chunk groups into the cache:

- Prefetch reads the data region in batches of consecutive chunk groups
	whose compressed bytes add up to `storage.fetch_size` (default 2 MiB),
	so prefetch and on-demand reads issue backend requests of the same size;
	a zero fetch size reads group by group.
- For each batch it issues a single contiguous backend range read, then
	decodes each contained chunk group (plain copy, zstd or LZ4), validates
	the group's length and CRC32C, writes the decoded bytes to the cache file
	at the chunks' padded blocks, and marks the group ready in the group map.
- A priority blob's batches are fetched by up to
	`prefetch.concurrent_blob_count` workers (default 10), handed out in blob
	order; the first batches are single groups (a "ramp") so the head of an
	ondemand blob — the workload's first reads — lands within one round trip
	while the rest streams in full batches. Blobs pulled by the phase-2 pool
	use one worker each.
- Prefetch uses its own decode buffer and takes no group locks. The group map
	bits are updated atomically and `set_ready` is idempotent, so racing with a
	FUSE read at worst decodes the same group twice into identical bytes at the
	same offset. This keeps prefetch fully decoupled from, and non-blocking to,
	the on-demand read path.
- Chunk groups already marked ready (for example, fetched on demand or from a
	previous run's persistent cache) are trimmed off the ends of a batch; a
	batch that is entirely ready costs no backend read.

Prefetch scheduling across blobs has two phases; `prefetch.scope` picks what
each phase covers. `auto` (the default) is resolved on the prefetch thread once
the priority blobs' metas are known: it becomes `ondemand` when one of them is
an ondemand blob and `all` otherwise, so an optimized image spends backend
bandwidth only on its hot set while an unoptimized one is still streamed the
way a classic nydusd mount would. The resolution is logged.

1. Priority blobs are prefetched first, sequentially, in the order listed by the
        root inode's `trusted.nydus.prefetch.blobs` xattr (a comma-separated list of
        device ids). The list is deduplicated and filtered to existing devices. The
        "ondemand" priority blobs (their blob meta carries a ChunkGroupRedirectTable) are
        always streamed first regardless of their position in the list. Under
        `ondemand` they are the only blobs warmed; other priority blobs are skipped
        so backend bandwidth is not spent pulling whole source blobs. Under `all` the
        other priority blobs follow, and the groups the redirect stream already
        filled in their caches are trimmed off their batches.
2. Only when `prefetch.scope` is `all`, the remaining blob devices are then
        prefetched concurrently by a worker pool sized to
        `min(prefetch.concurrent_blob_count, remaining)` (default `10`). Under
        `ondemand` and `auto` a pool of the same size instead opens every blob's
        cache (fetches and validates the blob metas, creates the sparse files)
        without pulling data, priority blobs first and running alongside phase 1
        rather than after it; the `auto` decision reuses those opens. An
        optimized image lists every blob in its prefetch xattr, so without this
        the phase 1 redirect checks alone would open the caches
	one blob at a time; with it neither those checks, nor the redirect fills
	into the source caches, nor a later first read of any blob, nor a
	block-device frontend's probe of many blobs right after the device appears
	pays the round trips serially.

The ondemand blob (produced by `nydus optimize`, listed first in the xattr)
is a redirect blob (its blob meta has a ChunkGroupRedirectTable): it is streamed in the order it was packed — the
workload's first-access order — and every decoded group is written into its
**source** blob's cache at the source group's blocks (after the length and
CRC32C checks) and marked ready there, so the earliest reads find their
groups resident first; the ramp above puts its first groups on the wire in
parallel before the bulk follows. The ondemand blob never builds a cache
file of its own. Groups whose source is already cached — by another process
sharing the directory, or by a previous run — are trimmed off the batches
and not fetched. Per-group failures (decode or CRC errors, an unknown source
blob, a failed fill) are logged, counted in `cache_redirect_skip_chunk_group`
and skipped, so a bad copy can only lose warmup, never poison a source cache
or abort the prefetch. The prefetch logs how long the ondemand blob took and
how many groups it filled and skipped, so operators can tell whether the
warmup outran the workload.

### Cross-process cache sharing and prefetch dedup

Many identical instances cold-starting on one node (for example, dozens of
hypervisor-embedded cores mounting the same optimized image) all target the
same cache directory, the same blobs, and the same access-ordered hot set.
Without coordination each instance would stream the whole ondemand blob and
decode every group independently — N× the backend traffic, decode CPU, and
cache writes for identical bytes. Two mechanisms make the warmup effectively
single-instance while leaving the on-demand read path untouched.

**Shared group map bitmap.** The `<digest>.group.map` file is a 4096-byte
header followed by one readiness bit per chunk group. The header carries the
8-byte ASCII magic `NDGRPMAP` (same raw-bytes style as the blob meta's
`NDBLMETA`), the `feature_compat` and `feature_incompat` words at offsets 8
and 12 (the blob meta prefix, without a crc32 since the file is mutable), the
group count at 16, a mutable ready-group counter at 20 and a mutable `state`
word at 24 whose bit 0 is `ALL_READY`; the rest of the header page is
reserved and zero. The whole file is mapped `MAP_SHARED`
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
- Bits are set only after the decoded, validated group bytes have been
	written to the cache data file, and persistence rides on regular kernel
	writeback of the dirty mapping — there is no per-bit write syscall on the hot
	path.

`is_all_ready()` is the O(1) fast path: the process that flips the last
missing bit (tracked by the shared ready counter) latches the sticky
`ALL_READY` flag in the header, and from then on a single atomic load answers
"is this blob fully cached?" for every process. Per-event handlers — uffd page
faults, FUSE reads — consult it before any
per-group bookkeeping (`ensure_range` and `ready_ranges` short-circuit on it),
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
	can observe progress while it waits: a waiter gives up on the lock as soon
	as the shared group map reports every group ready (its own prefetch then
	reduces to a cheap all-ready scan).
- Locking failures (unopenable lock file, unexpected errno) degrade to
	prefetching without the lock — correctness never depends on it, only the
	cross-process dedup guarantee does.
- The guard is the open file descriptor: dropping it — including by process
	death — releases the lock, so a crashed owner is taken over by a waiter, and
	the ready-skip logic resumes the warmup exactly where the crashed owner left
	off.
- **On-demand reads never touch the prefetch lock.** A cold group hit by a page
	fault is never queued behind a whole-blob warmup; it coordinates at group
	granularity instead (below).

**Per-group fetch claim.** On-demand reads coordinate at group granularity
with byte-range locks on the `<digest>.group.map` file, where byte `N` stands
for group `N` — one descriptor per blob however many groups it has, and no
extra sidecar. A reader that finds a group cold claims the bytes of the
whole fetch it plans (the missed group and the rest of its fetch-size cell),
and readers in the other instances that miss on any group of that fetch
block until the claim is released, which the fetcher does immediately after
publishing the groups in the shared group map. Waiters therefore re-check
readiness, trim their own fetch to what is still missing, and almost always
find nothing left, so a cold group costs one backend fetch per node rather
than one per instance.

- The claims are **open file description locks**, so the kernel releases them
	when the descriptor closes, including on process death. A fetcher that crashes
	mid-flight hands the group to a waiter instead of wedging it.
- Waiting blocks in the kernel rather than polling, so the handover follows the
	release immediately. What bounds the wait is the fetcher, not the waiter:
	every backend read carries a timeout (hence the short registry `timeout`
	default), so a claim is always released. **A claim must never be held across
	an operation that cannot time out** — what queues up behind it are reader
	threads. The wait is interruptible, so shutdown still works.
- The in-process fetch flight elects a single fetcher per group before any of
	this (one flight covers every group of the fetch it issues, so threads
	missing on neighbouring groups join it instead of fetching again), which is
	what makes a descriptor-owned lock meaningful: two threads locking the same
	bytes through one descriptor would both succeed and neither would wait.
- A filesystem that cannot provide the lock degrades to fetching without
	coordination, exactly as before this existed — a missing optimisation must
	never fail a read.

**Batch skipping.** A waiter that eventually acquires the prefetch lock (or a
restart replaying the warmup) must not re-download the blob just to discover
every fill is a no-op: each prefetch batch is trimmed to its groups that the
shared group map does not already report ready, and a batch that is entirely
ready is not fetched at all.

**What this buys.** With the claims in place the backend cost of a cold
node is independent of how many instances share the cache: the end-to-end
suite in `tests/e2e/cache_sharing_test.go` reads the same cold file from
four processes at once and requires the summed
`cache_ondemand_fill_chunk_group` to stay within one group of a single
process doing the same read, requires
four concurrent full prefetches to fill at most 1.5× the groups a single
prefetch fills (the per-blob prefetch lock keeps all but one process from
streaming the blob), and checks that a peer killed mid-fetch neither blocks
nor corrupts the survivors. The same suite covers two images that reference
one blob converging on a single set of cache files, which is what keeps a
node running many images cheap.

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
	which mirrors the padded kernel-visible block address space — a guest read of block
	`N` lands at byte `N * 4096` of the backing file.
- `NydusCore::new(bootstrap, Config)` parses the bootstrap and an already
	loaded `nydus_config::Config` (same structure as `nydus fuse --config`) lazily;
	per-blob work (blob meta download/validation, sparse cache file creation)
	happens on first touch through `blobs.prepare_all()` or `blobs.fetch`.
- Unless `config.prefetch.scope` is `none`, `new` spawns a background prefetch
	worker before returning — the same two-phase workflow as `nydus fuse`
	(ondemand blob first, then the rest only under `prefetch.scope: all`, or
	under the default `auto` when the image has no ondemand blob). The worker
	thread inherits the network namespace active at construction time, so
	callers that construct the core for a guest-facing backend must do so
	while the desired netns is active.
- Access traces record every chunk the guest reads, hit or miss, and
	`nydus_telemetry::metrics::snapshot()` exposes runtime counters for embedding
	into hypervisor stats endpoints; a saved trace JSON can be replayed offline
	via `nydus optimize --trace-file`. See [Metrics](#metrics).
- `BlobId` is the public blob digest type. It converts to/from 64-character
	SHA256 hex strings and `[u8; 32]` bytes.
- `blobs.prepare_all()` lists the device table in order as `BlobInfo` entries:
	blob index, `BlobId`, mapped block address and offset, block count, cache
	path and cache size. Calling it prepares the sparse cache data files, so
	`BlobInfo.cache_path` is immediately suitable as a virtio-pmem backing file
	and `BlobInfo.cache_size` is `blocks * 4096`.
- `blobs.fetch(id, offset, len)` guarantees the 4 KiB-aligned range is decoded,
	validated, and resident in the cache data file. It maps the range to chunk
	groups through ChunkGroupIndexTable and reuses the regular cache chain
	(the fetch-size fill), so it is idempotent, concurrency-safe, and shares
	trace/metrics recording with the FUSE path.
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
			"blob index={} id={} blocks={} cache={} bytes={}",
			blob.index,
			blob.id,
			blob.blocks,
			blob.cache_path.display(),
			blob.cache_size,
		);

		// Hypervisor wiring point:
		//   - map `bootstrap` as the EROFS primary device;
		//   - map `blob.cache_path` as the virtio-pmem backing file for
		//     external device `blob.index`, sized to `blob.cache_size`.
	}

	// Prepare a range before the guest touches it. The range must be 4 KiB
	// aligned; fetch expands to whole chunk groups (and its fetch-size cell)
	// internally and is safe to call repeatedly or concurrently.
	if let Some(blob) = blobs.first() {
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

z_erofs layers (`nydus build --compressor erofs-lz4|erofs-zstd`) sit in
between: their data region is a plain EROFS device the kernel mounts directly
(5.16+ for the layout, 6.1+ for fragments, 6.10+ for zstd pclusters), and the
full blob around it lets every nydus
frontend serve the same file — the block frontends and fanotify hand the raw
data to the kernel, `nydus fuse` decompresses pclusters in userspace (any
kernel), and `check`, `merge` and `export` read them too.

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
	`image/image.boot` and per-layer `image/<digest>.blob.meta` files, annotated
	with `containerd.io/snapshot/nydus-bootstrap`.
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

Putting the chunks together, a converted nydus image looks like:

```text
nydus image (OCI manifest, os.features: ["nydus.remoteimage.v1"])
+--------------------------------------------------------------------+
| config      diff_ids / history rewritten; runtime fields verbatim  |
|--------------------------------------------------------------------|
| layer 0     nydus blob layer   ...nydus.blob.v1   <- OCI layer 0   |
| layer 1     nydus blob layer   ...nydus.blob.v1   <- OCI layer 1   |
|  ...        (one full blob per source OCI layer                    |
|             or per local directory source)                         |
| layer N     bootstrap layer    gzip tar { image.boot, blob metas } |
|             = merged overlaid bootstrap referencing layers 0..N-1  |
+--------------------------------------------------------------------+
           |
           |  each blob layer is one full blob; layer digest =
           |  SHA256(full blob) (uncompressed layer, diff id = digest)
           v
+--------------------+-------------+-----------+--------+
| encoded data       | bootstrap   | blob meta | footer |  full blob
| (dense groups or   | (embedded  | chunk/group| 4 KiB  |
|  native device)    |  EROFS)    | tables, or |        |
|                    |            | absent for |        |
|                    |            | erofs-*    |        |
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
reference. `--compressor` picks the direction: `none`, `zstd`, `lz4`,
`erofs-none`, `erofs-lz4` and `erofs-zstd` run the OCI to nydus conversion;
the `oci-` prefixed
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
2. Decompress each OCI layer (gzip/zstd/plain), then stream its tar directly
	into `nydus build --source-type tar /dev/stdin`. PAX metadata and whiteout
	markers are preserved without extracting a rootfs. `--chunk-size` and
	`--compressor` are forwarded; output flows through
	a FIFO into the content store (`internal/pipeline/layer.go`). Input/build
	failures abort conversion; destination failures cancel the subprocess.
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

Existing nydus layers are reused, not transcoded. All merged inputs must have
compatible data layouts; chunk/z mixtures and differing packed-inode
compression algorithms fail explicitly. Rebuild incompatible source layers
with the selected compressor before stacking them.

Go stages and packages `.blob.meta` using footer offsets, without parsing its
chunk/group tables. Use matching `nydus` and `nydusify` builds; the Rust reader
owns format validation. `optimize` likewise preserves source sidecars and adds
the ondemand blob's sidecar rather than converting old experimental formats.

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
| `--chunk-size` | `0` (automatic) | Chunk size, 2MiB by default; explicit values are bytes (a power of two, at least 4KiB). The largest file chunk (chunk groups follow the builder's defaults). Not used by `erofs-lz4`/`erofs-zstd` and ignored when converting back to OCI. |
| `--compressor` | `zstd` | `none`, `zstd`, `lz4`: chunk-based layouts served on demand; `erofs-none`, `erofs-lz4`, `erofs-zstd`: native EROFS layers without blob meta; `oci-gzip`, `oci-zstd`, `oci-tar`: reverse OCI conversion. |
| `--platform` | all | Convert only the given platform (e.g. `linux/amd64`). |
| `--append-in-bootstrap` | empty | Local file paths to bundle into the bootstrap layer tar alongside `image.boot`; files inside a directory source are excluded from that source's blob data region. |
| `--source-insecure`, `--target-insecure` | `false` | Skip TLS verification independently for the selected source/target registry. |
| `--source-plain-http`, `--target-plain-http` | `false` | Use plain HTTP independently for the selected source/target registry. |
| `--log-level` | `info` | `trace`, `debug`, `info`, `warn`, `error`. Forwarded to the `nydus build`/`merge` subprocesses. |

Notes:

- OCI conversion does not need root: tar metadata is encoded directly, without
	chown, mknod or privileged xattr writes on the host. Directory sources still
	require permission to read their contents and metadata. Filesystem checking
	against an extracted OCI rootfs and a mounted target has separate privileges.
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
# Whole-image conversion; the source registry keeps TLS enabled.
nydusify convert \
  --source docker.io/library/mariadb:latest \
	--target localhost:5000/mariadb-nydus \
	--target-plain-http

# One-layer image from a local directory.
nydusify convert \
  --source ./models/llama \
	--target localhost:5000/llama-nydus \
	--target-plain-http

# Stack a nydus base image and two directories into one image:
# three blob layers plus one merged bootstrap layer.
nydusify convert \
  --source localhost:5000/base-nydus \
  --source ./layer-data \
  --source ./layer-config \
	--target localhost:5000/app-nydus \
	--source-plain-http --target-plain-http

# Convert a nydus image back to a plain OCI image with gzip layers.
nydusify convert \
  --compressor oci-gzip \
  --source localhost:5000/mariadb-nydus \
	--target localhost:5000/mariadb-oci \
	--source-plain-http --target-plain-http
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
| `--source-insecure`, `--target-insecure` | `false` | Skip TLS verification for the respective registry. |
| `--source-plain-http`, `--target-plain-http` | `false` | Use plain HTTP for the respective registry. |
| `--log-level` | `info` | `trace`, `debug`, `info`, `warn`, `error`. Forwarded to the `nydus fuse` subprocess (use `debug` to see per-request backend reads). |

Example:

```bash
sudo nydusify check \
  --source docker.io/library/mariadb:latest \
	--target localhost:5000/mariadb-nydus \
	--target-plain-http
```

A passing run logs `check passed`; any rule failure returns a non-zero exit code
with the failing rule and offending path in the error.

### nydusify optimize

`nydusify optimize --pattern <path> --source <nydus-ref> --target <nydus-ref> [OPTIONS]`

Publishes an optimized copy of a nydus image from a recorded access pattern:

1. Pull `--source` (must be a nydus image) and extract its bootstrap layer
	(`image.boot` plus the per-layer blob metas, which seed the cache dir).
2. Run `nydus optimize` against the bootstrap with `--trace-file`, using a
	registry-backed storage config so the source chunk groups are range-read
	from the source registry on demand.
3. Assemble the optimized manifest: the original data layers are reused as-is,
	the ondemand blob is appended as a new nydus data layer (annotated with
	`containerd.io/snapshot/nydus-blob-optimized` so it is recognizable without
	parsing it), and the bootstrap layer is rebuilt with the rewritten
	`image.boot` plus all blob metas (including the ondemand one). Config diff
	ids and history are updated.
4. Push the result to `--target`.

`--pattern` is a JSON access-pattern file in the same format served by a
mount's `GET /trace` endpoint
(`{"version":1,"patterns":[{"blob_index":1,"chunk_group_index":4},...]}`,
one entry per chunk group read). It can be
saved from the `/trace` endpoint of a `nydusify mount` apiserver, or exported
offline from a pmem/core mount trace (e.g. a rund sandbox extendedstats
snapshot). Record the pattern from a mount **without** prefetch so it captures
the pure on-demand access pattern, exercise the workload, then save the trace.
Mount the optimized image **with** `--prefetch` to get the phase-0 ondemand
blob warmup. Shared flags (`--builder`, `--work-dir`, `--platform`, source/target
`--*-insecure` and `--*-plain-http`, `--log-level`) behave as in `nydusify convert`. No root is
required: optimize never extracts OCI layers, it only rewrites metadata and
appends the ondemand layer.

Example:

```bash
sudo nydusify mount -t localhost:5000/app:nydus -m /mnt/app --work-dir /tmp/mnt --target-plain-http &
# ... run the workload against /mnt/app ...
curl --unix-socket /tmp/mnt/apiserver.sock http://localhost/trace > /tmp/pattern.json
nydusify optimize \
  --pattern /tmp/pattern.json \
  --source localhost:5000/app:nydus \
	--target localhost:5000/app:nydus-optimized \
	--source-plain-http --target-plain-http
```

## Validation Strategy

Run the non-privileged contracts first from the repository root:

```bash
cargo fmt --all -- --check
cargo test --workspace --features cli
cargo clippy --workspace --all-targets --features cli,fanotify,ublk,nbd -- -D warnings
make test-nydusify
```

`make test-nydusify` builds the current Rust CLI and runs all Go packages with
the race detector. `NYDUS_TEST_BUILDER` enables the real builder test when
invoking Go directly. The test streams gzip OCI content through Pack, checks
blob meta magic and feature words, stages metadata, merges, checks and exports each of
`none`, `zstd`, `lz4`, `erofs-none`, `erofs-lz4` and `erofs-zstd` (the native
layers carrying no blob meta). It verifies contents,
PAX nanosecond timestamps, ownership, whiteouts and device metadata without
mounting or creating host device nodes. Without that environment variable the
real-builder test explicitly skips; unit success alone is not this gate.

Registry/mount tests (`make test-e2e`, `make test-tooci`, `make test-ublk`,
`make test-nbd`, `make test-fanotify`, `make test-uffd`) need their documented
root, kernel and registry prerequisites. Run them only in an isolated test
environment. Guest DAX and workload performance require separate measurements.

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

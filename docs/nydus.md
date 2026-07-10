# Nydus Design

## Status

This document describes the current nydus artifact model, blob meta format and
runtime read path. Nydus no longer preserves compatibility with the original
split `image + --blobdev` prototype, the old blob_meta header layout, or the old
data-digest sidecar naming convention.

The user-facing commands are:

- `nydus build`
- `nydus check`
- `nydus merge`
- `nydus fuse`

The current merge implementation focuses on metadata overlay, blob-id
preservation and OCI whiteout handling. The build and runtime paths use the
embedded blob meta region as the canonical map from logical EROFS
external-device addresses to encoded ranges in the stored data region.

## Goals

- Use one user-visible `blob` artifact as the primary layer output.
- Allow an optional standalone `bootstrap` artifact for remote metadata-only use.
- Make `fuse` support either a direct blob path or a bootstrap plus blob-dir.
- Persist a stable blob identifier inside bootstrap metadata.
- Keep EROFS file chunk indexes logical and map a block to its compression group
	in O(1) via constant-sized groups.
- Support compressed blob data while preserving a plain decoded cache artifact
	for EROFS compatibility and repeated reads.

## Non-goals

- Preserve backward compatibility with the old `image + --blobdev` CLI.
- Preserve compatibility with old blob_meta headers or sidecar names.
- Implement all merge semantics in the first migration slice.
- Introduce cross-layer global deduplication beyond the current single-build dedup.
- Rework the full EROFS on-disk layout to match every upstream variant before the
  new artifact workflow is proven in-tree.

## CLI Contract

### Build

`nydus build [OPTIONS] <SOURCE>`

The `nydus build` command builds a source directory into EROFS format. It
optionally emits a standalone metadata-only bootstrap via `--bootstrap`, while
`--blob` remains the primary artifact and contains the encoded data region,
bootstrap, blob meta, and footer in one file. `--blob-dir` is an alternative
output mode that writes the full blob into the target directory through a
temporary random file, computes the full artifact SHA256, and finally renames the
file to that SHA256. The standalone bootstrap records the SHA256 blob id for the
data region in its device-table metadata so runtime can resolve the
corresponding full blob later.

Current CLI help:

```bash
nydus build -h
Create an nydus filesystem layer (chunk-based)

Usage: nydus build [OPTIONS] <SOURCE>

Arguments:
	<SOURCE>  source from which to build the filesystem

Options:
	--type <type>
		Conversion type: [default: dir-nydus] [possible values: dir-nydus]
	--blob <blob>
		File path to save the generated nydus blob (also include bootstrap)
	--blob-dir <blob-dir>
		Directory path to save the generated nydus blob with sha256 file name (conflict with `--blob`)
	--bootstrap <bootstrap>
		File path to save the generated nydus bootstrap (optional)
	--chunk-size <chunk-size>
		Set the EROFS file chunk size, must be power of two, 4KiB-aligned, and at least 4KiB: [default: 1048576]
	--compress-size <compress-size>
		Set the blob meta group uncompressed size, must be a multiple of 1MiB and at least the chunk size: [default: 1048576]
	--compressor <compressor>
		Algorithm to compress data chunks: [default: zstd] [possible values: none, zstd]
	--log-level <log-level>
		Log level: [default: info] [possible values: trace, debug, info, warn, error]
```

Current implementation notes:

- Either `--blob` or `--blob-dir` is required.
- `--bootstrap` is optional and emits a standalone metadata-only artifact.
- `--chunk-size` defaults to `1048576` (1 MiB) and controls EROFS file chunk
	indexes (the unit of file splitting and per-chunk BLAKE3 digests). Chunks are
	independent of compression groups and may straddle group boundaries, so a
	smaller chunk size does not fragment blob_meta into tiny compression units.
- `--compress-size` defaults to `4194304` (4 MiB) and sets the uncompressed size
	of each blob_meta group (the unit of compression and of a single backend
	read). Groups are formed by packing whole decoded blocks up to this size
	regardless of chunk boundaries, so every group but the last is exactly this
	many blocks. It must be a positive multiple of 1 MiB and at least
	`--chunk-size`. Note the alignment rules differ: `--chunk-size` must be a power
	of two and 4KiB-aligned, while `--compress-size` only needs to be a 1 MiB
	multiple. Raising `--chunk-size` above 1 MiB requires raising `--compress-size`
	to match or exceed it.
- `--blob <path>` stores the full blob at `<path>` and a standalone blob meta
	copy at `<path>.blob.meta`. If `<path>` already exists and is a FIFO, build
	writes the full blob stream to that FIFO instead of creating a regular file.
- `--blob-dir` stores the full blob under `<blob-dir>/<full_blob_sha256>` and a
	standalone blob meta copy under `<blob-dir>/<full_blob_sha256>.blob.meta`.
- `--compressor zstd` attempts to compress each blob_meta group as one
	unit. If the compressed bytes are larger than 70% of the uncompressed group,
	the group is stored plain and its blob_meta group record has
	`compressed_size == uncompressed_block_count * 4096`.
- `--compressor none` writes every group plain.
- Build prints one `Blobs` section grouped by `Blob N` with `blob_index`,
	`data_blob_digest`, `full_blob_digest`, `chunk_size`, `chunk_count`,
	`group_count`, `chunk_digester`, `chunk_compressor`,
	compressed/uncompressed totals, and full blob region offsets and block counts.

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
Merge multiple nydus bootstrap into a overlaid bootstrap

Usage: nydus merge [OPTIONS] <SOURCE>...

Arguments:
	<SOURCE>...  nydus blob paths with sha256 file name (allow one or more)

Options:
	--bootstrap <bootstrap>
		File path to save the generated overlaid nydus bootstrap
	--whiteout-spec [default: oci] [possible values: oci]
	--log-level <log-level>
		Log level: [default: info] [possible values: trace, debug, info, warn, error]
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
group access pattern and rewrites the bootstrap so the runtime prefetches that
blob first. The ondemand blob carries copies of the hot groups (in first-access
order); at mount time the phase-0 prefetch streams it and redirects each decoded
group into the source blob's cache, so early on-demand reads hit warm cache
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
	(`{"patterns":[{"blob_index":1,"group_index":4},...]}`); entries are
	deduplicated preserving first-access order. Run the workload against the
	mount before invoking optimize so the trace is populated.
- `--trace-file` is the offline alternative to `--apiserver` (the two are
	mutually exclusive; one of them is required). It accepts either the bare
	`{"patterns":[...]}` document or a wrapper object exposing the same under a
	top-level `trace` field (as returned by a hypervisor's stats endpoint
	embedding the accessor trace), so a trace captured from a pmem/accessor
	mount can be replayed without a live apiserver.
- `--parent-bootstrap` is the merged bootstrap to optimize; it is read-only, so
	optimize can be re-run against the same parent with new patterns.
- `--bootstrap` is the rewritten bootstrap output: the parent's inode tree with
	an appended ondemand device slot and the root `trusted.nydus.prefetch.blobs`
	xattr updated to list the ondemand device id first.
- `--blob-dir` receives the ondemand blob (named by its full SHA256) and its
	`<digest>.blob.meta` sidecar; the digest is printed as `ondemand_blob_digest:`.
- `--config` is the same storage config as `nydus fuse --config`: source group
	bytes are pulled through the regular blob cache, so groups already decoded in
	`cache.config.dir` are served from disk and cold groups are fetched from the
	backend (with CRC validation on every path).
- The ondemand artifact layout is `[group data][blob meta][footer]` with
	`bootstrap_blocks = 0` (no embedded bootstrap) and an empty chunk table. Each
	group record is a redirect: it stores the source device id and source group
	index, and its `crc32c` equals the source group's decoded CRC.

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
	`chunk_size`, `chunk_count`, `group_count`, `chunk_digester`,
	`chunk_compressor`, and compressed/uncompressed totals when the referenced
	blob can be resolved.
- `--blob-dir` resolves by scanning full blob candidates. Device slots normally
	store the data-region SHA256, while blob files are named by full blob SHA256
	when produced by `--blob-dir`.

### Fuse

`nydus fuse [OPTIONS]`

The `nydus fuse` command mounts nydus metadata as a filesystem at the target
mountpoint. It is the only runtime mount entrypoint. During read path
resolution, runtime uses the blob id recorded in bootstrap metadata to locate
the corresponding blob under `--blob-dir` and then serves chunk data from that
blob.

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
Mount nydus filesystem into a directory

Usage: nydus fuse [OPTIONS]

Options:
	--blob-dir <blob-dir>
		Directory path including nydus data blob
	--cache-dir <cache-dir>
		Directory path for persistent chunk cache files
	--config <config>
		File path to a YAML storage config providing backend/cache directories and prefetch options
	--prefetch
		Enable background blob prefetch after mounting (off by default)
	--bootstrap <bootstrap>
		File path to nydus bootstrap
	--blob <blob>
		File path to nydus blob
	--mountpoint <mountpoint>
		Directory path to mount nydus filesystem
	--log-level <log-level>
		Log level: [default: info] [possible values: trace, debug, info, warn, error]
	--log-dir <log-dir>
		Specify the log directory [default: /var/log/nydus/]
	--log-max-files <log-max-files>
		Specify the max number of log files [default: 6]
	--apiserver <apiserver>
		Serve Prometheus metrics over a Unix socket, e.g. unix:///run/nydus/api.sock
```

Supported forms:

- `nydus fuse --blob <blob> --mountpoint <mountpoint>`
- `nydus fuse --bootstrap <bootstrap> --blob-dir <blob-dir> --mountpoint <mountpoint>`
- `nydus fuse --bootstrap <bootstrap> --config <config.yaml> --mountpoint <mountpoint>`

The fuse command rejects mixed or partial combinations outside these forms.
`--cache-dir` is optional; without it (and without a cache directory from
`--config`), runtime fetches and validates requested blob_meta groups using a
temporary cache directory that is removed on exit. When `--config` is provided,
`backend.config.dir` supplies the blob directory and `cache.config.dir` supplies
the cache directory, so `--blob-dir` and `--cache-dir` can be omitted. Explicit
`--blob-dir`/`--cache-dir` flags take precedence over the config. See
[Storage config](#storage-config).

### Storage config

`nydus fuse` and `nydus check` accept a shared YAML storage config through
`--config <path>`. It centralizes the backend directory, cache directory, and
prefetch behavior so the directory flags can be omitted.

```yaml
backend:
  type: local
  config:
    dir: /var/lib/nydus/blobs
cache:
  type: local
  config:
    dir: /var/lib/nydus/cache
prefetch:
  enable: true
  threads: 10
  full: false
```

Fields:

- `backend.type` selects the blob backend, either `local` or `registry`.
	- `local`: `config.dir` is the directory holding nydus blob files
		(equivalent to `--blob-dir`).
	- `registry`: serves blobs on demand from an OCI registry. See
		[Registry backend](#registry-backend) for the full field list. `nydus
		check` only supports the `local` backend.
- `cache.type` selects the chunk cache. Only `local` is supported; its
	`config.dir` is the persistent cache directory (equivalent to `--cache-dir`).
- `prefetch.enable` (default `true`) toggles background blob prefetch after
	mount.
- `prefetch.threads` (default `10`) sets the number of concurrent prefetch
	worker threads.
- `prefetch.full` (default `false`) also prefetches every remaining blob in
	full after the priority blobs. When `false`, only the "ondemand" redirect
	blob (if any) is prefetched, warming the access-ordered hot set while
	leaving backend bandwidth to on-demand reads; non-redirect priority blobs
	and the remaining blobs are skipped. See [Blob prefetch](#blob-prefetch).

The whole `prefetch` block is optional and falls back to the defaults above;
individual fields may also be omitted independently. CLI directory flags
override the corresponding config directories, and `prefetch` only applies to
`nydus fuse`. Unknown `backend.type`/`cache.type` values are rejected at load
time.

Example invocations:

```bash
nydus fuse --bootstrap layer.bootstrap --config storage.yaml --mountpoint /mnt/nydus
nydus check --bootstrap layer.bootstrap --config storage.yaml
```

### Registry backend

The `registry` backend serves blobs on demand from an OCI registry instead of a
local directory. A blob id is the full-blob SHA256 digest, fetched via
`GET /v2/<repo>/blobs/sha256:<hex>` with HTTP range requests. A ready-to-edit
example lives at [`config.yaml`](../config.yaml) in the repo root.

```yaml
backend:
  type: registry
  config:
    host: 127.0.0.1:5000
    repo: library/nydus-demo
    insecure: true
    skip_verify: false
    timeout: 30
    retry_limit: 3
    # base64-encoded `username:password`
    auth: dGVzdHVzZXI6dGVzdHBhc3N3b3Jk
    ca_cert_files: []
    # proxy:
    #   url: http://127.0.0.1:65001
    #   dragonfly_scheduler_endpoint: http://127.0.0.1:65000
```

Fields under `backend.config`:

- `host` (required): registry host`[:port]`, e.g. `registry-1.docker.io` or
	`127.0.0.1:5000`.
- `repo` (required): image repository without tag/digest, e.g. `library/ubuntu`.
- `insecure` (default `false`): use the `http` scheme instead of `https`.
- `skip_verify` (default `false`): skip TLS certificate verification.
- `timeout` (default `30`): per-request timeout in seconds.
- `retry_limit` (default `3`): retries for on-demand reads (prefetch is tried
	once).
- `auth` (optional): base64-encoded `username:password` string for basic auth.
	Omit for anonymous / token-only registries.
- `ca_cert_files` (default `[]`): extra CA certificate PEM files to trust.
- `proxy` (optional): routes blob requests through a Dragonfly P2P transport
	instead of hitting the origin registry directly. Two transports are
	configured under the same block:
	- `url`: an HTTP **forward proxy** URL (e.g. a Dragonfly `dfdaemon` agent).
		Unlike a mirror — which rewrites the request host and must tell the proxy
		the upstream out of band — a forward proxy preserves the original upstream
		URL, so the proxy already knows which registry to back-source from.
		Requests carry Dragonfly hint headers: `X-Dragonfly-Priority` (`6` for
		on-demand reads, `3` for prefetch) and `X-Dragonfly-Use-P2P`.
	- `dragonfly_scheduler_endpoint`: routes blob `GET`s through the Dragonfly
		client SDK (crate `dragonfly-client-request`) talking directly to a
		scheduler, bypassing plain HTTP. Only available when the binary is built
		with the `backend-dragonfly-proxy` feature; takes precedence over `url`
		for `GET`s when both are set. The same priority hint is passed through
		the SDK request.

	Omit the whole `proxy` block to talk to the origin registry directly.
	Metrics attribute each read to the origin or proxy side (see
	[Metrics](#metrics)).


## Metrics

When `nydus fuse` is started with `--apiserver unix:///path/to/api.sock`, a
small HTTP server is bound to that Unix socket and serves the Prometheus text
exposition at `GET /metrics` and the recorded on-demand group access order at
`GET /trace` (any other path returns `404`). The server is torn down and the
socket unlinked when the mount exits. Scrape it with, e.g.:

```bash
curl --unix-socket /run/nydus/api.sock http://localhost/metrics
curl --unix-socket /run/nydus/api.sock http://localhost/trace
```

`GET /trace` returns JSON like
`{"patterns":[{"blob_index":1,"group_index":4},...]}` listing each `(blob,
group)` pair in first-access order, deduplicated. The blob index is the device
id from the bootstrap device table. The trace feeds `nydus optimize` /
`nydusify optimize`.

Each completed backend request is also logged at `debug` level after it returns,
carrying the request source, proxy type, method, URL, request headers, response
status and headers (or an error), and the wall-clock duration.

For library embedders (no apiserver socket), `nydus::metrics::snapshot()`
returns a serializable `MetricsSnapshot` (re-exported as
`nydus::MetricsSnapshot`) capturing every registered metric from the same
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

Filesystem:

- `fs_op_count{op}`, `fs_op_errors{op}` — successful and failed FUSE operations
	by op (`read`, `lookup`, `getattr`, ...).
- `fs_read_latency` — FUSE read latency histogram (seconds).

Cache:

- `cache_opened_files` — open blob data cache files (excludes `.blob.meta` and
	`.groupmap`).
- `cache_hit_group` — groups served from cache without a backend read.
- `cache_total_group` — total groups across loaded blob metas.
- `cache_fill_group` — groups written into a blob's own cache by regular blob
	prefetch.
- `cache_redirect_fill_group` — groups written into a **source** blob's cache
	from a redirect (ondemand) blob during phase-0 prefetch.
- `cache_redirect_skip_group` — redirect groups skipped during ondemand
	prefetch (decode/CRC failures, unknown source device, or failed fills);
	normally zero.

Redirect (ondemand blob) backend traffic:

- `backend_redirect_read_count`, `backend_redirect_read_bytes` — backend reads
	that fetched ondemand (redirect) blob data, a subset of the
	`backend_prefetch_*` counters. Together with `cache_redirect_fill_group`
	these attribute cache warmup to the optimize pipeline: after an optimized
	mount's prefetch quiesces, `backend_redirect_read_count > 0` proves the
	ondemand blob was fetched and `cache_redirect_fill_group` equals the number
	of traced groups written into the source caches.


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
groups directly into the final artifact without copying them behind metadata
later.

```text
full blob file: <full_blob_sha256>

+-------------------------------+  byte 0
| encoded data region           |
| zstd or stored plain groups   |
+-------------------------------+  byte = footer.compressed_data_offset + footer.compressed_data_size
| padding to 4 KiB alignment    |
+-------------------------------+  byte = footer.bootstrap_offset
| bootstrap                     |
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
| 48-byte header + chunk table  |
| group table                   |
| zero padding to 4 KiB         |
+-------------------------------+  byte = footer.blob_meta_offset + footer.blob_meta_blocks * 4096
| blob footer                   |
+-------------------------------+  EOF
```

The footer is fixed at 4096 bytes and is always located at EOF. The current
fields occupy the first 64 bytes; the remaining bytes are reserved for future
extension and must be zero.

```text
BlobFooter

u32 magic              "LFTR" / 0x4c465452
u32 features           currently 0
u32 crc32              crc32c over footer bytes with this field zeroed
u32 reserved0          must be 0
u64 compressed_data_offset
u64 bootstrap_offset
u64 blob_meta_offset
u64 compressed_data_size
u32 bootstrap_blocks
u32 blob_meta_blocks
u64 reserved1          must be 0
u8  reserved2[4032]    must be 0
```

Reader validation requires:

```text
compressed_data_offset + compressed_data_size <= bootstrap_offset
bootstrap_offset + bootstrap_blocks * 4096 <= blob_meta_offset
blob_meta_offset + blob_meta_blocks * 4096 == footer_offset
```

The inequalities allow alignment padding between regions. Offsets and the footer
offset must be 4 KiB aligned. The bootstrap and blob meta region lengths are
stored as 4 KiB block counts in the footer.

The bootstrap region is a valid metadata-only EROFS image by itself. When
`--bootstrap` is specified, the standalone bootstrap is byte-for-byte identical
to this embedded region.

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
blob's data region. The block is mapped to its group by
`group_index = blkaddr / group_block_count`, and the group record gives the
encoded `compressed_byte_offset` (for example 0 for the first encoded group).
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
meta chunk is a content-addressed record (BLAKE3 digest + absolute block range)
used for inspection and future deduplication; chunks are independent of groups.
A blob meta group is the compression unit and cache population unit. EROFS inode
chunk indexes point into the logical uncompressed external-device address space;
blob meta maps a block offset to its group by a single division and the cache
file mirrors that decoded address space directly.

Current blob_meta on-disk shape:

```text
embedded blob meta region

+-------------------------------+
| 48-byte header                |
| magic                         |
| features                      |
| crc32c                        |
| reserved0                     |
| chunks_offset                 |
| groups_offset                 |
| chunk_count                   |
| group_count                   |
| chunk_block_count             |
| group_block_count             |
+-------------------------------+
| chunk records                 |
| 48 bytes each                 |
|                               |
| digest (BLAKE3)               |
| uncompressed_block_offset     |
| uncompressed_block_count      |
| reserved                      |
+-------------------------------+
| group records                 |
| 40 bytes each                 |
|                               |
| uncompressed_block_offset     |
| compressed_byte_offset        |
| uncompressed_block_count      |
| compressed_size               |
| crc32c                        |
| source_group_index            |
| source_blob_index               |
| reserved (6 bytes)            |
+-------------------------------+
| zero padding to 4 KiB         |
+-------------------------------+
```

Header details:

- `magic` is `0x4c50424d`.
- `features` is a bitset. `COMPRESSOR_ZSTD` (`1 << 0`) means zstd is the blob's
	default compressor; no compressor bit means stored plain. `DIGESTER_BLAKE3`
	(`1 << 16`) is mandatory for chunk digests.
- `crc32c` covers the full blob meta region with this field zeroed: the fixed
	header, all chunk records, all group records, and trailing zero padding. The cache layer
	verifies this crc32c before mmaping a cached blob meta file for chunk lookup.
- `chunks_offset` is fixed at the header size. `groups_offset` follows the dense
	chunk table.
- `chunk_count` is the number of chunk records.
- `group_count` is the number of compressed group records.
- `chunk_block_count` is the EROFS chunk size in 4 KiB blocks.
- `group_block_count` is the number of decoded 4 KiB blocks per group. Every
	group except the last holds exactly this many blocks, so the read path maps a
	block to its group with `group_index = block_id / group_block_count` in O(1).
- The header intentionally does not store `header_size`, total compressed size,
	or total uncompressed size. The header size is fixed at 48 bytes, totals are
	computed from the group records, and the blob meta region is padded to a 4 KiB
	block boundary.

Chunk details:

- Chunks are decoupled from groups: a chunk may straddle a group boundary, and a
	group may contain parts of several chunks. The chunk table is a digest index,
	not a per-group map.
- `digest` is the BLAKE3 hash of the chunk's decoded, block-aligned bytes — the
	deduplication key.
- `uncompressed_block_offset` is the chunk's absolute 4 KiB block offset in the
	dense decoded address space (chunks are stored back-to-back).
- `uncompressed_block_count` is the chunk span in 4 KiB blocks. Only the chunk's
	final block carries zero padding; full chunks are already block-aligned, so the
	dense layout packs real blocks instead of large zero runs.

Group details:

- Groups are formed by packing whole decoded blocks up to `--compress-size`
	regardless of chunk boundaries, then compressing the batch as one unit. So
	every group but the last is exactly `group_block_count` blocks.
- `uncompressed_block_offset` is the decoded cache 4 KiB block offset for the
	group. Groups are dense and contiguous in the decoded address space.
- `compressed_byte_offset` is the encoded payload's byte offset within the data
	region (not inside the whole full blob file). Encoded groups are packed
	back-to-back with no inter-group padding, so this is a plain byte position and
	is not block-aligned for compressed groups. Runtime backends add the
	data-region base offset before issuing range reads.
- `uncompressed_block_count` describes the decoded group size in 4 KiB blocks.
- `compressed_size` is the actual encoded byte length. The next group starts at
	exactly the previous group's `compressed_byte_offset + compressed_size`.
- `crc32c` is computed over the decoded group. If `compressed_size` equals
	`uncompressed_block_count * 4096`, runtime treats the group as stored plain and
	skips decompression even when the header compressor is zstd.
- `source_blob_index` and `source_group_index` mark a redirect group. They are
	zero for normal groups. A non-zero `source_blob_index` means the group's data
	belongs to that source blob (1-based device-table index) at
	`source_group_index`; phase-0 prefetch writes the decoded bytes into the
	source blob's cache instead of this blob's own cache. A blob containing any
	redirect group is an "ondemand" blob: its groups may be non-uniform in size
	(the uniformity invariant is relaxed) and `group_index_for_byte_offset` is
	never used on it. The redirect group's `crc32c` equals the source group's
	decoded CRC so the fill is cross-checked before touching the source cache.

The writer does not bias `compressed_byte_offset` by the bootstrap size, and
does not bias `uncompressed_block_offset`. Only the data region as a whole is
padded to a 4 KiB boundary (so the embedded bootstrap that follows starts on a
block); groups themselves are not individually padded.

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
	range) and feed the decoded data stream into a block-oriented group builder
	that flushes a compression group whenever it fills to `--compress-size`,
	regardless of chunk boundaries. A chunk may therefore span two groups.
4. Compute BLAKE3 digest over each uncompressed chunk and CRC32C over each
	uncompressed group.
5. Compress each group according to the blob_meta header compressor and append
	the encoded bytes directly to the data region. Encoded groups are packed
	back-to-back with no inter-group padding. For zstd, groups that do not shrink
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
	chunk lookup, fetches encoded groups from the data region, and validates each
	decoded group.

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
	mmaping the cached file and using its chunk records.
7. Reads use logical uncompressed offsets from inode chunk indexes. The cache
	layer maps an offset to its group in O(1) with `block / group_block_count`,
	ensures every group covering the requested range is fetched and decoded from
	the data region (validating group CRC32C), and then reads the bytes straight
	out of the cache file. The cache file mirrors the dense decoded address space,
	so once the covering groups are ready the absolute offset indexes directly into
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
- `<full_blob_digest>.groupmap` records which blob_meta groups have been decoded
	(a shared readiness bitmap, see
	[Cross-process cache sharing](#cross-process-cache-sharing-and-prefetch-dedup)).
- `<full_blob_digest>.prefetch.lock` is the cross-process prefetch lock file
	(empty; only its `flock` state matters).

### Blob prefetch

After a successful mount, `nydus fuse` spawns a background prefetcher that warms
the local cache so later on-demand reads hit decoded data instead of fetching and
decoding groups synchronously. Prefetch is **off by default**: enable it with the
`--prefetch` flag, or through the storage config `prefetch.enable` (either one
turns it on); the config's `prefetch` block also sizes the worker pool. See
[Storage config](#storage-config).

Per-blob prefetch streams groups into the cache:

- The blob meta groups are the compression/cache unit. Prefetch reads the data
	region in windows that accumulate consecutive groups up to the default group
	uncompressed size (1 MiB), so each window decode covers one or more groups.
- For each window it issues a single contiguous backend range read, then decodes
	each contained group (plain copy or zstd), validates length and CRC32C, writes
	the decoded bytes to the cache file at the group's uncompressed offset, and
	marks the group ready in the groupmap.
- Prefetch uses its own decode buffer and does not take the on-demand read
	`fetch_lock`. The groupmap bits are updated atomically and `set_ready` is
	idempotent, so racing with a FUSE read at worst decodes the same group twice
	into identical bytes at the same offset. This keeps prefetch fully decoupled
	from, and non-blocking to, the on-demand read path.
- Groups already marked ready (for example, fetched on demand or from a previous
	run's persistent cache) are skipped.

Prefetch scheduling across blobs has two phases:

1. Priority blobs are prefetched first, sequentially, in the order listed by the
	root inode's `trusted.nydus.prefetch.blobs` xattr (a comma-separated list of
	device ids). The list is deduplicated and filtered to existing devices. When
	`prefetch.full` is `false` (the default), only redirect ("ondemand") priority
	blobs are warmed; non-redirect priority blobs are skipped so backend
	bandwidth is not spent pulling whole source blobs.
2. Only when `prefetch.full` is set, the remaining blob devices are then
	prefetched concurrently by a worker pool sized to
	`min(prefetch.threads, remaining)` (default `10` threads).

When a priority blob is an "ondemand" redirect blob (produced by `nydus
optimize`, listed first in the xattr), its prefetch is dispatched differently:
the groups are streamed and decoded as usual, but each decoded group is written
into its **source** device's cache (validated against the source group's length
and CRC) and marked ready there. The ondemand blob never builds a cache file of
its own. Per-group failures — unknown source device, CRC mismatch, source cache
errors — are logged and skipped, so a bad redirect can only lose warmup, never
poison a source cache or abort the mount. Blob device caches are opened lazily
on first read or prefetch, so a device fully covered by the ondemand warmup
pays no extra metadata fetch at mount time.

Redirect prefetch is itself parallelized when the ondemand blob is larger than
one segment and more than one worker thread is configured. The group list is
split into segments of up to 16 MiB uncompressed each and fetched concurrently
by the prefetch worker pool, with one twist: the earliest groups are emitted as
single-group segments (a "ramp") so they land in the first wave of workers
within a single round trip — ahead of the workload's first page faults — while
the rest are bundled into full-size segments for throughput. A small ondemand
blob (fitting in one segment) or a single-thread pool streams sequentially,
since segmentation and extra registry connections would add overhead without
overlapping any work. In a cold-registry container start benchmark this
parallel ramped prefetch cut end-to-end start time from 32.6s to 25.0s.

### Cross-process cache sharing and prefetch dedup

Many identical instances cold-starting on one node (for example, dozens of
hypervisor-embedded accessors mounting the same optimized image) all target the
same cache directory, the same blobs, and the same access-ordered hot set.
Without coordination each instance would stream the whole ondemand blob and
decode every group independently — N× the backend traffic, decode CPU, and
cache writes for identical bytes. Two mechanisms make the warmup effectively
single-instance while leaving the on-demand read path untouched.

**Shared groupmap bitmap.** The `<digest>.groupmap` file is a 16-byte header
(magic `LPGM0001`, version, group count — both little-endian `u32`) followed by
one readiness bit per blob_meta group. The whole file is mapped `MAP_SHARED`
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
- Bits are set only after the decoded, CRC-validated group bytes have been
	written to the cache data file, and persistence rides on regular kernel
	writeback of the dirty mapping — there is no per-bit write syscall on the hot
	path.

`all_ready()` scans the shared bitmap (masking the partial final byte), so any
instance can cheaply tell when another instance has finished warming a blob.

**Per-blob prefetch flock.** Blob-level prefetch — and only prefetch — is
serialized across processes with an exclusive `flock` on
`<digest>.prefetch.lock`, taken at the top of the per-blob prefetch entry point
(modeled on the nydus blob prefetcher):

- The lock is polled non-blocking with a 1s sleep between attempts, so a waiter
	can observe progress while it waits: a waiter on a regular blob gives up on
	the lock as soon as the shared groupmap reports every group ready (its own
	prefetch then reduces to a cheap all-ready scan).
- Locking failures (unopenable lock file, unexpected errno) degrade to
	prefetching without the lock — correctness never depends on it, only the
	cross-process dedup guarantee does.
- The guard is the open file descriptor: dropping it — including by process
	death — releases the lock, so a crashed owner is taken over by a waiter, and
	the ready-skip logic resumes the warmup exactly where the crashed owner left
	off.
- **On-demand reads never touch the lock.** A cold group hit by a page fault is
	fetched immediately by whichever instance needs it; the worst case is one
	duplicated group fetch racing the owner's warmup, which the idempotent cache
	write absorbs.

**Redirect segment skipping.** A waiter that eventually acquires the lock (or a
restart replaying the warmup) must not re-download the ondemand blob just to
discover every fill is a no-op: the parallel redirect stream accepts a `skip`
predicate that consults the **source** blobs' shared groupmaps, and any segment
whose groups are all already resident is not fetched at all. Partially-done
segments are still fetched whole to keep backend reads contiguous.

Measured on one node with the shared cache directory (cold registry, optimized
image): with 10 concurrent cold starts exactly one instance acquired the lock
and streamed the ondemand blob (≈230 MB, 222 groups filled) while the other
nine did zero prefetch backend reads (only 0–5 MB of early on-demand faults
each, thousands of shared-cache hits); with 50 concurrent cold starts the
cache grew to the same ≈900 MB a single instance produces and end-to-end
application readiness stayed at the single-instance baseline (24–27s across
all 50, vs ≈25s for one).

## Accessor (virtio-pmem integration)

`nydus::accessor::NydusAccessor` is the library entry point for hypervisors
that mount the nydus image inside the guest as a plain EROFS
filesystem over virtio-pmem, instead of using `nydus fuse` on the host:

- The bootstrap is the EROFS primary device; each data blob is an external
	device backed by its host cache data file (`{cache_dir}/{hex}.blob.data`),
	which mirrors the dense decoded block address space — a guest read of block
	`N` lands at byte `N * 4096` of the backing file.
- `NydusAccessor::new(bootstrap, Config)` parses the bootstrap and an already
	loaded `nydus::Config` (same structure as `nydus fuse --config`) lazily;
	per-blob work (blob meta download/validation, sparse cache file creation)
	happens on first touch through `blob.entries()` or `blob.fetch`.
- When `config.prefetch.enable` is set, `new` spawns a background prefetch
	worker before returning — the same two-phase workflow as `nydus fuse`
	(redirect blob first, then the rest only under `prefetch.full`). The worker
	thread inherits the network namespace active at construction time, so
	callers that construct the accessor for a guest-facing backend must do so
	while the desired netns is active.
- Access traces are recorded on actual backend fetches (not cache hits), and
	`nydus::metrics::snapshot()` exposes runtime counters for embedding into
	hypervisor stats endpoints; a saved trace JSON can be replayed offline via
	`nydus optimize --trace-file`. See [Metrics](#metrics).
- `BlobID` is the public blob digest type. It converts to/from 64-character
	SHA256 hex strings and `[u8; 32]` bytes.
- `blob.entries()` lists the device table in order as `BlobInfo` entries:
	blob index, `BlobID`, block count, cache path, cache size, and whether the
	blob is an ondemand redirect blob. Calling it prepares the sparse cache data
	files, so `BlobInfo.cache_path` is immediately suitable as a virtio-pmem
	backing file and `BlobInfo.cache_size` is `blocks * 4096`.
- `blob.fetch(id, offset, len)` guarantees the 4 KiB-aligned range is decoded,
	CRC-validated, and resident in the cache data file. It maps the range to
	blob meta groups with the O(1) division lookup and reuses the regular cache
	chain (`ensure_group`), so it is idempotent, concurrency-safe, and shares
	trace/metrics recording with the FUSE path. Redirect blobs are rejected.
- `fs.open(path)` resolves a path once and returns an `FsEntry`; use
	`entry.metadata()`, `entry.read_dir()`, `entry.read()`,
	`entry.read_at(...)`, `entry.read_link()`, and `entry.xattrs()` for
	metadata/data access without FUSE. Holding the entry avoids repeated path
	resolution and is the only filesystem API surface.

Complete example:

```rust
use std::path::Path;

use nydus::{Config, NydusAccessor};

fn wire_nydus_image(bootstrap: &Path, config_path: &Path) -> anyhow::Result<()> {
	// Load the same YAML schema accepted by `nydus fuse --config`.
	let config = Config::from_file(config_path)?;
	let accessor = NydusAccessor::new(bootstrap, config)?;

	// Materialize every blob cache file before creating guest pmem devices.
	// The vector is in bootstrap device-table order; `index` is the 1-based
	// EROFS external-device index used by chunk indexes.
	let blobs = accessor.blob.entries()?;
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
	// aligned; fetch expands to whole blob-meta groups internally and is
	// safe to call repeatedly or concurrently.
	if let Some(blob) = blobs.iter().find(|blob| !blob.is_redirect) {
		accessor.blob.fetch(&blob.id, 0, 4096 * 16)?;
	}

	// Static filesystem inspection without FUSE. Resolve a path once and
	// reuse the FsEntry for hot loops.
	let file = accessor.fs.open("path/to/file")?;
	let meta = file.metadata()?;
	println!("ino={} size={} mode={:o}", meta.ino, meta.size, meta.mode);

	let mut buf = vec![0u8; 128 * 1024];
	let n = file.read_at(0, &mut buf)?;
	println!("read {n} bytes");

	let root = accessor.fs.open("/")?;
	for entry in root.read_dir()? {
		println!("{} {:?} ino={}", entry.name, entry.file_type, entry.ino);
	}

	Ok(())
}
```

The accessor needs neither FUSE nor the CLI stack: building with
`--no-default-features --features backend-registry` produces a minimal
library surface (no fuser/hyper/tokio-server/clap) suitable for embedding.

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

Nydus's current format is intentionally self-consistent rather than backward
compatible. In particular, it does not support the old CLI shape, old blob_meta
header fields, or data-digest sidecar lookup.

EROFS compatibility is handled by exposing decoded cache data when running
compatibility checks against C erofsfuse. Compressed full blobs are Nydus runtime
artifacts and are not directly consumable as plain EROFS external devices.

## Image Conversion (nydusify)

`nydus` operates on local directories, blobs and bootstraps. `nydusify` is the
Go orchestrator that wraps `nydus` to operate on whole OCI images in a registry:
it pulls an OCI image, converts every layer into a nydus image, pushes the
result, and can validate that the converted image is faithful to its source.

`nydusify` lives in `nydusify/` as its own Go module
(`github.com/dragonflyoss/nydus/nydusify`) and shells out to the `nydus`
binary for the actual filesystem work (`nydus build`, `nydus merge`,
`nydus check`, `nydus fuse`).

```text
        nydusify convert                         nydusify check
        -----------------                         ---------------
  registry --pull--> content store          registry --pull--> content store
              |                                          |
   per-layer: nydus build                    manifest / bootstrap / filesystem
              |                                          rules
   index hook: nydus merge                              |
              |                                      pass / fail
  registry <--push-- nydus image
```

### Image format

A converted nydus image reuses the nydus on-wire manifest layout so existing
nydus-aware snapshotters and tooling can consume it (see
`internal/converter/constants.go`):

- Each OCI data layer becomes one nydus **blob** layer with media type
  `application/vnd.oci.image.layer.nydus.blob.v1`, annotated with
  `containerd.io/snapshot/nydus-blob`. A nydus full blob is uncompressed at the
  layer level, so its diff id equals the blob digest.
- One extra **bootstrap** layer is appended last as a gzip tarball containing
  `image/image.boot`, annotated with `containerd.io/snapshot/nydus-bootstrap`.
- The platform manifest is marked with the
  `nydus.remoteimage.v1` OS feature to flag it as a lazy-loadable remote image.
- Only `RootFS.DiffIDs` and `History` are rewritten in the image config; all
  runtime-relevant config fields (env, cmd, entrypoint, working dir, os,
  architecture) are preserved verbatim.

### Subcommand mapping

`nydusify` does not reimplement any filesystem logic; each high-level image
operation is composed from the lower-level `nydus` subcommands plus registry
pull/push:

| `nydusify` | Underlying `nydus` subcommands | Registry |
| --- | --- | --- |
| `convert` | `nydus build` (per OCI layer) + `nydus merge` (index hook) | pull source, push target |
| `check` | `nydus check` (bootstrap rule) + `nydus fuse` (filesystem rule) | pull source and/or target |

The `--builder` flag selects which `nydus` binary is invoked for all of the
above, so `nydusify` and `nydus` versions can be pinned together.

### convert

`nydusify convert --source <oci-ref> --target <nydus-ref> [OPTIONS]`

Pulls the source OCI image into a local content store, converts it, and pushes
the resulting nydus image to the target reference.

Pipeline:

1. Pull `--source` into a scratch content store
   (`internal/remote`, backed by containerd's local content store).
2. For each OCI layer, extract its rootfs (decompressing gzip/zstd, resolving
   whiteouts) and run `nydus build` with the configured `--chunk-size`,
   `--compress-size` and `--compressor`. The build output is streamed straight
   into the content store through a FIFO, so the full blob is never staged on
   disk twice (`internal/converter/layer.go`).
3. A post-convert index hook runs `nydus merge` over the per-layer blobs to
   produce the overlaid bootstrap, which is written back as the final bootstrap
   layer (`internal/converter/hook.go`).
4. Push the rewritten manifest and all new layers to `--target`
   (`internal/remote`).

Flags:

| Flag | Default | Description |
| --- | --- | --- |
| `--source`, `-s` | required | Source OCI image reference. |
| `--target`, `-t` | required | Target nydus image reference to push. |
| `--builder` | `nydus` | Path to the `nydus` binary (PATH-resolvable). |
| `--work-dir` | temp dir | Scratch directory; a temp dir is created and removed when omitted. |
| `--chunk-size` | `1048576` | Nydus file chunk size in bytes (1 MiB). |
| `--compress-size` | `4194304` | Blob meta group uncompressed size in bytes; a multiple of 1 MiB and at least `--chunk-size`. |
| `--compressor` | `zstd` | Chunk data compressor: `none` or `zstd`. |
| `--platform` | all | Convert only the given platform (e.g. `linux/amd64`). |
| `--insecure` | `false` | Skip TLS verification for the registry. |
| `--plain-http` | `false` | Use plain HTTP to talk to the registry. |
| `--log-level` | `info` | `trace`, `debug`, `info`, `warn`, `error`. Forwarded to the `nydus build`/`merge` subprocesses. |

Notes:

- Converting an image requires **root privileges**. Layer extraction must
  preserve original uid/gid, setuid/setgid/sticky bits, xattrs and device/fifo
  nodes; these operations fail without root, and `nydusify` treats such
  failures as fatal rather than silently producing a corrupted image.
- Image references are normalized like a container runtime: a bare name such as
  `mariadb` expands to `docker.io/library/mariadb:latest`, and a tagless
  reference defaults to `:latest`.

Example:

```bash
sudo nydusify convert \
  --source docker.io/library/mariadb:latest \
  --target localhost:5000/mariadb-nydus \
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

`nydusify optimize --apiserver <addr> --source <nydus-ref> --target <nydus-ref> [OPTIONS]`

Publishes an optimized copy of a nydus image from a live access trace:

1. Pull `--source` (must be a nydus image) and extract its bootstrap layer
	(`image.boot` plus the per-layer blob metas, which seed the cache dir).
2. Run `nydus optimize` against the bootstrap with `--apiserver`, using a
	registry-backed storage config so source group data is range-read from the
	source registry on demand.
3. Assemble the optimized manifest: the original data layers are reused as-is,
	the ondemand blob is appended as a new nydus data layer, and the bootstrap
	layer is rebuilt with the rewritten `image.boot` plus all blob metas
	(including the ondemand one). Config diff ids and history are updated.
4. Push the result to `--target`.

`--apiserver` points at the apiserver socket of a running `nydusify mount` of
the source image (`<work-dir>/apiserver.sock`; a bare path or `unix://` form is
accepted). Mount the image **without** `--prefetch` (the default) so the trace
records the pure on-demand access pattern, exercise the workload, then run
optimize while the mount is still up. Mount the optimized image **with**
`--prefetch` to get the phase-0 redirect warmup. Shared flags (`--builder`,
`--work-dir`, `--platform`, `--insecure`, `--plain-http`, `--log-level`) behave
as in `nydusify convert`. No root is required: optimize never extracts OCI
layers, it only rewrites metadata and appends the ondemand layer.

Example:

```bash
nydusify mount -t localhost:5000/app:nydus -m /mnt/app --work-dir /tmp/mnt &
# ... run the workload against /mnt/app ...
nydusify optimize \
  --apiserver /tmp/mnt/apiserver.sock \
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
4. xfstests and fio-backed performance checks for mount behavior.

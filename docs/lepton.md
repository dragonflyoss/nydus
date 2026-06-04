# Lepton Design

## Status

This document describes the current lepton artifact model, blob meta format and
runtime read path. Lepton no longer preserves compatibility with the original
split `image + --blobdev` prototype, the old blob_meta header layout, or the old
data-digest sidecar naming convention.

The user-facing commands are:

- `lepton build`
- `lepton check`
- `lepton merge`
- `lepton fuse`

The current merge implementation focuses on metadata overlay, blob-id
preservation and OCI whiteout handling. The build and runtime paths use the
embedded blob meta region as the canonical map from logical EROFS
external-device addresses to encoded ranges in the stored data region.

## Goals

- Use one user-visible `blob` artifact as the primary layer output.
- Allow an optional standalone `bootstrap` artifact for remote metadata-only use.
- Make `fuse` support either a direct blob path or a bootstrap plus blob-dir.
- Persist a stable blob identifier inside bootstrap metadata.
- Keep EROFS file chunk indexes logical and map them through blob_meta chunks.
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

`lepton build [OPTIONS] <SOURCE>`

The `lepton build` command builds a source directory into EROFS format. It
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
lepton build -h
Create an lepton filesystem layer (chunk-based)

Usage: lepton build [OPTIONS] <SOURCE>

Arguments:
	<SOURCE>  source from which to build the filesystem

Options:
	--type <type>
		Conversion type: [default: dir-lepton] [possible values: dir-lepton]
	--blob <blob>
		File path to save the generated lepton blob (also include bootstrap)
	--blob-dir <blob-dir>
		Directory path to save the generated lepton blob with sha256 file name (conflict with `--blob`)
	--bootstrap <bootstrap>
		File path to save the generated lepton bootstrap (optional)
	--chunk-size <chunk-size>
		Set the EROFS file chunk size, must be power of two, 4KiB-aligned, and at least 4KiB: [default: 1048576]
	--compressor <compressor>
		Algorithm to compress data chunks: [default: zstd] [possible values: none, zstd]
	--log-level <log-level>
		Log level: [default: info] [possible values: trace, debug, info, warn, error]
```

Current implementation notes:

- Either `--blob` or `--blob-dir` is required.
- `--bootstrap` is optional and emits a standalone metadata-only artifact.
- `--chunk-size` defaults to `1048576` (1 MiB) and controls EROFS file chunk
	indexes. Blobmeta compression groups are at least 1 MiB, so smaller file
	chunks do not fragment blob_meta into tiny compression units.
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

`lepton merge [OPTIONS] <SOURCE>...`

The `lepton merge` command merges multiple layer blobs in order into a single
overlaid bootstrap in EROFS metadata format. Each source path must be a full
blob file whose file name is its SHA256. Merge validates that invariant before
loading metadata. The emitted merged bootstrap preserves each source layer's
blob id from the source bootstrap device table and applies OCI whiteout
semantics so the final bootstrap reflects the merged filesystem view after
deletions and opaque-directory masking.

Current CLI help:

```bash
lepton merge -h
Merge multiple lepton bootstrap into a overlaid bootstrap

Usage: lepton merge [OPTIONS] <SOURCE>...

Arguments:
	<SOURCE>...  lepton blob paths with sha256 file name (allow one or more)

Options:
	--bootstrap <bootstrap>
		File path to save the generated overlaid lepton bootstrap
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
	single-layer outputs from `lepton build`, that blob id is currently the SHA256
	of the data region.
- Merge currently assumes source regular files use the lepton chunk-based data
	layout and preserves each file's original chunkbits.

### Check

`lepton check [OPTIONS]`

The `lepton check` command performs static inspection of a lepton / EROFS image
without mounting it. It prints image sizing, a full superblock dump, filesystem
summary data, and one grouped `Blobs` entry per external device.

Supported forms:

- `lepton check --blob <blob>`
- `lepton check --bootstrap <bootstrap>`
- `lepton check --bootstrap <bootstrap> --blob-dir <blob-dir>`
- `lepton check --bootstrap <bootstrap> --config <config.yaml>`

Current implementation notes:

- `--blob` inspects the full lepton blob, locates the bootstrap through the
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

`lepton fuse [OPTIONS]`

The `lepton fuse` command mounts lepton metadata as a filesystem at the target
mountpoint. It is the only runtime mount entrypoint. During read path
resolution, runtime uses the blob id recorded in bootstrap metadata to locate
the corresponding blob under `--blob-dir` and then serves chunk data from that
blob.

Current implementation notes:

- `SIGINT`/`SIGTERM`/`SIGQUIT` trigger a best-effort unmount before process exit,
	so interactive `Ctrl+C` tears down the mountpoint instead of leaving it behind.
- After mounting, runtime starts background blob prefetch unless it is disabled
	through the storage config. See [Blob prefetch](#blob-prefetch).

Current CLI help:

```bash
lepton fuse -h
Mount lepton filesystem into a directory

Usage: lepton fuse [OPTIONS]

Options:
	--blob-dir <blob-dir>
		Directory path including lepton data blob
	--cache-dir <cache-dir>
		Directory path for persistent chunk cache files
	--config <config>
		File path to a YAML storage config providing backend/cache directories and prefetch options
	--bootstrap <bootstrap>
		File path to lepton bootstrap
	--blob <blob>
		File path to lepton blob
	--mountpoint <mountpoint>
		Directory path to mount lepton filesystem
	--log-level <log-level>
		Log level: [default: info] [possible values: trace, debug, info, warn, error]
	--log-dir <log-dir>
		Specify the log directory [default: /var/log/lepton/]
	--log-max-files <log-max-files>
		Specify the max number of log files [default: 6]
```

Supported forms:

- `lepton fuse --blob <blob> --mountpoint <mountpoint>`
- `lepton fuse --bootstrap <bootstrap> --blob-dir <blob-dir> --mountpoint <mountpoint>`
- `lepton fuse --bootstrap <bootstrap> --config <config.yaml> --mountpoint <mountpoint>`

The fuse command rejects mixed or partial combinations outside these forms.
`--cache-dir` is optional; without it (and without a cache directory from
`--config`), runtime fetches and validates requested blob_meta groups using a
temporary cache directory that is removed on exit. When `--config` is provided,
`backend.config.dir` supplies the blob directory and `cache.config.dir` supplies
the cache directory, so `--blob-dir` and `--cache-dir` can be omitted. Explicit
`--blob-dir`/`--cache-dir` flags take precedence over the config. See
[Storage config](#storage-config).

### Storage config

`lepton fuse` and `lepton check` accept a shared YAML storage config through
`--config <path>`. It centralizes the backend directory, cache directory, and
prefetch behavior so the directory flags can be omitted.

```yaml
backend:
  type: local
  config:
    dir: /var/lib/lepton/blobs
cache:
  type: local
  config:
    dir: /var/lib/lepton/cache
prefetch:
  enable: true
  threads: 10
```

Fields:

- `backend.type` selects the blob backend. Only `local` is supported; its
	`config.dir` is the directory holding lepton blob files (equivalent to
	`--blob-dir`).
- `cache.type` selects the chunk cache. Only `local` is supported; its
	`config.dir` is the persistent cache directory (equivalent to `--cache-dir`).
- `prefetch.enable` (default `true`) toggles background blob prefetch after
	mount.
- `prefetch.threads` (default `10`) sets the number of concurrent prefetch
	worker threads.

The whole `prefetch` block is optional and falls back to the defaults above;
individual fields may also be omitted independently. CLI directory flags
override the corresponding config directories, and `prefetch` only applies to
`lepton fuse`. Unknown `backend.type`/`cache.type` values are rejected at load
time.

Example invocations:

```bash
lepton fuse --bootstrap layer.bootstrap --config storage.yaml --mountpoint /mnt/lepton
lepton check --bootstrap layer.bootstrap --config storage.yaml
```


## Artifact Model

### Build outputs

`lepton build` can materialize up to two distinct artifacts:

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
Both per-layer bootstraps generated by `lepton build` and merged bootstraps
generated by `lepton merge` pass through the same bootstrap writer, so both set
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
- for source layers produced by current `lepton build`, that preserved blob id
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
blob's data region, for example compressed_block_offset = 0 for the first
encoded group.
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
meta chunk is the dense record for one EROFS external-device chunk. A blob meta
group is the compressed unit and cache population unit. EROFS inode chunk
indexes point into the logical uncompressed external-device address space; blob
meta maps those chunk offsets to decoded group offsets and maps each group to an
encoded range in the full blob data region.

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
| reserved1                     |
+-------------------------------+
| chunk records                 |
| 48 bytes each                 |
|                               |
| digest (BLAKE3)               |
| group_index                   |
| group_uncompressed_block_off  |
| uncompressed_block_count      |
| reserved                      |
+-------------------------------+
| group records                 |
| 32 bytes each                 |
|                               |
| uncompressed_block_offset     |
| compressed_block_offset       |
| uncompressed_block_count      |
| compressed_size               |
| crc32c                        |
| reserved                      |
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
- `chunk_count` is the number of EROFS chunk records. The table is dense and a
	runtime lookup can compute `chunk_index = block_id / chunk_block_count`.
- `group_count` is the number of compressed group records.
- `chunk_block_count` is the EROFS chunk size in 4 KiB blocks.
- The header intentionally does not store `header_size`, total compressed size,
	or total uncompressed size. The header size is fixed at 48 bytes, totals are
	computed from the group records, and the blob meta region is padded to a 4 KiB
	block boundary.

Chunk details:

- `digest` is computed over the uncompressed, block-padded EROFS chunk.
- `group_index` references the compressed group that contains this chunk.
- `group_uncompressed_block_offset` is the chunk's 4 KiB block offset within its
	decoded group.
- `uncompressed_block_count` is the logical chunk span in 4 KiB blocks. The
	current builder reserves a full fixed EROFS chunk for each chunk index so the
	dense lookup remains valid.

Group details:

- `uncompressed_block_offset` is the decoded cache 4 KiB block offset for the
	group.
- `compressed_block_offset` is the encoded data-region 4 KiB block offset, not
	inside the whole full blob file. Runtime backends add the data-region base
	offset before issuing range reads.
- `uncompressed_block_count` describes the decoded group size in 4 KiB blocks.
- `compressed_size` is the actual encoded byte length and excludes group padding.
	The builder pads every encoded group to the next 4 KiB boundary so the next
	group can keep a block-granular `compressed_block_offset`.
- `crc32c` is computed over the decoded group. If `compressed_size` equals
	`uncompressed_block_count * 4096`, runtime treats the group as stored plain and
	skips decompression even when the header compressor is zstd.

The writer does not bias `compressed_block_offset` by the bootstrap size. It
also does not bias `uncompressed_block_offset`; that field remains the decoded
cache address for blob data.

### Merge output

The merge command emits an overlaid standalone bootstrap that references one or
more previously built full blobs.

## Build Pipeline

The build pipeline now follows this sequence:

1. Walk the source directory and build the in-memory inode tree.
2. Assign dense file chunk indexes into a logical uncompressed external-device
	address space. Each EROFS chunk advances by the fixed EROFS chunk size.
3. Record one blob_meta chunk entry for each EROFS chunk and group the decoded
	data stream into compression groups, normally 1 MiB each.
4. Compute BLAKE3 digest over each uncompressed chunk and CRC32C over each
	uncompressed group.
5. Compress each group according to the blob_meta header compressor and append
	the encoded bytes directly to the beginning of the full blob file. Encoded
	groups are padded to 4 KiB. For zstd, groups that do not shrink to at most 70%
	of their uncompressed size are stored plain and marked by
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
	layer maps those ranges to blob meta chunks, ensures the referenced groups are
	fetched and decoded from the data region, validates group CRC32C, and returns
	the requested chunk slices to FUSE.

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
- `<full_blob_digest>.groupmap` records which blob_meta groups have been decoded.

### Blob prefetch

After a successful mount, `lepton fuse` spawns a background prefetcher that warms
the local cache so later on-demand reads hit decoded data instead of fetching and
decoding groups synchronously. Prefetch is enabled by default and can be turned
off (or resized) through the storage config `prefetch` block; see
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
	`fetch_lock`. The groupmap is internally locked and `set_ready` is idempotent,
	so racing with a FUSE read at worst decodes the same group twice into identical
	bytes at the same offset. This keeps prefetch fully decoupled from, and
	non-blocking to, the on-demand read path.
- Groups already marked ready (for example, fetched on demand or from a previous
	run's persistent cache) are skipped.

Prefetch scheduling across blobs has two phases:

1. Priority blobs are prefetched first, sequentially, in the order listed by the
	root inode's `trusted.lepton.prefetch.blobs` xattr (a comma-separated list of
	device ids). The list is deduplicated and filtered to existing devices.
2. The remaining blob devices are then prefetched concurrently by a worker pool
	sized to `min(prefetch.threads, remaining)` (default `10` threads).

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

Lepton's current format is intentionally self-consistent rather than backward
compatible. In particular, it does not support the old CLI shape, old blob_meta
header fields, or data-digest sidecar lookup.

EROFS compatibility is handled by exposing decoded cache data when running
compatibility checks against C erofsfuse. Compressed full blobs are Lepton runtime
artifacts and are not directly consumable as plain EROFS external devices.

## Image Conversion (leptonify)

`lepton` operates on local directories, blobs and bootstraps. `leptonify` is the
Go orchestrator that wraps `lepton` to operate on whole OCI images in a registry:
it pulls an OCI image, converts every layer into a lepton image, pushes the
result, and can validate that the converted image is faithful to its source.

`leptonify` lives in `leptonify/` as its own Go module
(`github.com/dragonflyoss/lepton/leptonify`) and shells out to the `lepton`
binary for the actual filesystem work (`lepton build`, `lepton merge`,
`lepton check`, `lepton fuse`).

```text
        leptonify convert                         leptonify check
        -----------------                         ---------------
  registry --pull--> content store          registry --pull--> content store
              |                                          |
   per-layer: lepton build                    manifest / bootstrap / filesystem
              |                                          rules
   index hook: lepton merge                              |
              |                                      pass / fail
  registry <--push-- lepton image
```

### Image format

A converted lepton image reuses the nydus on-wire manifest layout so existing
nydus-aware snapshotters and tooling can consume it (see
`internal/converter/constants.go`):

- Each OCI data layer becomes one lepton **blob** layer with media type
  `application/vnd.oci.image.layer.nydus.blob.v1`, annotated with
  `containerd.io/snapshot/nydus-blob`. A lepton full blob is uncompressed at the
  layer level, so its diff id equals the blob digest.
- One extra **bootstrap** layer is appended last as a gzip tarball containing
  `image/image.boot`, annotated with `containerd.io/snapshot/nydus-bootstrap`.
- The platform manifest is marked with the
  `nydus.remoteimage.v1` OS feature to flag it as a lazy-loadable remote image.
- Only `RootFS.DiffIDs` and `History` are rewritten in the image config; all
  runtime-relevant config fields (env, cmd, entrypoint, working dir, os,
  architecture) are preserved verbatim.

### Subcommand mapping

`leptonify` does not reimplement any filesystem logic; each high-level image
operation is composed from the lower-level `lepton` subcommands plus registry
pull/push:

| `leptonify` | Underlying `lepton` subcommands | Registry |
| --- | --- | --- |
| `convert` | `lepton build` (per OCI layer) + `lepton merge` (index hook) | pull source, push target |
| `check` | `lepton check` (bootstrap rule) + `lepton fuse` (filesystem rule) | pull source and/or target |

The `--builder` flag selects which `lepton` binary is invoked for all of the
above, so `leptonify` and `lepton` versions can be pinned together.

### convert

`leptonify convert --source <oci-ref> --target <lepton-ref> [OPTIONS]`

Pulls the source OCI image into a local content store, converts it, and pushes
the resulting lepton image to the target reference.

Pipeline:

1. Pull `--source` into a scratch content store
   (`internal/remote`, backed by containerd's local content store).
2. For each OCI layer, extract its rootfs (decompressing gzip/zstd, resolving
   whiteouts) and run `lepton build` with the configured `--chunk-size` and
   `--compressor`. The build output is streamed straight into the content store
   through a FIFO, so the full blob is never staged on disk twice
   (`internal/converter/layer.go`).
3. A post-convert index hook runs `lepton merge` over the per-layer blobs to
   produce the overlaid bootstrap, which is written back as the final bootstrap
   layer (`internal/converter/hook.go`).
4. Push the rewritten manifest and all new layers to `--target`
   (`internal/remote`).

Flags:

| Flag | Default | Description |
| --- | --- | --- |
| `--source`, `-s` | required | Source OCI image reference. |
| `--target`, `-t` | required | Target lepton image reference to push. |
| `--builder` | `lepton` | Path to the `lepton` binary (PATH-resolvable). |
| `--work-dir` | temp dir | Scratch directory; a temp dir is created and removed when omitted. |
| `--chunk-size` | `1048576` | Lepton file chunk size in bytes (1 MiB). |
| `--compressor` | `zstd` | Chunk data compressor: `none` or `zstd`. |
| `--platform` | all | Convert only the given platform (e.g. `linux/amd64`). |
| `--insecure` | `false` | Skip TLS verification for the registry. |
| `--plain-http` | `false` | Use plain HTTP to talk to the registry. |
| `--log-level` | `info` | `trace`, `debug`, `info`, `warn`, `error`. |

Notes:

- Converting an image requires **root privileges**. Layer extraction must
  preserve original uid/gid, setuid/setgid/sticky bits, xattrs and device/fifo
  nodes; these operations fail without root, and `leptonify` treats such
  failures as fatal rather than silently producing a corrupted image.
- Image references are normalized like a container runtime: a bare name such as
  `mariadb` expands to `docker.io/library/mariadb:latest`, and a tagless
  reference defaults to `:latest`.

Example:

```bash
sudo leptonify convert \
  --source docker.io/library/mariadb:latest \
  --target localhost:5000/mariadb-nydus \
  --plain-http
```

### check

`leptonify check [--source <ref>] [--target <ref>] [OPTIONS]`

Validates the consistency of an OCI and/or lepton image. At least one of
`--source`/`--target` must be provided; the typical use is to pass both the
original OCI image and its converted lepton image to prove the conversion is
faithful.

`check` pulls each provided image into a content store, parses it (detecting OCI
vs lepton from the layer annotations), and runs the following rules in order
(`internal/checker`):

1. **manifest** — validates each manifest's structure (layer count equals diff-id
   count; for lepton images the last layer is the bootstrap and all preceding
   layers are blobs). When both images are present, it asserts their runtime
   configs are equivalent (env/cmd/entrypoint/working dir/os/architecture).
2. **bootstrap** — for each lepton image, materializes its blobs and bootstrap
   and runs `lepton check --bootstrap <b> --blob-dir <d>` to statically validate
   the metadata and verify blob digests.
3. **filesystem** — materializes both images into real root filesystems and
   compares them entry by entry. The OCI side is produced by applying its layers
   (preserving ownership); the lepton side is mounted via `lepton fuse`. The
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
| `--source`, `-s` | empty | Source image reference (OCI or lepton). |
| `--target`, `-t` | empty | Target image reference (OCI or lepton). |
| `--builder` | `lepton` | Path to the `lepton` binary. |
| `--work-dir` | temp dir | Scratch directory; created and removed when omitted. |
| `--platform` | host | Check only the given platform; defaults to the host platform. |
| `--insecure` | `false` | Skip TLS verification for the registry. |
| `--plain-http` | `false` | Use plain HTTP to talk to the registry. |
| `--log-level` | `info` | `trace`, `debug`, `info`, `warn`, `error`. |

Example:

```bash
sudo leptonify check \
  --source docker.io/library/mariadb:latest \
  --target localhost:5000/mariadb-nydus \
  --plain-http
```

A passing run logs `check passed`; any rule failure returns a non-zero exit code
with the failing rule and offending path in the error.

## Validation Strategy

The current validation surface is:

1. Rust compile checks for CLI, build, metadata, storage and mount wiring.
2. Unit coverage for blob_meta parsing, blob-id/device-slot helpers, local backend
	lookup, cache validation, and build-time compression decisions.
3. Integration tests for build full blob, build standalone bootstrap, direct
	blob mount, bootstrap plus blob-dir mount, cache artifact naming, merge, OCI
	whiteouts, and optional erofs-utils compatibility.
4. xfstests and fio-backed performance checks for mount behavior.

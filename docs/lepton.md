# Lepton Design

## Status

This document describes the current lepton artifact model, blob meta format and
runtime read path. Lepton no longer preserves compatibility with the original
split `image + --blobdev` prototype, the old blobmeta header layout, or the old
data-digest sidecar naming convention.

The user-facing commands are:

- `lepton build`
- `lepton check`
- `lepton merge`
- `lepton fuse`

The current merge implementation focuses on metadata overlay, blob-id
preservation and OCI whiteout handling. The build and runtime paths use the new
blobmeta sidecar as the canonical map from logical EROFS external-device
addresses to encoded ranges in the stored full blob.

## Goals

- Use one user-visible `blob` artifact as the primary layer output.
- Allow an optional standalone `bootstrap` artifact for remote metadata-only use.
- Make `fuse` support either a direct blob path or a bootstrap plus blob-dir.
- Persist a stable blob identifier inside bootstrap metadata.
- Keep EROFS file chunk indexes logical and map them through blobmeta chunks.
- Support compressed blob data while preserving a plain decoded cache artifact
	for EROFS compatibility and repeated reads.

## Non-goals

- Preserve backward compatibility with the old `image + --blobdev` CLI.
- Preserve compatibility with old blobmeta headers or sidecar names.
- Implement all merge semantics in the first migration slice.
- Introduce cross-layer global deduplication beyond the current single-build dedup.
- Rework the full EROFS on-disk layout to match every upstream variant before the
  new artifact workflow is proven in-tree.

## CLI Contract

### Build

`lepton build [OPTIONS] <SOURCE>`

The `lepton build` command builds a source directory into EROFS format. It
optionally emits a standalone metadata-only bootstrap via `--bootstrap`, while
`--blob` remains the primary artifact and contains both the EROFS metadata and
the appended chunk data region. Build now always emits a companion `.blob.meta`
sidecar for the full blob: `--blob <path>` writes `<path>.blob.meta`, while
`--blob-dir` writes `<dir>/<full_blob_sha256>.blob.meta`. `--blob-dir` is an
alternative output mode that writes the full blob into the target directory
through a temporary random file, computes the full artifact SHA256, and finally
renames the file to that SHA256. The standalone bootstrap records the SHA256
blob id for the data region in its device-table metadata so runtime can resolve
the corresponding blob later.

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
	indexes. Blobmeta data-block groups are at least 1 MiB, so smaller file chunks
	do not fragment blobmeta into tiny compression units.
- `--blob <path>` stores the full blob at `<path>` and also stores a companion
	blobmeta sidecar at `<path>.blob.meta`.
- `--blob-dir` stores the full blob under `<blob-dir>/<full_blob_sha256>`.
- `--blob-dir` also stores a blobmeta sidecar as
	`<blob-dir>/<full_blob_sha256>.blob.meta`.
- `--compressor zstd` attempts to compress each blobmeta data-block group as one
	unit. If the compressed bytes are larger than 70% of the uncompressed group,
	the group is stored plain and its blobmeta chunk records
	`compressed_size == uncompressed_size`.
- `--compressor none` writes every group plain.
- Build prints one `Blobs` section grouped by `Blob N` with `blob_index`,
	`data_blob_digest`, `full_blob_digest`, `chunk_size`, `chunk_count`,
	`chunk_digester`, `chunk_compressor`, compressed/uncompressed totals, and
	output paths.

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
	of the appended data region.
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

Current implementation notes:

- `--blob` inspects the full lepton blob and verifies the appended data-region
	SHA256 against the device-table blob id.
- `--bootstrap` inspects metadata only and reports blob sizes from device-table
	block counts.
- `--blob-dir` is optional for static inspection and is used only to resolve
	referenced blob files and verify their digests.
- Blob entries report `data_blob_digest`, `full_blob_digest`, blobmeta
	`chunk_size`, `chunk_count`, `chunk_digester`, `chunk_compressor`, and
	compressed/uncompressed totals when the referenced blob can be resolved.
- `--blob-dir` resolves by scanning full blob candidates. Device slots normally
	store the appended-data SHA256, while blob files and blobmeta sidecars are named
	by full blob SHA256 when produced by `--blob-dir`.

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

The fuse command rejects mixed or partial combinations outside these two forms.
`--cache-dir` is optional in both forms; without it, runtime fetches and
validates requested blobmeta chunks without persisting decoded data.

## Artifact Model

### Build outputs

`lepton build` can materialize up to three distinct artifacts:

1. Full blob.
2. Optional standalone bootstrap.
3. Companion `.blob.meta` sidecar for the full blob.

Current output shapes:

- `--blob <path>` writes one full blob exactly at `<path>`.
- `--blob <path>` also writes one blobmeta sidecar at `<path>.blob.meta`.
- `--blob-dir <dir>` writes one full blob at `<dir>/<full_blob_sha256>`.
- `--blob-dir <dir>` also writes one blobmeta sidecar at
	`<dir>/<full_blob_sha256>.blob.meta`.
- `--bootstrap <path>` additionally writes a standalone metadata-only bootstrap.

### Full blob byte layout

The full blob is the primary layer artifact. Its byte layout is:

1. Bootstrap prefix.
2. Appended data region.

The order matters: the file is `bootstrap + data`, not `data + bootstrap`.

```text
full blob file: <full_blob_sha256>

+-------------------------------+  byte 0
| bootstrap prefix              |
|                               |
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
+-------------------------------+  byte = bootstrap_blocks * 4096
| appended data region          |
| +---------------------------+ |
| | encoded blobmeta groups   | |
| | zstd or stored plain      | |
| | deduped before grouping   | |
| +---------------------------+ |
+-------------------------------+  EOF
```

The bootstrap prefix is a valid metadata-only EROFS image by itself. When
`--bootstrap` is specified, the standalone bootstrap is byte-for-byte identical
to this prefix.

### Bootstrap prefix details

Within the bootstrap prefix:

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

It does not carry the blob identity itself. It only points to the device table.

### Device table and chunk address semantics

Each external blob device is represented by one `ErofsDeviceSlot` entry.

For current single-layer build output:

- `tag[0..32]` stores the SHA256 of the appended encoded data region only.
- `tag[32..64]` is zero-filled.
- `blocks_lo/blocks_hi` store the logical uncompressed external-device size in
	4 KiB blocks.

For current merge output:

- merge preserves the blob id already stored in each source device slot;
- for source layers produced by current `lepton build`, that preserved blob id
	is also the appended-data SHA256.

Regular file chunk indexes continue to use `blkaddr` and `device_id`, where:

- `device_id` is only a device-table index;
- `blkaddr` for external data is a logical uncompressed external-device block
	address and is not rebased by the bootstrap size.

Example:

```text
first logical external data block starts at offset 0
	blkaddr = 0
	logical byte offset = 0 * 4096

blobmeta then maps that logical byte offset to a compressed range in the full
blob, for example compressed_offset = bootstrap_blocks * 4096.
```

Blob identity is therefore attached to the device slot, not to the chunk index
and not to the superblock directly.

### Blob ID semantics

The current implementation stores the SHA256 of the appended data region in the
device slot rather than the SHA256 of the whole full blob file.

This avoids a self-reference problem:

- the full blob starts with bootstrap metadata;
- bootstrap metadata contains the blob identifier;
- hashing the full file while embedding that hash into the file would be circular.

At the same time:

- the full blob file name written by `--blob-dir` is the SHA256 of the whole
	full blob artifact;
- the `.blob.meta` file name follows that full blob SHA256;
- the device slot blob id still refers to the appended data region SHA256.

### Blobmeta sidecar layout

Whenever build emits a full blob, it also writes one blobmeta sidecar next to
that blob. The sidecar file name matches the chosen full-blob path, but runtime
still associates the sidecar with the device-slot blob id it is resolving.

Blobmeta is the canonical catalog for the external data blob. A blobmeta chunk is
a contiguous collection of logical uncompressed data blocks, not a file-local
chunk. EROFS inode chunk indexes point into that logical uncompressed address
space; blobmeta maps those offsets to encoded ranges in the stored full blob.

Current blobmeta on-disk shape:

```text
<full_blob_sha256>.blob.meta

+-------------------------------+
| 4 KiB header                  |
| magic                         |
| features                      |
| chunk_entry_size              |
| chunk_count                   |
| chunk_size                    |
| reserved0                     |
| reserved                      |
+-------------------------------+
| chunk records                 |
| 64 bytes each                 |
|                               |
| uncompressed_offset           |
| compressed_offset             |
| uncompressed_size             |
| compressed_size               |
| crc32c                        |
| reserved                      |
| digest (BLAKE3)               |
+-------------------------------+
```

Header details:

- `magic` is `0x4c50424d`.
- `features` is a bitset. `COMPRESSOR_ZSTD` (`1 << 0`) means zstd is the blob's
	default compressor; no compressor bit means stored plain. `DIGESTER_BLAKE3`
	(`1 << 16`) is mandatory for chunk digests.
- `chunk_entry_size` is currently 64 bytes.
- `chunk_count` is the number of chunk records after the fixed header.
- `chunk_size` is the target logical blobmeta group size. It is at least 1 MiB.
- The header intentionally does not store `header_size`, total compressed size,
	or total uncompressed size. The header size is fixed at 4 KiB, and totals are
	computed from the chunk records.

Chunk details:

- `uncompressed_offset` is the logical external-device byte offset used by EROFS
	chunk indexes. It stays block aligned and is not biased by bootstrap size.
- `compressed_offset` is the byte offset in the source full blob. For build
	outputs, blobmeta is biased by `bootstrap_blocks * 4096` after the full blob is
	assembled, so this offset points directly into the appended data region.
- `uncompressed_size` and `compressed_size` describe the logical bytes and stored
	bytes for the group. If they are equal, runtime treats the group as stored plain
	and skips decompression even when the header compressor is zstd.
- `digest` and `crc32c` are computed over the uncompressed group.

The writer biases `compressed_offset` by the bootstrap size when the data is
stored as `bootstrap + data-region` in a full blob. It does not bias
`uncompressed_offset`; that field remains the logical external-device address
used by inode chunk indexes.

Sidecar lookup follows the source full blob path. For direct `--blob <path>`,
runtime expects `<path>.blob.meta`. For `--blob-dir`, runtime resolves the full
blob by scanning candidates and then expects `<full_blob_sha256>.blob.meta` next
to the resolved source. The old fallback to `<data_blob_digest>.blob.meta` is no
longer part of the format.

### Merge output

The merge command emits an overlaid standalone bootstrap that references one or
more previously built full blobs.

## Build Pipeline

The build pipeline now follows this sequence:

1. Walk the source directory and build the in-memory inode tree.
2. Assign file chunk indexes into a logical uncompressed external-device address
	space.
3. Group that logical data stream into blobmeta chunks, normally 1MiB each.
4. Compute BLAKE3 digest and CRC32C over each uncompressed group.
5. Compress each group according to the blobmeta header compressor and write the
	encoded bytes into a temporary data-region file. For zstd, groups that do not
	shrink to at most 70% of their uncompressed size are stored plain and marked by
	`compressed_size == uncompressed_size`.
6. Compute SHA256 over the temporary encoded data-region file and write it into
	the bootstrap device slot tag.
7. Serialize the bootstrap bytes in memory. External chunk `blkaddr` values stay
	logical and are not rebased by the bootstrap size.
8. Optionally persist the standalone bootstrap.
9. Persist the full blob as `bootstrap bytes + encoded data-region bytes`.
10. Compute SHA256 over the full blob artifact.
11. If `--blob-dir` is used, rename the full blob to `<full_blob_sha256>` and
	write `<full_blob_sha256>.blob.meta` next to it.
12. If `--blob <path>` is used, write `<path>.blob.meta` next to the full blob.

The temporary data-region file is an implementation detail and is removed after
the final blob has been written.

## Reader and Mount Design

### Direct blob mount

When mounting with `--blob`:

1. Open the blob as the primary image.
2. Read device slots and resolve the adjacent blobmeta sidecar for each external
	device.
3. Use the dummy cache path by default: fetch encoded blobmeta groups from the
	full blob, decompress only when needed, validate digest/CRC32C, and copy
	requested ranges.
4. If `--cache-dir` is provided, use the persistent local cache with the same
	blobmeta lookup rules.

### Bootstrap plus blob-dir mount

When mounting with `--bootstrap + --blob-dir`:

1. Open the bootstrap.
2. Read every external device slot.
3. Extract the raw 32-byte blob id from each slot tag.
4. Resolve the full blob and matching `.blob.meta` sidecar from `blob-dir`.
5. `--cache-dir` selects the persistent local cache; otherwise runtime uses the
	dummy cache.
6. Reads use logical uncompressed offsets from inode chunk indexes. The cache
	layer maps those ranges to blobmeta chunks, fetches compressed ranges, validates
	uncompressed data, and returns bytes to FUSE.

The runtime no longer reads external blob data by direct mmap offsets. External
blob reads always go through the blobmeta-aware cache abstraction.

The local backend opens source blob files lazily when read IO is first issued and
caches the file descriptor for later `pread` calls. The persistent local cache
also opens `<full_blob_digest>.blob.data` lazily, then serves repeated reads via
cached `pread`/`pwrite` file descriptors. Cache artifacts are named by the full
blob digest:

- `<full_blob_digest>.blob.data` stores decoded uncompressed data.
- `<full_blob_digest>.blob.meta` stores the blobmeta sidecar copy.
- `<full_blob_digest>.chunkmap` records which blobmeta chunks have been decoded.

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
compatible. In particular, it does not support the old CLI shape, old blobmeta
header fields, or data-digest sidecar lookup.

EROFS compatibility is handled by exposing decoded cache data when running
compatibility checks against C erofsfuse. Compressed full blobs are Lepton runtime
artifacts and are not directly consumable as plain EROFS external devices.

## Validation Strategy

The current validation surface is:

1. Rust compile checks for CLI, build, metadata, storage and mount wiring.
2. Unit coverage for blobmeta parsing, blob-id/device-slot helpers, local backend
	lookup, cache validation, and build-time compression decisions.
3. Integration tests for build full blob, build standalone bootstrap, direct
	blob mount, bootstrap plus blob-dir mount, cache artifact naming, merge, OCI
	whiteouts, and optional erofs-utils compatibility.
4. xfstests and fio-backed performance checks for mount behavior.

# Lepton Design

## Status

This document is the working design source for lepton.

The repository is migrating from the original split image/blobdev prototype to a
new artifact model with four user-facing commands:

- `lepton build`
- `lepton check`
- `lepton merge`
- `lepton fuse`

The first implementation slice included in this change migrates build, check,
merge and fuse to the new artifact shape and CLI surface. The current merge
implementation focuses on metadata overlay, blob-id preservation and OCI
whiteout handling before tackling broader format compatibility work.

## Goals

- Use one user-visible `blob` artifact as the primary layer output.
- Allow an optional standalone `bootstrap` artifact for remote metadata-only use.
- Make `fuse` support either a direct blob path or a bootstrap plus blob-dir.
- Persist a stable blob identifier inside bootstrap metadata.
- Keep the implementation close to the existing EROFS chunk-based layout.

## Non-goals

- Preserve backward compatibility with the old `image + --blobdev` CLI.
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
		Set the size of data chunks, must be power of two and between 0x1000-0x1000000: [default: 1048576]
	--compressor <compressor>
		Algorithm to compress data chunks: [default: zstd] [possible values: none, zstd]
	--log-level <log-level>
		Log level: [default: info] [possible values: trace, debug, info, warn, error]
```

Current implementation notes:

- Either `--blob` or `--blob-dir` is required.
- `--bootstrap` is optional and emits a standalone metadata-only artifact.
- `--chunk-size` defaults to `1048576` (1 MiB).
- `--blob <path>` stores the full blob at `<path>` and also stores a companion
	blobmeta sidecar at `<path>.blob.meta`.
- `--blob-dir` stores the full blob under `<blob-dir>/<full_blob_sha256>`.
- `--blob-dir` also stores a blobmeta sidecar as
	`<blob-dir>/<full_blob_sha256>.blob.meta`.
- `--compressor zstd` is accepted in the new CLI, but data is still written as
  uncompressed chunk payload in the current implementation slice.

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
without mounting it. It prints a full superblock dump, one ordered line per
blob device with full-blob SHA256, appended-data SHA256, and chunk statistics,
plus a filesystem summary covering inode counts, file-type counts, xattrs,
hardlinks, and chunk-size distribution.

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
- Blob lines report `slot_sha256` for the raw `ErofsDeviceSlot.tag`, plus both
	`blob_sha256` for the complete blob artifact and `data_sha256` for the appended
	blob data region when the blob can be resolved.
- Blob lines currently report `compressor=none` because the current lepton
	writer does not emit compressed chunk payload.

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
	--bootstrap <bootstrap>
		File path to lepton bootstrap
	--blob <blob>
		File path to lepton blob
	--mountpoint <mountpoint>
		Directory path to mount lepton filesystem
	--log-level <log-level>
		Log level: [default: info] [possible values: trace, debug, info, warn, error]
```

Supported forms:

- `lepton fuse --blob <blob> --mountpoint <mountpoint>`
- `lepton fuse --bootstrap <bootstrap> --blob-dir <blob-dir> --mountpoint <mountpoint>`

The fuse command rejects mixed or partial combinations outside these two forms.

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
| | raw chunk payload extents | |
| | 4 KiB-aligned writes      | |
| | deduped during build      | |
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

- `tag[0..32]` stores the SHA256 of the appended data region only.
- `tag[32..64]` is zero-filled.
- `blocks_lo/blocks_hi` store the referenced full blob size in 4 KiB blocks,
	that is `bootstrap_blocks + data_blocks`.

For current merge output:

- merge preserves the blob id already stored in each source device slot;
- for source layers produced by current `lepton build`, that preserved blob id
	is also the appended-data SHA256.

Regular file chunk indexes continue to use `blkaddr` and `device_id`, where:

- `device_id` is only a device-table index;
- `blkaddr` for external data is rebased during build so it becomes relative to
	the full blob file start, not to the start of the appended data region.

Example:

```text
bootstrap_blocks = 8
first chunk in temporary data file starts at offset 0

before rebase:
  blkaddr = 0

after rebase:
  blkaddr = 8
  source byte offset in full blob = 8 * 4096
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

Current blobmeta on-disk shape:

```text
<full_blob_sha256>.blob.meta

+-------------------------------+
| chunk records                 |
| 24 bytes each                 |
|                               |
| uncompressed_offset           |
| uncompressed_size             |
| compressed_offset             |
| compressed_size               |
+-------------------------------+
| zero padding                  |
| up to 4 KiB alignment         |
+-------------------------------+
| 4 KiB trailer header          |
| magic                         |
| features                      |
| chunk_count                   |
| reserved                      |
+-------------------------------+
```

The current writer biases each `compressed_offset` by the bootstrap size, so
blobmeta source offsets are also full-blob-relative.

### Merge output

The merge command emits an overlaid standalone bootstrap that references one or
more previously built full blobs.

## Build Pipeline

The build pipeline now follows this sequence:

1. Walk the source directory and build the in-memory inode tree.
2. Write deduplicated chunk payload into a temporary data-region file.
3. Compute SHA256 over the temporary data-region file.
4. Build a provisional bootstrap to learn the final bootstrap block count.
5. Rebase external chunk `blkaddr` values by `bootstrap_blocks` so they become
	full-blob-relative.
6. Serialize the final bootstrap bytes in memory.
7. Write the data-region SHA256 into the bootstrap device slot tag.
8. Optionally persist the standalone bootstrap.
9. Persist the full blob as `bootstrap bytes + data region bytes`.
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
2. Read chunk indexes whose external `blkaddr` values were already rebased to
	full-blob-relative offsets during build.
3. Use the same file as both metadata source and external chunk source.
4. Read device-backed chunk payload directly from `blkaddr * block_size + chunk_off`.

### Bootstrap plus blob-dir mount

When mounting with `--bootstrap + --blob-dir`:

1. Open the bootstrap.
2. Read every external device slot.
3. Extract the raw 32-byte blob id from each slot tag.
4. First try the legacy exact file name `<data_region_sha256>`.
5. Otherwise scan files under `blob-dir`, parse the bootstrap prefix of each
	candidate and compute SHA256 of its appended data region.
6. Match candidates against the required blob ids and build a device-id to
	full-blob mapping.
7. Read external chunk payload using the rebased full-blob-relative offsets.

This is intentionally simple for the first implementation slice. It trades a
startup scan for a straightforward, metadata-driven lookup path.

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

There is a known discrepancy between lepton's in-tree `ErofsDeviceSlot` layout
and the `erofs_deviceslot` shape visible in some upstream kernel headers.

For now, lepton continues to use its existing in-tree metadata structs so that
reader and writer stay self-consistent during the artifact migration.

Before claiming kernel-level compatibility for externally mounted artifacts, the
project still needs to settle which exact EROFS UAPI layout it wants to target.

## Validation Strategy

The migration is validated in phases:

1. Rust compile checks for CLI, build and mount wiring.
2. Unit coverage for blob-id/device-slot helpers.
3. Integration tests for:
	- build full blob
	- build standalone bootstrap
	- mount full blob
	- mount bootstrap plus blob-dir
4. Merge integration tests for mixed blob/bootstrap input, whiteout and opaque
	 directory handling.

## Immediate Next Steps

- Expand merge coverage beyond the current OCI whiteout path.
- Add focused tests for blob-id persistence and blob-dir lookup.
- Reconcile the in-tree device-slot layout with the chosen upstream EROFS target.

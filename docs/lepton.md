# Lepton Design

## Status

This document is the working design source for lepton.

The repository is migrating from the original split image/blobdev prototype to a
new artifact model with three user-facing commands:

- `lepton build`
- `lepton check`
- `lepton merge`
- `lepton mount`

The first implementation slice included in this change migrates build, check,
merge and mount to the new artifact shape and CLI surface. The current merge
implementation focuses on metadata overlay, blob-id preservation and OCI
whiteout handling before tackling broader format compatibility work.

## Goals

- Use one user-visible `blob` artifact as the primary layer output.
- Allow an optional standalone `bootstrap` artifact for remote metadata-only use.
- Make `mount` support either a direct blob path or a bootstrap plus blob-dir.
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
the appended chunk data region. `--blob-dir` is an alternative output mode that
writes the full blob into the target directory through a temporary random file,
computes the full artifact SHA256, and finally renames the file to that SHA256.
The standalone bootstrap records the SHA256 blob id for the data region in its
device-table metadata so runtime can resolve the corresponding blob later.

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
		Set the size of data chunks, must be power of two and between 0x1000-0x1000000:
	--compressor <compressor>
		Algorithm to compress data chunks: [default: zstd] [possible values: none, zstd]
	--log-level <log-level>
		Log level: [default: info] [possible values: trace, debug, info, warn, error]
```

Options:

- `--type <type>`
- `--blob <blob>`
- `--blob-dir <blob-dir>`
- `--bootstrap <bootstrap>`
- `--chunk-size <chunk-size>`
- `--compressor <compressor>`
- `--log-level <log-level>`

Current implementation notes:

- Either `--blob` or `--blob-dir` is required.
- `--bootstrap` is optional and emits a standalone metadata-only artifact.
- `--blob-dir` stores the full blob under `<blob-dir>/<blob_sha256>`.
- `--compressor zstd` is accepted in the new CLI, but data is still written as
  uncompressed chunk payload in the current implementation slice.

### Merge

`lepton merge [OPTIONS] <SOURCE>...`

The `lepton merge` command merges multiple layer blobs in order into a single
overlaid bootstrap in EROFS metadata format. Each source path must be a full
blob file whose file name is its SHA256. Merge validates that invariant before
loading metadata. The emitted merged bootstrap records each source layer's full
blob SHA256 in its device table and applies OCI whiteout semantics so the final
bootstrap reflects the merged filesystem view after deletions and opaque-directory
masking.

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

Options:

- `--bootstrap <bootstrap>`
- `--whiteout-spec <whiteout-spec>`
- `--log-level <log-level>`

Current implementation notes:

- Merge requires source blob file names to be 64-character SHA256 hex strings.
- Merge verifies each source file's content SHA256 against its file name.
- Merge rebuilds an overlaid bootstrap by loading each source into an in-memory
	metadata tree, applying OCI whiteout rules, and emitting a new device table.
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

### Mount

`lepton mount [OPTIONS]`

The `lepton mount` command mounts lepton metadata as a filesystem at the target
mountpoint. The current implementation supports only the FUSE driver. During
read path resolution, runtime uses the blob id recorded in bootstrap metadata
to locate the corresponding blob under `--blob-dir` and then serves chunk data
from that blob.

Current CLI help:

```bash
lepton mount -h
Mount lepton filesystem into a directory

Usage: lepton mount [OPTIONS]

Options:
	--blob-dir <blob-dir>
		Directory path including lepton data blob
	--bootstrap <bootstrap>
		File path to lepton bootstrap
	--blob <blob>
		File path to lepton blob
	--driver [default: fuse] [possible values: fuse]
	--mountpoint <mountpoint>
		Directory path to mount lepton filesystem
	--log-level <log-level>
		Log level: [default: info] [possible values: trace, debug, info, warn, error]
```

Supported forms:

- `lepton mount --blob <blob> --mountpoint <mountpoint>`
- `lepton mount --bootstrap <bootstrap> --blob-dir <blob-dir> --mountpoint <mountpoint>`

The mount command rejects mixed or partial combinations outside these two forms.

## Artifact Model

### Full blob

The full blob is the main output from `lepton build`.

Layout:

1. Primary EROFS bootstrap image.
2. Appended chunk payload region.

This means the blob contains both metadata and data. When mounted directly with
`--blob`, the reader uses the primary image header to compute where the appended
data region begins.

### Standalone bootstrap

The standalone bootstrap is optional and contains only the primary EROFS image.

It still includes a device table entry so that runtime can determine which blob
provides chunk payload. The bootstrap does not embed file data chunks.

### Merge output

The merge command emits an overlaid bootstrap that references one or more
previously built blobs.

## On-disk Metadata Design

### Superblock

The superblock continues to provide:

- `extra_devices`
- `devt_slotoff`
- primary image block count

It does not carry the blob identity itself. It only points to the device table.

### Device table

Each external blob device is represented by one `ErofsDeviceSlot` entry.

Within the current lepton layout:

- Single-layer bootstraps store the raw SHA256 digest of the appended blob data region in `tag[0..32]`.
- Merged bootstraps store the raw SHA256 digest of each source full blob artifact in `tag[0..32]`.
- `tag[32..64]` is zero-filled.
- `blocks_lo/blocks_hi` store the external blob data block count.

Blob identity is therefore attached to the device slot, not to the chunk index
and not to the superblock directly.

### Chunk index

Chunk indexes continue to use:

- `blkaddr`
- `device_id`

`device_id` is only a device-table index. It is not itself a digest and must not
be treated as a blob identifier.

## Blob ID Semantics

The current implementation stores the SHA256 of the blob data region rather than
the SHA256 of the whole full-blob file.

This avoids a self-reference problem:

- the full blob starts with bootstrap metadata;
- bootstrap metadata contains the blob identifier;
- hashing the full file while embedding that hash into the file would be circular.

By hashing only the appended chunk payload region, bootstrap can record a stable
blob id without self-reference.

## Build Pipeline

The build pipeline now follows this sequence:

1. Walk the source directory and build the in-memory inode tree.
2. Write deduplicated chunk payload into a temporary data-region file.
3. Serialize metadata and build bootstrap bytes in memory.
4. Compute SHA256 over the temporary data-region file.
5. Write that SHA256 into the bootstrap device slot tag.
6. Optionally persist the standalone bootstrap.
7. Persist the full blob as `bootstrap bytes + data region bytes`.

The temporary data-region file is an implementation detail and is removed after
the final blob has been written.

## Reader and Mount Design

### Direct blob mount

When mounting with `--blob`:

1. Open the blob as the primary image.
2. Read the superblock block count.
3. Compute `blob_data_offset = primary_image_blocks * block_size`.
4. Use the same file as the data source for external chunk reads, but add the
	computed base offset when addressing chunk payload.

### Bootstrap plus blob-dir mount

When mounting with `--bootstrap + --blob-dir`:

1. Open the bootstrap.
2. Read every external device slot.
3. Extract the raw 32-byte blob id from each slot tag.
4. Scan files under `blob-dir`.
5. For each candidate, parse its primary image and compute SHA256 of the appended
	data region.
6. Match candidates against every required blob id and build a device_id to blob
	mmap mapping.

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

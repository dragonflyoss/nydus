# EROFS Technical Internals

This document describes the EROFS structures emitted by this branch, not every
upstream EROFS feature. The private chunk-table `.blob.meta` format is version
**1**; its layout and cache translation belong in
[Nydus Design](nydus.md#blob-meta-region-layout). Older development images must
be rebuilt. See the [documentation index](../README.md#documentation) for
transport guides.

## Table of Contents

1. [Overview](#1-overview)
2. [Image Layout](#2-image-layout)
3. [Superblock](#3-superblock)
4. [Device Table](#4-device-table)
5. [Inode System](#5-inode-system)
6. [Chunk Index & Deduplication](#6-chunk-index--deduplication)
7. [Directory Format](#7-directory-format)
8. [Metadata Layout](#8-metadata-layout)
9. [Build Pipeline](#9-build-pipeline)
10. [Design Decisions](#10-design-decisions)

## 1. Overview

The bootstrap is the EROFS metadata image. Its device table names the external
data devices. The backend blobs encode those devices, but they are not generally
raw EROFS devices themselves.

| Build compressor | File layout | Backend data | Kernel-visible cache |
| --- | --- | --- | --- |
| `none`, `zstd`, `lz4` | CHUNK_BASED | Dense chunk bytes packed into fixed-size chunk groups, each independently decodable and optionally compressed, described by the blob meta | Plain data with each chunk starting on its own 4KiB block |
| `erofs-none` | CHUNK_BASED | The padded chunk address space itself, no blob meta | The device, read as-is |
| `erofs-lz4`, `erofs-zstd` | COMPRESSED_FULL | Native z_erofs pclusters and fragments, no blob meta | The device, read as-is; kernel EROFS decompresses it |

The default is chunk-based zstd with 1MiB chunks. The chunk size is also the
size of every *chunk group*: a chunk that fills a group is a group of its own,
smaller chunks (small files, file tails) are bin-packed into shared groups. A
small file is a chunk, not a special EROFS fragment; a nydus chunk group is a
compression unit of the blob meta, unrelated to z_erofs fragments.

## 2. Image Layout

```text
full blob:          encoded data | embedded bootstrap | blob.meta | footer
standalone image:   bootstrap referencing full-blob IDs
runtime flat view:  bootstrap | gap | cache device 1 | gap | cache device 2
```

Full-blob regions start on 4KiB boundaries; encoded groups inside the data
region are byte-packed. The embedded bootstrap can itself be zstd-compressed
as declared by the footer. Full-blob offsets must not be confused with offsets
inside a decoded bootstrap or an external device.

With explicit `device=` mounts, EROFS reads each cache device separately. In
flatdev mode, the device table supplies the mapped address of each device in
one flattened address space. Neither mode points the kernel at dense encoded
chunk bytes.

See [artifact packing](nydus.md#full-blob-byte-layout) and
[kernel requirements](nydus.md#kernel-compatibility-and-format-limits).

## 3. Superblock

The superblock starts at byte 1024 of the EROFS image and has a 128-byte base.
Important fields include block size, root NID, inode count, shared timestamp,
primary block count, metadata block address, feature bits, compression
configuration, device-table position and the optional packed-inode NID.

The implementation is [superblock.rs](../nydus-format/src/erofs/superblock.rs).
Do not infer the device-table offset from the superblock size: z_erofs adds
compression configuration records before the table. Use `devt_slotoff * 128`.

### Timestamp policy

Compact inodes use the superblock's `epoch` and `fixed_nsec`. **There is no
per-compact-inode mtime delta in the supported format.** The bytes named
`i_mtime` in the Rust compact struct are reserved and written as zero.
Extended inodes carry their own seconds and nanoseconds.

Build, merge and optimize choose the most frequent eligible zero-nanosecond
mtime from the final inode tree. An inode whose timestamp differs uses the
extended header. Source root timestamps are intentionally normalized to zero.

### Feature and size limits

- Chunk images use CHUNKED_FILE and DEVICE_TABLE; z images also declare their
  compression algorithms and required z_erofs features.
- The writer does not enable 48BIT or compact-time extensions.
- Primary/device block counts and mapped start addresses must each fit `u32`.
  Ordinary chunk addresses stop at `0xfffffffe`; `0xffffffff` is a hole.
- Arithmetic across a mapped start and a device length uses checked wider
  calculations. A per-device limit is not a limit on compressed blob bytes.

## 4. Device Table

Each device slot is 128 bytes:

| Offset | Bytes | Field | Current branch |
| ---: | ---: | --- | --- |
| 0 | 64 | `tag` | 64-character lowercase full/data SHA256 ID, according to bootstrap role |
| 64 | 4 | `blocks_lo` | Kernel-visible device length in 4KiB blocks |
| 68 | 4 | `uniaddr_lo` | Mapped start in the flattened address space |
| 72 | 2 | `blocks_hi` | Written zero; 48BIT unsupported |
| 74 | 2 | `uniaddr_hi` | Written zero; 48BIT unsupported |
| 76 | 52 | reserved | Written zero |

Device 0 is the primary image. Slot 0 describes device 1. A chunk index stores
the device ID explicitly; its block offset is relative to that device.
Identical full blobs can share a device registration when merging chunk layers.

An embedded bootstrap identifies its own data region without hashing itself
circularly. Standalone and merged bootstraps refer to the full blobs served by
the store/registry. `--blob-id` is a local-store naming override, not a verified
registry digest. See [blob identity](nydus.md#blob-id-semantics).

Source: [chunk.rs](../nydus-format/src/erofs/chunk.rs).

## 5. Inode System

### NID Addressing

```text
inode_byte_offset = meta_blkaddr * 4096 + nid * 32
```

NIDs are 32-byte slot addresses, not sequential file numbers. Header, xattrs
and inline/index tails can occupy several slots.

### Compact vs Extended format

| Header | Bytes | Selection |
| --- | ---: | --- |
| Compact | 32 | Size, UID/GID, link count and timestamp fit the compact contract |
| Extended | 64 | At least one field or timestamp requires the wider header |

Compact link counts can exceed one if they fit `u16`; hardlinks do not by
themselves require an extended inode. Both formats use checked 32-bit flat
data addresses. In compact headers, offset 6 is the link count, not high
address bits. Extended headers have the link count at offset 44.

`i_format` bit 0 selects the header; bits 1-3 select the data layout. The
reader rejects unsupported remaining bits. The old compact `nlink_1` bit and
48BIT address interpretations are not emitted.

| Object | Layout |
| --- | --- |
| Chunk-based regular file | CHUNK_BASED, followed by 8-byte chunk indexes |
| Native compressed regular file | COMPRESSED_FULL, followed by a z map header/index or whole-file fragment reference |
| Directory | FLAT_INLINE when its tail fits, otherwise FLAT_PLAIN |
| Symlink | FLAT_INLINE when its target fits, otherwise FLAT_PLAIN |
| Device node | FLAT_PLAIN, `i_u` contains `rdev` |
| FIFO/socket | FLAT_PLAIN with no data payload |

Xattrs sit between the inode header and its data/index tail. Chunk indexes are
8-byte aligned; inline data must stay within its allowed block boundary.

Sources: [inode format](../nydus-format/src/erofs/inode.rs) and
[inode selection/serialization](../nydus/src/build/inode.rs).

## 6. Chunk Index & Deduplication

### Chunk index entry (8 bytes)

| Offset | Bytes | Field |
| ---: | ---: | --- |
| 0 | 2 | Unused high address field, zero on output |
| 2 | 2 | Device ID |
| 4 | 4 | Device-relative block address, or `0xffffffff` for a hole |

Hole entries are **not** eight bytes of `0xff`; the low address word carries
the sentinel. The Rust API exposes a wider `EROFS_NULL_ADDR`, translated by the
serializer. Chunk format bits 0-4 encode the block-count exponent; INDEXES
selects these 8-byte entries. 48BIT is rejected.

```text
chunk_number = file_offset / chunk_size
within_chunk = file_offset % chunk_size
device_offset = index.block_address * 4096 + within_chunk
```

For flatdev, add the selected slot's mapped offset. A group lookup then
resolves this kernel-visible address to a backend range: the chunk group whose
slot holds the address (`address / chunk_size`), and the groups of its
fetch-size cell around it. A group holds whole chunks and can span many small
files.

### What is and is not deduplicated

The chunk-based writer stores repeated nonzero content again. Its BLAKE3
chunk digests (one per chunk by default; `--digester none` omits them all)
are an inspection/future-dedup index, **not an active chunk deduplication
implementation**. All-zero chunks use holes and consume no blob data or chunk
entry. Hardlinks reuse inodes/data by identity.

Native z_erofs stores every small file's bytes again in the packed inode,
even when identical to another file's; deduplication is left to the block
volume, helped by `--erofs-data-alignment`. Nothing provides cross-image CAS
or guarantees storage-provider deduplication from aligned offsets.

## 7. Directory Format

Each directory entry is 12 bytes: NID (`u64`), name offset (`u16`), file type
(`u8`) and reserved byte. Each directory block contains a sorted entry array
followed by names. `.` and `..` are explicit; root's parent is itself.

Complete directory blocks live in the data area. A partial final block can be
inlined after the inode/xattrs when it fits. Otherwise the directory uses a
block-backed layout. Directory `i_size` is the serialized length, **not always
a multiple of 4096**. Every referenced name range must remain within its block
or inline tail.

Source: [dir.rs](../nydus/src/build/dir.rs).

## 8. Metadata Layout

The builder selects header sizes before assigning offsets, allocates inode
slots, and places full data blocks separately from inline tails. Directory
children are allocated together for locality. Serialization follows allocated
offsets, not an assumed DFS inode order.

After allocating NIDs, parent references and directory entries are encoded.
Inline tails must not cross their permitted block boundary. Mapped z devices
are placed after the complete bootstrap; if metadata growth moves those
devices, all affected z block references are relocated consistently.

Sources: [layout.rs](../nydus/src/build/layout.rs) and
[bootstrap.rs](../nydus/src/build/bootstrap.rs).

## 9. Build Pipeline

1. Read a directory tree or stream an OCI tar, preserving representable
   metadata. Tar PAX size, ownership and nanosecond mtime override legacy
   fields. Whiteouts are retained for the merge pass.
2. Write dense chunks or native z pclusters. File content is not buffered for
   the entire image. Whole-file z fragments use the shared packed inode.
3. Finalize compression, resolve pending z metadata, and flatten the final
   tree. Choose the shared timestamp and appropriate inode headers.
4. Allocate metadata, encode device slots, and render the embedded bootstrap.
5. Append chunk-table blob metadata and the footer; optionally emit the
   standalone bootstrap and sidecar. Content IDs distinguish data and full blob.

`nydusify` streams decompressed OCI tars into the tar builder; directory
sources use the directory builder. It transports `.blob.meta` unchanged rather
than duplicating the Rust parser in Go.

Sources: [build/mod.rs](../nydus/src/build/mod.rs),
[tar.rs](../nydus/src/build/tar.rs),
[blob_chunk.rs](../nydus/src/build/blob_chunk.rs).

## 10. Design Decisions

- **Dense transport, padded cache:** `100B, 5000B, 40B` consumes 5140 payload
  bytes but occupies four 4KiB cache blocks. Chunk lengths reconstruct both
  positions; `pwritev` fills contiguous cache runs in bounded batches.
- **Fixed-size groups:** every group owns one chunk-size slot of the
  address space, so an address maps to its group by division and a group
  maps to its backend range by one table entry; there is no per-read scan
  and no runtime index to build at open. A chunk of at least the chunk
  group threshold (64 KiB by default) is a group of its own, so its encoded
  bytes are one frame addressable by its digest; the unused rest of its
  slot costs nothing (the blob is dense, the cache sparse).
- **DAX eligibility:** plain aligned cache pages preserve the prerequisites
  for guest mapping, but the guest kernel, filesystem mode and transport must
  also support DAX. Alignment alone does not enable it. Native compressed
  fragments cannot be directly mapped as file pages through EROFS DAX.
- **Transport is independent:** NBD/ublk copy block responses; UFFD can map
  backing ranges or copy them. A host mapping of compressed z device bytes
  does not remove the guest's decompressed page cache.
- **Merge is metadata-only:** chunk/z mixtures and differing packed-inode
  compression algorithms are rejected. No hidden data transcoding occurs.
- **Integrity:** group CRC32C checks decoded transport payloads; footer/meta
  CRCs detect corruption, while full-blob SHA256 provides content identity.
  CRC32C alone is not cryptographic authentication.

## Validation

```bash
cargo test --workspace --features cli
make test-nydusify
```

These include source metadata, dense scattering, z fragment bounds and
optimize-source-cache regressions. Native kernel, DAX and transport validation
require the separate environments listed in
[Validation Strategy](nydus.md#validation-strategy); a skipped kernel test is
not evidence of kernel compatibility.

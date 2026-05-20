# EROFS Technical Internals

A deep dive into the EROFS on-disk format and how `erofs-utils-rust` builds
chunk-based images. Read this alongside the source files in `src/` for full
understanding.

---

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

---

## 1. Overview

EROFS (Enhanced Read-Only File System) is designed for **read-only** scenarios
where startup speed and random-read performance matter — primarily container
images. Three core design choices drive everything:

| Goal | Mechanism |
|------|-----------|
| **On-demand loading** | File data split into fixed-size chunks; each chunk independently addressable |
| **Deduplication** | Content-addressed chunks (BLAKE3 hash); identical data stored once |
| **Minimal metadata overhead** | Compact 32-byte inodes; slot-aligned addressing; no indirection tables |

The chunk-based layout that `erofs-utils-rust` produces separates **metadata**
(inodes, directories) from **data** (file contents). Metadata lives in the
primary image; data lives in a separate **blob device**. This split allows a
container runtime to lazily pull data chunks on first access while the
metadata image remains small enough to fetch entirely at startup.

---

## 2. Image Layout

An EROFS image produced by `erofs-utils-rust` has the following block-level
structure (`BLOCK_SIZE = 4096`):

```
Image file (erofs.meta.img)
┌──────────────────────────────────────────────────────────────┐
│ Block 0                                                      │
│ ┌──────────────┬───────────────┬───────────────┬───────────┐ │
│ │ Boot area    │ Superblock    │ Device Slot   │ Unused    │ │
│ │ 1024 bytes   │ 128 bytes     │ 128 bytes     │           │ │
│ │ offset 0     │ offset 1024   │ offset 1152   │           │ │
│ └──────────────┴───────────────┴───────────────┴───────────┘ │
├──────────────────────────────────────────────────────────────┤
│ Block 1  ── Metadata area start (meta_blkaddr = 1)           │
│ ┌──────────────────────────────────────────────────────────┐ │
│ │ Inode slots (32-byte aligned, packed sequentially)       │ │
│ │ [inode_0] [inode_1] [inode_2] ...                        │ │
│ └──────────────────────────────────────────────────────────┘ │
├──────────────────────────────────────────────────────────────┤
│ Block N  ── Directory data (block-aligned)                   │
│ ┌──────────────────────────────────────────────────────────┐ │
│ │ [dir_block_0] [dir_block_1] ...                          │ │
│ └──────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────┘

Blob file (erofs.blob.img)
┌──────────────────────────────────────────────────────────────┐
│ [chunk_0] [chunk_1] [chunk_2] ...                            │
│  Each chunk: up to chunksize bytes, block-aligned            │
└──────────────────────────────────────────────────────────────┘
```

→ source: `superblock.rs` :: `write_image()` assembles Block 0 then appends
the metadata buffer. `blobchunk.rs` :: `BlobWriter` writes the blob file.

### Why this layout?

- **Block 0** packs the superblock and device table together because they are
  tiny and always read together at mount time.
- **Metadata** is in a contiguous region so the kernel can read it with
  sequential I/O. Inodes are packed tightly — no bitmap, no inode table
  indirection — because the filesystem is read-only and never needs allocation.
- **Blob** is a separate file so it can be stored on a remote registry and
  pulled lazily.

---

## 3. Superblock

The superblock sits at a **fixed byte offset 1024** from the start of the
image. This leaves room for bootloader code in the first 1024 bytes, matching
the convention used by ext2/ext4.

### On-disk layout (128 bytes)

```
Offset  Size  Field              Description
──────  ────  ─────              ───────────
   0     4    magic              0xE0F5E1E2 — identifies an EROFS image
   4     4    checksum           CRC32C of the entire block (0 if not computed)
   8     4    feature_compat     Compatible feature flags
  12     1    blkszbits          log2(block_size), e.g. 12 → 4096
  13     1    sb_extslots        Extra 16-byte extension slots (0 in our case)
  14     2    root_nid           NID of the root directory inode
  16     8    inos               Total number of inodes
  24     8    epoch              Base UNIX timestamp (seconds)
  32     4    fixed_nsec         Fixed nanoseconds component (0)
  36     4    blocks_lo          Total blocks in primary image (low 32 bits)
  40     4    meta_blkaddr       Block address where metadata area starts
  44     4    xattr_blkaddr      Shared xattr area start (0 = none)
  48    16    uuid               Filesystem UUID
  64    16    volume_name        Volume label (zero-padded)
  80     4    feature_incompat   Incompatible feature flags
  84     2    compr_algs         Available compression algorithms (0 = none)
  86     2    extra_devices      Number of extra devices (1 for blobdev)
  88     2    devt_slotoff       Byte offset / 128 of the device table
  90     1    dirblkbits         Directory block size bits (0 = same as blkszbits)
 108     4    build_time         Seconds added to epoch for build timestamp
```

→ source: `ondisk.rs` :: `serialize_superblock()`

### Feature flags used by erofs-utils-rust

| Flag | Value | Meaning |
|------|-------|---------|
| `FEATURE_COMPAT_MTIME` | 0x02 | Compact inodes store mtime as delta from epoch |
| `FEATURE_INCOMPAT_CHUNKED_FILE` | 0x04 | Files may use chunk-based data layout |
| `FEATURE_INCOMPAT_DEVICE_TABLE` | 0x08 | Image has a device table (enables blobdev) |

### Why `epoch` + per-inode delta?

Compact inodes only have a 32-bit `i_mtime` field. To avoid the year-2038
problem, EROFS stores a **base epoch** in the superblock and each compact
inode stores `mtime − epoch` as an unsigned 32-bit delta. This gives a ~136
year range from any base timestamp. Extended inodes store a full 64-bit
absolute timestamp and ignore the epoch.

### devt_slotoff calculation

The device table is placed right after the superblock in Block 0:

```
devt_slotoff = (EROFS_SUPER_OFFSET + SB_SIZE) / DEVICESLOT_SIZE
             = (1024 + 128) / 128
             = 9
```

The kernel multiplies `devt_slotoff × 128` to find the byte offset of the
device table from the start of the image.

---

## 4. Device Table

The device table describes extra block devices that hold file data. In the
chunk-based model, the primary image holds only metadata, and one or more
**blob devices** hold actual file content.

### Device slot (128 bytes)

```
Offset  Size  Field        Description
──────  ────  ─────        ───────────
   0    64    tag          Device identifier / digest (zeros in our case)
  64     4    blocks_lo    Number of blocks on this device (low 32 bits)
  68     4    uniaddr_lo   Unified address offset (0 for first device)
  72     4    blocks_hi    Number of blocks (high 32 bits)
  76     2    uniaddr_hi   Unified address offset (high 16 bits)
  78    50    reserved     Must be zero
```

→ source: `ondisk.rs` :: `serialize_device_slot()`

In `erofs-utils-rust`, we always have exactly **one** extra device
(`extra_devices = 1`). The `blocks` field records the total number of
4096-byte blocks in the blob device file.

### Why device_id starts at 1?

Device 0 implicitly refers to the **primary image** itself. The first entry
in the device table corresponds to device 1. When a chunk index has
`device_id = 1`, the kernel reads from the first external blob device.

```
device_id = 0  →  primary image (metadata)
device_id = 1  →  first device table entry (blob device)
device_id = 2  →  second device table entry (if present)
...
```

---

## 5. Inode System

### NID Addressing

EROFS uses **NID** (Node ID) as the address of every inode. A NID is not an
arbitrary number — it directly encodes the inode's **physical position** in
the metadata area:

```
byte_offset_in_image = meta_blkaddr × block_size + NID × 32
```

Since `meta_blkaddr = 1` and `block_size = 4096`:

```
NID 0   → byte 4096    (first inode slot)
NID 1   → byte 4128    (second slot, +32 bytes)
NID 2   → byte 4160
NID 128 → byte 8192    (start of block 2)
```

This design eliminates any inode table or bitmap — the NID **is** the address.
The kernel computes the inode location with a single shift and add, making
inode lookup O(1).

→ source: `layout.rs` :: `MetadataLayout::alloc_inode()` assigns offsets and
computes NIDs as `offset / 32`.

### Compact vs Extended format

EROFS has two inode formats:

| Format | Size | When used |
|--------|------|-----------|
| **Compact** | 32 bytes | Default: file ≤ 4 GB, UID/GID ≤ 65535, nlink = 1 |
| **Extended** | 64 bytes | file > 4 GB, UID/GID > 65535, or nlink > 1 |

→ source: `inode.rs` :: `build_tree_recursive()` sets `is_extended` based on
these thresholds.

### Compact inode (32 bytes)

```
Offset  Size  Field           Description
──────  ────  ─────           ───────────
   0     2    i_format        Version (bit 0) + data layout (bits 1-3) + flags
   2     2    i_xattr_icount  Xattr entry count (0 = no xattrs)
   4     2    i_mode          POSIX file mode (type + permissions)
   6     2    i_nb            startblk_hi (dirs) or unused
   8     4    i_size          File size (32-bit, max 4 GB)
  12     4    i_mtime         mtime − epoch (unsigned delta)
  16     4    i_u             Union: startblk_lo / rdev / chunk_info
  20     4    i_ino           Inode number (for stat compatibility)
  24     2    i_uid           Owner UID (16-bit)
  26     2    i_gid           Owner GID (16-bit)
  28     4    i_reserved      Must be zero
```

→ source: `ondisk.rs` :: `serialize_inode_compact()`

### Extended inode (64 bytes)

```
Offset  Size  Field           Description
──────  ────  ─────           ───────────
   0     2    i_format        Version (bit 0 = 1) + data layout (bits 1-3)
   2     2    i_xattr_icount  Xattr entry count
   4     2    i_mode          POSIX file mode
   6     2    i_nb            startblk_hi
   8     8    i_size          File size (64-bit)
  16     4    i_u             Union: startblk_lo / rdev / chunk_info
  20     4    i_ino           Inode number
  24     4    i_uid           Owner UID (32-bit)
  28     4    i_gid           Owner GID (32-bit)
  32     8    i_mtime         Absolute UNIX timestamp (seconds)
  40     4    i_mtime_nsec    Nanoseconds
  44     4    i_nlink         Hard link count (32-bit)
  48    16    i_reserved2     Must be zero
```

→ source: `ondisk.rs` :: `serialize_inode_extended()`

### i_format bit encoding

The 16-bit `i_format` field packs several fields:

```
 15                                    4   3   2   1   0
┌──────────────────────────────────┬───┬───┬───┬───┬───┐
│            reserved              │ N │ L₂│ L₁│ L₀│ V │
└──────────────────────────────────┴───┴───┴───┴───┴───┘

V  (bit 0)    : Version — 0 = compact (32B), 1 = extended (64B)
L₀-L₂ (bits 1-3) : Data layout:
                      0 = FLAT_PLAIN     (data in contiguous blocks)
                      2 = FLAT_INLINE    (tail data after inode header)
                      4 = CHUNK_BASED    (data via chunk index array)
N  (bit 4)    : nlink_1 flag (compact non-dir only; indicates nlink == 1)
```

→ source: `ondisk.rs` :: `compact_i_format()`, `extended_i_format()`

### The i_u union

The 4-byte `i_u` field is the most overloaded field in the inode. Its meaning
depends on the data layout:

| Data layout | i_u contains |
|-------------|-------------|
| FLAT_PLAIN (directory) | `startblk_lo` — start block of directory data |
| FLAT_PLAIN (device file) | `rdev` — device major/minor |
| FLAT_INLINE (symlink) | 0 (target data is inline after inode header) |
| CHUNK_BASED | `chunk_info.format` — chunk format bits (see §6) |

### Data layouts used in erofs-utils-rust

```
Regular files → CHUNK_BASED
                Inode followed by chunk index array.
                File data lives in the blob device.

Directories   → FLAT_PLAIN
                Directory data in separate contiguous blocks.
                i_u = startblk_lo, i_nb = startblk_hi.

Symlinks      → FLAT_INLINE
                Link target stored inline after inode header.
                i_size = target length (no null terminator).

Char/Block    → FLAT_PLAIN
                i_u = rdev (device major/minor), i_size = 0.

FIFO/Socket   → FLAT_PLAIN
                i_u = 0, i_size = 0.
```

### Chunk-based inode memory layout

For a regular file, the inode header is followed by an array of 8-byte chunk
indexes (aligned to an 8-byte boundary from the inode start):

```
┌─────────────────────────┬─────┬──────────┬──────────┬──────────┐
│ Inode header            │ pad │ ChkIdx 0 │ ChkIdx 1 │ ChkIdx 2 │
│ 32B (compact)           │     │ 8 bytes  │ 8 bytes  │ 8 bytes  │
│ or 64B (extended)       │     │          │          │          │
└─────────────────────────┴─────┴──────────┴──────────┴──────────┘
 ← inode_isize →                ← extent_isize = N × 8 →

Total metadata = round_up(inode_isize, 8) + N × 8
  compact: 32 + N × 8   (already 8-byte aligned)
  extended: 64 + N × 8  (already 8-byte aligned)

NID span (number of 32B slots consumed):
  = ceil(total_metadata / 32)
  e.g. compact inode with 4 chunks = ceil((32 + 32) / 32) = 2 slots
```

→ source: `inode.rs` :: `inode_meta_size()`, `serialize_inode()`

### Symlink inode memory layout

```
┌────────────────────────┬──────────────────────────┐
│ Inode header           │ "/path/to/target"        │
│ 32B or 64B             │ (i_size bytes, no NUL)   │
│ layout = FLAT_INLINE   │                          │
└────────────────────────┴──────────────────────────┘

Total metadata = inode_isize + target_len
```

---

## 6. Chunk Index & Deduplication

### Chunk index entry (8 bytes)

Each chunk of a regular file is described by an 8-byte index:

```
Offset  Size  Field         Description
──────  ────  ─────         ───────────
   0     2    startblk_hi   Block address bits 47-32
   2     2    device_id     Which device holds this chunk (1 = blobdev)
   4     4    startblk_lo   Block address bits 31-0
```

A hole (sparse region) is represented by all-`0xFF` bytes.

→ source: `ondisk.rs` :: `serialize_chunk_index()`

### Chunk format (stored in i_u)

The `chunk_info.format` 16-bit value stored in the inode's `i_u` field:

```
 15                              6   5   4   3   2   1   0
┌────────────────────────────┬───┬───┬───┬───┬───┬───┬───┐
│          reserved          │48B│IDX│     chunkbits      │
└────────────────────────────┴───┴───┴───┴───┴───┴───┴───┘

Bits 0-4 : chunkbits − blkszbits
             e.g. chunksize=1MB → chunkbits=20, blkszbits=12 → value=8
             The kernel computes: chunk_size = block_size << value
Bit 5    : INDEXES (0x0020) — use 8-byte chunk index entries
Bit 6    : 48BIT (0x0040) — addresses may exceed 32 bits
```

→ source: `inode.rs` :: `chunk_format()`

### How the kernel reads a chunk

To read byte range `[off, off+len)` of a chunk-based file:

```
chunk_nr     = off / chunk_size
chunk_offset = off % chunk_size

index_pos    = inode_pos + round_up(inode_isize, 8) + chunk_nr × 8
  → read 8-byte chunk index at index_pos

blkaddr = (startblk_hi << 32) | startblk_lo
device  = device_table[device_id - 1]

physical_pos = blkaddr × block_size + chunk_offset
  → read from blob device at physical_pos
```

### Deduplication via content hashing

`erofs-utils-rust` deduplicates at build time using a hash map:

```
                        ┌─────────────┐
 Read chunk data  ───►  │ BLAKE3 hash │ ───► 32-byte digest
                        └──────┬──────┘
                               │
                    ┌──────────▼──────────┐
                    │ HashMap lookup      │
                    │ key = [u8; 32]      │
                    │ val = BlobChunk     │
                    └──────────┬──────────┘
                         ┌─────┴─────┐
                         │           │
                       Found       Not found
                         │           │
                    Reuse blkaddr   Write chunk to blob
                    (skip write)    Insert into HashMap
                         │           │
                         └─────┬─────┘
                               │
                    Return ChunkIndex { blkaddr, device_id=1 }
```

**Key detail**: only the **actual data bytes** are hashed (not padded to
chunksize). The last chunk of a file is often smaller than chunksize. Writing
to the blob is block-aligned:

```
write_len = ceil(actual_bytes / 4096) × 4096
```

This avoids inflating the blob for small files. With `--chunksize=1048576`,
a 100-byte file writes only 4096 bytes (1 block) to the blob, not 1 MB.

→ source: `blobchunk.rs` :: `BlobWriter::write_file_chunks()`

### Why BLAKE3 instead of SHA256?

BLAKE3 is ~4× faster than SHA256 on modern CPUs while providing equivalent
collision resistance (256-bit output). Since the hash is only used internally
for dedup and never stored on disk, switching algorithms is transparent to the
EROFS format.

---

## 7. Directory Format

EROFS directories use the **FLAT_PLAIN** layout: directory data occupies one
or more contiguous blocks referenced by the inode's `startblk` field.

### Directory entry (12 bytes)

```
Offset  Size  Field       Description
──────  ────  ─────       ───────────
   0     8    nid         NID of the referenced child inode
   8     2    nameoff     Byte offset of filename within this block
  10     1    file_type   EROFS_FT_* constant (1=file, 2=dir, 7=symlink, ...)
  11     1    reserved    Must be zero
```

→ source: `ondisk.rs` :: `serialize_dirent()`

### Block-level layout

Each directory block is independently formatted and self-contained:

```
One directory block (4096 bytes):

 0                                                          4095
┌────────────┬────────────┬────────────┬────────────────────┬───┐
│ dirent[0]  │ dirent[1]  │ dirent[2]  │ "." ".." "myfile"  │pad│
│ 12 bytes   │ 12 bytes   │ 12 bytes   │   (name strings)   │   │
│ nid=A      │ nid=B      │ nid=C      │                    │   │
│ nameoff=36 │ nameoff=37 │ nameoff=39 │                    │   │
└────────────┴────────────┴────────────┴────────────────────┴───┘
 ↑ dirent area (count × 12 bytes)       ↑ name area starts
                                          at dirent[0].nameoff
```

The name of entry `i` spans from `nameoff[i]` to `nameoff[i+1]` (or to the
end of the used area for the last entry). The rest of the block is zero-padded.

→ source: `dir.rs` :: `serialize_directory()`

### Filling algorithm

```
for each entry to add:
    new_dirent_area = (entries_in_block + 1) × 12
    new_name_area   = current_name_area + name.len()

    if new_dirent_area + new_name_area > 4096:
        finalize current block (zero-pad to 4096)
        start new block

    add dirent with nameoff = current_name_offset
    append name bytes
```

### Key rules

1. **Sorted alphabetically**: entries in each block are in strict
   lexicographic order. The kernel uses binary search for O(log n) lookups.

2. **"." and ".." are explicit**: stored as regular entries.
   - `"."` → NID of the directory itself (`self_nid`)
   - `".."` → NID of the parent directory (`parent_nid`)
   - Root directory's `".."` points to itself.

3. **Cross-block splitting**: if entries don't fit in one block, they continue
   in the next block. Each block is independently valid.

4. **`inode.size`**: set to the total serialized directory data length
   (always a multiple of 4096).

---

## 8. Metadata Layout

The `MetadataLayout` struct manages a contiguous `Vec<u8>` buffer that becomes
blocks 1..N of the final image.

### Two-phase allocation

```
Phase 1 — Inode allocation (32-byte slot aligned)                       
──────────────────────────────────────────────────                      
cursor ──►                                                              
┌──────────┬──────────┬──────────────┬──────────┬──────────┬───        
│ inode_0  │ inode_1  │ inode_2      │ inode_3  │ inode_4  │...        
│ 32 bytes │ 64 bytes │ 32+3×8=56B  │ 32 bytes │ 32 bytes │           
│ NID=0    │ NID=1    │ NID=3       │ NID=5    │ NID=6    │           
│ (dir)    │ (dir,ext)│ (file,3chk) │ (symlink)│ (fifo)   │           
└──────────┴──────────┴──────────────┴──────────┴──────────┴───        
                                                                        
              ↓ pad_to_block() — align to 4096                          
                                                                        
Phase 2 — Directory data (block-aligned)                                
──────────────────────────────────────                                  
┌──────────────────┬──────────────────┬───                              
│ dir_data for     │ dir_data for     │...                              
│ inode_0 (4096B)  │ inode_1 (8192B)  │                                
│ startblk = X     │ startblk = X+1   │                                
└──────────────────┴──────────────────┴───                              
```

Notice that NIDs are **not sequential** — an inode that consumes 64 bytes
occupies 2 slots (NID span = 2), so the next NID skips by 2.

### NID assignment

```rust
fn alloc_inode(&mut self, size: usize) -> (usize, u64) {
    let aligned = round_up(size, 32);   // pad to 32B slot boundary
    let offset = self.cursor;
    self.cursor += aligned;
    let nid = offset / 32;             // NID = slot index
    (offset, nid)
}
```

→ source: `layout.rs` :: `MetadataLayout`

### Directory data block address

```rust
fn alloc_dir_data(&mut self, size: usize) -> (usize, u64) {
    let offset = round_up(self.cursor, 4096);  // block-align
    let startblk = meta_blkaddr + offset / 4096;
    ...
}
```

The `startblk` is an **absolute block address** in the image file, stored
in the directory inode's `i_u` (low 32 bits) and `i_nb` (high 16 bits).

---

## 9. Build Pipeline

The `main()` function orchestrates image creation in three phases:

```
┌─────────────────────────────────────────────────────────────────┐
│ Phase 1: Tree Building + Blob Writing                           │
│                                                                 │
│  Source directory                                               │
│       │                                                         │
│       ▼                                                         │
│  build_tree()  ──── DFS walk ────►  Vec<InodeInfo>              │
│  (inode.rs)         │                    │                      │
│                     │ for each           │                      │
│                     │ regular file:      │                      │
│                     ▼                    │                      │
│              BlobWriter                  │                      │
│              .write_file_chunks()        │                      │
│              (blobchunk.rs)              │                      │
│                     │                    │                      │
│                     ▼                    │                      │
│              Blob device file            │                      │
│              (chunk data)                │                      │
│                                          │                      │
├──────────────────────────────────────────┼──────────────────────┤
│ Phase 2: Metadata Layout                 │                      │
│                                          ▼                      │
│  ┌─ alloc_inode() ───────  assign NID to each inode             │
│  │  (layout.rs)                                                 │
│  │                                                              │
│  ├─ set_parent_nids() ───  wire up ".." references              │
│  │  (main.rs)                                                   │
│  │                                                              │
│  ├─ pad_to_block() ──────  align for directory data             │
│  │  (layout.rs)                                                 │
│  │                                                              │
│  ├─ serialize_directory()  serialize dir entries into blocks     │
│  │  (dir.rs)               alloc_dir_data() for each dir        │
│  │                                                              │
│  └─ serialize_inode() ───  write inode bytes into metadata buf  │
│     (inode.rs)                                                  │
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│ Phase 3: Image Writing                                          │
│                                                                 │
│  write_image()  ──►  Block 0: superblock + device table         │
│  (superblock.rs)     Block 1..N: metadata buffer                │
│                      Padding to block boundary                  │
│                                                                 │
│                 ──►  Final .img file                             │
└─────────────────────────────────────────────────────────────────┘
```

→ source: `main.rs` :: `main()`

### Phase 1 detail: Tree building

`build_tree()` does a DFS walk of the source directory:

1. `symlink_metadata()` (lstat) — get file attributes without following links
2. For directories: sort children by name, recurse into each
3. For regular files: call `BlobWriter::write_file_chunks()` — writes
   deduplicated chunks to the blob and returns chunk index metadata
4. For symlinks: `read_link()` to get the target path
5. For special files: extract `rdev` from stat
6. Hardlink detection: a `HashMap<(dev, ino), usize>` tracks files with
   `nlink > 1`. If a file's `(st_dev, st_ino)` pair was already seen, the
   new directory entry reuses the same `InodeInfo` index — no duplicate inode.

The result is a flat `Vec<InodeInfo>` in DFS pre-order. Index 0 is always the
root directory.

### Phase 2 detail: Parent NID wiring

After NID assignment, `set_parent_nids()` traverses the inode list:

- Root directory's `parent_nid` = its own NID (root's `".."` points to itself)
- For every other directory: `parent_nid` = its parent directory's NID

This information is needed by `serialize_directory()` to generate the `".."`
entry correctly.

### Phase 3 detail: Superblock parameters

`write_image()` computes:
- `meta_blkaddr = 1` (metadata starts at block 1)
- `total_blocks = 1 + metadata_blocks` (block 0 + metadata)
- `feature_incompat = CHUNKED_FILE | DEVICE_TABLE`
- `feature_compat = MTIME`
- UUID: random v4

---

## 10. Design Decisions

### Why is the superblock at offset 1024?

Convention inherited from ext2/ext4. The first 1024 bytes are reserved for
bootloader code or partition table data. EROFS follows this convention so
existing tools and partition layouts work without modification.

### Why 32-byte inode slots?

32 bytes is the size of the compact inode — the most common case. Using this
as the slot alignment means:

- **NID is a simple integer index**: `byte_offset = NID × 32`
- **No wasted space** for compact inodes (1 slot = 1 inode exactly)
- **Larger inodes** (extended: 64 bytes, or chunk-based: 32 + N×8) simply
  consume multiple consecutive slots
- **5-bit shift** (`EROFS_ISLOTBITS = 5`) makes address computation trivial

### Why are chunk indexes 8 bytes?

8 bytes accommodate:
- 48-bit block address (supporting blob devices up to 1 PB at 4K block size)
- 16-bit device ID (up to 65535 devices)

The alternative 4-byte block map entry only supports 32-bit addresses and no
device ID, which is insufficient for multi-device setups.

### Why BLAKE3 for dedup?

| Property | SHA256 | BLAKE3 |
|----------|--------|--------|
| Output size | 256 bits | 256 bits |
| Speed (single core) | ~500 MB/s | ~2 GB/s |
| Collision resistance | 128 bits | 128 bits |

BLAKE3 is 3–4× faster with identical security properties. Since the hash is
used only at build time (never stored on disk), the choice is invisible to the
EROFS format and kernel driver.

### Why sort directory entries?

EROFS directories are read-only. Sorting entries alphabetically at build time
enables **binary search** at runtime, giving O(log n) filename lookup instead
of O(n) linear scan. This is especially important for large directories
(e.g. `node_modules/` with thousands of entries).

### Why separate metadata and data?

The metadata image is typically a few megabytes even for large filesystems
(the Linux kernel tree: ~100K inodes → ~30 MB metadata). A container runtime
can download the metadata image in one shot at startup, then **lazily fetch**
individual data chunks as files are accessed. This is the core of EROFS's
on-demand loading for container use cases.

---

## Appendix: Quick Reference

### Structure sizes

| Structure | Size | Alignment |
|-----------|------|-----------|
| Superblock | 128 bytes | Fixed at offset 1024 |
| Device Slot | 128 bytes | 128-byte boundary |
| Compact Inode | 32 bytes | 32-byte slot |
| Extended Inode | 64 bytes | 32-byte slot (2 slots) |
| Chunk Index | 8 bytes | 8-byte (within inode) |
| Directory Entry | 12 bytes | Within 4096-byte block |
| Block | 4096 bytes | Natural alignment |

### Constants

| Name | Value | Defined in |
|------|-------|-----------|
| `EROFS_SUPER_MAGIC_V1` | `0xE0F5E1E2` | `ondisk.rs` |
| `EROFS_SUPER_OFFSET` | 1024 | `ondisk.rs` |
| `EROFS_BLOCK_SIZE` | 4096 | `ondisk.rs` |
| `EROFS_BLKSZBITS` | 12 | `ondisk.rs` |
| `EROFS_ISLOTBITS` | 5 | `ondisk.rs` |
| `EROFS_SLOTSIZE` | 32 | `ondisk.rs` |
| `EROFS_NULL_ADDR` | `0xFFFFFFFFFFFFFFFF` | `ondisk.rs` |

### File type constants

| Name | Value | Meaning |
|------|-------|---------|
| `EROFS_FT_REG_FILE` | 1 | Regular file |
| `EROFS_FT_DIR` | 2 | Directory |
| `EROFS_FT_CHRDEV` | 3 | Character device |
| `EROFS_FT_BLKDEV` | 4 | Block device |
| `EROFS_FT_FIFO` | 5 | Named pipe |
| `EROFS_FT_SOCK` | 6 | Socket |
| `EROFS_FT_SYMLINK` | 7 | Symbolic link |

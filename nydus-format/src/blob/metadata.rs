use crate::blob::algorithm::{BlobMetadataCompressor, BlobMetadataDigester};
use crate::blob::flag::validate_incompat_flags;
use crate::erofs::EROFS_BLOCK_SIZE;
use crate::error::{Context, Error, Result};
use crate::utils::le::{
    read_u16_at, read_u32_at, read_u64_at, read_u8_at, write_u16_at, write_u32_at, write_u64_at,
    write_u8_at,
};
use bitflags::bitflags;
use crc32c::{crc32c, crc32c_append};
use memmap2::{Mmap, MmapOptions};
use std::fs::File;
use std::io::Write;
use std::mem::{align_of, size_of};
use std::ops::Range;
use std::path::Path;

/// On-disk magic: 8 raw ASCII bytes ("LPBLMETA" = LePton BLob META), written
/// as-is so a hexdump of the file starts with the readable string. Same
/// style and `magic + version + flags` header prefix as the blob footer
/// (`LPFOOTER`) and block_group_map (`LPGRPMAP`) sidecars.
pub const NYDUS_BLOB_METADATA_MAGIC: [u8; 8] = *b"LPBLMETA";

/// On-disk format generation, informational only: readers do not gate on it.
/// Compatibility is governed EROFS-style by the magic and the incompat half
/// of `flags` (unknown incompat bits reject the file).
pub const NYDUS_BLOB_METADATA_VERSION: u32 = 1;

/// The header's fixed on-disk size: one EROFS block, keeping the chunk
/// table behind it block aligned by construction. The unused tail is
/// reserved for future compat fields (writers zero it, readers ignore it,
/// corruption is caught by the file crc32c).
pub const NYDUS_BLOB_METADATA_HEADER_SIZE: usize = EROFS_BLOCK_SIZE as usize;

/// On-disk size of one chunk entry, pinned to [`BlobMetadataChunk`]'s Rust
/// layout by a const assert so mapped tables are readable in place.
pub const NYDUS_BLOB_METADATA_CHUNK_ENTRY_SIZE: usize = 48;

/// On-disk size of one block group entry, pinned to
/// [`BlobMetadataBlockGroup`]'s Rust layout the same way.
pub const NYDUS_BLOB_METADATA_BLOCK_GROUP_ENTRY_SIZE: usize = 40;

/// Default chunk size: 1 MiB of the uncompressed address space per digest.
pub const DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE: u32 = 1024 * 1024;

/// The default chunk size in 4KiB blocks.
pub const DEFAULT_NYDUS_BLOB_METADATA_CHUNK_BLOCK_COUNT: u32 =
    DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE / EROFS_BLOCK_SIZE;

/// Default block group uncompressed size: the unit of compression and of a
/// single backend read, a multiple of the default chunk size so a
/// default-geometry chunk always fits in one block group.
pub const DEFAULT_NYDUS_BLOB_METADATA_BLOCK_GROUP_SIZE: u32 = 4 * 1024 * 1024;

/// The default block group size in 4KiB blocks.
pub const DEFAULT_NYDUS_BLOB_METADATA_BLOCK_GROUP_BLOCK_COUNT: u32 =
    DEFAULT_NYDUS_BLOB_METADATA_BLOCK_GROUP_SIZE / EROFS_BLOCK_SIZE;

/// File-name suffix of a blob meta sidecar file (`<blob>.blob.meta`).
pub const NYDUS_BLOB_METADATA_SUFFIX: &str = ".blob.meta";

/// Largest allowed block-count exponent (`chunk_block_count_bits` /
/// `block_group_block_count_bits`): keeps the derived byte size
/// (`4096 << bits`) within a `u32` (2 GiB at most).
const NYDUS_BLOB_METADATA_MAX_BLOCK_COUNT_BITS: u8 = 19;

/// Byte range of the crc32 field within the header.
const NYDUS_BLOB_METADATA_HEADER_CRC32_FIELD: Range<usize> = 16..20;

/// Chunk entries' reserved field, held to zero: entry-layout evolution is
/// signalled by an incompat flag bit, so writers zero it and readers reject
/// anything else.
const NYDUS_BLOB_METADATA_CHUNK_RESERVED: u32 = 0;

/// Block group entries' reserved tail, held to zero the same way.
const NYDUS_BLOB_METADATA_BLOCK_GROUP_RESERVED: [u8; 6] = [0u8; 6];

bitflags! {
    /// Feature bits, split EROFS-style (see [`crate::blob::flag`]): the low
    /// 16 bits are incompatible features (unknown bits reject the file), the
    /// high 16 bits are compatible features (unknown bits are ignored).
    /// Entry-layout changes take a new incompat bit, header growth uses the
    /// reserved tail plus a compat bit.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct BlobMetadataFlags: u32 {
        const COMPRESSOR_ZSTD = 1 << 0;
        const DIGESTER_BLAKE3 = 1 << 1;
    }
}

/// Every defined flag bit sits in the incompat half, so the full set doubles
/// as the supported-incompat set (unknown incompat bits reject the file).
const NYDUS_BLOB_METADATA_SUPPORTED_INCOMPAT: u32 = BlobMetadataFlags::all().bits();

/// The fixed-size header leading the serialized metadata: the geometry and
/// table map of the file, sealed with a crc32c over the whole file.
///
/// The header's own 4096 bytes (integers little-endian):
///
/// ```text
/// offset  size  field
///      0     8  magic                   b"LPBLMETA"
///      8     4  version                 informational, never gated on
///     12     4  flags                   low 16 incompat / high 16 compat
///     16     4  crc32                   crc32c of the whole serialized
///                                       metadata with this field treated
///                                       as zero
///     20     4  reserved0               future compat field slot
///     24     8  chunks_offset           always 4096: the chunk table
///                                       starts right after the header
///     32     8  block_groups_offset     chunks_offset plus the chunk
///                                       table's bytes
///     40     4  chunk_count
///     44     4  block_group_count
///     48     1  chunk_block_count_bits  log2 of the per-chunk 4KiB
///                                       block count
///     49     1  block_group_block_count_bits
///                                       log2 of the per-block group
///                                       4KiB block count
///     50     6  reserved1               writers zero it, readers ignore it
///     56  4040  reserved                writers zero it, readers ignore it
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlobMetadataHeader {
    magic: [u8; 8],
    version: u32,
    flags: u32,
    crc32: u32,
    reserved0: u32,
    chunks_offset: u64,
    block_groups_offset: u64,
    chunk_count: u32,
    block_group_count: u32,
    chunk_block_count_bits: u8,
    block_group_block_count_bits: u8,
}

impl BlobMetadataHeader {
    /// Parse a header from exactly its `NYDUS_BLOB_METADATA_HEADER_SIZE`
    /// bytes, verifying the intrinsic fields. The crc32 field seals the
    /// whole serialized metadata, so the metadata read paths verify it,
    /// not this parser.
    fn from_bytes(bytes: &[u8; NYDUS_BLOB_METADATA_HEADER_SIZE]) -> Result<Self> {
        let header = Self {
            magic: bytes[0..8].try_into().unwrap(),
            version: read_u32_at(bytes, 8),
            flags: read_u32_at(bytes, 12),
            crc32: read_u32_at(bytes, 16),
            reserved0: read_u32_at(bytes, 20),
            chunks_offset: read_u64_at(bytes, 24),
            block_groups_offset: read_u64_at(bytes, 32),
            chunk_count: read_u32_at(bytes, 40),
            block_group_count: read_u32_at(bytes, 44),
            chunk_block_count_bits: read_u8_at(bytes, 48),
            block_group_block_count_bits: read_u8_at(bytes, 49),
        };

        header.validate()?;
        Ok(header)
    }

    /// Serialize the header into its on-disk bytes. The reserved regions
    /// are zeroed, so this is only the writer's view: raw bytes read from
    /// disk may carry newer compat fields there that this type does not
    /// model.
    fn to_bytes(self) -> [u8; NYDUS_BLOB_METADATA_HEADER_SIZE] {
        let mut data = [0u8; NYDUS_BLOB_METADATA_HEADER_SIZE];
        data[0..8].copy_from_slice(&self.magic);
        write_u32_at(&mut data, 8, self.version);
        write_u32_at(&mut data, 12, self.flags);
        write_u32_at(&mut data, 16, self.crc32);
        write_u32_at(&mut data, 20, self.reserved0);
        write_u64_at(&mut data, 24, self.chunks_offset);
        write_u64_at(&mut data, 32, self.block_groups_offset);
        write_u32_at(&mut data, 40, self.chunk_count);
        write_u32_at(&mut data, 44, self.block_group_count);
        write_u8_at(&mut data, 48, self.chunk_block_count_bits);
        write_u8_at(&mut data, 49, self.block_group_block_count_bits);
        data
    }

    /// Validate the intrinsic field invariants, needing nothing beyond the
    /// fields themselves. Run once per entry point: by [`Self::from_bytes`]
    /// on the read side and by [`BlobMetadata::new`] on the write side.
    ///
    /// Deliberately not checked: `version` is informational (compatibility
    /// is governed by the magic and the incompat flag bits), `reserved0` and
    /// the reserved tail may carry a newer writer's compat fields (corruption
    /// is caught by the crc32), and the entry counts are anchored against
    /// the actual table bytes by [`BlobMetadata::validate_bytes`].
    fn validate(&self) -> Result<()> {
        if self.magic != NYDUS_BLOB_METADATA_MAGIC {
            return Err(Error::InvalidImage("invalid blob meta magic".to_string()));
        }

        if self.chunk_block_count_bits > NYDUS_BLOB_METADATA_MAX_BLOCK_COUNT_BITS {
            return Err(Error::InvalidImage(format!(
                "blob meta chunk block count bits too large: {}",
                self.chunk_block_count_bits
            )));
        }

        if self.block_group_block_count_bits > NYDUS_BLOB_METADATA_MAX_BLOCK_COUNT_BITS {
            return Err(Error::InvalidImage(format!(
                "blob meta block group block count bits too large: {}",
                self.block_group_block_count_bits
            )));
        }

        if self.chunks_offset != NYDUS_BLOB_METADATA_HEADER_SIZE as u64 {
            return Err(Error::InvalidImage(format!(
                "invalid blob meta chunks offset: {}",
                self.chunks_offset
            )));
        }

        let expected_block_groups_offset = self
            .chunks_offset
            .checked_add(self.chunk_table_size())
            .ok_or_else(|| Error::Overflow("blob meta block group offset overflow".to_string()))?;

        if self.block_groups_offset != expected_block_groups_offset {
            return Err(Error::InvalidImage(format!(
                "invalid blob meta block groups offset: {}",
                self.block_groups_offset
            )));
        }

        if self.chunks_offset % align_of::<BlobMetadataChunk>() as u64 != 0 {
            return Err(Error::InvalidImage(
                "blob meta chunks offset is not aligned".to_string(),
            ));
        }

        if self.block_groups_offset % align_of::<BlobMetadataBlockGroup>() as u64 != 0 {
            return Err(Error::InvalidImage(
                "blob meta block groups offset is not aligned".to_string(),
            ));
        }

        let flags = BlobMetadataFlags::from_bits_truncate(self.flags);
        BlobMetadataDigester::try_from(flags)?;
        validate_incompat_flags(self.flags, NYDUS_BLOB_METADATA_SUPPORTED_INCOMPAT)?;
        Ok(())
    }

    /// On-disk format generation, informational only: readers never gate
    /// on it.
    pub fn version(&self) -> u32 {
        self.version
    }

    /// The known feature bits as a typed view. Unknown compat bits are
    /// dropped here (unknown incompat bits were already rejected at
    /// validation).
    pub fn flags(&self) -> BlobMetadataFlags {
        BlobMetadataFlags::from_bits_truncate(self.flags)
    }

    /// crc32c sealing the whole serialized metadata, exactly as stored on
    /// disk.
    pub fn crc32(&self) -> u32 {
        self.crc32
    }

    /// The block group payload compressor, per the flags.
    pub fn compressor(&self) -> BlobMetadataCompressor {
        BlobMetadataCompressor::from(self.flags())
    }

    /// The chunk digest algorithm, per the flags (vetted at validation, so
    /// the conversion cannot fail).
    pub fn digester(&self) -> BlobMetadataDigester {
        BlobMetadataDigester::try_from(self.flags()).unwrap()
    }

    /// Number of entries in the chunk table.
    pub fn chunk_count(&self) -> u32 {
        self.chunk_count
    }

    /// Uncompressed 4KiB blocks per chunk (`1 << chunk_block_count_bits`).
    pub fn chunk_block_count(&self) -> u32 {
        1u32 << self.chunk_block_count_bits
    }

    /// Uncompressed bytes per chunk.
    pub fn chunk_size(&self) -> u32 {
        EROFS_BLOCK_SIZE << self.chunk_block_count_bits
    }

    /// Byte offset of the chunk table, always right after the header.
    pub fn chunks_offset(&self) -> u64 {
        self.chunks_offset
    }

    /// Byte size of the chunk table.
    pub fn chunk_table_size(&self) -> u64 {
        self.chunk_count as u64 * size_of::<BlobMetadataChunk>() as u64
    }

    /// Number of entries in the block group table.
    pub fn block_group_count(&self) -> u32 {
        self.block_group_count
    }

    /// Uncompressed 4KiB blocks per block group
    /// (`1 << block_group_block_count_bits`).
    pub fn block_group_block_count(&self) -> u32 {
        1u32 << self.block_group_block_count_bits
    }

    /// Byte offset of the block group table, right after the chunk table.
    pub fn block_groups_offset(&self) -> u64 {
        self.block_groups_offset
    }

    /// Byte size of the block group table.
    pub fn block_group_table_size(&self) -> u64 {
        self.block_group_count as u64 * size_of::<BlobMetadataBlockGroup>() as u64
    }

    /// Bytes the header and the tables actually use, before the tail
    /// padding.
    pub fn used_size(&self) -> u64 {
        self.block_groups_offset + self.block_group_table_size()
    }

    /// The full serialized size: [`Self::used_size`] aligned up to one
    /// 4KiB block.
    pub fn padded_size(&self) -> u64 {
        crate::utils::align_up_u64(self.used_size(), EROFS_BLOCK_SIZE as u64)
            .expect("blob meta size overflowed")
    }
}

/// One chunk entry: the digest of a fixed-size span of the blob's dense
/// uncompressed address space. Chunk entries are packed back to back in the
/// chunk table right after the header.
///
/// The entry's 48 bytes (integers little-endian):
///
/// ```text
/// offset  size  field
///      0    32  digest                     of the chunk's uncompressed
///                                          bytes, algorithm per the
///                                          digester flag
///     32     8  uncompressed_block_offset  4KiB blocks
///     40     4  uncompressed_block_count   4KiB blocks, never zero
///     44     4  reserved                   must be zero
/// ```
///
/// The Rust layout is pinned to the on-disk layout (`repr(C)` plus the const
/// size assert) so a mapped chunk table is readable in place, zero-copy.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlobMetadataChunk {
    digest: [u8; 32],
    uncompressed_block_offset: u64,
    uncompressed_block_count: u32,
    reserved: u32,
}

// Pins the Rust layout to the on-disk entry size: a drift would break the
// in-place mapped tables, so it fails the build instead.
const _: () = assert!(size_of::<BlobMetadataChunk>() == NYDUS_BLOB_METADATA_CHUNK_ENTRY_SIZE);

impl BlobMetadataChunk {
    /// Creates a validated chunk entry, so a constructed chunk is valid by
    /// definition.
    pub fn new(
        digest: [u8; 32],
        uncompressed_block_offset: u64,
        uncompressed_block_count: u32,
    ) -> Result<Self> {
        let chunk = Self {
            digest,
            uncompressed_block_offset,
            uncompressed_block_count,
            reserved: NYDUS_BLOB_METADATA_CHUNK_RESERVED,
        };

        chunk.validate()?;
        Ok(chunk)
    }

    /// Parse a chunk entry from exactly its 48 bytes, verifying the
    /// intrinsic fields.
    pub fn from_bytes(bytes: &[u8; NYDUS_BLOB_METADATA_CHUNK_ENTRY_SIZE]) -> Result<Self> {
        let chunk = Self {
            digest: bytes[0..32].try_into().unwrap(),
            uncompressed_block_offset: read_u64_at(bytes, 32),
            uncompressed_block_count: read_u32_at(bytes, 40),
            reserved: read_u32_at(bytes, 44),
        };

        chunk.validate()?;
        Ok(chunk)
    }

    /// Serialize the chunk entry into its on-disk bytes.
    fn to_bytes(self) -> [u8; NYDUS_BLOB_METADATA_CHUNK_ENTRY_SIZE] {
        let mut data = [0u8; NYDUS_BLOB_METADATA_CHUNK_ENTRY_SIZE];
        data[0..32].copy_from_slice(&self.digest);
        write_u64_at(&mut data, 32, self.uncompressed_block_offset);
        write_u32_at(&mut data, 40, self.uncompressed_block_count);
        write_u32_at(&mut data, 44, self.reserved);
        data
    }

    /// Validate the intrinsic field invariants. Run by every construction
    /// path ([`Self::new`], [`Self::from_bytes`]), so a chunk in hand is
    /// always valid. Mapped tables are validated entry by entry at load.
    fn validate(&self) -> Result<()> {
        if self.uncompressed_block_count == 0 {
            return Err(Error::InvalidImage(
                "blob meta chunk uncompressed block count must be non-zero".to_string(),
            ));
        }

        if self.reserved != NYDUS_BLOB_METADATA_CHUNK_RESERVED {
            return Err(Error::InvalidImage(
                "blob meta chunk reserved field must be zero".to_string(),
            ));
        }

        self.uncompressed_block_offset
            .checked_mul(EROFS_BLOCK_SIZE as u64)
            .ok_or_else(|| {
                Error::Overflow("blob meta chunk uncompressed byte offset overflow".to_string())
            })?;

        self.uncompressed_offset()
            .checked_add(self.uncompressed_size())
            .ok_or_else(|| Error::Overflow("blob meta chunk byte range overflow".to_string()))?;

        Ok(())
    }

    /// Write the chunk entry's on-disk bytes to `writer`.
    pub fn write_to(&self, writer: &mut dyn Write) -> Result<()> {
        writer.write_all(&self.to_bytes())?;
        Ok(())
    }

    /// Digest of the chunk's uncompressed bytes, algorithm per the header's
    /// digester flag.
    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    /// Start of the chunk's span, in 4KiB blocks of the uncompressed
    /// address space.
    pub fn uncompressed_block_offset(&self) -> u64 {
        self.uncompressed_block_offset
    }

    /// Length of the chunk's span in 4KiB blocks, never zero.
    pub fn uncompressed_block_count(&self) -> u32 {
        self.uncompressed_block_count
    }

    /// Start of the chunk's span in bytes (validation vetted the
    /// conversion, so it cannot overflow).
    pub fn uncompressed_offset(&self) -> u64 {
        self.uncompressed_block_offset
            .checked_mul(EROFS_BLOCK_SIZE as u64)
            .expect("validated blob meta chunk byte offset")
    }

    /// Length of the chunk's span in bytes.
    pub fn uncompressed_size(&self) -> u64 {
        self.uncompressed_block_count as u64 * EROFS_BLOCK_SIZE as u64
    }
}

/// One block group entry: how a span of the dense uncompressed address
/// space maps onto the blob's encoded payload — the unit of decode, cache
/// fill, and prefetch. Block group entries are packed back to back in the
/// block group table right after the chunk table.
///
/// The two coordinate spaces the entry bridges:
///
/// ```text
/// uncompressed address space: dense 4KiB blocks from 0, uniform span
/// ┌───────────┬───────────┬──────┐
/// │  group 0  │  group 1  │ gr 2 │        (final group may be short)
/// └─────┬─────┴─────┬─────┴───┬──┘
///       ▼           ▼         ▼           each group encoded on its own
/// ┌─────────┬──┬──────┐
/// │   p0    │p1│  p2  │                   compressed payloads: packed in
/// └─────────┴──┴──────┘                   order, gaps allowed, byte-exact
/// ```
///
/// The entry's 40 bytes (integers little-endian):
///
/// ```text
/// offset  size  field
///      0     8  uncompressed_block_offset  4KiB blocks
///      8     8  compressed_offset          bytes: payloads pack back to
///                                          back, no block alignment
///     16     4  uncompressed_block_count   4KiB blocks, never zero
///     20     4  compressed_size            bytes, never zero
///     24     4  crc32                      crc32c of the uncompressed
///                                          payload
///     28     4  source_block_group_index   redirect only, else zero
///     32     2  source_blob_index          non-zero marks a redirect
///                                          (see [`Self::new_redirect`])
///     34     6  reserved                   must be zero
/// ```
///
/// The Rust layout is pinned to the on-disk layout (`repr(C)` plus the const
/// size assert) so a mapped block group table is readable in place,
/// zero-copy.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlobMetadataBlockGroup {
    uncompressed_block_offset: u64,
    compressed_offset: u64,
    uncompressed_block_count: u32,
    compressed_size: u32,
    crc32: u32,
    source_block_group_index: u32,
    source_blob_index: u16,
    reserved: [u8; 6],
}

// The same layout pin for block group entries.
const _: () =
    assert!(size_of::<BlobMetadataBlockGroup>() == NYDUS_BLOB_METADATA_BLOCK_GROUP_ENTRY_SIZE);

impl BlobMetadataBlockGroup {
    /// Creates a validated entry for a payload stored in this blob itself.
    pub fn new(
        uncompressed_block_offset: u64,
        uncompressed_block_count: u32,
        compressed_offset: u64,
        compressed_size: u32,
        crc32: u32,
    ) -> Result<Self> {
        let block_group = Self {
            uncompressed_block_offset,
            compressed_offset,
            uncompressed_block_count,
            compressed_size,
            crc32,
            source_block_group_index: 0,
            source_blob_index: 0,
            reserved: NYDUS_BLOB_METADATA_BLOCK_GROUP_RESERVED,
        };

        block_group.validate()?;
        Ok(block_group)
    }

    /// Creates a validated redirect entry: the payload lives in a block
    /// group of another source blob, and the non-zero `source_blob_index`
    /// is what marks the entry as a redirect.
    #[allow(clippy::too_many_arguments)]
    pub fn new_redirect(
        uncompressed_block_offset: u64,
        uncompressed_block_count: u32,
        compressed_offset: u64,
        compressed_size: u32,
        crc32: u32,
        source_blob_index: u16,
        source_block_group_index: u32,
    ) -> Result<Self> {
        let block_group = Self {
            uncompressed_block_offset,
            compressed_offset,
            uncompressed_block_count,
            compressed_size,
            crc32,
            source_block_group_index,
            source_blob_index,
            reserved: NYDUS_BLOB_METADATA_BLOCK_GROUP_RESERVED,
        };

        block_group.validate_redirect()?;
        Ok(block_group)
    }

    /// Parse a block group entry from exactly its 40 bytes, verifying the
    /// intrinsic fields.
    pub fn from_bytes(bytes: &[u8; NYDUS_BLOB_METADATA_BLOCK_GROUP_ENTRY_SIZE]) -> Result<Self> {
        let block_group = Self {
            uncompressed_block_offset: read_u64_at(bytes, 0),
            compressed_offset: read_u64_at(bytes, 8),
            uncompressed_block_count: read_u32_at(bytes, 16),
            compressed_size: read_u32_at(bytes, 20),
            crc32: read_u32_at(bytes, 24),
            source_block_group_index: read_u32_at(bytes, 28),
            source_blob_index: read_u16_at(bytes, 32),
            reserved: bytes[34..40].try_into().unwrap(),
        };

        block_group.validate()?;
        Ok(block_group)
    }

    /// Serialize the block group entry into its on-disk bytes.
    fn to_bytes(self) -> [u8; NYDUS_BLOB_METADATA_BLOCK_GROUP_ENTRY_SIZE] {
        let mut data = [0u8; NYDUS_BLOB_METADATA_BLOCK_GROUP_ENTRY_SIZE];
        write_u64_at(&mut data, 0, self.uncompressed_block_offset);
        write_u64_at(&mut data, 8, self.compressed_offset);
        write_u32_at(&mut data, 16, self.uncompressed_block_count);
        write_u32_at(&mut data, 20, self.compressed_size);
        write_u32_at(&mut data, 24, self.crc32);
        write_u32_at(&mut data, 28, self.source_block_group_index);
        write_u16_at(&mut data, 32, self.source_blob_index);
        data[34..40].copy_from_slice(&self.reserved);
        data
    }

    /// Validate the intrinsic field invariants. Run by every construction
    /// path, so a block group in hand is always valid. Cross-entry rules
    /// (density, ordering) live in [`BlobMetadata::validate_block_groups`].
    fn validate(&self) -> Result<()> {
        if self.uncompressed_block_count == 0 {
            return Err(Error::InvalidImage(
                "blob meta block group uncompressed block count must be non-zero".to_string(),
            ));
        }

        if self.compressed_size == 0 {
            return Err(Error::InvalidImage(
                "blob meta block group compressed size must be non-zero".to_string(),
            ));
        }

        if self.source_blob_index == 0 && self.source_block_group_index != 0 {
            return Err(Error::InvalidImage(
                "blob meta block group source block group index requires a source blob index"
                    .to_string(),
            ));
        }

        if self.reserved != NYDUS_BLOB_METADATA_BLOCK_GROUP_RESERVED {
            return Err(Error::InvalidImage(
                "blob meta block group reserved field must be zero".to_string(),
            ));
        }

        self.uncompressed_block_offset
            .checked_mul(EROFS_BLOCK_SIZE as u64)
            .ok_or_else(|| {
                Error::Overflow(
                    "blob meta block group uncompressed byte offset overflow".to_string(),
                )
            })?;

        self.uncompressed_offset()
            .checked_add(self.uncompressed_size())
            .ok_or_else(|| {
                Error::Overflow(
                    "blob meta block group uncompressed byte range overflow".to_string(),
                )
            })?;

        self.compressed_offset
            .checked_add(self.compressed_size as u64)
            .ok_or_else(|| {
                Error::Overflow("blob meta block group compressed byte range overflow".to_string())
            })?;

        Ok(())
    }

    /// The redirect variant of [`Self::validate`]: additionally requires
    /// the non-zero `source_blob_index` that marks a redirect.
    fn validate_redirect(&self) -> Result<()> {
        if self.source_blob_index == 0 {
            return Err(Error::InvalidImage(
                "blob meta redirect block group source blob index must be non-zero".to_string(),
            ));
        }

        if self.uncompressed_block_count == 0 {
            return Err(Error::InvalidImage(
                "blob meta block group uncompressed block count must be non-zero".to_string(),
            ));
        }

        if self.compressed_size == 0 {
            return Err(Error::InvalidImage(
                "blob meta block group compressed size must be non-zero".to_string(),
            ));
        }

        if self.reserved != NYDUS_BLOB_METADATA_BLOCK_GROUP_RESERVED {
            return Err(Error::InvalidImage(
                "blob meta block group reserved field must be zero".to_string(),
            ));
        }

        self.uncompressed_block_offset
            .checked_mul(EROFS_BLOCK_SIZE as u64)
            .ok_or_else(|| {
                Error::Overflow(
                    "blob meta block group uncompressed byte offset overflow".to_string(),
                )
            })?;

        self.uncompressed_offset()
            .checked_add(self.uncompressed_size())
            .ok_or_else(|| {
                Error::Overflow(
                    "blob meta block group uncompressed byte range overflow".to_string(),
                )
            })?;

        self.compressed_offset
            .checked_add(self.compressed_size as u64)
            .ok_or_else(|| {
                Error::Overflow("blob meta block group compressed byte range overflow".to_string())
            })?;

        Ok(())
    }

    /// Write the block group entry's on-disk bytes to `writer`.
    pub fn write_to(&self, writer: &mut dyn Write) -> Result<()> {
        writer.write_all(&self.to_bytes())?;
        Ok(())
    }

    /// A copy with the compressed offset shifted by `bias`, for payloads
    /// embedded at an offset inside a full blob.
    pub fn checked_add_compressed_offset(&self, bias: u64) -> Result<Self> {
        let block_group = Self {
            compressed_offset: self.compressed_offset().checked_add(bias).ok_or_else(|| {
                Error::Overflow("blob meta compressed byte offset overflow".to_string())
            })?,
            ..*self
        };

        block_group.validate()?;
        Ok(block_group)
    }

    /// Whether the payload lives in another source blob.
    pub fn is_redirect(&self) -> bool {
        self.source_blob_index != 0
    }

    /// The source blob holding the payload, zero when the payload is local.
    pub fn source_blob_index(&self) -> u16 {
        self.source_blob_index
    }

    /// The block group within the source blob, redirect only.
    pub fn source_block_group_index(&self) -> u32 {
        self.source_block_group_index
    }

    /// Start of the group's span, in 4KiB blocks of the uncompressed
    /// address space.
    pub fn uncompressed_block_offset(&self) -> u64 {
        self.uncompressed_block_offset
    }

    /// Length of the group's span in 4KiB blocks, never zero.
    pub fn uncompressed_block_count(&self) -> u32 {
        self.uncompressed_block_count
    }

    /// Start of the group's span in bytes (validation vetted the
    /// conversion, so it cannot overflow).
    pub fn uncompressed_offset(&self) -> u64 {
        self.uncompressed_block_offset
            .checked_mul(EROFS_BLOCK_SIZE as u64)
            .expect("validated blob meta block group byte offset")
    }

    /// Length of the group's span in bytes.
    pub fn uncompressed_size(&self) -> u64 {
        self.uncompressed_block_count as u64 * EROFS_BLOCK_SIZE as u64
    }

    /// Byte offset of the encoded payload (payloads pack back to back, no
    /// block alignment).
    pub fn compressed_offset(&self) -> u64 {
        self.compressed_offset
    }

    /// Byte size of the encoded payload, never zero.
    pub fn compressed_size(&self) -> u32 {
        self.compressed_size
    }

    /// crc32c of the group's uncompressed payload, checked after decode.
    pub fn crc32(&self) -> u32 {
        self.crc32
    }

    /// True when any block group redirects to another source blob.
    fn has_redirect(block_groups: &[Self]) -> bool {
        block_groups.iter().any(Self::is_redirect)
    }

    /// Derive the header's `block_group_block_count_bits` from the groups
    /// themselves: the first group carries the uniform span (validated
    /// later), a lone group rounds up to a power of two, and empty or
    /// redirect tables fall back to the default geometry.
    fn infer_block_count_bits(block_groups: &[Self]) -> Result<u8> {
        let default_bits = DEFAULT_NYDUS_BLOB_METADATA_BLOCK_GROUP_BLOCK_COUNT.ilog2() as u8;
        if Self::has_redirect(block_groups) {
            return Ok(default_bits);
        }

        match block_groups {
            [] => Ok(default_bits),
            [only] => block_count_to_bits(only.uncompressed_block_count().next_power_of_two()),
            [first, ..] => block_count_to_bits(first.uncompressed_block_count()),
        }
    }
}

/// In-memory backing of the tables: owned vectors on the write side, a
/// shared file mapping read in place on the read side.
#[derive(Debug)]
enum BlobMetadataStorage {
    Owned {
        chunks: Vec<BlobMetadataChunk>,
        block_groups: Vec<BlobMetadataBlockGroup>,
    },
    Mapped(Mmap),
}

/// A nydus blob's metadata: the chunk digest table and the block group table
/// describing how the blob's dense uncompressed address space maps onto its
/// encoded payload, sealed with a crc32c in the header.
///
/// Serialized, it is the `.blob.meta` sidecar file — and, embedded verbatim,
/// the blob meta region of a full blob (see [`super::footer::BlobFooter`]):
///
/// ```text
/// ┌────────┬─────────────┬───────────────────┬──────────────┐
/// │ header │ chunk table │ block group table │ zero padding │
/// └────────┴─────────────┴───────────────────┴──────────────┘
/// 0        4096                              ▲              EOF
///                            the entries end here, the padding
///                            runs to the 4KiB-aligned padded_size
/// ```
///
/// In memory the tables are either owned (the write side, built by
/// [`Self::new`]) or a shared file mapping read in place
/// ([`Self::from_path`]), zero-copy thanks to the entries' pinned layout.
#[derive(Debug)]
pub struct BlobMetadata {
    header: BlobMetadataHeader,
    storage: BlobMetadataStorage,
}

impl BlobMetadata {
    /// Creates validated, sealed metadata from owned tables: the header is
    /// derived from the tables and both are validated first, so constructed
    /// metadata is valid by definition, then the crc32 is computed over the
    /// final bytes.
    pub fn new(
        compressor: BlobMetadataCompressor,
        chunk_block_count: u32,
        chunks: Vec<BlobMetadataChunk>,
        block_groups: Vec<BlobMetadataBlockGroup>,
    ) -> Result<Self> {
        let chunks_offset = NYDUS_BLOB_METADATA_HEADER_SIZE as u64;
        let header = BlobMetadataHeader {
            magic: NYDUS_BLOB_METADATA_MAGIC,
            version: NYDUS_BLOB_METADATA_VERSION,
            flags: (BlobMetadataDigester::Blake3.flag() | compressor.flag()).bits(),
            crc32: 0,
            reserved0: 0,
            chunks_offset,
            block_groups_offset: chunks_offset
                .checked_add(chunks.len() as u64 * size_of::<BlobMetadataChunk>() as u64)
                .ok_or_else(|| {
                    Error::Overflow("blob meta block group offset overflow".to_string())
                })?,
            chunk_count: chunks.len() as u32,
            block_group_count: block_groups.len() as u32,
            chunk_block_count_bits: block_count_to_bits(chunk_block_count)?,
            block_group_block_count_bits: BlobMetadataBlockGroup::infer_block_count_bits(
                &block_groups,
            )?,
        };
        header.validate()?;

        let mut blob_metadata = Self {
            header,
            storage: BlobMetadataStorage::Owned {
                chunks,
                block_groups,
            },
        };
        blob_metadata.validate()?;
        blob_metadata.header.crc32 = blob_metadata.compute_crc32_from_parts();
        Ok(blob_metadata)
    }

    /// Read blob metadata from an in-memory byte slice, optionally verifying
    /// the header crc32 over the full metadata.
    pub fn from_bytes(bytes: &[u8], verify_crc32: bool) -> Result<Self> {
        let Some((header_bytes, _)) = bytes.split_first_chunk::<NYDUS_BLOB_METADATA_HEADER_SIZE>()
        else {
            return Err(Error::InvalidImage("blob meta data too small".to_string()));
        };

        let header = BlobMetadataHeader::from_bytes(header_bytes)?;
        Self::validate_bytes(bytes, &header, verify_crc32)?;

        let chunk_table =
            &bytes[header.chunks_offset() as usize..header.block_groups_offset() as usize];
        let chunks = chunk_table
            .chunks_exact(size_of::<BlobMetadataChunk>())
            .enumerate()
            .map(|(index, entry)| {
                BlobMetadataChunk::from_bytes(entry.try_into().unwrap())
                    .with_context(|| format!("failed to read blob meta chunk {index}"))
            })
            .collect::<Result<Vec<_>>>()?;

        let block_group_table =
            &bytes[header.block_groups_offset() as usize..header.used_size() as usize];
        let block_groups = block_group_table
            .chunks_exact(size_of::<BlobMetadataBlockGroup>())
            .enumerate()
            .map(|(index, entry)| {
                BlobMetadataBlockGroup::from_bytes(entry.try_into().unwrap())
                    .with_context(|| format!("failed to read blob meta block group {index}"))
            })
            .collect::<Result<Vec<_>>>()?;

        let blob_metadata = Self {
            header,
            storage: BlobMetadataStorage::Owned {
                chunks,
                block_groups,
            },
        };
        blob_metadata.validate()?;
        Ok(blob_metadata)
    }

    /// Read blob metadata from a file (mmap-backed), optionally verifying
    /// the header crc32 over the full metadata.
    pub fn from_path(path: &Path, verify_crc32: bool) -> Result<Self> {
        let file = File::open(path)
            .with_context(|| format!("failed to open blob meta: {}", path.display()))?;
        let mmap = unsafe { MmapOptions::new().map(&file) }
            .with_context(|| format!("failed to mmap blob meta: {}", path.display()))?;

        let Some((header_bytes, _)) = mmap.split_first_chunk::<NYDUS_BLOB_METADATA_HEADER_SIZE>()
        else {
            return Err(Error::InvalidImage("blob meta file too small".to_string()));
        };

        let header = BlobMetadataHeader::from_bytes(header_bytes)?;
        Self::validate_bytes(&mmap, &header, verify_crc32)?;

        let blob_metadata = Self {
            header,
            storage: BlobMetadataStorage::Mapped(mmap),
        };
        blob_metadata.validate()?;
        Ok(blob_metadata)
    }

    /// Validate the cross-entry table invariants. Run by every construction
    /// path, so metadata in hand is always valid.
    fn validate(&self) -> Result<()> {
        self.validate_chunks()?;
        self.validate_block_groups()
    }

    /// Every chunk must be intrinsically valid and end within the blocks
    /// the block groups cover. Runs before the density checks, so the bound
    /// is just the last group's end, not yet a total.
    fn validate_chunks(&self) -> Result<()> {
        let uncompressed_block_end = self
            .block_groups()
            .last()
            .map(|block_group| {
                block_group.uncompressed_block_offset()
                    + block_group.uncompressed_block_count() as u64
            })
            .unwrap_or(0);

        for (index, chunk) in self.chunks().iter().enumerate() {
            chunk
                .validate()
                .with_context(|| format!("invalid blob meta chunk {index}"))?;

            let chunk_block_end = chunk
                .uncompressed_block_offset()
                .checked_add(chunk.uncompressed_block_count() as u64)
                .ok_or_else(|| {
                    Error::Overflow(format!("blob meta chunk {index} block range overflow"))
                })?;

            if chunk_block_end > uncompressed_block_end {
                return Err(Error::InvalidImage(format!(
                    "blob meta chunk {index} exceeds the blob block range: \
                     ends at block {chunk_block_end}, blob ends at block {uncompressed_block_end}"
                )));
            }
        }

        Ok(())
    }

    /// The block groups must tile the uncompressed address space densely
    /// from block 0 (making the last group's end the blob's total size),
    /// keep the uniform span the header declares (the final group may be
    /// short, redirect blobs are exempt), and keep their compressed ranges
    /// ordered and non-overlapping (gaps allowed).
    fn validate_block_groups(&self) -> Result<()> {
        let block_groups = self.block_groups();
        let block_group_block_count = self.header.block_group_block_count();
        if block_group_block_count == 0 {
            return Err(Error::InvalidImage(
                "blob meta block group block count must be non-zero".to_string(),
            ));
        }

        let is_redirect = BlobMetadataBlockGroup::has_redirect(block_groups);
        let mut next_uncompressed_block_offset = 0u64;
        let mut next_compressed_offset = 0u64;
        for (index, block_group) in block_groups.iter().enumerate() {
            block_group
                .validate()
                .with_context(|| format!("invalid blob meta block group {index}"))?;
            if block_group.uncompressed_block_offset() != next_uncompressed_block_offset {
                return Err(Error::InvalidImage(format!(
                    "blob meta block groups must be dense: block group {index} starts at block {}, \
                     expected block {next_uncompressed_block_offset}",
                    block_group.uncompressed_block_offset()
                )));
            }

            if !is_redirect {
                match (
                    index + 1 == block_groups.len(),
                    block_group.uncompressed_block_count(),
                ) {
                    (false, block_count) if block_count != block_group_block_count => {
                        return Err(Error::InvalidImage(format!(
                            "blob meta block group {index} must be exactly \
                             {block_group_block_count} blocks, got {block_count}"
                        )));
                    }
                    (true, block_count) if block_count > block_group_block_count => {
                        return Err(Error::InvalidImage(format!(
                            "blob meta final block group {index} exceeds \
                             {block_group_block_count} blocks, got {block_count}"
                        )));
                    }
                    _ => {}
                }
            }

            if block_group.compressed_offset() < next_compressed_offset {
                return Err(Error::InvalidImage(format!(
                    "blob meta block group {index} overlaps the previous compressed range: \
                     starts at byte {}, previous ends at byte {next_compressed_offset}",
                    block_group.compressed_offset()
                )));
            }

            next_uncompressed_block_offset = block_group
                .uncompressed_block_offset()
                .checked_add(block_group.uncompressed_block_count() as u64)
                .ok_or_else(|| {
                    Error::Overflow(format!(
                        "blob meta block group {index} uncompressed block range overflow"
                    ))
                })?;

            next_compressed_offset = block_group
                .compressed_offset()
                .checked_add(block_group.compressed_size() as u64)
                .ok_or_else(|| {
                    Error::Overflow(format!(
                        "blob meta block group {index} compressed range overflow"
                    ))
                })?;
        }

        Ok(())
    }

    /// Anchor a serialized buffer against its header: the buffer must be
    /// exactly the declared padded size with a zeroed tail padding, and
    /// with `verify_crc32` the stored seal must match the raw incoming
    /// bytes — never a re-serialization, which would zero a newer writer's
    /// compat fields and reject a valid image.
    fn validate_bytes(bytes: &[u8], header: &BlobMetadataHeader, verify_crc32: bool) -> Result<()> {
        if bytes.len() as u64 != header.padded_size() {
            return Err(Error::InvalidImage(format!(
                "blob meta size mismatch: expected {}, got {}",
                header.padded_size(),
                bytes.len()
            )));
        }

        let padding = &bytes[header.used_size() as usize..];
        if padding.iter().any(|byte| *byte != 0) {
            return Err(Error::InvalidImage(
                "blob meta padding must be zero".to_string(),
            ));
        }

        if verify_crc32 {
            let expected_crc32 = header.crc32();
            let actual_crc32 = Self::compute_crc32(bytes);
            if expected_crc32 != actual_crc32 {
                return Err(Error::InvalidImage(format!(
                    "blob meta crc32 mismatch: expected {expected_crc32:#010x}, \
                     got {actual_crc32:#010x}"
                )));
            }
        }

        Ok(())
    }

    /// Rebuilt metadata with every compressed offset shifted by `bias`, for
    /// compressed data embedded at `bias` inside a full blob (resealed via
    /// [`Self::new`]).
    pub fn checked_add_compressed_offset(&self, bias: u64) -> Result<Self> {
        let mut block_groups = Vec::with_capacity(self.block_group_count());
        for block_group in self.block_groups() {
            block_groups.push(block_group.checked_add_compressed_offset(bias)?);
        }

        Self::new(
            self.compressor(),
            self.chunk_block_count(),
            self.chunks().to_vec(),
            block_groups,
        )
    }

    /// Write the serialized metadata (header, tables, zero padding) to
    /// `writer`, resealing the crc32 over the emitted bytes: metadata
    /// mapped from a newer writer re-serializes with the reserved compat
    /// fields zeroed, so the stored seal may not match what is written.
    pub fn write_to(&self, writer: &mut dyn Write) -> Result<()> {
        let mut header = self.header;
        header.crc32 = self.compute_crc32_from_parts();

        writer.write_all(&header.to_bytes())?;
        for chunk in self.chunks() {
            chunk.write_to(writer)?;
        }

        for block_group in self.block_groups() {
            block_group.write_to(writer)?;
        }

        let padding_size = (self.padded_size() - self.header.used_size()) as usize;
        writer.write_all(&[0u8; EROFS_BLOCK_SIZE as usize][..padding_size])?;
        Ok(())
    }

    /// Write the serialized metadata to a new sidecar file at `path`.
    pub fn save(&self, path: &Path) -> Result<()> {
        let mut file = File::create(path)
            .with_context(|| format!("failed to create blob meta: {}", path.display()))?;
        self.write_to(&mut file)?;
        file.flush()
            .with_context(|| format!("failed to flush blob meta: {}", path.display()))?;

        Ok(())
    }

    /// The parsed header, exactly as stored on disk.
    pub fn header(&self) -> &BlobMetadataHeader {
        &self.header
    }

    /// Number of entries in the chunk table.
    pub fn chunk_count(&self) -> usize {
        self.header.chunk_count() as usize
    }

    /// Number of entries in the block group table.
    pub fn block_group_count(&self) -> usize {
        self.header.block_group_count() as usize
    }

    /// Uncompressed 4KiB blocks per chunk.
    pub fn chunk_block_count(&self) -> u32 {
        self.header.chunk_block_count()
    }

    /// Uncompressed bytes per chunk.
    pub fn chunk_size(&self) -> u32 {
        self.header.chunk_size()
    }

    /// The block group payload compressor.
    pub fn compressor(&self) -> BlobMetadataCompressor {
        self.header.compressor()
    }

    /// The chunk digest algorithm.
    pub fn digester(&self) -> BlobMetadataDigester {
        self.header.digester()
    }

    /// The chunk table: the owned vector on the write side, the mapped file
    /// region reinterpreted in place on the read side (sound because the
    /// entry layout is pinned and the load path validated the table's
    /// offset, alignment, and bounds).
    pub fn chunks(&self) -> &[BlobMetadataChunk] {
        match &self.storage {
            BlobMetadataStorage::Owned { chunks, .. } => chunks,
            BlobMetadataStorage::Mapped(mmap) => {
                let offset = self.header.chunks_offset() as usize;
                let count = self.header.chunk_count() as usize;
                let bytes = &mmap[offset..offset + count * size_of::<BlobMetadataChunk>()];
                unsafe { std::slice::from_raw_parts(bytes.as_ptr().cast(), count) }
            }
        }
    }

    /// The block group table, backed the same two ways as [`Self::chunks`].
    pub fn block_groups(&self) -> &[BlobMetadataBlockGroup] {
        match &self.storage {
            BlobMetadataStorage::Owned { block_groups, .. } => block_groups,
            BlobMetadataStorage::Mapped(mmap) => {
                let offset = self.header.block_groups_offset() as usize;
                let count = self.header.block_group_count() as usize;
                let bytes = &mmap[offset..offset + count * size_of::<BlobMetadataBlockGroup>()];
                unsafe { std::slice::from_raw_parts(bytes.as_ptr().cast(), count) }
            }
        }
    }

    /// The block group at `index`, `None` past the table.
    pub fn block_group(&self, index: usize) -> Option<&BlobMetadataBlockGroup> {
        self.block_groups().get(index)
    }

    /// Whether any block group redirects to another source blob (an
    /// ondemand redirect blob).
    pub fn is_redirect(&self) -> bool {
        BlobMetadataBlockGroup::has_redirect(self.block_groups())
    }

    /// Total uncompressed size of the blob in 4KiB blocks: block groups are
    /// validated dense from block 0, so the last group's end offset is the
    /// block count.
    pub fn uncompressed_block_count(&self) -> u64 {
        self.block_groups()
            .last()
            .map(|block_group| {
                block_group.uncompressed_block_offset()
                    + block_group.uncompressed_block_count() as u64
            })
            .unwrap_or(0)
    }

    /// The block group covering `uncompressed_offset`, `None` past the end
    /// of the blob: dense fixed-size groups make this a single shift, no
    /// search.
    pub fn block_group_index_from_uncompressed_offset(
        &self,
        uncompressed_offset: u64,
    ) -> Option<usize> {
        let block = uncompressed_offset / EROFS_BLOCK_SIZE as u64;
        if block >= self.uncompressed_block_count() {
            return None;
        }

        usize::try_from(block >> self.header.block_group_block_count_bits).ok()
    }

    /// Total uncompressed byte size of the blob: block groups are validated
    /// dense from offset 0, so the last group's end offset is the size.
    pub fn uncompressed_size(&self) -> u64 {
        self.block_groups()
            .last()
            .map(|block_group| block_group.uncompressed_offset() + block_group.uncompressed_size())
            .unwrap_or(0)
    }

    /// End of the last block group's compressed range: the compressed data
    /// region's byte size when payloads pack from offset 0 without gaps
    /// (the standalone layout), otherwise just an end coordinate (gaps and
    /// bias shifts are legal on the compressed side).
    pub fn compressed_end(&self) -> u64 {
        self.block_groups()
            .last()
            .map(|block_group| {
                block_group.compressed_offset() + block_group.compressed_size() as u64
            })
            .unwrap_or(0)
    }

    /// The full serialized size, 4KiB aligned.
    pub fn padded_size(&self) -> u64 {
        self.header.padded_size()
    }

    /// crc32c over a serialized buffer with the header's crc32 field
    /// treated as zero: what the read side verifies raw incoming bytes
    /// against.
    fn compute_crc32(bytes: &[u8]) -> u32 {
        let (header, tail) = bytes.split_at(NYDUS_BLOB_METADATA_HEADER_SIZE);
        let mut zeroed: [u8; NYDUS_BLOB_METADATA_HEADER_SIZE] = header.try_into().unwrap();
        zeroed[NYDUS_BLOB_METADATA_HEADER_CRC32_FIELD].fill(0);
        crc32c_append(crc32c(&zeroed), tail)
    }

    /// The same seal computed from the in-memory parts exactly as
    /// [`Self::write_to`] emits them (reserved regions zeroed): the write
    /// side's view.
    fn compute_crc32_from_parts(&self) -> u32 {
        let mut zeroed = self.header.to_bytes();
        zeroed[NYDUS_BLOB_METADATA_HEADER_CRC32_FIELD].fill(0);

        let mut crc32 = crc32c(&zeroed);
        for chunk in self.chunks() {
            crc32 = crc32c_append(crc32, &chunk.to_bytes());
        }

        for block_group in self.block_groups() {
            crc32 = crc32c_append(crc32, &block_group.to_bytes());
        }

        let padding_size = (self.padded_size() - self.header.used_size()) as usize;
        crc32c_append(crc32, &[0u8; EROFS_BLOCK_SIZE as usize][..padding_size])
    }
}

/// Encode a power-of-two 4KiB block count as the log2 stored in the
/// header's `*_block_count_bits` fields.
fn block_count_to_bits(blocks: u32) -> Result<u8> {
    if !blocks.is_power_of_two() {
        return Err(Error::InvalidImage(format!(
            "blob meta block count must be a non-zero power of two: {blocks}"
        )));
    }

    let bits = blocks.ilog2() as u8;
    if bits > NYDUS_BLOB_METADATA_MAX_BLOCK_COUNT_BITS {
        return Err(Error::InvalidImage(format!(
            "blob meta block count too large: {blocks}"
        )));
    }

    Ok(bits)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn digest(bytes: &[u8]) -> [u8; 32] {
        *blake3::hash(bytes).as_bytes()
    }

    fn chunk(payload: &[u8], block_offset: u64, block_count: u32) -> BlobMetadataChunk {
        BlobMetadataChunk::new(digest(payload), block_offset, block_count).unwrap()
    }

    fn block_group(
        block_offset: u64,
        block_count: u32,
        compressed_offset: u64,
        compressed_size: u32,
        payload: &[u8],
    ) -> BlobMetadataBlockGroup {
        BlobMetadataBlockGroup::new(
            block_offset,
            block_count,
            compressed_offset,
            compressed_size,
            crc32c::crc32c(payload),
        )
        .unwrap()
    }

    fn build(
        chunks: Vec<BlobMetadataChunk>,
        block_groups: Vec<BlobMetadataBlockGroup>,
    ) -> Result<BlobMetadata> {
        BlobMetadata::new(BlobMetadataCompressor::None, 1, chunks, block_groups)
    }

    fn blob_metadata() -> BlobMetadata {
        let payload = vec![0x33; EROFS_BLOCK_SIZE as usize];
        BlobMetadata::new(
            BlobMetadataCompressor::None,
            1,
            vec![chunk(&payload, 0, 1)],
            vec![block_group(0, 1, 0, EROFS_BLOCK_SIZE, &payload)],
        )
        .unwrap()
    }

    fn sealed_metadata() -> Vec<u8> {
        let mut raw = Vec::new();
        blob_metadata().write_to(&mut raw).unwrap();
        raw
    }

    #[test]
    fn accessors_expose_the_sealed_tables() {
        let blob_metadata = blob_metadata();
        let header = blob_metadata.header();

        assert_eq!(header.version(), NYDUS_BLOB_METADATA_VERSION);
        assert_eq!(header.compressor(), BlobMetadataCompressor::None);
        assert_eq!(header.digester(), BlobMetadataDigester::Blake3);
        assert_eq!(header.chunks_offset(), 4096);
        assert_eq!(header.chunk_table_size(), 48);
        assert_eq!(header.block_groups_offset(), 4144);
        assert_eq!(header.block_group_table_size(), 40);
        assert_eq!(header.used_size(), 4184);
        assert_eq!(header.padded_size(), 8192);
        assert_eq!(header.chunk_block_count(), 1);
        assert_eq!(header.chunk_size(), EROFS_BLOCK_SIZE);
        assert_eq!(header.block_group_block_count(), 1);
        assert_ne!(header.crc32(), 0);

        assert_eq!(blob_metadata.chunk_count(), 1);
        assert_eq!(blob_metadata.block_group_count(), 1);
        assert_eq!(blob_metadata.chunk_block_count(), 1);
        assert_eq!(blob_metadata.chunk_size(), EROFS_BLOCK_SIZE);
        assert_eq!(blob_metadata.compressor(), BlobMetadataCompressor::None);
        assert_eq!(blob_metadata.digester(), BlobMetadataDigester::Blake3);
        assert!(!blob_metadata.is_redirect());
        assert_eq!(blob_metadata.uncompressed_block_count(), 1);
        assert_eq!(blob_metadata.uncompressed_size(), 4096);
        assert_eq!(blob_metadata.compressed_end(), 4096);
        assert_eq!(blob_metadata.padded_size(), 8192);

        let chunk = &blob_metadata.chunks()[0];
        assert_eq!(chunk.uncompressed_block_offset(), 0);
        assert_eq!(chunk.uncompressed_block_count(), 1);
        assert_eq!(chunk.uncompressed_offset(), 0);
        assert_eq!(chunk.uncompressed_size(), 4096);

        let block_group = blob_metadata.block_group(0).unwrap();
        assert_eq!(block_group.uncompressed_block_offset(), 0);
        assert_eq!(block_group.uncompressed_block_count(), 1);
        assert_eq!(block_group.uncompressed_offset(), 0);
        assert_eq!(block_group.uncompressed_size(), 4096);
        assert_eq!(block_group.compressed_offset(), 0);
        assert_eq!(block_group.compressed_size(), EROFS_BLOCK_SIZE);
        assert!(blob_metadata.block_group(1).is_none());
    }

    #[test]
    fn round_trips_through_a_sidecar_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("blob.meta");
        let payload_a = vec![0x11; EROFS_BLOCK_SIZE as usize];
        let payload_b = vec![0x22; EROFS_BLOCK_SIZE as usize];
        let both = [payload_a.as_slice(), payload_b.as_slice()].concat();
        let blob_metadata = BlobMetadata::new(
            BlobMetadataCompressor::None,
            1,
            vec![chunk(&payload_a, 0, 1), chunk(&payload_b, 1, 1)],
            vec![block_group(0, 2, 8192, 8192, &both)],
        )
        .unwrap();
        blob_metadata.save(&path).unwrap();

        let loaded = BlobMetadata::from_path(&path, false).unwrap();
        assert_eq!(loaded.chunk_count(), 2);
        assert_eq!(loaded.block_group_count(), 1);
        assert_eq!(loaded.header().block_group_block_count(), 2);
        assert_eq!(loaded.chunks()[1].digest(), &digest(&payload_b));
        assert_eq!(loaded.chunks()[1].uncompressed_block_offset(), 1);
        assert_eq!(loaded.block_groups()[0].compressed_offset(), 8192);
        assert_eq!(
            loaded.block_group_index_from_uncompressed_offset(4096),
            Some(0)
        );
        assert_eq!(loaded.uncompressed_size(), 8192);

        BlobMetadata::from_path(&path, true).unwrap();
    }

    #[test]
    fn the_header_crc32_seals_the_full_serialized_metadata() {
        let raw = sealed_metadata();

        let stored_crc32 = u32::from_le_bytes(
            raw[NYDUS_BLOB_METADATA_HEADER_CRC32_FIELD]
                .try_into()
                .unwrap(),
        );
        let mut zeroed = raw.clone();
        zeroed[NYDUS_BLOB_METADATA_HEADER_CRC32_FIELD].fill(0);

        assert_eq!(stored_crc32, crc32c::crc32c(&zeroed));
    }

    #[test]
    fn an_unchecked_read_keeps_a_bad_crc32_and_a_checked_read_rejects_it() {
        let mut raw = sealed_metadata();
        raw[NYDUS_BLOB_METADATA_HEADER_CRC32_FIELD.start] ^= 0xff;
        let corrupted_crc32 = u32::from_le_bytes(
            raw[NYDUS_BLOB_METADATA_HEADER_CRC32_FIELD]
                .try_into()
                .unwrap(),
        );

        let loaded = BlobMetadata::from_bytes(&raw, false).unwrap();
        assert_eq!(loaded.header().crc32(), corrupted_crc32);

        let err = BlobMetadata::from_bytes(&raw, true).unwrap_err();
        assert!(err.to_string().contains("crc32"), "{err}");
    }

    #[test]
    fn the_reserved_tail_is_ignored_but_fails_the_crc32_check() {
        let mut raw = sealed_metadata();
        raw[NYDUS_BLOB_METADATA_HEADER_SIZE - 1] = 0xff;

        BlobMetadata::from_bytes(&raw, false).unwrap();
        let err = BlobMetadata::from_bytes(&raw, true).unwrap_err();
        assert!(err.to_string().contains("crc32"), "{err}");
    }

    #[test]
    fn header_mutations_follow_the_compat_rules() {
        let base_flags = BlobMetadataDigester::Blake3.flag().bits();
        let cases: [(&str, usize, [u8; 4], Option<&str>); 4] = [
            (
                "future version is readable",
                8,
                (NYDUS_BLOB_METADATA_VERSION + 1).to_le_bytes(),
                None,
            ),
            (
                "unknown compat flag is ignored",
                12,
                (base_flags | (1u32 << 31)).to_le_bytes(),
                None,
            ),
            (
                "unknown incompat flag rejects",
                12,
                (base_flags | (1u32 << 15)).to_le_bytes(),
                Some("incompat"),
            ),
            (
                "nonzero reserved tail is readable",
                NYDUS_BLOB_METADATA_HEADER_SIZE - 4,
                [0, 0, 0, 0xff],
                None,
            ),
        ];

        for (case, offset, value, expected_err) in cases {
            let mut raw = sealed_metadata();
            raw[offset..offset + 4].copy_from_slice(&value);

            let result = BlobMetadata::from_bytes(&raw, false);
            match expected_err {
                None => {
                    result.unwrap_or_else(|err| panic!("{case}: {err}"));
                }
                Some(expected) => {
                    let err = match result {
                        Ok(_) => panic!("{case}: should be rejected"),
                        Err(err) => err,
                    };
                    assert!(err.to_string().contains(expected), "{case}: {err}");
                }
            }
        }

        let mut future = sealed_metadata();
        future[8..12].copy_from_slice(&(NYDUS_BLOB_METADATA_VERSION + 1).to_le_bytes());
        let loaded = BlobMetadata::from_bytes(&future, false).unwrap();
        assert_eq!(loaded.header().version(), NYDUS_BLOB_METADATA_VERSION + 1);
    }

    #[test]
    fn legacy_magics_reject() {
        let dir = tempdir().unwrap();

        for (name, magic) in [
            ("nydus.blob.meta", 0xb10b_b10bu32),
            ("v0.blob.meta", 0x4c50_424du32),
        ] {
            let path = dir.path().join(name);
            let mut raw = vec![0u8; NYDUS_BLOB_METADATA_HEADER_SIZE];
            raw[..4].copy_from_slice(&magic.to_le_bytes());
            std::fs::write(&path, raw).unwrap();

            let err = match BlobMetadata::from_path(&path, false) {
                Ok(_) => panic!("{name}: legacy magic should be rejected"),
                Err(err) => err,
            };
            assert!(err.to_string().contains("magic"), "{name}: {err}");
        }
    }

    #[test]
    fn undersized_inputs_reject() {
        let raw = sealed_metadata();

        let err = BlobMetadata::from_bytes(&raw[..10], false).unwrap_err();
        assert!(err.to_string().contains("too small"), "{err}");

        let err = BlobMetadata::from_bytes(&raw[..raw.len() - 1], false).unwrap_err();
        assert!(err.to_string().contains("size mismatch"), "{err}");

        let dir = tempdir().unwrap();
        let path = dir.path().join("short.blob.meta");
        std::fs::write(&path, &raw[..10]).unwrap();
        let err = BlobMetadata::from_path(&path, false).unwrap_err();
        assert!(err.to_string().contains("too small"), "{err}");
    }

    #[test]
    fn nonzero_tail_padding_rejects() {
        let mut raw = sealed_metadata();
        let used_size = blob_metadata().header().used_size() as usize;
        raw[used_size] = 0xff;

        let err = BlobMetadata::from_bytes(&raw, false).unwrap_err();
        assert!(err.to_string().contains("padding must be zero"), "{err}");
    }

    #[test]
    fn invalid_entries_reject() {
        let cases = [
            (
                "zero uncompressed block count",
                BlobMetadataBlockGroup::new(0, 0, 0, 4096, 0),
                "must be non-zero",
            ),
            (
                "zero compressed size",
                BlobMetadataBlockGroup::new(0, 1, 0, 0, 0),
                "must be non-zero",
            ),
            (
                "uncompressed byte offset overflow",
                BlobMetadataBlockGroup::new(u64::MAX, 1, 0, 4096, 0),
                "overflow",
            ),
            (
                "compressed byte range overflow",
                BlobMetadataBlockGroup::new(0, 1, u64::MAX, 4096, 0),
                "overflow",
            ),
        ];

        for (case, result, expected) in cases {
            let err = result.unwrap_err();
            assert!(err.to_string().contains(expected), "{case}: {err}");
        }

        let err = BlobMetadataChunk::new([0u8; 32], 0, 0).unwrap_err();
        assert!(err.to_string().contains("must be non-zero"), "{err}");

        let err = BlobMetadataChunk::new([0u8; 32], u64::MAX, 1).unwrap_err();
        assert!(err.to_string().contains("overflow"), "{err}");

        let valid = BlobMetadataBlockGroup::new(0, 1, 0, 4096, 0)
            .unwrap()
            .to_bytes();

        let mut orphan_source = valid;
        write_u32_at(&mut orphan_source, 28, 7);
        let err = BlobMetadataBlockGroup::from_bytes(&orphan_source).unwrap_err();
        assert!(
            err.to_string().contains("requires a source blob index"),
            "{err}"
        );

        let mut dirty_reserved = valid;
        dirty_reserved[34] = 0xff;
        let err = BlobMetadataBlockGroup::from_bytes(&dirty_reserved).unwrap_err();
        assert!(err.to_string().contains("reserved"), "{err}");

        let mut dirty_chunk = chunk(&[0x11], 0, 1).to_bytes();
        write_u32_at(&mut dirty_chunk, 44, 1);
        let err = BlobMetadataChunk::from_bytes(&dirty_chunk).unwrap_err();
        assert!(err.to_string().contains("reserved"), "{err}");
    }

    #[test]
    fn a_chunk_past_the_block_groups_rejects() {
        let one = vec![0x11; EROFS_BLOCK_SIZE as usize];
        let err = build(
            vec![chunk(&one, 1, 1)],
            vec![block_group(0, 1, 0, EROFS_BLOCK_SIZE, &one)],
        )
        .unwrap_err();

        assert!(
            err.to_string().contains("exceeds the blob block range"),
            "{err}"
        );
    }

    #[test]
    fn block_groups_must_be_dense_from_block_zero() {
        let one = vec![0x11; EROFS_BLOCK_SIZE as usize];
        let err = build(
            vec![chunk(&one, 0, 1)],
            vec![block_group(1, 1, 0, EROFS_BLOCK_SIZE, &one)],
        )
        .unwrap_err();
        assert!(err.to_string().contains("dense"), "{err}");

        let two = vec![0x22; 2 * EROFS_BLOCK_SIZE as usize];
        let err = build(
            vec![chunk(&two, 0, 2)],
            vec![
                block_group(0, 2, 0, 2 * EROFS_BLOCK_SIZE, &two),
                block_group(
                    3,
                    2,
                    2 * EROFS_BLOCK_SIZE as u64,
                    2 * EROFS_BLOCK_SIZE,
                    &two,
                ),
            ],
        )
        .unwrap_err();
        assert!(err.to_string().contains("dense"), "{err}");
    }

    #[test]
    fn block_group_index_from_uncompressed_offset_maps_by_division() {
        let two = vec![0x11; 2 * EROFS_BLOCK_SIZE as usize];
        let one = vec![0x22; EROFS_BLOCK_SIZE as usize];
        let blob_metadata = build(
            vec![chunk(&two, 0, 2), chunk(&two, 2, 2), chunk(&one, 4, 1)],
            vec![
                block_group(0, 2, 0, 2 * EROFS_BLOCK_SIZE, &two),
                block_group(
                    2,
                    2,
                    2 * EROFS_BLOCK_SIZE as u64,
                    2 * EROFS_BLOCK_SIZE,
                    &two,
                ),
                block_group(4, 1, 4 * EROFS_BLOCK_SIZE as u64, EROFS_BLOCK_SIZE, &one),
            ],
        )
        .unwrap();
        assert_eq!(blob_metadata.header().block_group_block_count(), 2);

        let block = EROFS_BLOCK_SIZE as u64;
        let cases = [
            (0, Some(0)),
            (2 * block - 1, Some(0)),
            (2 * block, Some(1)),
            (4 * block - 1, Some(1)),
            (4 * block, Some(2)),
            (5 * block - 1, Some(2)),
            (5 * block, None),
        ];
        for (offset, expected) in cases {
            assert_eq!(
                blob_metadata.block_group_index_from_uncompressed_offset(offset),
                expected,
                "offset {offset}"
            );
        }
    }

    #[test]
    fn non_uniform_block_group_sizes_reject() {
        let two = vec![0x11; 2 * EROFS_BLOCK_SIZE as usize];
        let three = vec![0x22; 3 * EROFS_BLOCK_SIZE as usize];
        let one = vec![0x33; EROFS_BLOCK_SIZE as usize];

        let err = build(
            vec![chunk(&two, 0, 2), chunk(&three, 2, 3), chunk(&one, 5, 1)],
            vec![
                block_group(0, 2, 0, 2 * EROFS_BLOCK_SIZE, &two),
                block_group(
                    2,
                    3,
                    2 * EROFS_BLOCK_SIZE as u64,
                    3 * EROFS_BLOCK_SIZE,
                    &three,
                ),
                block_group(5, 1, 5 * EROFS_BLOCK_SIZE as u64, EROFS_BLOCK_SIZE, &one),
            ],
        )
        .unwrap_err();
        assert!(err.to_string().contains("must be exactly"), "{err}");

        let err = build(
            vec![chunk(&two, 0, 2), chunk(&three, 2, 3)],
            vec![
                block_group(0, 2, 0, 2 * EROFS_BLOCK_SIZE, &two),
                block_group(
                    2,
                    3,
                    2 * EROFS_BLOCK_SIZE as u64,
                    3 * EROFS_BLOCK_SIZE,
                    &three,
                ),
            ],
        )
        .unwrap_err();
        assert!(err.to_string().contains("exceeds"), "{err}");
    }

    #[test]
    fn a_single_block_group_uses_a_covering_power_of_two_exponent() {
        let three = vec![0x44; 3 * EROFS_BLOCK_SIZE as usize];
        let blob_metadata = build(
            vec![chunk(&three, 0, 3)],
            vec![block_group(0, 3, 0, 3 * EROFS_BLOCK_SIZE, &three)],
        )
        .unwrap();

        assert_eq!(blob_metadata.header().block_group_block_count(), 4);
        let block = EROFS_BLOCK_SIZE as u64;
        for index in 0..3u64 {
            assert_eq!(
                blob_metadata.block_group_index_from_uncompressed_offset(index * block),
                Some(0)
            );
        }
        assert_eq!(
            blob_metadata.block_group_index_from_uncompressed_offset(3 * block),
            None
        );
    }

    #[test]
    fn multi_block_group_blobs_require_power_of_two_full_block_groups() {
        let three = vec![0x55; 3 * EROFS_BLOCK_SIZE as usize];
        let one = vec![0x66; EROFS_BLOCK_SIZE as usize];
        let err = build(
            vec![chunk(&three, 0, 3), chunk(&one, 3, 1)],
            vec![
                block_group(0, 3, 0, 3 * EROFS_BLOCK_SIZE, &three),
                block_group(3, 1, 3 * EROFS_BLOCK_SIZE as u64, EROFS_BLOCK_SIZE, &one),
            ],
        )
        .unwrap_err();

        assert!(err.to_string().contains("power of two"), "{err}");
    }

    #[test]
    fn packed_compressed_offsets_need_no_block_alignment() {
        let two = vec![0x11; 2 * EROFS_BLOCK_SIZE as usize];
        let blob_metadata = build(
            vec![chunk(&two, 0, 2), chunk(&two, 2, 2)],
            vec![
                block_group(0, 2, 0, 5000, &two),
                block_group(2, 2, 5000, 3000, &two),
            ],
        )
        .unwrap();

        assert_eq!(blob_metadata.block_groups()[1].compressed_offset(), 5000);
        assert_eq!(blob_metadata.compressed_end(), 8000);
    }

    #[test]
    fn overlapping_compressed_ranges_reject() {
        let two = vec![0x22; 2 * EROFS_BLOCK_SIZE as usize];
        let err = build(
            vec![chunk(&two, 0, 2), chunk(&two, 2, 2)],
            vec![
                block_group(0, 2, 0, 5000, &two),
                block_group(2, 2, 4999, 3000, &two),
            ],
        )
        .unwrap_err();

        assert!(err.to_string().contains("overlap"), "{err}");
    }

    #[test]
    fn checked_add_compressed_offset_shifts_and_reseals() {
        let shifted = blob_metadata().checked_add_compressed_offset(8192).unwrap();

        assert_eq!(shifted.block_groups()[0].compressed_offset(), 8192);
        assert_eq!(shifted.uncompressed_size(), 4096);

        let mut raw = Vec::new();
        shifted.write_to(&mut raw).unwrap();
        BlobMetadata::from_bytes(&raw, true).unwrap();
    }

    #[test]
    fn redirect_block_groups_round_trip_and_report_their_source() {
        let payload = vec![0x44; 2 * EROFS_BLOCK_SIZE as usize];
        let crc32 = crc32c::crc32c(&payload);
        let redirect =
            BlobMetadataBlockGroup::new_redirect(0, 2, 0, 2 * EROFS_BLOCK_SIZE, crc32, 3, 7)
                .unwrap();

        assert!(redirect.is_redirect());
        assert_eq!(redirect.source_blob_index(), 3);
        assert_eq!(redirect.source_block_group_index(), 7);

        let mut written = Vec::new();
        redirect.write_to(&mut written).unwrap();
        let bytes: [u8; 40] = written.as_slice().try_into().unwrap();
        assert_eq!(
            BlobMetadataBlockGroup::from_bytes(&bytes).unwrap(),
            redirect
        );

        let normal = block_group(0, 2, 0, 2 * EROFS_BLOCK_SIZE, &payload);
        assert!(!normal.is_redirect());
        let loaded = BlobMetadataBlockGroup::from_bytes(&normal.to_bytes()).unwrap();
        assert!(!loaded.is_redirect());
        assert_eq!(loaded.source_block_group_index(), 0);
    }

    #[test]
    fn a_redirect_with_a_zero_source_blob_index_rejects() {
        let err =
            BlobMetadataBlockGroup::new_redirect(0, 1, 0, EROFS_BLOCK_SIZE, 0, 0, 1).unwrap_err();
        assert!(err.to_string().contains("non-zero"), "{err}");
    }

    #[test]
    fn a_redirect_blob_allows_non_uniform_block_groups_and_round_trips() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("ondemand.blob.meta");
        let two = vec![0x55; 2 * EROFS_BLOCK_SIZE as usize];
        let three = vec![0x66; 3 * EROFS_BLOCK_SIZE as usize];
        let one = vec![0x77; EROFS_BLOCK_SIZE as usize];
        let block_groups = vec![
            BlobMetadataBlockGroup::new_redirect(
                0,
                2,
                0,
                2 * EROFS_BLOCK_SIZE,
                crc32c::crc32c(&two),
                1,
                4,
            )
            .unwrap(),
            BlobMetadataBlockGroup::new_redirect(
                2,
                3,
                2 * EROFS_BLOCK_SIZE as u64,
                3 * EROFS_BLOCK_SIZE,
                crc32c::crc32c(&three),
                2,
                0,
            )
            .unwrap(),
            BlobMetadataBlockGroup::new_redirect(
                5,
                1,
                5 * EROFS_BLOCK_SIZE as u64,
                EROFS_BLOCK_SIZE,
                crc32c::crc32c(&one),
                1,
                9,
            )
            .unwrap(),
        ];

        let blob_metadata = BlobMetadata::new(
            BlobMetadataCompressor::None,
            DEFAULT_NYDUS_BLOB_METADATA_CHUNK_BLOCK_COUNT,
            Vec::new(),
            block_groups.clone(),
        )
        .unwrap();
        assert!(blob_metadata.is_redirect());
        assert_eq!(
            blob_metadata.header().block_group_block_count(),
            DEFAULT_NYDUS_BLOB_METADATA_BLOCK_GROUP_BLOCK_COUNT
        );

        blob_metadata.save(&path).unwrap();
        let loaded = BlobMetadata::from_path(&path, false).unwrap();
        assert!(loaded.is_redirect());
        assert_eq!(loaded.block_groups(), block_groups.as_slice());
        assert_eq!(loaded.block_groups()[1].source_blob_index(), 2);
        assert_eq!(loaded.block_groups()[2].source_block_group_index(), 9);
    }
}

use crate::blob::algorithm::{BlobMetadataCompressor, BlobMetadataDigester};
use crate::blob::flag::validate_incompat_flags;
use crate::erofs::EROFS_BLOCK_SIZE;
use crate::error::{Context, Error, Result};
use crate::utils::le::{
    read_u16_at, read_u32_at, read_u64_at, read_u8_at, write_u16_at, write_u32_at, write_u64_at,
    write_u8_at,
};
use crate::utils::SHA256_DIGEST_SIZE;
use bitflags::bitflags;
use crc32c::{crc32c, crc32c_append};
use memmap2::{Mmap, MmapOptions};
use std::fs::File;
use std::io::Write;
use std::mem::{align_of, size_of};
use std::ops::Range;
use std::path::Path;

/// On-disk magic: 8 raw ASCII bytes ("LPBLMETA" = LePton BLob META), written
/// as-is so a hexdump of the file starts with the readable string. Same style
/// and `magic + version + flags` header prefix as the blob footer
/// (`LPFOOTER`) and block_group_map (`LPGRPMAP`) sidecars.
pub const NYDUS_BLOB_METADATA_MAGIC: [u8; 8] = *b"LPBLMETA";

/// On-disk format generation, informational only: readers do not gate on it.
/// Compatibility is governed EROFS-style by the magic (a new format family
/// gets a new magic) and the incompat half of `flags` (unknown incompat bits
/// reject the file).
pub const NYDUS_BLOB_METADATA_VERSION: u32 = 1;

/// The header's fixed on-disk size: one EROFS block. The chunk table starts
/// right after the header, so it is block aligned by construction, and the
/// unused tail of the header block is reserved for future compat fields
/// (writers zero it, readers ignore it; corruption is caught by the file
/// crc32c).
pub const NYDUS_BLOB_METADATA_HEADER_SIZE: usize = EROFS_BLOCK_SIZE as usize;

/// On-disk size of one chunk entry in the chunk table.
pub const NYDUS_BLOB_METADATA_CHUNK_ENTRY_SIZE: usize = 48;

/// On-disk size of one block group entry in the block group table.
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
/// `block_group_block_count_bits`): keeps the derived byte size (`4096 << bits`)
/// representable in a `u32` (2 GiB at most).
const NYDUS_BLOB_METADATA_MAX_BLOCK_COUNT_BITS: u8 = 19;

/// Byte range of the crc32 field within the header.
const NYDUS_BLOB_METADATA_HEADER_CRC32_FIELD: Range<usize> = 16..20;

const NYDUS_BLOB_METADATA_CHUNK_RESERVED: u32 = 0;
const NYDUS_BLOB_METADATA_BLOCK_GROUP_RESERVED: [u8; 6] = [0u8; 6];

bitflags! {
    /// Feature bits, split EROFS-style (see [`crate::blob::flag`]): the
    /// low 16 bits are **incompatible** features — a reader that does not
    /// know a set bit cannot interpret the file and must reject it (like
    /// `feature_incompat`). The high 16 bits are **compatible** features —
    /// unknown bits are ignored so old readers keep working (like
    /// `feature_compat`). Entry-layout evolution (wider chunk/block group
    /// entries, new entry kinds) is expressed as a new incompat bit; header
    /// growth uses the reserved tail plus a compat bit.
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

    pub fn version(&self) -> u32 {
        self.version
    }

    pub fn flags(&self) -> BlobMetadataFlags {
        BlobMetadataFlags::from_bits_truncate(self.flags)
    }

    pub fn crc32(&self) -> u32 {
        self.crc32
    }

    pub fn compressor(&self) -> BlobMetadataCompressor {
        BlobMetadataCompressor::from(self.flags())
    }

    pub fn digester(&self) -> BlobMetadataDigester {
        BlobMetadataDigester::try_from(self.flags()).unwrap()
    }

    pub fn chunk_count(&self) -> u32 {
        self.chunk_count
    }

    pub fn chunk_block_count(&self) -> u32 {
        1u32 << self.chunk_block_count_bits
    }

    pub fn chunk_size(&self) -> u32 {
        EROFS_BLOCK_SIZE << self.chunk_block_count_bits
    }

    pub fn chunks_offset(&self) -> u64 {
        self.chunks_offset
    }

    pub fn chunk_table_size(&self) -> u64 {
        self.chunk_count as u64 * size_of::<BlobMetadataChunk>() as u64
    }

    pub fn block_group_count(&self) -> u32 {
        self.block_group_count
    }

    pub fn block_group_block_count(&self) -> u32 {
        1u32 << self.block_group_block_count_bits
    }

    pub fn block_groups_offset(&self) -> u64 {
        self.block_groups_offset
    }

    pub fn block_group_table_size(&self) -> u64 {
        self.block_group_count as u64 * size_of::<BlobMetadataBlockGroup>() as u64
    }

    pub fn used_size(&self) -> u64 {
        self.block_groups_offset + self.block_group_table_size()
    }

    pub fn padded_size(&self) -> u64 {
        crate::utils::align_up(self.used_size(), EROFS_BLOCK_SIZE as u64)
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
    /// always valid; mapped tables are validated entry by entry at load.
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

    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    pub fn uncompressed_block_offset(&self) -> u64 {
        self.uncompressed_block_offset
    }

    pub fn uncompressed_block_count(&self) -> u32 {
        self.uncompressed_block_count
    }

    pub fn uncompressed_offset(&self) -> u64 {
        self.uncompressed_block_offset
            .checked_mul(EROFS_BLOCK_SIZE as u64)
            .expect("validated blob meta chunk byte offset")
    }

    pub fn uncompressed_size(&self) -> u64 {
        self.uncompressed_block_count as u64 * EROFS_BLOCK_SIZE as u64
    }
}

/// One block group entry: how a span of the dense uncompressed address
/// space maps onto the blob's encoded payload — the unit of decode, cache
/// fill, and prefetch. Block group entries are packed back to back in the
/// block group table right after the chunk table.
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

const _: () =
    assert!(size_of::<BlobMetadataBlockGroup>() == NYDUS_BLOB_METADATA_BLOCK_GROUP_ENTRY_SIZE);

impl BlobMetadataBlockGroup {
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

    pub fn write_to(&self, writer: &mut dyn Write) -> Result<()> {
        writer.write_all(&self.to_bytes())?;
        Ok(())
    }

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

    pub fn is_redirect(&self) -> bool {
        self.source_blob_index != 0
    }

    pub fn source_blob_index(&self) -> u16 {
        self.source_blob_index
    }

    pub fn source_block_group_index(&self) -> u32 {
        self.source_block_group_index
    }

    pub fn uncompressed_block_offset(&self) -> u64 {
        self.uncompressed_block_offset
    }

    pub fn uncompressed_block_count(&self) -> u32 {
        self.uncompressed_block_count
    }

    pub fn uncompressed_offset(&self) -> u64 {
        self.uncompressed_block_offset
            .checked_mul(EROFS_BLOCK_SIZE as u64)
            .expect("validated blob meta block group byte offset")
    }

    pub fn uncompressed_size(&self) -> u64 {
        self.uncompressed_block_count as u64 * EROFS_BLOCK_SIZE as u64
    }

    pub fn compressed_offset(&self) -> u64 {
        self.compressed_offset
    }

    pub fn compressed_size(&self) -> u32 {
        self.compressed_size
    }

    pub fn crc32(&self) -> u32 {
        self.crc32
    }

    /// True when any block group redirects to another source blob.
    fn has_redirect(block_groups: &[Self]) -> bool {
        block_groups.iter().any(Self::is_redirect)
    }

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

    fn compute_uncompressed_block_end(block_groups: &[Self]) -> u64 {
        block_groups
            .last()
            .map(|block_group| {
                block_group.uncompressed_block_offset()
                    + block_group.uncompressed_block_count() as u64
            })
            .unwrap_or(0)
    }

    fn compute_uncompressed_end(block_groups: &[Self]) -> u64 {
        block_groups
            .last()
            .map(|block_group| block_group.uncompressed_offset() + block_group.uncompressed_size())
            .unwrap_or(0)
    }

    fn compute_compressed_end(block_groups: &[Self]) -> u64 {
        block_groups
            .last()
            .map(|block_group| {
                block_group.compressed_offset() + block_group.compressed_size() as u64
            })
            .unwrap_or(0)
    }
}

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
///                            the entries end here; the padding
///                            runs to the 4KiB-aligned padded_size
/// ```
///
/// In memory the tables are either owned (the write side, built by
/// [`Self::new`]) or a shared file mapping read in place
/// ([`Self::load`]), zero-copy thanks to the entries' pinned layout.
pub struct BlobMetadata {
    header: BlobMetadataHeader,
    blob_id: [u8; SHA256_DIGEST_SIZE],
    storage: BlobMetadataStorage,
}

impl BlobMetadata {
    /// Creates validated, sealed metadata from owned tables: the header is
    /// derived from the tables and both are validated first, so constructed
    /// metadata is valid by definition, then the crc32 is computed over the
    /// final bytes.
    pub fn new(
        blob_id: [u8; SHA256_DIGEST_SIZE],
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
            blob_id,
            storage: BlobMetadataStorage::Owned {
                chunks,
                block_groups,
            },
        };
        blob_metadata.validate()?;
        blob_metadata.header.crc32 = blob_metadata.compute_crc32_from_parts();
        Ok(blob_metadata)
    }

    fn from_bytes(
        data: &[u8],
        blob_id: [u8; SHA256_DIGEST_SIZE],
        check_crc32: bool,
    ) -> Result<Self> {
        if data.len() < NYDUS_BLOB_METADATA_HEADER_SIZE {
            return Err(Error::InvalidImage("blob meta data too small".to_string()));
        }

        let header = BlobMetadataHeader::from_bytes(
            data[..NYDUS_BLOB_METADATA_HEADER_SIZE]
                .try_into()
                .expect("length checked"),
        )?;
        if data.len() as u64 != header.padded_size() {
            return Err(Error::InvalidImage(format!(
                "blob meta data size mismatch: expected {}, got {}",
                header.padded_size(),
                data.len()
            )));
        }
        validate_padding(data, &header)?;
        if check_crc32 {
            validate_blob_metadata_crc32(data, &header)?;
        }

        let chunks = (0..header.chunk_count() as usize)
            .map(|index| {
                let start =
                    header.chunks_offset() as usize + index * size_of::<BlobMetadataChunk>();
                BlobMetadataChunk::from_bytes(
                    data[start..start + size_of::<BlobMetadataChunk>()]
                        .try_into()
                        .expect("length checked"),
                )
                .with_context(|| format!("failed to read blob meta chunk {index}"))
            })
            .collect::<Result<Vec<_>>>()?;

        let block_groups = (0..header.block_group_count() as usize)
            .map(|index| {
                let start = header.block_groups_offset() as usize
                    + index * size_of::<BlobMetadataBlockGroup>();
                BlobMetadataBlockGroup::from_bytes(
                    data[start..start + size_of::<BlobMetadataBlockGroup>()]
                        .try_into()
                        .expect("length checked"),
                )
                .with_context(|| format!("failed to read blob meta block group {index}"))
            })
            .collect::<Result<Vec<_>>>()?;
        let blob_metadata = Self {
            header,
            blob_id,
            storage: BlobMetadataStorage::Owned {
                chunks,
                block_groups,
            },
        };
        blob_metadata.validate()?;
        Ok(blob_metadata)
    }

    /// Read blob metadata from a file (mmap-backed), without verifying the
    /// crc32; [`Self::loader`] holds the knobs.
    pub fn load(path: &Path) -> Result<Self> {
        Self::load_inner(path, false)
    }

    fn load_inner(path: &Path, check_crc32: bool) -> Result<Self> {
        let file = File::open(path)
            .with_context(|| format!("failed to open blob meta: {}", path.display()))?;
        let file_len = file.metadata()?.len();
        if file_len < NYDUS_BLOB_METADATA_HEADER_SIZE as u64 {
            return Err(Error::InvalidImage("blob meta file too small".to_string()));
        }
        let mmap = unsafe { MmapOptions::new().map(&file) }
            .with_context(|| format!("failed to mmap blob meta: {}", path.display()))?;
        let header = BlobMetadataHeader::from_bytes(
            mmap[..NYDUS_BLOB_METADATA_HEADER_SIZE]
                .try_into()
                .expect("length checked"),
        )?;
        if file_len != header.padded_size() {
            return Err(Error::InvalidImage(format!(
                "blob meta file size mismatch: expected {}, got {}",
                header.padded_size(),
                file_len
            )));
        }
        validate_padding(&mmap, &header)?;
        if check_crc32 {
            validate_blob_metadata_crc32(&mmap, &header)?;
        }
        let blob_metadata = Self {
            header,
            blob_id: [0u8; SHA256_DIGEST_SIZE],
            storage: BlobMetadataStorage::Mapped(mmap),
        };
        blob_metadata.validate()?;
        Ok(blob_metadata)
    }

    fn validate(&self) -> Result<()> {
        self.validate_chunks()?;
        self.validate_block_groups()
    }

    fn validate_block_groups(&self) -> Result<()> {
        let block_groups = self.block_groups();
        let block_group_block_count = self.header.block_group_block_count();
        if block_group_block_count == 0 {
            return Err(Error::InvalidImage(
                "blob meta block group block count must be non-zero".to_string(),
            ));
        }

        let is_redirect_blob = BlobMetadataBlockGroup::has_redirect(block_groups);
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

            if !is_redirect_blob {
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

    fn validate_chunks(&self) -> Result<()> {
        let uncompressed_block_end =
            BlobMetadataBlockGroup::compute_uncompressed_block_end(self.block_groups());
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

    pub fn checked_add_compressed_offset(&self, bias: u64) -> Result<Self> {
        let mut block_groups = Vec::with_capacity(self.block_group_count());
        for block_group in self.block_groups() {
            block_groups.push(block_group.checked_add_compressed_offset(bias)?);
        }

        Self::new(
            self.blob_id,
            self.compressor(),
            self.chunk_block_count(),
            self.chunks().to_vec(),
            block_groups,
        )
    }

    /// Start configuring a blob meta read; finish with
    /// [`load`](BlobMetadataLoader::load) or
    /// [`from_bytes`](BlobMetadataLoader::from_bytes).
    pub fn loader() -> BlobMetadataLoader {
        BlobMetadataLoader::default()
    }

    /// Write the serialized metadata (header, tables, zero padding) to
    /// `writer`.
    pub fn write_to(&self, writer: &mut dyn Write) -> Result<()> {
        // Reseal on write rather than emitting the stored crc32: for
        // metadata mapped from a newer writer, `to_bytes` zeroes the compat
        // fields in the reserved header tail, so the emitted bytes differ
        // from the stored ones and need their own seal.
        let mut header = self.header;
        header.crc32 = self.compute_crc32_from_parts();
        writer.write_all(&header.to_bytes())?;
        for chunk in self.chunks() {
            chunk.write_to(writer)?;
        }
        for block_group in self.block_groups() {
            block_group.write_to(writer)?;
        }
        // The tail padding is sub-block by construction (`padded_size` is
        // `used_size` aligned up to one block), so one zero block covers it.
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

    pub fn header(&self) -> &BlobMetadataHeader {
        &self.header
    }

    pub fn blob_id(&self) -> &[u8; SHA256_DIGEST_SIZE] {
        &self.blob_id
    }

    pub fn chunk_count(&self) -> usize {
        self.header.chunk_count() as usize
    }

    pub fn block_group_count(&self) -> usize {
        self.header.block_group_count() as usize
    }

    pub fn chunk_block_count(&self) -> u32 {
        self.header.chunk_block_count()
    }

    pub fn chunk_size(&self) -> u32 {
        self.header.chunk_size()
    }

    pub fn compressor(&self) -> BlobMetadataCompressor {
        self.header.compressor()
    }

    pub fn digester(&self) -> BlobMetadataDigester {
        self.header.digester()
    }

    pub fn chunks(&self) -> &[BlobMetadataChunk] {
        match &self.storage {
            BlobMetadataStorage::Owned { chunks, .. } => chunks,
            BlobMetadataStorage::Mapped(mmap) => mapped_chunks(mmap, &self.header),
        }
    }

    pub fn block_groups(&self) -> &[BlobMetadataBlockGroup] {
        match &self.storage {
            BlobMetadataStorage::Owned { block_groups, .. } => block_groups,
            BlobMetadataStorage::Mapped(mmap) => mapped_block_groups(mmap, &self.header),
        }
    }

    pub fn block_group_at(&self, index: usize) -> Option<&BlobMetadataBlockGroup> {
        self.block_groups().get(index)
    }

    /// True when this blob is an "ondemand" redirect blob: its block groups
    /// carry data belonging to other source blob devices.
    pub fn is_redirect_blob(&self) -> bool {
        BlobMetadataBlockGroup::has_redirect(self.block_groups())
    }

    /// Total number of uncompressed blocks in the dense address space.
    pub fn total_blocks(&self) -> u64 {
        BlobMetadataBlockGroup::compute_uncompressed_block_end(self.block_groups())
    }

    /// O(1) mapping from an uncompressed byte offset in the dense address
    /// space to the index of the block group that contains it, or `None`
    /// when the offset is past the end of the blob. Block groups are formed
    /// by packing blocks up to the block group size independent of chunk
    /// boundaries, so every block group except the last is exactly
    /// `1 << block_group_block_count_bits` blocks and the block group index is a
    /// single shift.
    pub fn block_group_index_for_offset(&self, offset: u64) -> Option<usize> {
        let block = offset / EROFS_BLOCK_SIZE as u64;
        if block >= self.total_blocks() {
            return None;
        }
        usize::try_from(block >> self.header.block_group_block_count_bits).ok()
    }

    pub fn total_uncompressed_size(&self) -> u64 {
        BlobMetadataBlockGroup::compute_uncompressed_end(self.block_groups())
    }

    pub fn total_compressed_size(&self) -> u64 {
        BlobMetadataBlockGroup::compute_compressed_end(self.block_groups())
    }

    pub fn padded_size(&self) -> u64 {
        self.header.padded_size()
    }

    fn compute_crc32(bytes: &[u8]) -> u32 {
        let (header, tail) = bytes.split_at(NYDUS_BLOB_METADATA_HEADER_SIZE);
        let mut zeroed: [u8; NYDUS_BLOB_METADATA_HEADER_SIZE] = header.try_into().unwrap();
        zeroed[NYDUS_BLOB_METADATA_HEADER_CRC32_FIELD].fill(0);
        crc32c_append(crc32c(&zeroed), tail)
    }

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

/// Options for reading a [`BlobMetadata`], created via [`BlobMetadata::loader`].
/// The two orthogonal knobs (CRC32 verification, attached blob id) replace
/// the previous per-combination constructors.
#[derive(Default, Clone, Copy)]
pub struct BlobMetadataLoader {
    verify_crc32: bool,
    blob_id: Option<[u8; SHA256_DIGEST_SIZE]>,
}

impl BlobMetadataLoader {
    /// Verify the header CRC32 over the full metadata during the read.
    pub fn verify_crc32(mut self) -> Self {
        self.verify_crc32 = true;
        self
    }

    /// Attach the owning blob id to the loaded metadata.
    pub fn blob_id(mut self, blob_id: [u8; SHA256_DIGEST_SIZE]) -> Self {
        self.blob_id = Some(blob_id);
        self
    }

    /// Read blob metadata from a file (mmap-backed).
    pub fn load(self, path: &Path) -> Result<BlobMetadata> {
        let mut blob_metadata = BlobMetadata::load_inner(path, self.verify_crc32)?;
        if let Some(blob_id) = self.blob_id {
            blob_metadata.blob_id = blob_id;
        }
        Ok(blob_metadata)
    }

    /// Read blob metadata from an in-memory byte slice.
    pub fn from_bytes(self, data: &[u8]) -> Result<BlobMetadata> {
        BlobMetadata::from_bytes(
            data,
            self.blob_id.unwrap_or([0u8; SHA256_DIGEST_SIZE]),
            self.verify_crc32,
        )
    }
}

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

fn validate_padding(data: &[u8], header: &BlobMetadataHeader) -> Result<()> {
    let padding_start = header.used_size() as usize;
    if data[padding_start..].iter().any(|byte| *byte != 0) {
        return Err(Error::InvalidImage(
            "blob meta padding must be zero".to_string(),
        ));
    }
    Ok(())
}

fn validate_blob_metadata_crc32(data: &[u8], header: &BlobMetadataHeader) -> Result<()> {
    let computed = BlobMetadata::compute_crc32(data);
    if computed != header.crc32() {
        return Err(Error::InvalidImage(format!(
            "blob meta header crc32 mismatch: stored {:#010x}, computed {:#010x}",
            header.crc32(),
            computed
        )));
    }
    Ok(())
}

fn mapped_chunks<'a>(data: &'a [u8], header: &BlobMetadataHeader) -> &'a [BlobMetadataChunk] {
    let offset = header.chunks_offset() as usize;
    let byte_len = header.chunk_count() as usize * size_of::<BlobMetadataChunk>();
    let bytes = &data[offset..offset + byte_len];
    let ptr = bytes.as_ptr().cast::<BlobMetadataChunk>();
    unsafe { std::slice::from_raw_parts(ptr, header.chunk_count() as usize) }
}

fn mapped_block_groups<'a>(
    data: &'a [u8],
    header: &BlobMetadataHeader,
) -> &'a [BlobMetadataBlockGroup] {
    let offset = header.block_groups_offset() as usize;
    let byte_len = header.block_group_count() as usize * size_of::<BlobMetadataBlockGroup>();
    let bytes = &data[offset..offset + byte_len];
    let ptr = bytes.as_ptr().cast::<BlobMetadataBlockGroup>();
    unsafe { std::slice::from_raw_parts(ptr, header.block_group_count() as usize) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn digest(bytes: &[u8]) -> [u8; 32] {
        *blake3::hash(bytes).as_bytes()
    }

    fn block_group(
        uncompressed_block_offset: u64,
        uncompressed_block_count: u32,
        compressed_offset: u64,
        compressed_size: u32,
        payload: &[u8],
    ) -> BlobMetadataBlockGroup {
        BlobMetadataBlockGroup::new(
            uncompressed_block_offset,
            uncompressed_block_count,
            compressed_offset,
            compressed_size,
            crc32c::crc32c(payload),
        )
        .unwrap()
    }

    fn chunk(
        payload: &[u8],
        uncompressed_block_offset: u64,
        uncompressed_block_count: u32,
    ) -> BlobMetadataChunk {
        BlobMetadataChunk::new(
            digest(payload),
            uncompressed_block_offset,
            uncompressed_block_count,
        )
        .unwrap()
    }

    /// The smallest interesting metadata: one single-block chunk in one
    /// block group.
    fn minimal_blob_metadata() -> BlobMetadata {
        let payload = vec![0x33; EROFS_BLOCK_SIZE as usize];
        BlobMetadata::new(
            [0x7bu8; SHA256_DIGEST_SIZE],
            BlobMetadataCompressor::None,
            1,
            vec![chunk(&payload, 0, 1)],
            vec![block_group(0, 1, 0, 4096, &payload)],
        )
        .unwrap()
    }

    fn sealed_metadata() -> Vec<u8> {
        let mut raw = Vec::new();
        minimal_blob_metadata().write_to(&mut raw).unwrap();
        raw
    }

    #[test]
    fn round_trips_through_mmap() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("blob.meta");
        let blob_id = [0x5au8; SHA256_DIGEST_SIZE];
        let payload_a = vec![0x11; EROFS_BLOCK_SIZE as usize];
        let payload_b = vec![0x22; EROFS_BLOCK_SIZE as usize];
        let block_group_payload = [payload_a.as_slice(), payload_b.as_slice()].concat();
        let blob_metadata = BlobMetadata::new(
            blob_id,
            BlobMetadataCompressor::None,
            1,
            vec![chunk(&payload_a, 0, 1), chunk(&payload_b, 1, 1)],
            vec![block_group(0, 2, 8192, 8192, &block_group_payload)],
        )
        .unwrap();

        blob_metadata.save(&path).unwrap();
        let loaded = BlobMetadata::load(&path).unwrap();

        assert_eq!(loaded.header().chunk_count(), 2);
        assert_eq!(loaded.header().block_group_count(), 1);
        assert_eq!(loaded.header().version(), NYDUS_BLOB_METADATA_VERSION);
        assert_eq!(loaded.header().chunk_table_size(), 96);
        assert_eq!(loaded.header().block_group_table_size(), 40);
        assert_eq!(loaded.header().used_size(), 4096 + 96 + 40);
        assert_eq!(loaded.header().padded_size(), 8192);
        assert_eq!(loaded.header().chunk_size(), EROFS_BLOCK_SIZE);
        assert_eq!(loaded.header().block_group_block_count(), 2);
        assert_eq!(loaded.header().compressor(), BlobMetadataCompressor::None);
        assert_eq!(loaded.header().digester(), BlobMetadataDigester::Blake3);
        assert_ne!(loaded.header().crc32(), 0);
        assert_eq!(loaded.block_groups()[0].compressed_offset(), 8192);
        assert_eq!(loaded.chunks()[1].digest(), &digest(&payload_b));
        assert_eq!(loaded.chunks()[1].uncompressed_block_offset(), 1);
        assert_eq!(loaded.block_group_index_for_offset(4096), Some(0));
        assert_eq!(loaded.total_uncompressed_size(), 8192);
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

        let loaded = BlobMetadata::loader().from_bytes(&raw).unwrap();

        assert_eq!(loaded.header().crc32(), corrupted_crc32);
        let err = match BlobMetadata::loader().verify_crc32().from_bytes(&raw) {
            Ok(_) => panic!("corrupted blob meta crc32 should be rejected"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("crc32"), "{err}");
    }

    #[test]
    fn legacy_magics_reject() {
        let dir = tempdir().unwrap();

        // Legacy magics from earlier format generations must all be rejected:
        // the old nydus compression-context magic and the v0 u32 "LPBM" magic
        // (which serialized as "MBPL" on disk).
        for (name, magic) in [
            ("nydus.blob.meta", 0xb10b_b10bu32),
            ("v0.blob.meta", 0x4c50_424du32),
        ] {
            let path = dir.path().join(name);
            let mut raw = vec![0u8; NYDUS_BLOB_METADATA_HEADER_SIZE];
            raw[..4].copy_from_slice(&magic.to_le_bytes());
            std::fs::write(&path, raw).unwrap();

            let err = match BlobMetadata::load(&path) {
                Ok(_) => panic!("{name}: legacy magic should be rejected"),
                Err(err) => err,
            };
            assert!(err.to_string().contains("magic"), "{name}: {err}");
        }
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

            // The unchecked read applies only the compat rules; the crc32
            // seal is a separate, opt-in check.
            let result = BlobMetadata::loader().from_bytes(&raw);
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

        // A future format generation is readable and preserved verbatim:
        // version is informational.
        let mut future = sealed_metadata();
        future[8..12].copy_from_slice(&(NYDUS_BLOB_METADATA_VERSION + 1).to_le_bytes());
        let loaded = BlobMetadata::loader().from_bytes(&future).unwrap();
        assert_eq!(loaded.header().version(), NYDUS_BLOB_METADATA_VERSION + 1);
    }

    #[test]
    fn the_reserved_tail_is_ignored_but_fails_the_crc32_check() {
        // Poke a byte inside the reserved header tail (between the last field
        // and the end of the 4 KiB header block): a future writer may place
        // compat fields there, so the unchecked read must ignore it — while
        // the crc-checked read still flags it, since this file's crc was
        // sealed over a zero tail.
        let mut raw = sealed_metadata();
        raw[NYDUS_BLOB_METADATA_HEADER_SIZE - 1] = 0xff;

        BlobMetadata::loader()
            .from_bytes(&raw)
            .expect("nonzero reserved tail must be ignored");
        let err = match BlobMetadata::loader().verify_crc32().from_bytes(&raw) {
            Ok(_) => panic!("crc check should catch the unsealed tail change"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("crc32"), "{err}");
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

        // Two invariants only raw bytes can violate — the constructors
        // cannot express a source block group index without a source blob,
        // nor a dirty reserved field.
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
    fn block_group_index_for_offset_maps_constant_sized_block_groups_by_division() {
        // Block groups pack blocks up to the block group size, so every block
        // group but the last holds exactly `block_group_block_count` blocks
        // (2 here) and the index is a single division. Chunk boundaries are
        // irrelevant to this mapping.
        let two = vec![0x11; 2 * EROFS_BLOCK_SIZE as usize];
        let one = vec![0x22; EROFS_BLOCK_SIZE as usize];
        let blob_metadata = BlobMetadata::new(
            [0u8; SHA256_DIGEST_SIZE],
            BlobMetadataCompressor::None,
            1,
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
        assert_eq!(blob_metadata.block_group_index_for_offset(0), Some(0));
        assert_eq!(
            blob_metadata.block_group_index_for_offset(2 * block - 1),
            Some(0)
        );
        assert_eq!(
            blob_metadata.block_group_index_for_offset(2 * block),
            Some(1)
        );
        assert_eq!(
            blob_metadata.block_group_index_for_offset(4 * block - 1),
            Some(1)
        );
        // The short final block group still maps by division.
        assert_eq!(
            blob_metadata.block_group_index_for_offset(4 * block),
            Some(2)
        );
        assert_eq!(
            blob_metadata.block_group_index_for_offset(5 * block - 1),
            Some(2)
        );
        // Past the end of the blob.
        assert_eq!(blob_metadata.block_group_index_for_offset(5 * block), None);
    }

    #[test]
    fn non_uniform_block_group_sizes_reject() {
        let two = vec![0x11; 2 * EROFS_BLOCK_SIZE as usize];
        let three = vec![0x22; 3 * EROFS_BLOCK_SIZE as usize];
        let one = vec![0x33; EROFS_BLOCK_SIZE as usize];
        // The first block group fixes the block group block count (2). The
        // middle block group is a non-final block group of 3 blocks, which
        // must be rejected.
        let err = match BlobMetadata::new(
            [0u8; SHA256_DIGEST_SIZE],
            BlobMetadataCompressor::None,
            1,
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
        ) {
            Ok(_) => panic!("non-uniform block group sizes should be rejected"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("must be exactly"), "{err}");
    }

    #[test]
    fn single_block_group_blob_uses_covering_power_of_two_exponent() {
        // A lone block group is also the (possibly short) tail, so its block
        // count may be any value — 3 here. The header stores the covering
        // exponent (4 blocks -> bits 2) so every block still shifts to block
        // group index 0.
        let three = vec![0x44; 3 * EROFS_BLOCK_SIZE as usize];
        let blob_metadata = BlobMetadata::new(
            [0u8; SHA256_DIGEST_SIZE],
            BlobMetadataCompressor::None,
            1,
            vec![chunk(&three, 0, 3)],
            vec![block_group(0, 3, 0, 3 * EROFS_BLOCK_SIZE, &three)],
        )
        .unwrap();

        assert_eq!(blob_metadata.header().block_group_block_count(), 4);
        let block = EROFS_BLOCK_SIZE as u64;
        for index in 0..3u64 {
            assert_eq!(
                blob_metadata.block_group_index_for_offset(index * block),
                Some(0)
            );
        }
        assert_eq!(blob_metadata.block_group_index_for_offset(3 * block), None);
    }

    #[test]
    fn multi_block_group_blob_requires_power_of_two_full_block_groups() {
        // With more than one block group the first is a full block group and
        // defines the exponent, so a non-power-of-two size (3 blocks) cannot
        // be encoded.
        let three = vec![0x55; 3 * EROFS_BLOCK_SIZE as usize];
        let one = vec![0x66; EROFS_BLOCK_SIZE as usize];
        let err = match BlobMetadata::new(
            [0u8; SHA256_DIGEST_SIZE],
            BlobMetadataCompressor::None,
            1,
            vec![chunk(&three, 0, 3), chunk(&one, 3, 1)],
            vec![
                block_group(0, 3, 0, 3 * EROFS_BLOCK_SIZE, &three),
                block_group(3, 1, 3 * EROFS_BLOCK_SIZE as u64, EROFS_BLOCK_SIZE, &one),
            ],
        ) {
            Ok(_) => panic!("non-power-of-two full block group should be rejected"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("power of two"), "{err}");
    }

    #[test]
    fn packed_compressed_offsets_need_no_block_alignment() {
        let two = vec![0x11; 2 * EROFS_BLOCK_SIZE as usize];
        // Block group 1 starts exactly at block group 0's compressed byte end
        // (5000), which is deliberately not block aligned: compressed block
        // groups pack back-to-back.
        let blob_metadata = BlobMetadata::new(
            [0u8; SHA256_DIGEST_SIZE],
            BlobMetadataCompressor::None,
            1,
            vec![chunk(&two, 0, 2), chunk(&two, 2, 2)],
            vec![
                block_group(0, 2, 0, 5000, &two),
                block_group(2, 2, 5000, 3000, &two),
            ],
        )
        .unwrap();

        assert_eq!(blob_metadata.block_groups()[1].compressed_offset(), 5000);
        assert_eq!(blob_metadata.total_compressed_size(), 8000);
    }

    #[test]
    fn overlapping_compressed_ranges_reject() {
        let two = vec![0x22; 2 * EROFS_BLOCK_SIZE as usize];
        // Block group 1 starts before block group 0's compressed byte end
        // (5000) -> overlap.
        let err = match BlobMetadata::new(
            [0u8; SHA256_DIGEST_SIZE],
            BlobMetadataCompressor::None,
            1,
            vec![chunk(&two, 0, 2), chunk(&two, 2, 2)],
            vec![
                block_group(0, 2, 0, 5000, &two),
                block_group(2, 2, 4999, 3000, &two),
            ],
        ) {
            Ok(_) => panic!("overlapping compressed ranges should be rejected"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("overlap"), "{err}");
    }

    #[test]
    fn redirect_block_group_round_trips_and_reports_source() {
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

        // Normal block groups stay non-redirect after a round trip.
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
            [0x9du8; SHA256_DIGEST_SIZE],
            BlobMetadataCompressor::None,
            DEFAULT_NYDUS_BLOB_METADATA_CHUNK_BLOCK_COUNT,
            Vec::new(),
            block_groups.clone(),
        )
        .unwrap();
        assert!(blob_metadata.is_redirect_blob());
        // Redirect block groups are non-uniform and never use the
        // block-to-block group mapping, so the header keeps the default
        // exponent.
        assert_eq!(
            blob_metadata.header().block_group_block_count(),
            DEFAULT_NYDUS_BLOB_METADATA_BLOCK_GROUP_BLOCK_COUNT
        );

        blob_metadata.save(&path).unwrap();
        let loaded = BlobMetadata::load(&path).unwrap();
        assert!(loaded.is_redirect_blob());
        assert_eq!(loaded.block_groups(), block_groups.as_slice());
        assert_eq!(loaded.block_groups()[1].source_blob_index(), 2);
        assert_eq!(loaded.block_groups()[2].source_block_group_index(), 9);
    }
}

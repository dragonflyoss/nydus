use crate::blob::validate::{crc32_with_zeroed_field, validate_incompat_flags};
use crate::erofs::EROFS_BLOCK_SIZE;
use crate::error::{Context, Error, Result};
use crate::utils::le::{read_u16_from, read_u32_from, read_u64_from};
use crate::utils::SHA256_DIGEST_SIZE;
use bitflags::bitflags;
use crc32c::crc32c_append;
use memmap2::{Mmap, MmapOptions};
use std::fmt;
use std::fs::File;
use std::io::{Cursor, Read, Write};
use std::mem::{align_of, size_of};
use std::path::Path;

/// On-disk magic: 8 raw ASCII bytes ("LPBLMETA" = LePton BLob META),
/// written as-is so a hexdump of the file starts with the readable string.
pub const BLOB_METADATA_MAGIC: [u8; 8] = *b"LPBLMETA";
/// On-disk format generation, informational only: readers do not gate on it.
/// Compatibility is governed EROFS-style by the magic (a new format family
/// gets a new magic) and by the incompat half of `flags` (unknown incompat
/// bits reject the file).
pub const BLOB_METADATA_VERSION: u32 = 1;
/// Fixed header size: one EROFS block. The chunk table starts right after
/// the header, so it is block aligned by construction, and the unused tail
/// of the header block is reserved for future compat fields (writers zero
/// it, readers ignore it; corruption is caught by the file crc32c).
pub const BLOB_METADATA_HEADER_SIZE: u64 = EROFS_BLOCK_SIZE as u64;
pub const BLOB_METADATA_DEFAULT_CHUNK_SIZE: u32 = 1024 * 1024;
pub const BLOB_METADATA_DEFAULT_CHUNK_BLOCK_COUNT: u32 =
    BLOB_METADATA_DEFAULT_CHUNK_SIZE / EROFS_BLOCK_SIZE;
/// File-name suffix of a blob meta sidecar file (`<blob>.blob.meta`).
pub const BLOB_METADATA_SUFFIX: &str = ".blob.meta";

/// Largest allowed block-count exponent (`chunk_block_bits` /
/// `group_block_bits`): keeps the derived byte size (`4096 << bits`)
/// representable in a `u32` (2 GiB at most).
const BLOB_METADATA_MAX_BLOCK_BITS: u8 = 19;

const BLOB_METADATA_HEADER_CRC32_OFFSET: usize = 16;
/// Bytes of the header actually carrying fields; the rest of the 4 KiB
/// header block is a reserved compat area (writer-zeroed, reader-ignored).
const BLOB_METADATA_HEADER_FIELD_BYTES: usize = 64;
const BLOB_METADATA_GROUP_RESERVED: [u8; 6] = [0u8; 6];
const BLOB_METADATA_CHUNK_RESERVED: u32 = 0;
const BLOB_METADATA_CDC_CHUNK_RESERVED: u32 = 0;

bitflags! {
    /// Feature bits, split EROFS-style: the low 16 bits are **incompatible**
    /// features — a reader that does not know a set bit cannot interpret the
    /// file and must reject it (like `feature_incompat`). The high 16 bits
    /// are **compatible** features — unknown bits are ignored so old readers
    /// keep working (like `feature_compat`). Record-layout evolution (wider
    /// chunk/group records, new record kinds) is expressed as a new incompat
    /// bit; header growth uses the reserved tail plus a compat bit.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct BlobMetadataFlags: u32 {
        const COMPRESSOR_ZSTD = 1 << 0;
        const DIGESTER_BLAKE3 = 1 << 1;
        /// Incompat: the chunk table holds variable-size CDC (content-defined
        /// chunking) records ([`BlobMetadataCdcChunk`], 56 bytes each) instead
        /// of fixed-size [`BlobMetadataChunk`] records. Groups then describe
        /// the deduplicated *unique* data stream, while EROFS inode chunk
        /// indexes keep pointing into the dense *logical* address space whose
        /// size is carried by the header `logical_block_count` field.
        const CHUNK_CDC = 1 << 2;
    }
}

const BLOB_METADATA_COMPRESSOR_MASK: u32 = BlobMetadataFlags::COMPRESSOR_ZSTD.bits();
const BLOB_METADATA_DIGESTER_MASK: u32 = BlobMetadataFlags::DIGESTER_BLAKE3.bits();

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlobMetadataCompressor {
    None = 0,
    Zstd = 1,
}

impl BlobMetadataCompressor {
    pub fn flag(self) -> BlobMetadataFlags {
        match self {
            Self::None => BlobMetadataFlags::empty(),
            Self::Zstd => BlobMetadataFlags::COMPRESSOR_ZSTD,
        }
    }
}

impl fmt::Display for BlobMetadataCompressor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => f.write_str("none"),
            Self::Zstd => f.write_str("zstd"),
        }
    }
}

impl TryFrom<BlobMetadataFlags> for BlobMetadataCompressor {
    type Error = crate::error::Error;

    fn try_from(value: BlobMetadataFlags) -> Result<Self> {
        match value.bits() & BLOB_METADATA_COMPRESSOR_MASK {
            0 => Ok(Self::None),
            bits if bits == BlobMetadataFlags::COMPRESSOR_ZSTD.bits() => Ok(Self::Zstd),
            bits => Err(crate::error::Error::Unsupported(format!(
                "unsupported blob meta compressor flag set: {bits:#x}"
            ))),
        }
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlobMetadataDigester {
    Blake3 = 1,
}

impl BlobMetadataDigester {
    pub fn flag(self) -> BlobMetadataFlags {
        match self {
            Self::Blake3 => BlobMetadataFlags::DIGESTER_BLAKE3,
        }
    }
}

impl fmt::Display for BlobMetadataDigester {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Blake3 => f.write_str("blake3"),
        }
    }
}

impl TryFrom<BlobMetadataFlags> for BlobMetadataDigester {
    type Error = crate::error::Error;

    fn try_from(value: BlobMetadataFlags) -> Result<Self> {
        match value.bits() & BLOB_METADATA_DIGESTER_MASK {
            bits if bits == BlobMetadataFlags::DIGESTER_BLAKE3.bits() => Ok(Self::Blake3),
            0 => Err(crate::error::Error::InvalidImage(
                "blob meta digester flag is missing".to_string(),
            )),
            bits => Err(crate::error::Error::Unsupported(format!(
                "unsupported blob meta digester flag set: {bits:#x}"
            ))),
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlobMetadataHeader {
    magic: [u8; 8],
    version: u32,
    flags: u32,
    crc32: u32,
    reserved0: u32,
    chunks_offset: u64,
    groups_offset: u64,
    chunk_count: u32,
    group_count: u32,
    /// log2 of the chunk size in 4 KiB blocks, EROFS-style (the same quantity
    /// as `chunk_format & EROFS_CHUNK_FORMAT_BLKBITS_MASK`, i.e. `chunkbits -
    /// blkbits`). Storing the exponent makes non-power-of-two chunk sizes
    /// unrepresentable and feeds shift-based offset math directly.
    chunk_block_bits: u8,
    /// log2 of the per-group block count, same representation as
    /// `chunk_block_bits`. The read path maps a block to its group with
    /// `block >> group_block_bits`.
    group_block_bits: u8,
    /// Size of the dense logical (deduplicated-view) address space in 4 KiB
    /// blocks. Only meaningful when [`BlobMetadataFlags::CHUNK_CDC`] is set:
    /// with dedup the logical space referenced by EROFS chunk indexes is
    /// larger than the unique data space described by the groups, so it can
    /// no longer be derived from the group table. Zero for non-CDC blobs.
    logical_block_count: u64,
}

const _: () = assert!(size_of::<BlobMetadataHeader>() == BLOB_METADATA_HEADER_FIELD_BYTES);

impl Default for BlobMetadataHeader {
    fn default() -> Self {
        Self {
            magic: BLOB_METADATA_MAGIC,
            version: BLOB_METADATA_VERSION,
            flags: BlobMetadataDigester::Blake3.flag().bits(),
            crc32: 0,
            reserved0: 0,
            chunks_offset: BLOB_METADATA_HEADER_SIZE,
            groups_offset: BLOB_METADATA_HEADER_SIZE,
            chunk_count: 0,
            group_count: 0,
            chunk_block_bits: BLOB_METADATA_DEFAULT_CHUNK_BLOCK_COUNT.trailing_zeros() as u8,
            group_block_bits: BLOB_METADATA_DEFAULT_CHUNK_BLOCK_COUNT.trailing_zeros() as u8,
            logical_block_count: 0,
        }
    }
}

impl BlobMetadataHeader {
    pub fn version(&self) -> u32 {
        self.version
    }

    pub fn chunk_count(&self) -> u32 {
        self.chunk_count
    }

    pub fn group_count(&self) -> u32 {
        self.group_count
    }

    /// Number of 4 KiB blocks per chunk, derived from the stored exponent.
    pub fn chunk_block_count(&self) -> u32 {
        1u32 << self.chunk_block_bits
    }

    /// log2 of the per-group block count.
    pub fn group_block_bits(&self) -> u8 {
        self.group_block_bits
    }

    /// Number of uncompressed blocks per group, derived from the stored
    /// exponent. Every group except the last is exactly this many blocks, so
    /// the read path maps a block to its group by `block >> group_block_bits`.
    pub fn group_block_count(&self) -> u32 {
        1u32 << self.group_block_bits
    }

    pub fn chunk_size(&self) -> u32 {
        EROFS_BLOCK_SIZE << self.chunk_block_bits
    }

    pub fn flags(&self) -> BlobMetadataFlags {
        self.validated_flags().expect("validated blob meta flags")
    }

    pub fn crc32(&self) -> u32 {
        self.crc32
    }

    pub fn compressor(&self) -> BlobMetadataCompressor {
        BlobMetadataCompressor::try_from(self.flags()).expect("validated blob meta compressor")
    }

    pub fn digester(&self) -> BlobMetadataDigester {
        BlobMetadataDigester::try_from(self.flags()).expect("validated blob meta digester")
    }

    pub fn chunks_offset(&self) -> u64 {
        self.chunks_offset
    }

    pub fn groups_offset(&self) -> u64 {
        self.groups_offset
    }

    /// Whether the chunk table holds variable-size CDC records.
    pub fn is_cdc(&self) -> bool {
        self.flags().contains(BlobMetadataFlags::CHUNK_CDC)
    }

    /// Size of the dense logical address space in 4 KiB blocks (CDC blobs
    /// only; zero otherwise).
    pub fn logical_block_count(&self) -> u64 {
        self.logical_block_count
    }

    /// On-disk size of one chunk record, depending on the chunk table kind.
    fn chunk_record_size(&self) -> u64 {
        if self.is_cdc() {
            size_of::<BlobMetadataCdcChunk>() as u64
        } else {
            size_of::<BlobMetadataChunk>() as u64
        }
    }

    pub fn chunk_bytes(&self) -> u64 {
        self.chunk_count as u64 * self.chunk_record_size()
    }

    pub fn group_bytes(&self) -> u64 {
        self.group_count as u64 * size_of::<BlobMetadataGroup>() as u64
    }

    /// End offset of the record region (header plus chunk and group tables),
    /// before padding to the block-aligned `metadata_size`.
    pub fn records_end(&self) -> u64 {
        self.groups_offset + self.group_bytes()
    }

    pub fn metadata_size(&self) -> u64 {
        crate::utils::align_up(self.records_end(), EROFS_BLOCK_SIZE as u64)
            .expect("blob meta size overflowed")
    }

    fn set_counts_and_offsets(&mut self, chunk_count: u32, group_count: u32) -> Result<()> {
        self.chunk_count = chunk_count;
        self.group_count = group_count;
        self.chunks_offset = BLOB_METADATA_HEADER_SIZE;
        self.groups_offset = self
            .chunks_offset
            .checked_add(chunk_count as u64 * self.chunk_record_size())
            .ok_or_else(|| Error::Overflow("blob meta group offset overflow".to_string()))?;
        Ok(())
    }

    fn set_cdc(&mut self, logical_block_count: u64) {
        self.flags |= BlobMetadataFlags::CHUNK_CDC.bits();
        self.logical_block_count = logical_block_count;
    }

    fn set_chunk_block_count(&mut self, blocks: u32) -> Result<()> {
        self.chunk_block_bits = block_count_to_bits(blocks, "chunk")?;
        Ok(())
    }

    fn set_compressor(&mut self, compressor: BlobMetadataCompressor) {
        let mut flags = self.flags();
        flags.remove(BlobMetadataFlags::COMPRESSOR_ZSTD);
        flags.insert(compressor.flag());
        self.flags = flags.bits();
    }

    fn validate(&self) -> Result<()> {
        if self.magic != BLOB_METADATA_MAGIC {
            return Err(Error::InvalidImage("invalid blob meta magic".to_string()));
        }
        // `version` is informational and deliberately not gated on:
        // compatibility is carried by the magic and the incompat flag bits.
        // `reserved0` is likewise not enforced to zero: it is a future
        // compat-field slot, and corruption is caught by the file crc32c.
        if self.chunk_block_bits > BLOB_METADATA_MAX_BLOCK_BITS {
            return Err(Error::InvalidImage(format!(
                "blob meta chunk block bits too large: {}",
                self.chunk_block_bits
            )));
        }
        if self.group_block_bits > BLOB_METADATA_MAX_BLOCK_BITS {
            return Err(Error::InvalidImage(format!(
                "blob meta group block bits too large: {}",
                self.group_block_bits
            )));
        }
        self.validated_flags()?;
        if self.chunks_offset != BLOB_METADATA_HEADER_SIZE {
            return Err(Error::InvalidImage(format!(
                "invalid blob meta chunks offset: {}",
                self.chunks_offset
            )));
        }
        let expected_groups_offset = self
            .chunks_offset
            .checked_add(self.chunk_bytes())
            .ok_or_else(|| Error::Overflow("blob meta group offset overflow".to_string()))?;
        if self.groups_offset != expected_groups_offset {
            return Err(Error::InvalidImage(format!(
                "invalid blob meta groups offset: {}",
                self.groups_offset
            )));
        }
        if self.chunks_offset % align_of::<BlobMetadataChunk>() as u64 != 0
            || self.chunks_offset % align_of::<BlobMetadataCdcChunk>() as u64 != 0
        {
            return Err(Error::InvalidImage(
                "blob meta chunks offset is not aligned".to_string(),
            ));
        }
        if self.groups_offset % align_of::<BlobMetadataGroup>() as u64 != 0 {
            return Err(Error::InvalidImage(
                "blob meta groups offset is not aligned".to_string(),
            ));
        }
        if self.is_cdc() {
            if self.logical_block_count == 0 && self.chunk_count != 0 {
                return Err(Error::InvalidImage(
                    "blob meta CDC logical block count must be non-zero".to_string(),
                ));
            }
        } else if self.logical_block_count != 0 {
            return Err(Error::InvalidImage(
                "blob meta logical block count requires the CDC flag".to_string(),
            ));
        }
        Ok(())
    }

    fn validated_flags(&self) -> Result<BlobMetadataFlags> {
        // EROFS-style feature gating: unknown incompat (low-half) bits mean
        // the file cannot be read correctly and must be rejected; unknown
        // compat (high-half) bits are ignored.
        validate_incompat_flags(self.flags, BlobMetadataFlags::all().bits(), "blob meta")?;
        let flags = BlobMetadataFlags::from_bits_truncate(self.flags);
        BlobMetadataCompressor::try_from(flags)?;
        BlobMetadataDigester::try_from(flags)?;
        Ok(flags)
    }

    fn write_to_with_crc32(&self, writer: &mut dyn Write, crc32: u32) -> Result<()> {
        writer.write_all(&self.to_bytes_with_crc32(crc32))?;
        Ok(())
    }

    fn to_bytes_with_crc32(self, crc32: u32) -> [u8; BLOB_METADATA_HEADER_SIZE as usize] {
        let mut data = [0u8; BLOB_METADATA_HEADER_SIZE as usize];
        data[0..8].copy_from_slice(&self.magic);
        data[8..12].copy_from_slice(&self.version.to_le_bytes());
        data[12..16].copy_from_slice(&self.flags.to_le_bytes());
        data[BLOB_METADATA_HEADER_CRC32_OFFSET..BLOB_METADATA_HEADER_CRC32_OFFSET + 4]
            .copy_from_slice(&crc32.to_le_bytes());
        data[20..24].copy_from_slice(&self.reserved0.to_le_bytes());
        data[24..32].copy_from_slice(&self.chunks_offset.to_le_bytes());
        data[32..40].copy_from_slice(&self.groups_offset.to_le_bytes());
        data[40..44].copy_from_slice(&self.chunk_count.to_le_bytes());
        data[44..48].copy_from_slice(&self.group_count.to_le_bytes());
        data[48] = self.chunk_block_bits;
        data[49] = self.group_block_bits;
        // data[50..56] stays zero: reserved after the two u8 exponents.
        data[56..64].copy_from_slice(&self.logical_block_count.to_le_bytes());
        // data[64..4096] stays zero: reserved header tail.
        data
    }

    fn read_from(reader: &mut dyn Read) -> Result<Self> {
        let header = Self {
            magic: read_magic(reader)?,
            version: read_u32_from(reader)?,
            flags: read_u32_from(reader)?,
            crc32: read_u32_from(reader)?,
            reserved0: read_u32_from(reader)?,
            chunks_offset: read_u64_from(reader)?,
            groups_offset: read_u64_from(reader)?,
            chunk_count: read_u32_from(reader)?,
            group_count: read_u32_from(reader)?,
            chunk_block_bits: read_u8(reader)?,
            group_block_bits: {
                let bits = read_u8(reader)?;
                // Skip the 6 reserved bytes after the two u8 exponents.
                let mut pad = [0u8; 6];
                reader.read_exact(&mut pad)?;
                bits
            },
            logical_block_count: read_u64_from(reader)?,
        };
        // The rest of the header block is reserved for future compat fields.
        // Writers zero it, but readers deliberately do not enforce that
        // (EROFS-style): a newer writer may have placed compat fields here
        // that this reader ignores. Corruption is caught by the file crc32c.
        let mut tail = [0u8; BLOB_METADATA_HEADER_SIZE as usize - BLOB_METADATA_HEADER_FIELD_BYTES];
        reader.read_exact(&mut tail)?;
        header.validate()?;
        Ok(header)
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BlobMetadataGroup {
    uncompressed_block_offset: u64,
    compressed_byte_offset: u64,
    uncompressed_block_count: u32,
    compressed_size: u32,
    crc32: u32,
    source_group_index: u32,
    source_blob_index: u16,
    reserved: [u8; 6],
}

const _: () = assert!(size_of::<BlobMetadataGroup>() == 40);

impl BlobMetadataGroup {
    pub fn new(
        uncompressed_block_offset: u64,
        uncompressed_block_count: u32,
        compressed_byte_offset: u64,
        compressed_size: u32,
        crc32: u32,
    ) -> Result<Self> {
        let group = Self {
            uncompressed_block_offset,
            compressed_byte_offset,
            uncompressed_block_count,
            compressed_size,
            crc32,
            source_group_index: 0,
            source_blob_index: 0,
            reserved: BLOB_METADATA_GROUP_RESERVED,
        };
        group.validate()?;
        Ok(group)
    }

    /// A redirect group carries data that belongs to another (source) blob.
    /// At prefetch time the decoded bytes are written into the source blob's
    /// cache instead of this blob's own cache. `source_blob_index` is the
    /// 1-based blob index from the bootstrap device table and must be
    /// non-zero; `crc32` must equal the source group's crc32 so the redirect
    /// can be cross-checked before filling the source cache.
    #[allow(clippy::too_many_arguments)]
    pub fn new_redirect(
        uncompressed_block_offset: u64,
        uncompressed_block_count: u32,
        compressed_byte_offset: u64,
        compressed_size: u32,
        crc32: u32,
        source_blob_index: u16,
        source_group_index: u32,
    ) -> Result<Self> {
        if source_blob_index == 0 {
            return Err(Error::InvalidImage(
                "blob meta redirect group source blob index must be non-zero".to_string(),
            ));
        }
        let group = Self {
            uncompressed_block_offset,
            compressed_byte_offset,
            uncompressed_block_count,
            compressed_size,
            crc32,
            source_group_index,
            source_blob_index,
            reserved: BLOB_METADATA_GROUP_RESERVED,
        };
        group.validate()?;
        Ok(group)
    }

    pub fn is_redirect(&self) -> bool {
        self.source_blob_index != 0
    }

    pub fn source_blob_index(&self) -> u16 {
        self.source_blob_index
    }

    pub fn source_group_index(&self) -> u32 {
        self.source_group_index
    }

    pub fn uncompressed_block_offset(&self) -> u64 {
        self.uncompressed_block_offset
    }

    pub fn uncompressed_block_count(&self) -> u32 {
        self.uncompressed_block_count
    }

    pub fn compressed_size(&self) -> u32 {
        self.compressed_size
    }

    pub fn crc32(&self) -> u32 {
        self.crc32
    }

    pub fn uncompressed_byte_offset(&self) -> u64 {
        self.uncompressed_block_offset
            .checked_mul(EROFS_BLOCK_SIZE as u64)
            .expect("validated blob meta group byte offset")
    }

    pub fn uncompressed_byte_size(&self) -> u64 {
        self.uncompressed_block_count as u64 * EROFS_BLOCK_SIZE as u64
    }

    pub fn uncompressed_byte_end(&self) -> u64 {
        self.uncompressed_byte_offset() + self.uncompressed_byte_size()
    }

    /// Byte offset of this group's encoded payload within the blob data region.
    /// Groups are packed back-to-back, so this is a plain byte position and is
    /// not block-aligned for compressed groups.
    pub fn compressed_byte_offset(&self) -> u64 {
        self.compressed_byte_offset
    }

    pub fn compressed_byte_end(&self) -> u64 {
        self.compressed_byte_offset + self.compressed_size as u64
    }

    pub fn with_compressed_byte_offset_bias(&self, byte_bias: u64) -> Result<Self> {
        let group = Self {
            compressed_byte_offset: self
                .compressed_byte_offset()
                .checked_add(byte_bias)
                .ok_or_else(|| {
                    Error::Overflow("blob meta compressed byte offset overflow".to_string())
                })?,
            ..*self
        };
        group.validate()?;
        Ok(group)
    }

    pub fn write_to(&self, writer: &mut dyn Write) -> Result<()> {
        self.validate()?;
        writer.write_all(&self.to_bytes())?;
        Ok(())
    }

    fn to_bytes(self) -> [u8; 40] {
        let mut data = [0u8; 40];
        data[0..8].copy_from_slice(&self.uncompressed_block_offset.to_le_bytes());
        data[8..16].copy_from_slice(&self.compressed_byte_offset.to_le_bytes());
        data[16..20].copy_from_slice(&self.uncompressed_block_count.to_le_bytes());
        data[20..24].copy_from_slice(&self.compressed_size.to_le_bytes());
        data[24..28].copy_from_slice(&self.crc32.to_le_bytes());
        data[28..32].copy_from_slice(&self.source_group_index.to_le_bytes());
        data[32..34].copy_from_slice(&self.source_blob_index.to_le_bytes());
        data[34..40].copy_from_slice(&self.reserved);
        data
    }

    pub fn read_from(reader: &mut dyn Read) -> Result<Self> {
        let group = Self {
            uncompressed_block_offset: read_u64_from(reader)?,
            compressed_byte_offset: read_u64_from(reader)?,
            uncompressed_block_count: read_u32_from(reader)?,
            compressed_size: read_u32_from(reader)?,
            crc32: read_u32_from(reader)?,
            source_group_index: read_u32_from(reader)?,
            source_blob_index: read_u16_from(reader)?,
            reserved: read_group_reserved(reader)?,
        };
        group.validate()?;
        Ok(group)
    }

    fn validate(&self) -> Result<()> {
        if self.uncompressed_block_count == 0 {
            return Err(Error::InvalidImage(
                "blob meta group uncompressed block count must be non-zero".to_string(),
            ));
        }
        if self.compressed_size == 0 {
            return Err(Error::InvalidImage(
                "blob meta group compressed size must be non-zero".to_string(),
            ));
        }
        self.uncompressed_block_offset
            .checked_mul(EROFS_BLOCK_SIZE as u64)
            .ok_or_else(|| {
                Error::Overflow("blob meta group uncompressed byte offset overflow".to_string())
            })?;
        self.uncompressed_byte_offset()
            .checked_add(self.uncompressed_byte_size())
            .ok_or_else(|| {
                Error::Overflow("blob meta group uncompressed byte range overflow".to_string())
            })?;
        self.compressed_byte_offset
            .checked_add(self.compressed_size as u64)
            .ok_or_else(|| {
                Error::Overflow("blob meta group compressed byte range overflow".to_string())
            })?;
        if self.source_blob_index == 0 && self.source_group_index != 0 {
            return Err(Error::InvalidImage(
                "blob meta group source group index requires a source blob index".to_string(),
            ));
        }
        if self.reserved != BLOB_METADATA_GROUP_RESERVED {
            return Err(Error::InvalidImage(
                "blob meta group reserved field must be zero".to_string(),
            ));
        }
        Ok(())
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BlobMetadataChunk {
    digest: [u8; 32],
    uncompressed_block_offset: u64,
    uncompressed_block_count: u32,
    reserved: u32,
}

const _: () = assert!(size_of::<BlobMetadataChunk>() == 48);

impl BlobMetadataChunk {
    pub fn new(
        digest: [u8; 32],
        uncompressed_block_offset: u64,
        uncompressed_block_count: u32,
    ) -> Result<Self> {
        let chunk = Self {
            digest,
            uncompressed_block_offset,
            uncompressed_block_count,
            reserved: BLOB_METADATA_CHUNK_RESERVED,
        };
        chunk.validate()?;
        Ok(chunk)
    }

    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    /// Absolute block offset of this chunk within the dense uncompressed address
    /// space. Chunks are independent of groups, so this is a plain block index
    /// into the blob, not a group-relative offset.
    pub fn uncompressed_block_offset(&self) -> u64 {
        self.uncompressed_block_offset
    }

    pub fn uncompressed_block_count(&self) -> u32 {
        self.uncompressed_block_count
    }

    pub fn uncompressed_byte_offset(&self) -> u64 {
        self.uncompressed_block_offset * EROFS_BLOCK_SIZE as u64
    }

    pub fn uncompressed_byte_size(&self) -> u64 {
        self.uncompressed_block_count as u64 * EROFS_BLOCK_SIZE as u64
    }

    pub fn write_to(&self, writer: &mut dyn Write) -> Result<()> {
        self.validate()?;
        writer.write_all(&self.to_bytes())?;
        Ok(())
    }

    fn to_bytes(self) -> [u8; 48] {
        let mut data = [0u8; 48];
        data[0..32].copy_from_slice(&self.digest);
        data[32..40].copy_from_slice(&self.uncompressed_block_offset.to_le_bytes());
        data[40..44].copy_from_slice(&self.uncompressed_block_count.to_le_bytes());
        data[44..48].copy_from_slice(&self.reserved.to_le_bytes());
        data
    }

    pub fn read_from(reader: &mut dyn Read) -> Result<Self> {
        let chunk = Self {
            digest: read_digest(reader)?,
            uncompressed_block_offset: read_u64_from(reader)?,
            uncompressed_block_count: read_u32_from(reader)?,
            reserved: read_u32_from(reader)?,
        };
        chunk.validate()?;
        Ok(chunk)
    }

    fn validate(&self) -> Result<()> {
        if self.uncompressed_block_count == 0 {
            return Err(Error::InvalidImage(
                "blob meta chunk uncompressed block count must be non-zero".to_string(),
            ));
        }
        self.uncompressed_byte_offset()
            .checked_add(self.uncompressed_byte_size())
            .ok_or_else(|| Error::Overflow("blob meta chunk byte range overflow".to_string()))?;
        if self.reserved != BLOB_METADATA_CHUNK_RESERVED {
            return Err(Error::InvalidImage(
                "blob meta chunk reserved field must be zero".to_string(),
            ));
        }
        Ok(())
    }
}

/// A variable-size content-defined (CDC) chunk record — 56 bytes on disk,
/// present when [`BlobMetadataFlags::CHUNK_CDC`] is set.
///
/// A CDC record maps one byte range of the dense *logical* address space
/// (what EROFS inode chunk indexes point at) to the byte range holding its
/// deduplicated content in the *unique* data stream (what the groups
/// compress). Several records may share the same unique range — that is the
/// deduplication. Records are sorted by logical offset and never overlap;
/// logical bytes not covered by any record (file-tail block padding and
/// holes) read as zeros.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BlobMetadataCdcChunk {
    digest: [u8; 32],
    logical_byte_offset: u64,
    unique_byte_offset: u64,
    size: u32,
    reserved: u32,
}

const _: () = assert!(size_of::<BlobMetadataCdcChunk>() == 56);

impl BlobMetadataCdcChunk {
    pub fn new(
        digest: [u8; 32],
        logical_byte_offset: u64,
        unique_byte_offset: u64,
        size: u32,
    ) -> Result<Self> {
        let chunk = Self {
            digest,
            logical_byte_offset,
            unique_byte_offset,
            size,
            reserved: BLOB_METADATA_CDC_CHUNK_RESERVED,
        };
        chunk.validate()?;
        Ok(chunk)
    }

    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    /// Byte offset of this chunk within the dense logical address space.
    pub fn logical_byte_offset(&self) -> u64 {
        self.logical_byte_offset
    }

    /// Byte offset of this chunk's content within the unique data stream
    /// described by the groups.
    pub fn unique_byte_offset(&self) -> u64 {
        self.unique_byte_offset
    }

    pub fn size(&self) -> u32 {
        self.size
    }

    pub fn logical_byte_end(&self) -> u64 {
        self.logical_byte_offset + self.size as u64
    }

    pub fn unique_byte_end(&self) -> u64 {
        self.unique_byte_offset + self.size as u64
    }

    pub fn write_to(&self, writer: &mut dyn Write) -> Result<()> {
        self.validate()?;
        writer.write_all(&self.to_bytes())?;
        Ok(())
    }

    fn to_bytes(self) -> [u8; 56] {
        let mut data = [0u8; 56];
        data[0..32].copy_from_slice(&self.digest);
        data[32..40].copy_from_slice(&self.logical_byte_offset.to_le_bytes());
        data[40..48].copy_from_slice(&self.unique_byte_offset.to_le_bytes());
        data[48..52].copy_from_slice(&self.size.to_le_bytes());
        data[52..56].copy_from_slice(&self.reserved.to_le_bytes());
        data
    }

    pub fn read_from(reader: &mut dyn Read) -> Result<Self> {
        let chunk = Self {
            digest: read_digest(reader)?,
            logical_byte_offset: read_u64_from(reader)?,
            unique_byte_offset: read_u64_from(reader)?,
            size: read_u32_from(reader)?,
            reserved: read_u32_from(reader)?,
        };
        chunk.validate()?;
        Ok(chunk)
    }

    fn validate(&self) -> Result<()> {
        if self.size == 0 {
            return Err(Error::InvalidImage(
                "blob meta CDC chunk size must be non-zero".to_string(),
            ));
        }
        self.logical_byte_offset
            .checked_add(self.size as u64)
            .ok_or_else(|| {
                Error::Overflow("blob meta CDC chunk logical byte range overflow".to_string())
            })?;
        self.unique_byte_offset
            .checked_add(self.size as u64)
            .ok_or_else(|| {
                Error::Overflow("blob meta CDC chunk unique byte range overflow".to_string())
            })?;
        if self.reserved != BLOB_METADATA_CDC_CHUNK_RESERVED {
            return Err(Error::InvalidImage(
                "blob meta CDC chunk reserved field must be zero".to_string(),
            ));
        }
        Ok(())
    }
}

enum BlobMetadataStorage {
    Owned {
        chunks: Vec<BlobMetadataChunk>,
        cdc_chunks: Vec<BlobMetadataCdcChunk>,
        groups: Vec<BlobMetadataGroup>,
    },
    Mapped(Mmap),
}

pub struct BlobMetadata {
    header: BlobMetadataHeader,
    blob_id: [u8; SHA256_DIGEST_SIZE],
    storage: BlobMetadataStorage,
}

impl BlobMetadata {
    pub fn from_parts(
        blob_id: [u8; SHA256_DIGEST_SIZE],
        chunk_block_count: u32,
        groups: Vec<BlobMetadataGroup>,
        chunks: Vec<BlobMetadataChunk>,
    ) -> Result<Self> {
        Self::from_parts_with_options(
            blob_id,
            chunk_block_count,
            BlobMetadataCompressor::None,
            groups,
            chunks,
        )
    }

    pub fn from_parts_with_options(
        blob_id: [u8; SHA256_DIGEST_SIZE],
        chunk_block_count: u32,
        compressor: BlobMetadataCompressor,
        groups: Vec<BlobMetadataGroup>,
        chunks: Vec<BlobMetadataChunk>,
    ) -> Result<Self> {
        let mut header = BlobMetadataHeader::default();
        header.set_chunk_block_count(chunk_block_count)?;
        header.set_compressor(compressor);
        header.set_counts_and_offsets(chunks.len() as u32, groups.len() as u32)?;
        header.group_block_bits = infer_group_block_bits(&groups)?;
        validate_tables(&groups, &chunks, header.group_block_count())?;
        let mut blob_metadata = Self {
            header,
            blob_id,
            storage: BlobMetadataStorage::Owned {
                chunks,
                cdc_chunks: Vec::new(),
                groups,
            },
        };
        blob_metadata.header.crc32 = blob_metadata.compute_crc32();
        Ok(blob_metadata)
    }

    /// Construct CDC blob metadata: groups describe the deduplicated unique
    /// data stream, `cdc_chunks` map the dense logical address space (of
    /// `logical_block_count` 4 KiB blocks) onto it.
    pub fn from_cdc_parts(
        blob_id: [u8; SHA256_DIGEST_SIZE],
        chunk_block_count: u32,
        compressor: BlobMetadataCompressor,
        groups: Vec<BlobMetadataGroup>,
        cdc_chunks: Vec<BlobMetadataCdcChunk>,
        logical_block_count: u64,
    ) -> Result<Self> {
        let mut header = BlobMetadataHeader::default();
        header.set_chunk_block_count(chunk_block_count)?;
        header.set_compressor(compressor);
        header.set_cdc(logical_block_count);
        header.set_counts_and_offsets(cdc_chunks.len() as u32, groups.len() as u32)?;
        header.group_block_bits = infer_group_block_bits(&groups)?;
        validate_groups(&groups, header.group_block_count())?;
        validate_cdc_chunks(&groups, &cdc_chunks, logical_block_count)?;
        let mut blob_metadata = Self {
            header,
            blob_id,
            storage: BlobMetadataStorage::Owned {
                chunks: Vec::new(),
                cdc_chunks,
                groups,
            },
        };
        blob_metadata.header.crc32 = blob_metadata.compute_crc32();
        Ok(blob_metadata)
    }

    pub fn with_compressed_offset_bias(&self, bias: u64) -> Result<Self> {
        let mut groups = Vec::with_capacity(self.group_count());
        for group in self.groups() {
            groups.push(group.with_compressed_byte_offset_bias(bias)?);
        }
        if self.is_cdc() {
            Self::from_cdc_parts(
                self.blob_id,
                self.chunk_block_count(),
                self.compressor(),
                groups,
                self.cdc_chunks().to_vec(),
                self.header.logical_block_count(),
            )
        } else {
            Self::from_parts_with_options(
                self.blob_id,
                self.chunk_block_count(),
                self.compressor(),
                groups,
                self.chunks().to_vec(),
            )
        }
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

    pub fn group_count(&self) -> usize {
        self.header.group_count() as usize
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
        if self.is_cdc() {
            return &[];
        }
        match &self.storage {
            BlobMetadataStorage::Owned { chunks, .. } => chunks,
            BlobMetadataStorage::Mapped(mmap) => mapped_chunks(mmap, &self.header),
        }
    }

    /// The CDC chunk records, sorted by logical byte offset. Empty when the
    /// blob is not CDC.
    pub fn cdc_chunks(&self) -> &[BlobMetadataCdcChunk] {
        if !self.is_cdc() {
            return &[];
        }
        match &self.storage {
            BlobMetadataStorage::Owned { cdc_chunks, .. } => cdc_chunks,
            BlobMetadataStorage::Mapped(mmap) => mapped_cdc_chunks(mmap, &self.header),
        }
    }

    /// Whether the chunk table holds variable-size CDC dedup records.
    pub fn is_cdc(&self) -> bool {
        self.header.is_cdc()
    }

    /// Indexes of the CDC records overlapping the logical byte range
    /// `[offset, end)`, via binary search over the sorted record table. The
    /// range may include logical gaps (padding/holes) not covered by any
    /// record; those bytes read as zeros.
    pub fn cdc_chunks_overlapping(&self, offset: u64, end: u64) -> std::ops::Range<usize> {
        let records = self.cdc_chunks();
        if offset >= end {
            return 0..0;
        }
        // First record whose logical end is past `offset`.
        let first = records.partition_point(|record| record.logical_byte_end() <= offset);
        // First record starting at or past `end`.
        let last = records.partition_point(|record| record.logical_byte_offset() < end);
        first..last
    }

    pub fn groups(&self) -> &[BlobMetadataGroup] {
        match &self.storage {
            BlobMetadataStorage::Owned { groups, .. } => groups,
            BlobMetadataStorage::Mapped(mmap) => mapped_groups(mmap, &self.header),
        }
    }

    pub fn group_at(&self, index: usize) -> Option<&BlobMetadataGroup> {
        self.groups().get(index)
    }

    /// True when this blob is an "ondemand" redirect blob: its groups carry
    /// data belonging to other source blob devices.
    pub fn is_redirect_blob(&self) -> bool {
        self.groups().iter().any(BlobMetadataGroup::is_redirect)
    }

    /// Total number of uncompressed blocks in the dense address space.
    pub fn total_blocks(&self) -> u64 {
        self.groups()
            .last()
            .map(|group| {
                group.uncompressed_block_offset() + group.uncompressed_block_count() as u64
            })
            .unwrap_or(0)
    }

    /// O(1) mapping from an uncompressed byte offset in the dense address space
    /// to the index of the group that contains it, or `None` when the offset is
    /// past the end of the blob. Groups are formed by packing blocks up to the
    /// compress size independent of chunk boundaries, so every group except the
    /// last is exactly `1 << group_block_bits` blocks and the group index is a
    /// single shift.
    pub fn group_index_for_byte_offset(&self, offset: u64) -> Option<usize> {
        let block = offset / EROFS_BLOCK_SIZE as u64;
        if block >= self.total_blocks() {
            return None;
        }
        usize::try_from(block >> self.header.group_block_bits()).ok()
    }

    pub fn total_uncompressed_size(&self) -> u64 {
        groups_total_uncompressed_size(self.groups())
    }

    /// Size in bytes of the dense logical address space that EROFS chunk
    /// indexes point into — what the cache data file must be sized to. For a
    /// CDC blob this is the header's logical block count (dedup makes it
    /// larger than the unique data described by the groups); otherwise the
    /// logical and unique spaces coincide.
    pub fn logical_uncompressed_size(&self) -> u64 {
        if self.is_cdc() {
            self.header.logical_block_count() * EROFS_BLOCK_SIZE as u64
        } else {
            self.total_uncompressed_size()
        }
    }

    pub fn total_compressed_size(&self) -> u64 {
        groups_total_compressed_size(self.groups())
    }

    pub fn metadata_size(&self) -> u64 {
        self.header.metadata_size()
    }

    fn compute_crc32(&self) -> u32 {
        // Seal over the serialized metadata with the crc field zeroed; the
        // header bytes seed the running crc32c that continues over the
        // records and padding.
        let mut crc32 = crc32_with_zeroed_field(
            &self.header.to_bytes_with_crc32(0),
            blob_metadata_crc32_field(),
        );
        for chunk in self.chunks() {
            crc32 = crc32c_append(crc32, &chunk.to_bytes());
        }
        for chunk in self.cdc_chunks() {
            crc32 = crc32c_append(crc32, &chunk.to_bytes());
        }
        for group in self.groups() {
            crc32 = crc32c_append(crc32, &group.to_bytes());
        }
        crc32c_append(crc32, &vec![0u8; self.padding_size()])
    }

    fn padding_size(&self) -> usize {
        (self.metadata_size() - self.header.records_end()) as usize
    }

    pub fn write_to(&self, writer: &mut dyn Write) -> Result<()> {
        self.header
            .write_to_with_crc32(writer, self.compute_crc32())?;
        for chunk in self.chunks() {
            chunk.write_to(writer)?;
        }
        for chunk in self.cdc_chunks() {
            chunk.write_to(writer)?;
        }
        for group in self.groups() {
            group.write_to(writer)?;
        }
        let padding_size = self.padding_size();
        if padding_size > 0 {
            writer.write_all(&vec![0u8; padding_size])?;
        }
        Ok(())
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let mut file = File::create(path)
            .with_context(|| format!("failed to create blob meta: {}", path.display()))?;
        self.write_to(&mut file)?;
        file.flush()
            .with_context(|| format!("failed to flush blob meta: {}", path.display()))?;
        Ok(())
    }

    /// Start configuring a blob meta read; finish with
    /// [`load`](BlobMetadataLoader::load) or [`from_bytes`](BlobMetadataLoader::from_bytes).
    pub fn loader() -> BlobMetadataLoader {
        BlobMetadataLoader::default()
    }

    fn from_bytes_inner(
        data: &[u8],
        blob_id: [u8; SHA256_DIGEST_SIZE],
        check_crc32: bool,
    ) -> Result<Self> {
        if data.len() < BLOB_METADATA_HEADER_SIZE as usize {
            return Err(Error::InvalidImage("blob meta data too small".to_string()));
        }

        let mut cursor = Cursor::new(data);
        let header = BlobMetadataHeader::read_from(&mut cursor)?;
        if data.len() as u64 != header.metadata_size() {
            return Err(Error::InvalidImage(format!(
                "blob meta data size mismatch: expected {}, got {}",
                header.metadata_size(),
                data.len()
            )));
        }
        validate_padding(data, &header)?;
        if check_crc32 {
            validate_blob_metadata_crc32(data, &header)?;
        }

        let mut chunks = Vec::new();
        let mut cdc_chunks = Vec::new();
        cursor.set_position(header.chunks_offset());
        if header.is_cdc() {
            cdc_chunks.reserve(header.chunk_count() as usize);
            for index in 0..header.chunk_count() as usize {
                cdc_chunks.push(
                    BlobMetadataCdcChunk::read_from(&mut cursor)
                        .with_context(|| format!("failed to read blob meta CDC chunk {index}"))?,
                );
            }
        } else {
            chunks.reserve(header.chunk_count() as usize);
            for index in 0..header.chunk_count() as usize {
                chunks.push(
                    BlobMetadataChunk::read_from(&mut cursor)
                        .with_context(|| format!("failed to read blob meta chunk {index}"))?,
                );
            }
        }

        let mut groups = Vec::with_capacity(header.group_count() as usize);
        cursor.set_position(header.groups_offset());
        for index in 0..header.group_count() as usize {
            groups.push(
                BlobMetadataGroup::read_from(&mut cursor)
                    .with_context(|| format!("failed to read blob meta group {index}"))?,
            );
        }
        if header.is_cdc() {
            validate_groups(&groups, header.group_block_count())?;
            validate_cdc_chunks(&groups, &cdc_chunks, header.logical_block_count())?;
        } else {
            validate_tables(&groups, &chunks, header.group_block_count())?;
        }
        Ok(Self {
            header,
            blob_id,
            storage: BlobMetadataStorage::Owned {
                chunks,
                cdc_chunks,
                groups,
            },
        })
    }

    pub fn load(path: &Path) -> Result<Self> {
        Self::load_inner(path, false)
    }

    fn load_inner(path: &Path, check_crc32: bool) -> Result<Self> {
        let file = File::open(path)
            .with_context(|| format!("failed to open blob meta: {}", path.display()))?;
        let file_len = file.metadata()?.len();
        if file_len < BLOB_METADATA_HEADER_SIZE {
            return Err(Error::InvalidImage("blob meta file too small".to_string()));
        }
        let mmap = unsafe { MmapOptions::new().map(&file) }
            .with_context(|| format!("failed to mmap blob meta: {}", path.display()))?;
        let mut cursor = Cursor::new(&mmap[..BLOB_METADATA_HEADER_SIZE as usize]);
        let header = BlobMetadataHeader::read_from(&mut cursor)?;
        if file_len != header.metadata_size() {
            return Err(Error::InvalidImage(format!(
                "blob meta file size mismatch: expected {}, got {}",
                header.metadata_size(),
                file_len
            )));
        }
        validate_padding(&mmap, &header)?;
        if check_crc32 {
            validate_blob_metadata_crc32(&mmap, &header)?;
        }
        if header.is_cdc() {
            validate_groups(mapped_groups(&mmap, &header), header.group_block_count())?;
            validate_cdc_chunks(
                mapped_groups(&mmap, &header),
                mapped_cdc_chunks(&mmap, &header),
                header.logical_block_count(),
            )?;
        } else {
            validate_tables(
                mapped_groups(&mmap, &header),
                mapped_chunks(&mmap, &header),
                header.group_block_count(),
            )?;
        }
        Ok(Self {
            header,
            blob_id: [0u8; SHA256_DIGEST_SIZE],
            storage: BlobMetadataStorage::Mapped(mmap),
        })
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
        BlobMetadata::from_bytes_inner(
            data,
            self.blob_id.unwrap_or([0u8; SHA256_DIGEST_SIZE]),
            self.verify_crc32,
        )
    }
}

fn block_count_to_bits(blocks: u32, what: &str) -> Result<u8> {
    if blocks == 0 {
        return Err(Error::InvalidImage(format!(
            "blob meta {what} block count must be non-zero"
        )));
    }
    if !blocks.is_power_of_two() {
        return Err(Error::InvalidImage(format!(
            "blob meta {what} block count must be a power of two"
        )));
    }
    let bits = blocks.trailing_zeros() as u8;
    if bits > BLOB_METADATA_MAX_BLOCK_BITS {
        return Err(Error::InvalidImage(format!(
            "blob meta {what} block count too large: {blocks}"
        )));
    }
    Ok(bits)
}

fn validate_padding(data: &[u8], header: &BlobMetadataHeader) -> Result<()> {
    let padding_start = header.records_end() as usize;
    if data[padding_start..].iter().any(|byte| *byte != 0) {
        return Err(Error::InvalidImage(
            "blob meta padding must be zero".to_string(),
        ));
    }
    Ok(())
}

fn validate_blob_metadata_crc32(data: &[u8], header: &BlobMetadataHeader) -> Result<()> {
    let computed = compute_blob_metadata_crc32(data);
    if computed != header.crc32() {
        return Err(Error::InvalidImage(format!(
            "blob meta header crc32 mismatch: stored {:#010x}, computed {:#010x}",
            header.crc32(),
            computed
        )));
    }
    Ok(())
}

fn compute_blob_metadata_crc32(data: &[u8]) -> u32 {
    crc32_with_zeroed_field(data, blob_metadata_crc32_field())
}

fn blob_metadata_crc32_field() -> std::ops::Range<usize> {
    BLOB_METADATA_HEADER_CRC32_OFFSET..BLOB_METADATA_HEADER_CRC32_OFFSET + 4
}

fn validate_tables(
    groups: &[BlobMetadataGroup],
    chunks: &[BlobMetadataChunk],
    group_block_count: u32,
) -> Result<()> {
    validate_groups(groups, group_block_count)?;
    validate_chunks(groups, chunks)
}

/// Infer the per-group block-count exponent from the group table.
///
/// - A redirect (ondemand) blob copies groups of arbitrary sizes from its
///   source blobs and never uses the block-to-group mapping, so it keeps the
///   default exponent.
/// - A single-group blob's only group is also its (possibly short) tail, so
///   the exponent is the next power of two covering it: every block then
///   shifts to group index 0.
/// - Otherwise the first group is a full group and must be a power of two.
fn infer_group_block_bits(groups: &[BlobMetadataGroup]) -> Result<u8> {
    let default_bits = BLOB_METADATA_DEFAULT_CHUNK_BLOCK_COUNT.trailing_zeros() as u8;
    if groups.is_empty() || groups.iter().any(BlobMetadataGroup::is_redirect) {
        return Ok(default_bits);
    }
    if groups.len() == 1 {
        let covering = groups[0].uncompressed_block_count().next_power_of_two();
        return block_count_to_bits(covering, "group");
    }
    block_count_to_bits(groups[0].uncompressed_block_count(), "group")
}

fn validate_groups(groups: &[BlobMetadataGroup], group_block_count: u32) -> Result<()> {
    if group_block_count == 0 {
        return Err(Error::InvalidImage(
            "blob meta group block count must be non-zero".to_string(),
        ));
    }
    // Redirect blobs copy groups from arbitrary source blobs, so their group
    // sizes are inherently non-uniform and `group_index_for_byte_offset` is
    // never used on them. Only the dense-layout and compressed-overlap
    // invariants apply.
    let allow_nonuniform = groups.iter().any(BlobMetadataGroup::is_redirect);
    let mut previous_uncompressed_block_end = 0u64;
    let mut previous_compressed_byte_end = 0u64;
    let last_index = groups.len().saturating_sub(1);
    for (index, group) in groups.iter().enumerate() {
        group
            .validate()
            .with_context(|| format!("invalid blob meta group {index}"))?;
        if group.uncompressed_block_offset() != previous_uncompressed_block_end {
            return Err(Error::InvalidImage(format!(
                "blob meta groups must be dense at index {index}"
            )));
        }
        // Groups pack whole blocks up to the compress size regardless of chunk
        // boundaries, so every group but the last holds exactly
        // `group_block_count` blocks and the last holds at most that many.
        if !allow_nonuniform {
            if index < last_index {
                if group.uncompressed_block_count() != group_block_count {
                    return Err(Error::InvalidImage(format!(
                        "blob meta group {index} must be exactly {group_block_count} blocks, got {}",
                        group.uncompressed_block_count()
                    )));
                }
            } else if group.uncompressed_block_count() > group_block_count {
                return Err(Error::InvalidImage(format!(
                    "blob meta final group {index} exceeds {group_block_count} blocks, got {}",
                    group.uncompressed_block_count()
                )));
            }
        }
        // Encoded payloads are packed back-to-back in the data region, so each
        // group must start at or after the previous group's byte end. No block
        // alignment is required between compressed groups.
        if index > 0 && group.compressed_byte_offset() < previous_compressed_byte_end {
            return Err(Error::InvalidImage(format!(
                "blob meta groups overlap compressed ranges at index {index}"
            )));
        }
        previous_uncompressed_block_end = group
            .uncompressed_block_offset()
            .checked_add(group.uncompressed_block_count() as u64)
            .ok_or_else(|| {
                Error::Overflow("blob meta group uncompressed block range overflow".to_string())
            })?;
        previous_compressed_byte_end = group.compressed_byte_end();
    }
    Ok(())
}

fn validate_chunks(groups: &[BlobMetadataGroup], chunks: &[BlobMetadataChunk]) -> Result<()> {
    let total_blocks = groups
        .last()
        .map(|group| group.uncompressed_block_offset() + group.uncompressed_block_count() as u64)
        .unwrap_or(0);
    for (index, chunk) in chunks.iter().enumerate() {
        chunk
            .validate()
            .with_context(|| format!("invalid blob meta chunk {index}"))?;
        // Chunks are independent of groups; they only need to point at a valid
        // block range inside the dense uncompressed address space.
        let chunk_end = chunk
            .uncompressed_block_offset()
            .checked_add(chunk.uncompressed_block_count() as u64)
            .ok_or_else(|| Error::Overflow("blob meta chunk block range overflow".to_string()))?;
        if chunk_end > total_blocks {
            return Err(Error::InvalidImage(format!(
                "blob meta chunk {index} exceeds the blob block range"
            )));
        }
    }
    Ok(())
}

fn validate_cdc_chunks(
    groups: &[BlobMetadataGroup],
    chunks: &[BlobMetadataCdcChunk],
    logical_block_count: u64,
) -> Result<()> {
    let unique_size = groups_total_uncompressed_size(groups);
    let logical_size = logical_block_count
        .checked_mul(EROFS_BLOCK_SIZE as u64)
        .ok_or_else(|| Error::Overflow("blob meta logical byte size overflow".to_string()))?;
    let mut previous_logical_end = 0u64;
    for (index, chunk) in chunks.iter().enumerate() {
        chunk
            .validate()
            .with_context(|| format!("invalid blob meta CDC chunk {index}"))?;
        // Records are sorted by logical offset and never overlap; gaps are
        // allowed (padding/holes read as zeros).
        if chunk.logical_byte_offset() < previous_logical_end {
            return Err(Error::InvalidImage(format!(
                "blob meta CDC chunks must be sorted and non-overlapping at index {index}"
            )));
        }
        if chunk.logical_byte_end() > logical_size {
            return Err(Error::InvalidImage(format!(
                "blob meta CDC chunk {index} exceeds the logical byte range"
            )));
        }
        // The referenced unique bytes must lie inside the group-described
        // unique data stream (shared ranges are the point of dedup, so no
        // uniqueness is enforced there).
        if chunk.unique_byte_end() > unique_size {
            return Err(Error::InvalidImage(format!(
                "blob meta CDC chunk {index} exceeds the unique byte range"
            )));
        }
        previous_logical_end = chunk.logical_byte_end();
    }
    Ok(())
}

fn groups_total_uncompressed_size(groups: &[BlobMetadataGroup]) -> u64 {
    groups
        .last()
        .map(BlobMetadataGroup::uncompressed_byte_end)
        .unwrap_or(0)
}

fn groups_total_compressed_size(groups: &[BlobMetadataGroup]) -> u64 {
    groups
        .last()
        .map(BlobMetadataGroup::compressed_byte_end)
        .unwrap_or(0)
}

fn mapped_chunks<'a>(data: &'a [u8], header: &BlobMetadataHeader) -> &'a [BlobMetadataChunk] {
    let offset = header.chunks_offset() as usize;
    let byte_len = header.chunk_count() as usize * size_of::<BlobMetadataChunk>();
    let bytes = &data[offset..offset + byte_len];
    let ptr = bytes.as_ptr().cast::<BlobMetadataChunk>();
    unsafe { std::slice::from_raw_parts(ptr, header.chunk_count() as usize) }
}

fn mapped_cdc_chunks<'a>(
    data: &'a [u8],
    header: &BlobMetadataHeader,
) -> &'a [BlobMetadataCdcChunk] {
    let offset = header.chunks_offset() as usize;
    let byte_len = header.chunk_count() as usize * size_of::<BlobMetadataCdcChunk>();
    let bytes = &data[offset..offset + byte_len];
    let ptr = bytes.as_ptr().cast::<BlobMetadataCdcChunk>();
    unsafe { std::slice::from_raw_parts(ptr, header.chunk_count() as usize) }
}

fn mapped_groups<'a>(data: &'a [u8], header: &BlobMetadataHeader) -> &'a [BlobMetadataGroup] {
    let offset = header.groups_offset() as usize;
    let byte_len = header.group_count() as usize * size_of::<BlobMetadataGroup>();
    let bytes = &data[offset..offset + byte_len];
    let ptr = bytes.as_ptr().cast::<BlobMetadataGroup>();
    unsafe { std::slice::from_raw_parts(ptr, header.group_count() as usize) }
}

fn read_u8(reader: &mut dyn Read) -> Result<u8> {
    let mut buf = [0u8; 1];
    reader.read_exact(&mut buf)?;
    Ok(buf[0])
}

fn read_magic(reader: &mut dyn Read) -> Result<[u8; 8]> {
    let mut buf = [0u8; 8];
    reader.read_exact(&mut buf)?;
    Ok(buf)
}

fn read_group_reserved(reader: &mut dyn Read) -> Result<[u8; 6]> {
    let mut buf = [0u8; 6];
    reader.read_exact(&mut buf)?;
    Ok(buf)
}

fn read_digest(reader: &mut dyn Read) -> Result<[u8; 32]> {
    let mut digest = [0u8; 32];
    reader.read_exact(&mut digest)?;
    Ok(digest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn digest(bytes: &[u8]) -> [u8; 32] {
        *blake3::hash(bytes).as_bytes()
    }

    fn group(
        uncompressed_block_offset: u64,
        uncompressed_block_count: u32,
        compressed_byte_offset: u64,
        compressed_size: u32,
        payload: &[u8],
    ) -> BlobMetadataGroup {
        BlobMetadataGroup::new(
            uncompressed_block_offset,
            uncompressed_block_count,
            compressed_byte_offset,
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

    #[test]
    fn blob_metadata_round_trips_through_mmap() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("blob.meta");
        let blob_id = [0x5au8; SHA256_DIGEST_SIZE];
        let payload_a = vec![0x11; EROFS_BLOCK_SIZE as usize];
        let payload_b = vec![0x22; EROFS_BLOCK_SIZE as usize];
        let group_payload = [payload_a.as_slice(), payload_b.as_slice()].concat();
        let blob_metadata = BlobMetadata::from_parts(
            blob_id,
            1,
            vec![group(0, 2, 8192, 8192, &group_payload)],
            vec![chunk(&payload_a, 0, 1), chunk(&payload_b, 1, 1)],
        )
        .unwrap();

        blob_metadata.save(&path).unwrap();
        let loaded = BlobMetadata::load(&path).unwrap();

        assert_eq!(loaded.header().chunk_count(), 2);
        assert_eq!(loaded.header().group_count(), 1);
        assert_eq!(loaded.header().version(), BLOB_METADATA_VERSION);
        assert_eq!(loaded.header().chunk_bytes(), 96);
        assert_eq!(loaded.header().group_bytes(), 40);
        assert_eq!(loaded.header().records_end(), 4096 + 96 + 40);
        assert_eq!(loaded.header().metadata_size(), 8192);
        assert_eq!(loaded.header().chunk_size(), EROFS_BLOCK_SIZE);
        assert_eq!(loaded.header().group_block_count(), 2);
        assert_eq!(loaded.header().compressor(), BlobMetadataCompressor::None);
        assert_eq!(loaded.header().digester(), BlobMetadataDigester::Blake3);
        assert_ne!(loaded.header().crc32(), 0);
        assert_eq!(loaded.groups()[0].compressed_byte_offset(), 8192);
        assert_eq!(loaded.chunks()[1].digest(), &digest(&payload_b));
        assert_eq!(loaded.chunks()[1].uncompressed_block_offset(), 1);
        assert_eq!(loaded.group_index_for_byte_offset(4096), Some(0));
        assert_eq!(loaded.total_uncompressed_size(), 8192);
    }

    #[test]
    fn blob_metadata_header_crc32_covers_full_metadata() {
        let payload = vec![0x33; EROFS_BLOCK_SIZE as usize];
        let blob_metadata = BlobMetadata::from_parts(
            [0x7bu8; SHA256_DIGEST_SIZE],
            1,
            vec![group(0, 1, 0, 4096, &payload)],
            vec![chunk(&payload, 0, 1)],
        )
        .unwrap();
        let mut raw = Vec::new();
        blob_metadata.write_to(&mut raw).unwrap();

        let stored_crc32 = u32::from_le_bytes(
            raw[BLOB_METADATA_HEADER_CRC32_OFFSET..BLOB_METADATA_HEADER_CRC32_OFFSET + 4]
                .try_into()
                .unwrap(),
        );
        raw[BLOB_METADATA_HEADER_CRC32_OFFSET..BLOB_METADATA_HEADER_CRC32_OFFSET + 4].fill(0);

        assert_eq!(stored_crc32, crc32c::crc32c(&raw));
    }

    #[test]
    fn blob_metadata_read_keeps_but_checked_read_rejects_bad_header_crc32() {
        let payload = vec![0x55; EROFS_BLOCK_SIZE as usize];
        let blob_metadata = BlobMetadata::from_parts(
            [0x8cu8; SHA256_DIGEST_SIZE],
            1,
            vec![group(0, 1, 0, 4096, &payload)],
            vec![chunk(&payload, 0, 1)],
        )
        .unwrap();
        let mut raw = Vec::new();
        blob_metadata.write_to(&mut raw).unwrap();
        raw[BLOB_METADATA_HEADER_CRC32_OFFSET] ^= 0xff;
        let corrupted_crc32 = u32::from_le_bytes(
            raw[BLOB_METADATA_HEADER_CRC32_OFFSET..BLOB_METADATA_HEADER_CRC32_OFFSET + 4]
                .try_into()
                .unwrap(),
        );

        let loaded = BlobMetadata::loader().from_bytes(&raw).unwrap();

        assert_eq!(loaded.header().crc32(), corrupted_crc32);
        let err = match BlobMetadata::loader().verify_crc32().from_bytes(&raw) {
            Ok(_) => panic!("corrupted blob meta crc32 should be rejected"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("crc32"));
    }

    #[test]
    fn blob_metadata_rejects_legacy_magics() {
        let dir = tempdir().unwrap();

        // Legacy magics from earlier format generations must all be rejected:
        // the old nydus compression-context magic and the v0 u32 "LPBM" magic
        // (which serialized as "MBPL" on disk).
        for (name, magic) in [
            ("nydus.blob.meta", 0xb10b_b10bu32),
            ("v0.blob.meta", 0x4c50_424du32),
        ] {
            let path = dir.path().join(name);
            let mut raw = vec![0u8; BLOB_METADATA_HEADER_SIZE as usize];
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
    fn blob_metadata_version_is_informational_and_flags_split_compat_incompat() {
        let payload = vec![0x66; EROFS_BLOCK_SIZE as usize];
        let blob_metadata = BlobMetadata::from_parts(
            [0x1au8; SHA256_DIGEST_SIZE],
            1,
            vec![group(0, 1, 0, 4096, &payload)],
            vec![chunk(&payload, 0, 1)],
        )
        .unwrap();
        let mut raw = Vec::new();
        blob_metadata.write_to(&mut raw).unwrap();

        // A future format generation is readable: version is informational.
        let mut future = raw.clone();
        future[8..12].copy_from_slice(&(BLOB_METADATA_VERSION + 1).to_le_bytes());
        let loaded = BlobMetadata::loader()
            .from_bytes(&future)
            .expect("future version must be readable");
        assert_eq!(loaded.header().version(), BLOB_METADATA_VERSION + 1);

        // An unknown compat (high-half) flag bit is ignored.
        let mut compat = raw.clone();
        let flags = u32::from_le_bytes(compat[12..16].try_into().unwrap()) | (1 << 31);
        compat[12..16].copy_from_slice(&flags.to_le_bytes());
        BlobMetadata::loader()
            .from_bytes(&compat)
            .expect("unknown compat flag must be ignored");

        // An unknown incompat (low-half) flag bit rejects the file.
        let mut incompat = raw;
        let flags = u32::from_le_bytes(incompat[12..16].try_into().unwrap()) | (1 << 15);
        incompat[12..16].copy_from_slice(&flags.to_le_bytes());
        let err = match BlobMetadata::loader().from_bytes(&incompat) {
            Ok(_) => panic!("unknown incompat flag should be rejected"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("incompat"), "{err}");
    }

    #[test]
    fn blob_metadata_ignores_reserved_tail_but_crc_check_catches_corruption() {
        let payload = vec![0x77; EROFS_BLOCK_SIZE as usize];
        let blob_metadata = BlobMetadata::from_parts(
            [0x2bu8; SHA256_DIGEST_SIZE],
            1,
            vec![group(0, 1, 0, 4096, &payload)],
            vec![chunk(&payload, 0, 1)],
        )
        .unwrap();
        let mut raw = Vec::new();
        blob_metadata.write_to(&mut raw).unwrap();
        // Poke a byte inside the reserved header tail (between the last field
        // and the end of the 4 KiB header block): a future writer may place
        // compat fields there, so the unchecked read must ignore it — while
        // the crc-checked read still flags it, since this file's crc was
        // sealed over a zero tail.
        raw[BLOB_METADATA_HEADER_SIZE as usize - 1] = 0xff;

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
    fn group_index_for_byte_offset_maps_constant_sized_groups_by_division() {
        // Groups pack blocks up to the compress size, so every group but the
        // last holds exactly `group_block_count` blocks (2 here) and the index
        // is a single division. Chunk boundaries are irrelevant to this mapping.
        let two = vec![0x11; 2 * EROFS_BLOCK_SIZE as usize];
        let one = vec![0x22; EROFS_BLOCK_SIZE as usize];
        let blob_metadata = BlobMetadata::from_parts(
            [0u8; SHA256_DIGEST_SIZE],
            1,
            vec![
                group(0, 2, 0, 2 * EROFS_BLOCK_SIZE, &two),
                group(
                    2,
                    2,
                    2 * EROFS_BLOCK_SIZE as u64,
                    2 * EROFS_BLOCK_SIZE,
                    &two,
                ),
                group(4, 1, 4 * EROFS_BLOCK_SIZE as u64, EROFS_BLOCK_SIZE, &one),
            ],
            vec![chunk(&two, 0, 2), chunk(&two, 2, 2), chunk(&one, 4, 1)],
        )
        .unwrap();

        assert_eq!(blob_metadata.header().group_block_count(), 2);
        let block = EROFS_BLOCK_SIZE as u64;
        assert_eq!(blob_metadata.group_index_for_byte_offset(0), Some(0));
        assert_eq!(
            blob_metadata.group_index_for_byte_offset(2 * block - 1),
            Some(0)
        );
        assert_eq!(
            blob_metadata.group_index_for_byte_offset(2 * block),
            Some(1)
        );
        assert_eq!(
            blob_metadata.group_index_for_byte_offset(4 * block - 1),
            Some(1)
        );
        // The short final group still maps by division.
        assert_eq!(
            blob_metadata.group_index_for_byte_offset(4 * block),
            Some(2)
        );
        assert_eq!(
            blob_metadata.group_index_for_byte_offset(5 * block - 1),
            Some(2)
        );
        // Past the end of the blob.
        assert_eq!(blob_metadata.group_index_for_byte_offset(5 * block), None);
    }

    #[test]
    fn validate_groups_rejects_non_uniform_group_sizes() {
        let two = vec![0x11; 2 * EROFS_BLOCK_SIZE as usize];
        let three = vec![0x22; 3 * EROFS_BLOCK_SIZE as usize];
        let one = vec![0x33; EROFS_BLOCK_SIZE as usize];
        // The first group fixes the group block count (2). The middle group is a
        // non-final group of 3 blocks, which must be rejected.
        let err = match BlobMetadata::from_parts(
            [0u8; SHA256_DIGEST_SIZE],
            1,
            vec![
                group(0, 2, 0, 2 * EROFS_BLOCK_SIZE, &two),
                group(
                    2,
                    3,
                    2 * EROFS_BLOCK_SIZE as u64,
                    3 * EROFS_BLOCK_SIZE,
                    &three,
                ),
                group(5, 1, 5 * EROFS_BLOCK_SIZE as u64, EROFS_BLOCK_SIZE, &one),
            ],
            vec![chunk(&two, 0, 2), chunk(&three, 2, 3), chunk(&one, 5, 1)],
        ) {
            Ok(_) => panic!("non-uniform group sizes should be rejected"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("must be exactly"));
    }

    #[test]
    fn single_group_blob_uses_covering_power_of_two_exponent() {
        // A lone group is also the (possibly short) tail, so its block count
        // may be any value — 3 here. The header stores the covering exponent
        // (4 blocks -> bits 2) so every block still shifts to group index 0.
        let three = vec![0x44; 3 * EROFS_BLOCK_SIZE as usize];
        let blob_metadata = BlobMetadata::from_parts(
            [0u8; SHA256_DIGEST_SIZE],
            1,
            vec![group(0, 3, 0, 3 * EROFS_BLOCK_SIZE, &three)],
            vec![chunk(&three, 0, 3)],
        )
        .unwrap();

        assert_eq!(blob_metadata.header().group_block_bits(), 2);
        assert_eq!(blob_metadata.header().group_block_count(), 4);
        let block = EROFS_BLOCK_SIZE as u64;
        for index in 0..3u64 {
            assert_eq!(
                blob_metadata.group_index_for_byte_offset(index * block),
                Some(0)
            );
        }
        assert_eq!(blob_metadata.group_index_for_byte_offset(3 * block), None);
    }

    #[test]
    fn multi_group_blob_requires_power_of_two_full_groups() {
        // With more than one group the first is a full group and defines the
        // exponent, so a non-power-of-two size (3 blocks) cannot be encoded.
        let three = vec![0x55; 3 * EROFS_BLOCK_SIZE as usize];
        let one = vec![0x66; EROFS_BLOCK_SIZE as usize];
        let err = match BlobMetadata::from_parts(
            [0u8; SHA256_DIGEST_SIZE],
            1,
            vec![
                group(0, 3, 0, 3 * EROFS_BLOCK_SIZE, &three),
                group(3, 1, 3 * EROFS_BLOCK_SIZE as u64, EROFS_BLOCK_SIZE, &one),
            ],
            vec![chunk(&three, 0, 3), chunk(&one, 3, 1)],
        ) {
            Ok(_) => panic!("non-power-of-two full group should be rejected"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("power of two"), "{err}");
    }

    #[test]
    fn validate_groups_accepts_packed_non_block_aligned_compressed_offsets() {
        let two = vec![0x11; 2 * EROFS_BLOCK_SIZE as usize];
        // Group 1 starts exactly at group 0's compressed byte end (5000), which
        // is deliberately not block aligned: compressed groups pack back-to-back.
        let blob_metadata = BlobMetadata::from_parts(
            [0u8; SHA256_DIGEST_SIZE],
            1,
            vec![group(0, 2, 0, 5000, &two), group(2, 2, 5000, 3000, &two)],
            vec![chunk(&two, 0, 2), chunk(&two, 2, 2)],
        )
        .unwrap();

        assert_eq!(blob_metadata.groups()[1].compressed_byte_offset(), 5000);
        assert_eq!(blob_metadata.total_compressed_size(), 8000);
    }

    #[test]
    fn validate_groups_rejects_overlapping_compressed_ranges() {
        let two = vec![0x22; 2 * EROFS_BLOCK_SIZE as usize];
        // Group 1 starts before group 0's compressed byte end (5000) -> overlap.
        let err = match BlobMetadata::from_parts(
            [0u8; SHA256_DIGEST_SIZE],
            1,
            vec![group(0, 2, 0, 5000, &two), group(2, 2, 4999, 3000, &two)],
            vec![chunk(&two, 0, 2), chunk(&two, 2, 2)],
        ) {
            Ok(_) => panic!("overlapping compressed ranges should be rejected"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("overlap"));
    }

    #[test]
    fn redirect_group_round_trips_and_reports_source() {
        let payload = vec![0x44; 2 * EROFS_BLOCK_SIZE as usize];
        let crc32 = crc32c::crc32c(&payload);
        let redirect =
            BlobMetadataGroup::new_redirect(0, 2, 0, 2 * EROFS_BLOCK_SIZE, crc32, 3, 7).unwrap();

        assert!(redirect.is_redirect());
        assert_eq!(redirect.source_blob_index(), 3);
        assert_eq!(redirect.source_group_index(), 7);

        let mut raw = Vec::new();
        redirect.write_to(&mut raw).unwrap();
        assert_eq!(raw.len(), 40);
        let loaded = BlobMetadataGroup::read_from(&mut Cursor::new(&raw)).unwrap();
        assert_eq!(loaded, redirect);

        // Normal groups stay non-redirect after a round trip.
        let normal = group(0, 2, 0, 2 * EROFS_BLOCK_SIZE, &payload);
        assert!(!normal.is_redirect());
        let mut raw = Vec::new();
        normal.write_to(&mut raw).unwrap();
        let loaded = BlobMetadataGroup::read_from(&mut Cursor::new(&raw)).unwrap();
        assert!(!loaded.is_redirect());
        assert_eq!(loaded.source_group_index(), 0);
    }

    #[test]
    fn redirect_group_rejects_zero_source_blob_index() {
        let err = match BlobMetadataGroup::new_redirect(0, 1, 0, EROFS_BLOCK_SIZE, 0, 0, 1) {
            Ok(_) => panic!("zero source blob index should be rejected"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("non-zero"));
    }

    #[test]
    fn redirect_blob_metadata_allows_non_uniform_groups_and_round_trips() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("ondemand.blob.meta");
        let two = vec![0x55; 2 * EROFS_BLOCK_SIZE as usize];
        let three = vec![0x66; 3 * EROFS_BLOCK_SIZE as usize];
        let one = vec![0x77; EROFS_BLOCK_SIZE as usize];
        let groups = vec![
            BlobMetadataGroup::new_redirect(
                0,
                2,
                0,
                2 * EROFS_BLOCK_SIZE,
                crc32c::crc32c(&two),
                1,
                4,
            )
            .unwrap(),
            BlobMetadataGroup::new_redirect(
                2,
                3,
                2 * EROFS_BLOCK_SIZE as u64,
                3 * EROFS_BLOCK_SIZE,
                crc32c::crc32c(&three),
                2,
                0,
            )
            .unwrap(),
            BlobMetadataGroup::new_redirect(
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

        let blob_metadata = BlobMetadata::from_parts(
            [0x9du8; SHA256_DIGEST_SIZE],
            BLOB_METADATA_DEFAULT_CHUNK_BLOCK_COUNT,
            groups.clone(),
            Vec::new(),
        )
        .unwrap();
        assert!(blob_metadata.is_redirect_blob());
        // Redirect groups are non-uniform and never use the block-to-group
        // mapping, so the header keeps the default exponent.
        assert_eq!(
            blob_metadata.header().group_block_bits(),
            BLOB_METADATA_DEFAULT_CHUNK_BLOCK_COUNT.trailing_zeros() as u8
        );

        blob_metadata.save(&path).unwrap();
        let loaded = BlobMetadata::load(&path).unwrap();
        assert!(loaded.is_redirect_blob());
        assert_eq!(loaded.groups(), groups.as_slice());
        assert_eq!(loaded.groups()[1].source_blob_index(), 2);
        assert_eq!(loaded.groups()[2].source_group_index(), 9);
    }
}

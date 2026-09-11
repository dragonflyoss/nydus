use crate::blob::algorithm::{BlobMetadataCompressor, BlobMetadataDigester};
use crate::blob::flag::FeatureFlags;
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

/// Chunk entries' reserved field, held to zero in the padded layout:
/// entry-layout evolution is signalled by an incompat flag bit, so writers
/// zero it and readers reject anything else. Dense blobs
/// ([`BlobMetadataFlags::DENSE_GROUPS`]) store the chunk's byte length there.
const NYDUS_BLOB_METADATA_CHUNK_RESERVED: u32 = 0;

/// Bit of a dense chunk's byte-length field marking a pack chunk: several
/// whole small files stored back to back, laid out by the pack layout table.
pub const NYDUS_BLOB_METADATA_CHUNK_PACK_FLAG: u32 = 1 << 31;

/// Block group entries' reserved tail, held to zero.
const NYDUS_BLOB_METADATA_BLOCK_GROUP_RESERVED: [u8; 2] = [0u8; 2];

bitflags! {
    /// Feature bits, split EROFS-style (see [`crate::blob::flag`]): the low
    /// 16 bits are incompatible features (unknown bits reject the file), the
    /// high 16 bits are compatible features (unknown bits are ignored).
    /// Entry-layout changes take a new incompat bit, header growth uses the
    /// reserved tail plus a compat bit.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct BlobMetadataFlags: u32 {
        const COMPRESSOR_ZSTD = 1 << 0;
        const COMPRESSOR_LZ4 = 1 << 1;
        const DIGESTER_BLAKE3 = 1 << 2;
        const REDIRECT = 1 << 3;
        const INCREMENTAL = 1 << 4;
        /// Chunk digests are all-zero placeholders (see `BlobMetadataDigester::None`).
        const DIGESTER_NONE = 1 << 5;
        /// Incompat: block groups encode the chunks' bytes back to back
        /// without the per-chunk tail-block padding of the uncompressed
        /// address space. Chunk entries carry their byte length (pack
        /// chunks bundle several small files, laid out by the pack layout
        /// table), block group entries carry their dense payload size and
        /// span a variable number of blocks, and a decoded group is
        /// scattered back into the padded address space on cache fill.
        const DENSE_GROUPS = 1 << 6;
        /// Compat: the data region is a raw z_erofs device (the kernel's
        /// pcluster map addresses it) and the block groups are stored-plain
        /// identity windows over it, carrying only fetch and crc granularity.
        const Z_EROFS_DEVICE = 1 << 16;
    }
}

/// Every defined incompat bit is supported (unknown incompat bits reject the
/// file); the compat half is masked off by the validation itself.
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
///                                       4KiB block count, zero when the
///                                       table is empty or redirects
///     50     6  reserved1               writers zero it, readers ignore it
///     56     8  pack_layout_offset      dense blobs only: byte offset of
///                                       the pack layout table, right
///                                       after the block group table
///     64     4  pack_layout_size        dense blobs only: its byte size
///     68  4028  reserved                writers zero it, readers ignore it
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
    pack_layout_offset: u64,
    pack_layout_size: u32,
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
            pack_layout_offset: read_u64_at(bytes, 56),
            pack_layout_size: read_u32_at(bytes, 64),
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
        write_u64_at(&mut data, 56, self.pack_layout_offset);
        write_u32_at(&mut data, 64, self.pack_layout_size);
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
        FeatureFlags::from_bits(self.flags)
            .validate_incompat(NYDUS_BLOB_METADATA_SUPPORTED_INCOMPAT)?;

        // The pack layout fields sit in the reserved tail: a dense writer
        // anchors the table right behind the block groups, any other
        // writer's values there are ignored compat data.
        if flags.contains(BlobMetadataFlags::DENSE_GROUPS) {
            let expected_pack_layout_offset = self
                .block_groups_offset
                .checked_add(self.block_group_table_size())
                .ok_or_else(|| {
                    Error::Overflow("blob meta pack layout offset overflow".to_string())
                })?;
            if self.pack_layout_offset != expected_pack_layout_offset {
                return Err(Error::InvalidImage(format!(
                    "invalid blob meta pack layout offset: {}",
                    self.pack_layout_offset
                )));
            }
            if self.block_group_block_count_bits == 0
                && !flags.contains(BlobMetadataFlags::REDIRECT)
            {
                return Err(Error::InvalidImage(
                    "dense blob meta must declare its block group size".to_string(),
                ));
            }
        }
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

    /// Whether the blob is an ondemand redirect blob, per the flags.
    pub fn is_redirect(&self) -> bool {
        self.flags().contains(BlobMetadataFlags::REDIRECT)
    }

    /// Whether the data region is a raw z_erofs device described by identity
    /// windows (see [`BlobMetadataFlags::Z_EROFS_DEVICE`]).
    pub fn is_z_erofs_device(&self) -> bool {
        self.flags().contains(BlobMetadataFlags::Z_EROFS_DEVICE)
    }

    /// Whether block groups encode the chunks' bytes densely, without the
    /// tail-block padding of the uncompressed address space (see
    /// [`BlobMetadataFlags::DENSE_GROUPS`]).
    pub fn is_dense(&self) -> bool {
        self.flags().contains(BlobMetadataFlags::DENSE_GROUPS)
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

    /// Uncompressed bytes per block group; for a dense blob, the dense
    /// payload budget a group is filled up to.
    pub fn block_group_size(&self) -> u32 {
        EROFS_BLOCK_SIZE << self.block_group_block_count_bits
    }

    /// Byte offset of the block group table, right after the chunk table.
    pub fn block_groups_offset(&self) -> u64 {
        self.block_groups_offset
    }

    /// Byte size of the block group table.
    pub fn block_group_table_size(&self) -> u64 {
        self.block_group_count as u64 * size_of::<BlobMetadataBlockGroup>() as u64
    }

    /// Byte offset of the pack layout table (dense blobs), right after the
    /// block group table; zero otherwise.
    pub fn pack_layout_offset(&self) -> u64 {
        self.pack_layout_offset
    }

    /// Byte size of the pack layout table (dense blobs); zero otherwise.
    pub fn pack_layout_size(&self) -> u32 {
        self.pack_layout_size
    }

    /// Bytes the header and the tables actually use, before the tail
    /// padding.
    pub fn used_size(&self) -> u64 {
        let tables_end = self.block_groups_offset + self.block_group_table_size();
        if self.is_dense() {
            tables_end + self.pack_layout_size as u64
        } else {
            tables_end
        }
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
///     44     4  byte_len                   dense blobs: the chunk's exact
///                                          byte length in the encoded
///                                          stream, bit 31 marking a pack
///                                          chunk; zero otherwise
/// ```
///
/// In a dense blob a plain chunk's `uncompressed_block_count` is its byte
/// length rounded up to whole blocks. A pack chunk bundles several whole
/// small files back to back in the encoded stream, each starting on its own
/// block of the uncompressed address space; the pack layout table lists
/// their byte lengths in order.
///
/// The Rust layout is pinned to the on-disk layout (`repr(C)` plus the const
/// size assert) so a mapped chunk table is readable in place, zero-copy.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlobMetadataChunk {
    digest: [u8; 32],
    uncompressed_block_offset: u64,
    uncompressed_block_count: u32,
    byte_len: u32,
}

// Pins the Rust layout to the on-disk entry size: a drift would break the
// in-place mapped tables, so it fails the build instead.
const _: () = assert!(size_of::<BlobMetadataChunk>() == NYDUS_BLOB_METADATA_CHUNK_ENTRY_SIZE);

impl BlobMetadataChunk {
    /// Creates a validated chunk entry of a padded blob, so a constructed
    /// chunk is valid by definition.
    pub fn new(
        digest: [u8; 32],
        uncompressed_block_offset: u64,
        uncompressed_block_count: u32,
    ) -> Result<Self> {
        let chunk = Self {
            digest,
            uncompressed_block_offset,
            uncompressed_block_count,
            byte_len: NYDUS_BLOB_METADATA_CHUNK_RESERVED,
        };

        chunk.validate()?;
        Ok(chunk)
    }

    /// Creates a validated chunk entry of a dense blob: `byte_len` is the
    /// chunk's exact length in the encoded stream and `is_pack` marks a pack
    /// of small files (whose `uncompressed_block_count` sums the files'
    /// padded blocks). Cross-checks against the pack layout happen at table
    /// validation.
    pub fn new_dense(
        digest: [u8; 32],
        uncompressed_block_offset: u64,
        uncompressed_block_count: u32,
        byte_len: u32,
        is_pack: bool,
    ) -> Result<Self> {
        if byte_len == 0 || byte_len & NYDUS_BLOB_METADATA_CHUNK_PACK_FLAG != 0 {
            return Err(Error::InvalidImage(format!(
                "blob meta dense chunk byte length out of range: {byte_len}"
            )));
        }
        let chunk = Self {
            digest,
            uncompressed_block_offset,
            uncompressed_block_count,
            byte_len: byte_len
                | if is_pack {
                    NYDUS_BLOB_METADATA_CHUNK_PACK_FLAG
                } else {
                    0
                },
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
            byte_len: read_u32_at(bytes, 44),
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
        write_u32_at(&mut data, 44, self.byte_len);
        data
    }

    /// Validate the intrinsic field invariants. Run by every construction
    /// path ([`Self::new`], [`Self::from_bytes`]), so a chunk in hand is
    /// always valid. Whether the byte length field may be non-zero depends
    /// on the header's dense flag, checked at table validation.
    fn validate(&self) -> Result<()> {
        if self.uncompressed_block_count == 0 {
            return Err(Error::InvalidImage(
                "blob meta chunk uncompressed block count must be non-zero".to_string(),
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

    /// Dense blobs: the chunk's exact byte length in the encoded stream
    /// (zero in a padded blob, whose chunks are whole blocks).
    pub fn byte_len(&self) -> u32 {
        self.byte_len & !NYDUS_BLOB_METADATA_CHUNK_PACK_FLAG
    }

    /// Dense blobs: whether the chunk is a pack of small files laid out by
    /// the pack layout table.
    pub fn is_pack(&self) -> bool {
        self.byte_len & NYDUS_BLOB_METADATA_CHUNK_PACK_FLAG != 0
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
///     24     4  crc32                      crc32c of the decoded payload
///     28     4  source_block_group_index   redirect only, else zero
///     32     2  source_blob_index          non-zero marks a redirect
///     34     2  reserved                   must be zero
///     36     4  dense_size                 dense blobs: bytes of the
///                                          decoded payload, the chunks'
///                                          bytes back to back; zero in a
///                                          padded blob (payload = span)
/// ```
///
/// In a dense blob the group's span is variable: it covers the padded
/// blocks of the chunk bytes it encodes (plus any alignment gap before them)
/// and starts where the previous group ends. Every group but the last
/// encodes more than `block_group_size - 4KiB` dense bytes, so its span is
/// at least the block group size and any block group sized window of the
/// address space meets at most two groups (see
/// [`BlobMetadata::block_group_index_from_uncompressed_offset`]).
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
    reserved: [u8; 2],
    dense_size: u32,
}

// The same layout pin for block group entries.
const _: () =
    assert!(size_of::<BlobMetadataBlockGroup>() == NYDUS_BLOB_METADATA_BLOCK_GROUP_ENTRY_SIZE);

impl BlobMetadataBlockGroup {
    /// Creates a validated entry of a padded blob. `is_redirect` must agree
    /// with the non-zero `source_blob_index` that marks a payload living in
    /// another source blob.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        uncompressed_block_offset: u64,
        uncompressed_block_count: u32,
        compressed_offset: u64,
        compressed_size: u32,
        crc32: u32,
        source_blob_index: u16,
        source_block_group_index: u32,
        is_redirect: bool,
    ) -> Result<Self> {
        Self::new_dense(
            uncompressed_block_offset,
            uncompressed_block_count,
            compressed_offset,
            compressed_size,
            crc32,
            source_blob_index,
            source_block_group_index,
            is_redirect,
            0,
        )
    }

    /// [`Self::new`] with the dense payload size: the number of bytes the
    /// group decodes to when the blob is dense (zero for a padded blob or
    /// a redirect of a padded source group).
    #[allow(clippy::too_many_arguments)]
    pub fn new_dense(
        uncompressed_block_offset: u64,
        uncompressed_block_count: u32,
        compressed_offset: u64,
        compressed_size: u32,
        crc32: u32,
        source_blob_index: u16,
        source_block_group_index: u32,
        is_redirect: bool,
        dense_size: u32,
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
            dense_size,
        };

        block_group.validate(is_redirect)?;
        Ok(block_group)
    }

    /// Parse a block group entry from exactly its 40 bytes, verifying the
    /// intrinsic fields and `is_redirect`.
    pub fn from_bytes(
        bytes: &[u8; NYDUS_BLOB_METADATA_BLOCK_GROUP_ENTRY_SIZE],
        is_redirect: bool,
    ) -> Result<Self> {
        let block_group = Self {
            uncompressed_block_offset: read_u64_at(bytes, 0),
            compressed_offset: read_u64_at(bytes, 8),
            uncompressed_block_count: read_u32_at(bytes, 16),
            compressed_size: read_u32_at(bytes, 20),
            crc32: read_u32_at(bytes, 24),
            source_block_group_index: read_u32_at(bytes, 28),
            source_blob_index: read_u16_at(bytes, 32),
            reserved: bytes[34..36].try_into().unwrap(),
            dense_size: read_u32_at(bytes, 36),
        };

        block_group.validate(is_redirect)?;
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
        data[34..36].copy_from_slice(&self.reserved);
        write_u32_at(&mut data, 36, self.dense_size);
        data
    }

    /// Validate the intrinsic field invariants and that `is_redirect` agrees
    /// with the source blob index. Run by every construction path, so a
    /// block group in hand is always valid. Cross-entry rules (density,
    /// ordering) live in [`BlobMetadata::validate_block_groups`].
    fn validate(&self, is_redirect: bool) -> Result<()> {
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

        if self.is_redirect() != is_redirect {
            return Err(Error::InvalidImage(
                "blob meta block group source blob index does not match the redirect flag"
                    .to_string(),
            ));
        }

        if self.reserved != NYDUS_BLOB_METADATA_BLOCK_GROUP_RESERVED {
            return Err(Error::InvalidImage(
                "blob meta block group reserved field must be zero".to_string(),
            ));
        }

        if self.dense_size as u64 > self.uncompressed_size() {
            return Err(Error::InvalidImage(format!(
                "blob meta block group dense size {} exceeds its {}-byte span",
                self.dense_size,
                self.uncompressed_size()
            )));
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

        block_group.validate(self.is_redirect())?;
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

    /// crc32c of the group's decoded payload, checked after decode.
    pub fn crc32(&self) -> u32 {
        self.crc32
    }

    /// Dense blobs: byte size of the decoded payload (the chunks' bytes
    /// back to back); zero when the payload is the padded span itself.
    pub fn dense_size(&self) -> u32 {
        self.dense_size
    }

    /// Byte size the encoded payload decodes to: the dense size when set,
    /// else the whole padded span.
    pub fn payload_size(&self) -> u64 {
        if self.dense_size != 0 {
            self.dense_size as u64
        } else {
            self.uncompressed_size()
        }
    }

    /// Whether the payload is the padded span itself, so a decoded group
    /// is written to the cache in one piece at its span offset.
    pub fn is_padded_payload(&self) -> bool {
        self.dense_size == 0
    }

    /// Derive the header's `block_group_block_count_bits` from the groups
    /// themselves: the first group carries the uniform span (validated
    /// later), a lone group rounds up to a power of two, and empty or
    /// redirect tables have no uniform span so the field is left zero.
    fn infer_block_count_bits(block_groups: &[Self], is_redirect: bool) -> Result<u8> {
        if is_redirect {
            return Ok(0);
        }

        match block_groups {
            [] => Ok(0),
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
        pack_layout: Vec<u8>,
    },
    Mapped(Mmap),
}

/// Append one pack's record to a pack layout table: a LEB128 varint file
/// count followed by the files' LEB128 varint byte lengths, in the order
/// the files sit in the pack.
pub fn encode_pack_layout(file_lens: &[u32], out: &mut Vec<u8>) {
    write_varint(file_lens.len() as u32, out);
    for len in file_lens {
        write_varint(*len, out);
    }
}

fn write_varint(mut value: u32, out: &mut Vec<u8>) {
    while value >= 0x80 {
        out.push((value as u8 & 0x7f) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

fn read_varint(bytes: &[u8], pos: &mut usize) -> Result<u32> {
    let mut value = 0u32;
    for shift in (0..35).step_by(7) {
        let byte = *bytes
            .get(*pos)
            .ok_or_else(|| Error::InvalidImage("blob meta pack layout truncated".to_string()))?;
        *pos += 1;
        let bits = (byte & 0x7f) as u32;
        if shift == 28 && bits > 0xf {
            break;
        }
        value |= bits << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err(Error::InvalidImage(
        "blob meta pack layout varint overflow".to_string(),
    ))
}

/// The byte lengths of one pack's files, decoded from the pack layout table
/// at the pack's record offset.
pub struct PackFiles<'a> {
    layout: &'a [u8],
    pos: usize,
    remaining: u32,
}

impl Iterator for PackFiles<'_> {
    type Item = Result<u32>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        self.remaining -= 1;
        Some(read_varint(self.layout, &mut self.pos))
    }
}

/// Lookup structures a dense blob derives from its tables at load, so the
/// variable-span block groups still answer offset queries in O(1) and a
/// decoded group scatters back into the padded address space without a
/// search. All prefix sums over tables the load already walks; a few bytes
/// per block group and per chunk.
#[derive(Debug)]
struct DenseIndex {
    /// Per block-group-sized window of the uncompressed address space, the
    /// first block group meeting it. Groups span at least one window, so a
    /// window meets this group and at most the next one.
    window_first_group: Vec<u32>,
    /// Each group's start in the dense stream (prefix sum of dense sizes).
    group_dense_offset: Vec<u64>,
    /// Each group's first chunk: the first whose dense range reaches into
    /// the group.
    group_first_chunk: Vec<u32>,
    /// Each chunk's start in the dense stream (prefix sum of byte lengths).
    chunk_dense_offset: Vec<u64>,
    /// Each chunk's record offset in the pack layout table, `u32::MAX` for
    /// a plain chunk.
    chunk_pack_layout: Vec<u32>,
}

impl DenseIndex {
    /// Build the index, validating the dense invariants on the way: chunks
    /// sorted and non-overlapping with byte lengths matching their spans,
    /// pack records matching their chunks, group payloads filling the block
    /// group size (all but the last), and both streams summing to the same
    /// dense length.
    fn build(
        header: &BlobMetadataHeader,
        chunks: &[BlobMetadataChunk],
        block_groups: &[BlobMetadataBlockGroup],
        pack_layout: &[u8],
    ) -> Result<Self> {
        let is_redirect = header.is_redirect();
        let block_size = EROFS_BLOCK_SIZE as u64;
        let chunk_size = header.chunk_size() as u64;

        let mut chunk_dense_offset = Vec::with_capacity(chunks.len());
        let mut chunk_pack_layout = Vec::with_capacity(chunks.len());
        let mut dense_pos = 0u64;
        let mut next_block = 0u64;
        let mut layout_pos = 0usize;
        for (index, chunk) in chunks.iter().enumerate() {
            let byte_len = chunk.byte_len() as u64;
            if byte_len == 0 || byte_len > chunk_size {
                return Err(Error::InvalidImage(format!(
                    "blob meta dense chunk {index} byte length {byte_len} out of range"
                )));
            }
            if chunk.uncompressed_block_offset() < next_block {
                return Err(Error::InvalidImage(format!(
                    "blob meta dense chunk {index} overlaps the previous chunk"
                )));
            }
            let expected_blocks = if chunk.is_pack() {
                let record = layout_pos;
                let count = read_varint(pack_layout, &mut layout_pos)?;
                let mut sum = 0u64;
                let mut blocks = 0u64;
                for _ in 0..count {
                    let len = read_varint(pack_layout, &mut layout_pos)? as u64;
                    if len == 0 {
                        return Err(Error::InvalidImage(format!(
                            "blob meta pack chunk {index} lists an empty file"
                        )));
                    }
                    sum += len;
                    blocks += len.div_ceil(block_size);
                }
                if sum != byte_len {
                    return Err(Error::InvalidImage(format!(
                        "blob meta pack chunk {index} files sum to {sum} bytes, chunk has {byte_len}"
                    )));
                }
                chunk_pack_layout.push(u32::try_from(record).map_err(|_| {
                    Error::Overflow("blob meta pack layout offset exceeds u32".to_string())
                })?);
                blocks
            } else {
                chunk_pack_layout.push(u32::MAX);
                byte_len.div_ceil(block_size)
            };
            if chunk.uncompressed_block_count() as u64 != expected_blocks {
                return Err(Error::InvalidImage(format!(
                    "blob meta dense chunk {index} spans {} blocks, its bytes need {expected_blocks}",
                    chunk.uncompressed_block_count()
                )));
            }
            chunk_dense_offset.push(dense_pos);
            dense_pos += byte_len;
            next_block =
                chunk.uncompressed_block_offset() + chunk.uncompressed_block_count() as u64;
        }
        if layout_pos != pack_layout.len() {
            return Err(Error::InvalidImage(
                "blob meta pack layout has trailing bytes".to_string(),
            ));
        }
        let chunk_dense_total = dense_pos;

        let group_size = header.block_group_size() as u64;
        let mut group_dense_offset = Vec::with_capacity(block_groups.len());
        let mut group_first_chunk = Vec::with_capacity(block_groups.len());
        let mut dense_pos = 0u64;
        let mut chunk = 0usize;
        for (index, block_group) in block_groups.iter().enumerate() {
            let dense_size = block_group.dense_size() as u64;
            let last = index + 1 == block_groups.len();
            if !is_redirect {
                if dense_size == 0 || dense_size > group_size {
                    return Err(Error::InvalidImage(format!(
                        "blob meta dense block group {index} payload {dense_size} out of range"
                    )));
                }
                if !last && dense_size + block_size <= group_size {
                    return Err(Error::InvalidImage(format!(
                        "blob meta dense block group {index} payload {dense_size} leaves more than \
                         a block of the {group_size}-byte group unused"
                    )));
                }
            }
            group_dense_offset.push(dense_pos);
            while chunk < chunks.len()
                && chunk_dense_offset[chunk] + chunks[chunk].byte_len() as u64 <= dense_pos
            {
                chunk += 1;
            }
            group_first_chunk.push(chunk as u32);
            dense_pos += dense_size;
        }
        if !is_redirect && dense_pos != chunk_dense_total {
            return Err(Error::InvalidImage(format!(
                "blob meta dense block groups decode to {dense_pos} bytes, chunks hold {chunk_dense_total}"
            )));
        }

        let total_blocks = block_groups
            .last()
            .map(|g| g.uncompressed_block_offset() + g.uncompressed_block_count() as u64)
            .unwrap_or(0);
        let bits = header.block_group_block_count_bits;
        let windows = if bits == 0 {
            0
        } else {
            usize::try_from(total_blocks.div_ceil(1u64 << bits))
                .map_err(|_| Error::Overflow("blob meta window count exceeds usize".to_string()))?
        };
        let mut window_first_group = vec![u32::MAX; windows];
        for (index, block_group) in block_groups.iter().enumerate() {
            if bits == 0 {
                break;
            }
            let start = block_group.uncompressed_block_offset() >> bits;
            let end = (block_group.uncompressed_block_offset()
                + block_group.uncompressed_block_count() as u64
                - 1)
                >> bits;
            for window in start..=end {
                let slot = &mut window_first_group[window as usize];
                if *slot == u32::MAX {
                    *slot = index as u32;
                }
            }
        }

        Ok(Self {
            window_first_group,
            group_dense_offset,
            group_first_chunk,
            chunk_dense_offset,
            chunk_pack_layout,
        })
    }
}

/// A nydus blob's metadata: the chunk digest table and the block group table
/// describing how the blob's dense uncompressed address space maps onto its
/// encoded payload, sealed with a crc32c in the header.
///
/// Serialized, it is the `.blob.meta` sidecar file — and, embedded verbatim,
/// the blob meta region of a full blob (see [`super::footer::BlobFooter`]):
///
/// ```text
/// ┌────────┬─────────────┬───────────────────┬─────────────┬──────────────┐
/// │ header │ chunk table │ block group table │ pack layout │ zero padding │
/// └────────┴─────────────┴───────────────────┴─────────────┴──────────────┘
/// 0        4096                              (dense only)  ▲              EOF
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
    dense: Option<DenseIndex>,
}

impl BlobMetadata {
    /// Creates validated, sealed metadata from owned tables. `is_redirect`
    /// marks an ondemand blob and must agree with every block group.
    pub fn new(
        compressor: BlobMetadataCompressor,
        digester: BlobMetadataDigester,
        chunk_block_count: u32,
        chunks: Vec<BlobMetadataChunk>,
        block_groups: Vec<BlobMetadataBlockGroup>,
        is_redirect: bool,
    ) -> Result<Self> {
        Self::new_with_flags(
            compressor,
            digester,
            chunk_block_count,
            chunks,
            block_groups,
            is_redirect,
            BlobMetadataFlags::empty(),
        )
    }

    /// [`Self::new`] with additional compat flags (the compressor, digester
    /// and redirect bits are derived from the other arguments).
    pub fn new_with_flags(
        compressor: BlobMetadataCompressor,
        digester: BlobMetadataDigester,
        chunk_block_count: u32,
        chunks: Vec<BlobMetadataChunk>,
        block_groups: Vec<BlobMetadataBlockGroup>,
        is_redirect: bool,
        extra: BlobMetadataFlags,
    ) -> Result<Self> {
        let block_group_block_count_bits =
            BlobMetadataBlockGroup::infer_block_count_bits(&block_groups, is_redirect)?;
        Self::assemble(
            compressor,
            digester,
            block_count_to_bits(chunk_block_count)?,
            block_group_block_count_bits,
            chunks,
            block_groups,
            Vec::new(),
            is_redirect,
            extra,
        )
    }

    /// Creates validated, sealed metadata of a dense blob
    /// ([`BlobMetadataFlags::DENSE_GROUPS`]): the block group size is given
    /// explicitly since the groups' spans vary, and `pack_layout` holds the
    /// pack chunks' records in chunk table order (see
    /// [`encode_pack_layout`]).
    #[allow(clippy::too_many_arguments)]
    pub fn new_dense(
        compressor: BlobMetadataCompressor,
        digester: BlobMetadataDigester,
        chunk_block_count: u32,
        block_group_block_count: u32,
        chunks: Vec<BlobMetadataChunk>,
        block_groups: Vec<BlobMetadataBlockGroup>,
        pack_layout: Vec<u8>,
        is_redirect: bool,
        extra: BlobMetadataFlags,
    ) -> Result<Self> {
        Self::assemble(
            compressor,
            digester,
            block_count_to_bits(chunk_block_count)?,
            block_count_to_bits(block_group_block_count)?,
            chunks,
            block_groups,
            pack_layout,
            is_redirect,
            extra | BlobMetadataFlags::DENSE_GROUPS,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn assemble(
        compressor: BlobMetadataCompressor,
        digester: BlobMetadataDigester,
        chunk_block_count_bits: u8,
        block_group_block_count_bits: u8,
        chunks: Vec<BlobMetadataChunk>,
        block_groups: Vec<BlobMetadataBlockGroup>,
        pack_layout: Vec<u8>,
        is_redirect: bool,
        extra: BlobMetadataFlags,
    ) -> Result<Self> {
        let mut flags = extra;
        flags.set(compressor.flag(), true);
        flags.set(digester.flag(), true);
        flags.set(BlobMetadataFlags::REDIRECT, is_redirect);
        let is_dense = flags.contains(BlobMetadataFlags::DENSE_GROUPS);
        if !is_dense && !pack_layout.is_empty() {
            return Err(Error::InvalidParameter(
                "blob meta pack layout requires dense block groups".to_string(),
            ));
        }

        let chunks_offset = NYDUS_BLOB_METADATA_HEADER_SIZE as u64;
        let block_groups_offset = chunks_offset
            .checked_add(chunks.len() as u64 * size_of::<BlobMetadataChunk>() as u64)
            .ok_or_else(|| Error::Overflow("blob meta block group offset overflow".to_string()))?;
        let pack_layout_offset = if is_dense {
            block_groups_offset
                .checked_add(block_groups.len() as u64 * size_of::<BlobMetadataBlockGroup>() as u64)
                .ok_or_else(|| {
                    Error::Overflow("blob meta pack layout offset overflow".to_string())
                })?
        } else {
            0
        };
        let header = BlobMetadataHeader {
            magic: NYDUS_BLOB_METADATA_MAGIC,
            version: NYDUS_BLOB_METADATA_VERSION,
            flags: flags.bits(),
            crc32: 0,
            reserved0: 0,
            chunks_offset,
            block_groups_offset,
            chunk_count: chunks.len() as u32,
            block_group_count: block_groups.len() as u32,
            chunk_block_count_bits,
            block_group_block_count_bits,
            pack_layout_offset,
            pack_layout_size: u32::try_from(pack_layout.len())
                .map_err(|_| Error::Overflow("blob meta pack layout exceeds u32".to_string()))?,
        };
        header.validate()?;

        let mut blob_metadata = Self {
            header,
            storage: BlobMetadataStorage::Owned {
                chunks,
                block_groups,
                pack_layout,
            },
            dense: None,
        };
        blob_metadata.validate()?;
        blob_metadata.index_dense()?;
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

        let block_groups_end =
            header.block_groups_offset() as usize + header.block_group_table_size() as usize;
        let block_group_table = &bytes[header.block_groups_offset() as usize..block_groups_end];
        let block_groups = block_group_table
            .chunks_exact(size_of::<BlobMetadataBlockGroup>())
            .enumerate()
            .map(|(index, entry)| {
                BlobMetadataBlockGroup::from_bytes(entry.try_into().unwrap(), header.is_redirect())
                    .with_context(|| format!("failed to read blob meta block group {index}"))
            })
            .collect::<Result<Vec<_>>>()?;
        let pack_layout = bytes[block_groups_end..header.used_size() as usize].to_vec();

        let mut blob_metadata = Self {
            header,
            storage: BlobMetadataStorage::Owned {
                chunks,
                block_groups,
                pack_layout,
            },
            dense: None,
        };
        blob_metadata.validate()?;
        blob_metadata.index_dense()?;
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

        let mut blob_metadata = Self {
            header,
            storage: BlobMetadataStorage::Mapped(mmap),
            dense: None,
        };
        blob_metadata.validate()?;
        blob_metadata.index_dense()?;
        Ok(blob_metadata)
    }

    /// Derive the dense lookup index when the header declares dense block
    /// groups (a padded blob keeps `None` and the shift-based lookup).
    fn index_dense(&mut self) -> Result<()> {
        if self.header.is_dense() {
            self.dense = Some(DenseIndex::build(
                &self.header,
                self.chunks(),
                self.block_groups(),
                self.pack_layout(),
            )?);
        }
        Ok(())
    }

    /// Validate the cross-entry table invariants. Run by every construction
    /// path, so metadata in hand is always valid.
    fn validate(&self) -> Result<()> {
        self.validate_chunks()?;
        self.validate_block_groups()
    }

    /// Every chunk must be intrinsically valid and end within the blocks
    /// the block groups cover. Runs before the density checks, so the bound
    /// is just the last group's end, not yet a total. A padded blob's
    /// chunks must leave the byte length field zero; a dense blob's are
    /// cross-checked in [`DenseIndex::build`].
    fn validate_chunks(&self) -> Result<()> {
        let uncompressed_block_end = self
            .block_groups()
            .last()
            .map(|block_group| {
                block_group.uncompressed_block_offset()
                    + block_group.uncompressed_block_count() as u64
            })
            .unwrap_or(0);
        let is_dense = self.header.is_dense();

        for (index, chunk) in self.chunks().iter().enumerate() {
            chunk
                .validate()
                .with_context(|| format!("invalid blob meta chunk {index}"))?;

            if !is_dense && chunk.byte_len != NYDUS_BLOB_METADATA_CHUNK_RESERVED {
                return Err(Error::InvalidImage(format!(
                    "blob meta chunk {index} reserved field must be zero"
                )));
            }

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
    /// short; redirect blobs and dense blobs, whose spans vary, are exempt),
    /// and keep their compressed ranges ordered and non-overlapping (gaps
    /// allowed). A padded blob's groups must leave the dense size zero.
    fn validate_block_groups(&self) -> Result<()> {
        let block_groups = self.block_groups();
        let block_group_block_count = self.header.block_group_block_count();
        if block_group_block_count == 0 {
            return Err(Error::InvalidImage(
                "blob meta block group block count must be non-zero".to_string(),
            ));
        }

        let is_redirect = self.is_redirect();
        let is_dense = self.header.is_dense();
        let mut next_uncompressed_block_offset = 0u64;
        let mut next_compressed_offset = 0u64;
        for (index, block_group) in block_groups.iter().enumerate() {
            block_group
                .validate(is_redirect)
                .with_context(|| format!("invalid blob meta block group {index}"))?;

            if !is_dense && block_group.dense_size() != 0 {
                return Err(Error::InvalidImage(format!(
                    "blob meta block group {index} dense size must be zero"
                )));
            }

            if block_group.uncompressed_block_offset() != next_uncompressed_block_offset {
                return Err(Error::InvalidImage(format!(
                    "blob meta block groups must be dense: block group {index} starts at block {}, \
                     expected block {next_uncompressed_block_offset}",
                    block_group.uncompressed_block_offset()
                )));
            }

            if !is_redirect && !is_dense {
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
        writer.write_all(self.pack_layout())?;

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

    /// The pack layout table (dense blobs; empty otherwise), backed the
    /// same two ways as [`Self::chunks`].
    pub fn pack_layout(&self) -> &[u8] {
        match &self.storage {
            BlobMetadataStorage::Owned { pack_layout, .. } => pack_layout,
            BlobMetadataStorage::Mapped(mmap) => {
                if !self.header.is_dense() {
                    return &[];
                }
                let offset = self.header.pack_layout_offset() as usize;
                &mmap[offset..offset + self.header.pack_layout_size() as usize]
            }
        }
    }

    /// Whether block groups encode the chunks' bytes densely (see
    /// [`BlobMetadataFlags::DENSE_GROUPS`]), per the header flag.
    pub fn is_dense(&self) -> bool {
        self.header.is_dense()
    }

    /// Dense blobs: the byte lengths of the files in pack chunk
    /// `chunk_index`, in pack order; `None` for a plain chunk or a padded
    /// blob.
    pub fn pack_files(&self, chunk_index: usize) -> Option<PackFiles<'_>> {
        let dense = self.dense.as_ref()?;
        let record = *dense.chunk_pack_layout.get(chunk_index)?;
        if record == u32::MAX {
            return None;
        }
        let layout = self.pack_layout();
        let mut pos = record as usize;
        let remaining = read_varint(layout, &mut pos).ok()?;
        Some(PackFiles {
            layout,
            pos,
            remaining,
        })
    }

    /// Dense blobs: scatter block group `group_index`'s decoded payload
    /// back into the padded uncompressed address space, calling `sink` with
    /// every contiguous piece's absolute byte offset and bytes, in address
    /// order. Pieces are the chunks (or, in a pack chunk, the files)
    /// overlapping the group: each starts on its own block, so the bytes
    /// between pieces are the tail-block padding the cache leaves zero.
    /// For a padded blob the whole payload is one piece at the span start.
    pub fn for_each_decoded_piece(
        &self,
        group_index: usize,
        payload: &[u8],
        sink: &mut dyn FnMut(u64, &[u8]) -> std::io::Result<()>,
    ) -> std::io::Result<()> {
        let block_group = self.block_group(group_index).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "block group index out of range",
            )
        })?;
        if payload.len() as u64 != block_group.payload_size() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "decoded block group length does not match its payload size",
            ));
        }
        let Some(dense) = self
            .dense
            .as_ref()
            .filter(|_| !block_group.is_padded_payload())
        else {
            return sink(block_group.uncompressed_offset(), payload);
        };

        let chunks = self.chunks();
        let layout = self.pack_layout();
        let block_size = EROFS_BLOCK_SIZE as u64;
        let group_start = dense.group_dense_offset[group_index];
        let group_end = group_start + payload.len() as u64;
        let mut index = dense.group_first_chunk[group_index] as usize;
        while index < chunks.len() {
            let chunk = &chunks[index];
            let chunk_start = dense.chunk_dense_offset[index];
            if chunk_start >= group_end {
                break;
            }
            let chunk_end = chunk_start + chunk.byte_len() as u64;
            let piece_start = chunk_start.max(group_start);
            let piece_end = chunk_end.min(group_end);
            if piece_start < piece_end {
                let record = dense.chunk_pack_layout[index];
                if record == u32::MAX {
                    let offset = chunk.uncompressed_offset() + (piece_start - chunk_start);
                    sink(
                        offset,
                        &payload[(piece_start - group_start) as usize
                            ..(piece_end - group_start) as usize],
                    )?;
                } else {
                    let mut pos = record as usize;
                    let count = read_varint(layout, &mut pos).map_err(invalid_layout)?;
                    let mut file_start = chunk_start;
                    let mut file_offset = chunk.uncompressed_offset();
                    for _ in 0..count {
                        let len = read_varint(layout, &mut pos).map_err(invalid_layout)? as u64;
                        let file_end = file_start + len;
                        if file_start >= piece_end {
                            break;
                        }
                        let start = file_start.max(piece_start);
                        let end = file_end.min(piece_end);
                        if start < end {
                            sink(
                                file_offset + (start - file_start),
                                &payload
                                    [(start - group_start) as usize..(end - group_start) as usize],
                            )?;
                        }
                        file_start = file_end;
                        file_offset += len.div_ceil(block_size) * block_size;
                    }
                }
            }
            index += 1;
        }
        Ok(())
    }

    /// Whether the blob is an ondemand redirect blob (every block group
    /// redirects to another source blob), per the header flag.
    pub fn is_redirect(&self) -> bool {
        self.header.is_redirect()
    }

    /// Whether the data region is a raw z_erofs device described by identity
    /// windows, per the header flag.
    pub fn is_z_erofs_device(&self) -> bool {
        self.header.is_z_erofs_device()
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
    /// of the blob. Padded blobs have fixed-size groups, so this is a
    /// single shift; dense blobs look the block group sized window up in
    /// the load-time index and step to the next group when the offset lies
    /// past its start (a window meets at most two groups). No search either
    /// way.
    pub fn block_group_index_from_uncompressed_offset(
        &self,
        uncompressed_offset: u64,
    ) -> Option<usize> {
        let block = uncompressed_offset / EROFS_BLOCK_SIZE as u64;
        if block >= self.uncompressed_block_count() {
            return None;
        }

        let window = usize::try_from(block >> self.header.block_group_block_count_bits).ok()?;
        let Some(dense) = self.dense.as_ref() else {
            return Some(window);
        };
        let mut index = *dense.window_first_group.get(window)? as usize;
        if let Some(next) = self.block_group(index + 1) {
            if block >= next.uncompressed_block_offset() {
                index += 1;
            }
        }
        Some(index)
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
        crc32 = crc32c_append(crc32, self.pack_layout());

        let padding_size = (self.padded_size() - self.header.used_size()) as usize;
        crc32c_append(crc32, &[0u8; EROFS_BLOCK_SIZE as usize][..padding_size])
    }
}

fn invalid_layout(err: Error) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, err.to_string())
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
            0,
            0,
            false,
        )
        .unwrap()
    }

    #[allow(clippy::too_many_arguments)]
    fn redirect_block_group(
        block_offset: u64,
        block_count: u32,
        compressed_offset: u64,
        compressed_size: u32,
        payload: &[u8],
        source_blob_index: u16,
        source_block_group_index: u32,
    ) -> BlobMetadataBlockGroup {
        BlobMetadataBlockGroup::new(
            block_offset,
            block_count,
            compressed_offset,
            compressed_size,
            crc32c::crc32c(payload),
            source_blob_index,
            source_block_group_index,
            true,
        )
        .unwrap()
    }

    fn blob_metadata(
        chunks: Vec<BlobMetadataChunk>,
        block_groups: Vec<BlobMetadataBlockGroup>,
    ) -> Result<BlobMetadata> {
        BlobMetadata::new(
            BlobMetadataCompressor::None,
            BlobMetadataDigester::Blake3,
            1,
            chunks,
            block_groups,
            false,
        )
    }

    fn minimal_blob_metadata() -> BlobMetadata {
        let payload = vec![0x33; EROFS_BLOCK_SIZE as usize];
        blob_metadata(
            vec![chunk(&payload, 0, 1)],
            vec![block_group(0, 1, 0, EROFS_BLOCK_SIZE, &payload)],
        )
        .unwrap()
    }

    fn sealed_metadata() -> Vec<u8> {
        let mut raw = Vec::new();
        minimal_blob_metadata().write_to(&mut raw).unwrap();
        raw
    }

    #[test]
    fn accessors_expose_the_sealed_tables() {
        let blob_metadata = minimal_blob_metadata();
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
        let blob_metadata = blob_metadata(
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
    fn mutated_bytes_follow_the_read_rules() {
        let base_flags = BlobMetadataDigester::Blake3.flag().bits();
        let used_size = minimal_blob_metadata().header().used_size() as usize;
        let cases: [(&str, usize, [u8; 4], Option<&str>); 7] = [
            (
                "legacy nydus magic rejects",
                0,
                0xb10b_b10bu32.to_le_bytes(),
                Some("magic"),
            ),
            (
                "legacy v0 magic rejects",
                0,
                0x4c50_424du32.to_le_bytes(),
                Some("magic"),
            ),
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
            (
                "nonzero tail padding rejects",
                used_size,
                [0xff, 0, 0, 0],
                Some("padding must be zero"),
            ),
        ];

        for (case, offset, value, expected_err) in cases {
            let mut raw = sealed_metadata();
            raw[offset..offset + 4].copy_from_slice(&value);

            match expected_err {
                None => {
                    BlobMetadata::from_bytes(&raw, false)
                        .unwrap_or_else(|err| panic!("{case}: {err}"));
                    let err = BlobMetadata::from_bytes(&raw, true).unwrap_err();
                    assert!(err.to_string().contains("crc32"), "{case}: {err}");
                }
                Some(expected) => {
                    let err = match BlobMetadata::from_bytes(&raw, false) {
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
    fn undersized_inputs_reject() {
        let dir = tempdir().unwrap();
        let raw = sealed_metadata();
        let cases = [
            ("shorter than the header", 10, "too small"),
            (
                "shorter than the padded size",
                raw.len() - 1,
                "size mismatch",
            ),
        ];

        for (case, len, expected) in cases {
            let err = BlobMetadata::from_bytes(&raw[..len], false).unwrap_err();
            assert!(err.to_string().contains(expected), "{case}: {err}");

            let path = dir.path().join(format!("{len}.blob.meta"));
            std::fs::write(&path, &raw[..len]).unwrap();
            let err = BlobMetadata::from_path(&path, false).unwrap_err();
            assert!(err.to_string().contains(expected), "{case}: {err}");
        }
    }

    #[test]
    fn invalid_block_group_entries_reject() {
        let valid = BlobMetadataBlockGroup::new(0, 1, 0, 4096, 0, 0, 0, false)
            .unwrap()
            .to_bytes();
        let mut orphan_source = valid;
        write_u32_at(&mut orphan_source, 28, 7);
        let mut dirty_reserved = valid;
        dirty_reserved[34] = 0xff;

        let cases = [
            (
                "zero uncompressed block count",
                BlobMetadataBlockGroup::new(0, 0, 0, 4096, 0, 0, 0, false),
                "must be non-zero",
            ),
            (
                "zero compressed size",
                BlobMetadataBlockGroup::new(0, 1, 0, 0, 0, 0, 0, false),
                "must be non-zero",
            ),
            (
                "uncompressed byte offset overflow",
                BlobMetadataBlockGroup::new(u64::MAX, 1, 0, 4096, 0, 0, 0, false),
                "overflow",
            ),
            (
                "compressed byte range overflow",
                BlobMetadataBlockGroup::new(0, 1, u64::MAX, 4096, 0, 0, 0, false),
                "overflow",
            ),
            (
                "redirect flag without a source blob index",
                BlobMetadataBlockGroup::new(0, 1, 0, 4096, 0, 0, 0, true),
                "redirect flag",
            ),
            (
                "source blob index without the redirect flag",
                BlobMetadataBlockGroup::new(0, 1, 0, 4096, 0, 1, 0, false),
                "redirect flag",
            ),
            (
                "source block group index without a source blob",
                BlobMetadataBlockGroup::from_bytes(&orphan_source, false),
                "requires a source blob index",
            ),
            (
                "nonzero reserved tail",
                BlobMetadataBlockGroup::from_bytes(&dirty_reserved, false),
                "reserved",
            ),
        ];

        for (case, result, expected) in cases {
            let err = result.unwrap_err();
            assert!(err.to_string().contains(expected), "{case}: {err}");
        }
    }

    #[test]
    fn invalid_chunk_entries_reject() {
        let cases = [
            (
                "zero block count",
                BlobMetadataChunk::new([0u8; 32], 0, 0),
                "must be non-zero",
            ),
            (
                "block offset overflow",
                BlobMetadataChunk::new([0u8; 32], u64::MAX, 1),
                "overflow",
            ),
        ];

        for (case, result, expected) in cases {
            let err = result.unwrap_err();
            assert!(err.to_string().contains(expected), "{case}: {err}");
        }

        // The byte length field is reserved in a padded blob: the entry
        // parses, the table rejects it.
        let mut bytes = sealed_metadata();
        write_u32_at(&mut bytes, NYDUS_BLOB_METADATA_HEADER_SIZE + 44, 1);
        let err = BlobMetadata::from_bytes(&bytes, false).unwrap_err();
        assert!(err.to_string().contains("reserved"), "{err}");
    }

    #[test]
    fn invalid_tables_reject() {
        let one = vec![0x11; EROFS_BLOCK_SIZE as usize];
        let two = vec![0x22; 2 * EROFS_BLOCK_SIZE as usize];
        let three = vec![0x33; 3 * EROFS_BLOCK_SIZE as usize];
        let block = EROFS_BLOCK_SIZE as u64;
        let cases = [
            (
                "chunk past the block groups",
                vec![chunk(&one, 1, 1)],
                vec![block_group(0, 1, 0, EROFS_BLOCK_SIZE, &one)],
                "exceeds the blob block range",
            ),
            (
                "first block group not at block zero",
                vec![chunk(&one, 0, 1)],
                vec![block_group(1, 1, 0, EROFS_BLOCK_SIZE, &one)],
                "dense",
            ),
            (
                "gap between block groups",
                vec![chunk(&two, 0, 2)],
                vec![
                    block_group(0, 2, 0, 2 * EROFS_BLOCK_SIZE, &two),
                    block_group(3, 2, 2 * block, 2 * EROFS_BLOCK_SIZE, &two),
                ],
                "dense",
            ),
            (
                "oversized middle block group",
                vec![chunk(&two, 0, 2), chunk(&three, 2, 3), chunk(&one, 5, 1)],
                vec![
                    block_group(0, 2, 0, 2 * EROFS_BLOCK_SIZE, &two),
                    block_group(2, 3, 2 * block, 3 * EROFS_BLOCK_SIZE, &three),
                    block_group(5, 1, 5 * block, EROFS_BLOCK_SIZE, &one),
                ],
                "must be exactly",
            ),
            (
                "oversized final block group",
                vec![chunk(&two, 0, 2), chunk(&three, 2, 3)],
                vec![
                    block_group(0, 2, 0, 2 * EROFS_BLOCK_SIZE, &two),
                    block_group(2, 3, 2 * block, 3 * EROFS_BLOCK_SIZE, &three),
                ],
                "final block group",
            ),
            (
                "full block groups not a power of two",
                vec![chunk(&three, 0, 3), chunk(&one, 3, 1)],
                vec![
                    block_group(0, 3, 0, 3 * EROFS_BLOCK_SIZE, &three),
                    block_group(3, 1, 3 * block, EROFS_BLOCK_SIZE, &one),
                ],
                "power of two",
            ),
            (
                "overlapping compressed ranges",
                vec![chunk(&two, 0, 2), chunk(&two, 2, 2)],
                vec![
                    block_group(0, 2, 0, 5000, &two),
                    block_group(2, 2, 4999, 3000, &two),
                ],
                "overlap",
            ),
        ];

        for (case, chunks, block_groups, expected) in cases {
            let err = blob_metadata(chunks, block_groups).unwrap_err();
            assert!(err.to_string().contains(expected), "{case}: {err}");
        }
    }

    #[test]
    fn block_group_index_from_uncompressed_offset_maps_by_division() {
        let two = vec![0x11; 2 * EROFS_BLOCK_SIZE as usize];
        let one = vec![0x22; EROFS_BLOCK_SIZE as usize];
        let block = EROFS_BLOCK_SIZE as u64;
        let blob_metadata = blob_metadata(
            vec![chunk(&two, 0, 2), chunk(&two, 2, 2), chunk(&one, 4, 1)],
            vec![
                block_group(0, 2, 0, 2 * EROFS_BLOCK_SIZE, &two),
                block_group(2, 2, 2 * block, 2 * EROFS_BLOCK_SIZE, &two),
                block_group(4, 1, 4 * block, EROFS_BLOCK_SIZE, &one),
            ],
        )
        .unwrap();
        assert_eq!(blob_metadata.header().block_group_block_count(), 2);

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
    fn a_single_block_group_uses_a_covering_power_of_two_exponent() {
        let three = vec![0x44; 3 * EROFS_BLOCK_SIZE as usize];
        let block = EROFS_BLOCK_SIZE as u64;
        let blob_metadata = blob_metadata(
            vec![chunk(&three, 0, 3)],
            vec![block_group(0, 3, 0, 3 * EROFS_BLOCK_SIZE, &three)],
        )
        .unwrap();
        assert_eq!(blob_metadata.header().block_group_block_count(), 4);

        let cases = [
            (0, Some(0)),
            (2 * block, Some(0)),
            (3 * block - 1, Some(0)),
            (3 * block, None),
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
    fn packed_compressed_offsets_need_no_block_alignment() {
        let two = vec![0x11; 2 * EROFS_BLOCK_SIZE as usize];
        let blob_metadata = blob_metadata(
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
    fn redirect_block_groups_round_trip_and_report_their_source() {
        let payload = vec![0x44; 2 * EROFS_BLOCK_SIZE as usize];
        let redirect = redirect_block_group(0, 2, 0, 2 * EROFS_BLOCK_SIZE, &payload, 3, 7);

        assert!(redirect.is_redirect());
        assert_eq!(redirect.source_blob_index(), 3);
        assert_eq!(redirect.source_block_group_index(), 7);

        let mut written = Vec::new();
        redirect.write_to(&mut written).unwrap();
        let bytes: [u8; 40] = written.as_slice().try_into().unwrap();
        assert_eq!(
            BlobMetadataBlockGroup::from_bytes(&bytes, true).unwrap(),
            redirect
        );

        let normal = block_group(0, 2, 0, 2 * EROFS_BLOCK_SIZE, &payload);
        assert!(!normal.is_redirect());
        let loaded = BlobMetadataBlockGroup::from_bytes(&normal.to_bytes(), false).unwrap();
        assert!(!loaded.is_redirect());
        assert_eq!(loaded.source_block_group_index(), 0);
    }

    #[test]
    fn block_groups_must_match_the_redirect_flag() {
        let payload = vec![0x45; EROFS_BLOCK_SIZE as usize];
        let regular = block_group(0, 1, 0, EROFS_BLOCK_SIZE, &payload);
        let redirect = redirect_block_group(0, 1, 0, EROFS_BLOCK_SIZE, &payload, 1, 0);
        let cases = [
            ("regular entry under the redirect flag", regular, true),
            ("redirect entry without the redirect flag", redirect, false),
        ];

        for (case, block_group, is_redirect) in cases {
            let err = BlobMetadata::new(
                BlobMetadataCompressor::None,
                BlobMetadataDigester::Blake3,
                1,
                Vec::new(),
                vec![block_group],
                is_redirect,
            )
            .unwrap_err();
            assert!(err.to_string().contains("block group 0"), "{case}: {err}");
        }
    }

    #[test]
    fn a_redirect_blob_round_trips_with_non_uniform_block_groups() {
        let two = vec![0x55; 2 * EROFS_BLOCK_SIZE as usize];
        let three = vec![0x66; 3 * EROFS_BLOCK_SIZE as usize];
        let one = vec![0x77; EROFS_BLOCK_SIZE as usize];
        let block = EROFS_BLOCK_SIZE as u64;
        let block_groups = vec![
            redirect_block_group(0, 2, 0, 2 * EROFS_BLOCK_SIZE, &two, 1, 4),
            redirect_block_group(2, 3, 2 * block, 3 * EROFS_BLOCK_SIZE, &three, 2, 0),
            redirect_block_group(5, 1, 5 * block, EROFS_BLOCK_SIZE, &one, 1, 9),
        ];
        let blob_metadata = BlobMetadata::new(
            BlobMetadataCompressor::None,
            BlobMetadataDigester::Blake3,
            1,
            Vec::new(),
            block_groups.clone(),
            true,
        )
        .unwrap();
        assert!(blob_metadata.is_redirect());
        assert_eq!(blob_metadata.header().block_group_block_count(), 1);

        let mut raw = Vec::new();
        blob_metadata.write_to(&mut raw).unwrap();
        let loaded = BlobMetadata::from_bytes(&raw, true).unwrap();
        assert!(loaded.is_redirect());
        assert_eq!(loaded.block_groups(), block_groups.as_slice());
    }

    /// A dense fixture: a 2-block group budget (8 KiB), one pack of three
    /// small files (100 + 5000 + 40 bytes, spanning 1 + 2 + 1 blocks) and a
    /// 6000-byte plain chunk (2 blocks), cut into groups at aligned points.
    /// Dense stream: [pack 5140][chunk 6000]; group 0 takes the whole pack
    /// plus the first 4096 bytes of the chunk (9236 > 8192 - 4096, but the
    /// cut must be block aligned, so 5140 + 4096 = 9236 exceeds the 8192
    /// budget: group 0 is the pack alone and group 1 the chunk).
    fn dense_fixture() -> (BlobMetadata, Vec<u8>, Vec<u8>) {
        let files: [Vec<u8>; 3] = [vec![0xa1; 100], vec![0xb2; 5000], vec![0xc3; 40]];
        let chunk_bytes = vec![0xd4; 6000];
        let pack_bytes: Vec<u8> = files.concat();
        let mut layout = Vec::new();
        encode_pack_layout(&[100, 5000, 40], &mut layout);
        let chunks = vec![
            BlobMetadataChunk::new_dense(digest(&pack_bytes), 0, 4, 5140, true).unwrap(),
            BlobMetadataChunk::new_dense(digest(&chunk_bytes), 4, 2, 6000, false).unwrap(),
        ];
        let block_groups = vec![
            BlobMetadataBlockGroup::new_dense(
                0,
                4,
                0,
                5140,
                crc32c::crc32c(&pack_bytes),
                0,
                0,
                false,
                5140,
            )
            .unwrap(),
            BlobMetadataBlockGroup::new_dense(
                4,
                2,
                5140,
                6000,
                crc32c::crc32c(&chunk_bytes),
                0,
                0,
                false,
                6000,
            )
            .unwrap(),
        ];
        let meta = BlobMetadata::new_dense(
            BlobMetadataCompressor::None,
            BlobMetadataDigester::Blake3,
            2,
            2,
            chunks,
            block_groups,
            layout,
            false,
            BlobMetadataFlags::empty(),
        )
        .unwrap();
        (meta, pack_bytes, chunk_bytes)
    }

    #[test]
    fn dense_metadata_round_trips_and_scatters_packs() {
        let (meta, pack_bytes, chunk_bytes) = dense_fixture();
        assert!(meta.is_dense());
        assert_eq!(meta.header().block_group_size(), 8192);
        assert_eq!(meta.uncompressed_size(), 6 * EROFS_BLOCK_SIZE as u64);

        let mut raw = Vec::new();
        meta.write_to(&mut raw).unwrap();
        let loaded = BlobMetadata::from_bytes(&raw, true).unwrap();
        assert_eq!(loaded.chunks(), meta.chunks());
        assert_eq!(loaded.block_groups(), meta.block_groups());
        assert_eq!(loaded.pack_layout(), meta.pack_layout());
        let dir = tempdir().unwrap();
        let path = dir.path().join("dense.blob.meta");
        meta.save(&path).unwrap();
        let mapped = BlobMetadata::from_path(&path, true).unwrap();
        assert_eq!(mapped.pack_layout(), meta.pack_layout());
        assert!(mapped.chunks()[0].is_pack());
        assert_eq!(mapped.chunks()[0].byte_len(), 5140);
        assert!(!mapped.chunks()[1].is_pack());
        assert_eq!(
            mapped
                .pack_files(0)
                .unwrap()
                .collect::<Result<Vec<_>>>()
                .unwrap(),
            vec![100, 5000, 40]
        );
        assert!(mapped.pack_files(1).is_none());

        // Scatter: the pack's files land on their own blocks, the chunk at
        // block 4.
        let mut pieces = Vec::new();
        mapped
            .for_each_decoded_piece(0, &pack_bytes, &mut |offset, bytes| {
                pieces.push((offset, bytes.to_vec()));
                Ok(())
            })
            .unwrap();
        assert_eq!(
            pieces,
            vec![
                (0, vec![0xa1; 100]),
                (4096, vec![0xb2; 5000]),
                (3 * 4096, vec![0xc3; 40]),
            ]
        );
        pieces.clear();
        mapped
            .for_each_decoded_piece(1, &chunk_bytes, &mut |offset, bytes| {
                pieces.push((offset, bytes.to_vec()));
                Ok(())
            })
            .unwrap();
        assert_eq!(pieces, vec![(4 * 4096, chunk_bytes.clone())]);
        assert!(mapped
            .for_each_decoded_piece(1, &chunk_bytes[..10], &mut |_, _| Ok(()))
            .is_err());
    }

    #[test]
    fn dense_lookup_is_by_window_and_handles_variable_spans() {
        // Three groups whose spans differ from the 2-block budget: group 0
        // spans 3 blocks (a 100-byte file padded twice over), group 1 spans
        // 2, group 2 spans 4. Windows of 2 blocks each meet at most two.
        let f = |len: usize, fill: u8| vec![fill; len];
        let g0 = [f(100, 1), f(8000, 2)].concat(); // pack: 1 + 2 blocks
        let g1 = f(8192, 3); // plain chunk, 2 blocks
        let g2 = [f(1, 4), f(1, 5), f(1, 6), f(1, 7)].concat(); // pack: 4 blocks
        let mut layout = Vec::new();
        encode_pack_layout(&[100, 8000], &mut layout);
        encode_pack_layout(&[1, 1, 1, 1], &mut layout);
        let chunks = vec![
            BlobMetadataChunk::new_dense(digest(&g0), 0, 3, 8100, true).unwrap(),
            BlobMetadataChunk::new_dense(digest(&g1), 3, 2, 8192, false).unwrap(),
            BlobMetadataChunk::new_dense(digest(&g2), 5, 4, 4, true).unwrap(),
        ];
        let groups = vec![
            BlobMetadataBlockGroup::new_dense(
                0,
                3,
                0,
                8100,
                crc32c::crc32c(&g0),
                0,
                0,
                false,
                8100,
            )
            .unwrap(),
            BlobMetadataBlockGroup::new_dense(
                3,
                2,
                8100,
                8192,
                crc32c::crc32c(&g1),
                0,
                0,
                false,
                8192,
            )
            .unwrap(),
            BlobMetadataBlockGroup::new_dense(5, 4, 16292, 4, crc32c::crc32c(&g2), 0, 0, false, 4)
                .unwrap(),
        ];
        let meta = BlobMetadata::new_dense(
            BlobMetadataCompressor::None,
            BlobMetadataDigester::Blake3,
            2,
            2,
            chunks,
            groups,
            layout,
            false,
            BlobMetadataFlags::empty(),
        )
        .unwrap();
        let block = EROFS_BLOCK_SIZE as u64;
        let expect = [0, 0, 0, 1, 1, 2, 2, 2, 2];
        for (b, g) in expect.iter().enumerate() {
            assert_eq!(
                meta.block_group_index_from_uncompressed_offset(b as u64 * block),
                Some(*g),
                "block {b}"
            );
            assert_eq!(
                meta.block_group_index_from_uncompressed_offset(b as u64 * block + block - 1),
                Some(*g),
                "block {b} end"
            );
        }
        assert_eq!(
            meta.block_group_index_from_uncompressed_offset(9 * block),
            None
        );

        let mut pieces = Vec::new();
        meta.for_each_decoded_piece(2, &g2, &mut |offset, bytes| {
            pieces.push((offset, bytes.to_vec()));
            Ok(())
        })
        .unwrap();
        assert_eq!(
            pieces,
            vec![
                (5 * block, vec![4]),
                (6 * block, vec![5]),
                (7 * block, vec![6]),
                (8 * block, vec![7]),
            ]
        );
    }

    #[test]
    fn dense_tables_reject_inconsistent_layouts() {
        let (meta, pack_bytes, chunk_bytes) = dense_fixture();
        let chunks = meta.chunks().to_vec();
        let groups = meta.block_groups().to_vec();
        let layout = meta.pack_layout().to_vec();
        let build = |chunks: Vec<BlobMetadataChunk>,
                     groups: Vec<BlobMetadataBlockGroup>,
                     layout: Vec<u8>| {
            BlobMetadata::new_dense(
                BlobMetadataCompressor::None,
                BlobMetadataDigester::Blake3,
                2,
                2,
                chunks,
                groups,
                layout,
                false,
                BlobMetadataFlags::empty(),
            )
        };

        // Pack files not summing to the chunk's bytes.
        let mut bad_layout = Vec::new();
        encode_pack_layout(&[100, 5000, 41], &mut bad_layout);
        let err = build(chunks.clone(), groups.clone(), bad_layout).unwrap_err();
        assert!(err.to_string().contains("sum to"), "{err}");

        // Plain chunk whose block count does not cover its bytes.
        let mut short = chunks.clone();
        short[1] = BlobMetadataChunk::new_dense(digest(&chunk_bytes), 4, 1, 6000, false).unwrap();
        let mut short_groups = groups.clone();
        short_groups[1] = BlobMetadataBlockGroup::new_dense(
            4,
            1,
            5140,
            6000,
            crc32c::crc32c(&chunk_bytes),
            0,
            0,
            false,
            4096,
        )
        .unwrap();
        let err = build(short, short_groups, layout.clone()).unwrap_err();
        assert!(err.to_string().contains("spans 1 blocks"), "{err}");

        // Groups decoding to fewer bytes than the chunks hold.
        let mut light = groups.clone();
        light[1] = BlobMetadataBlockGroup::new_dense(
            4,
            2,
            5140,
            6000,
            crc32c::crc32c(&chunk_bytes),
            0,
            0,
            false,
            5999,
        )
        .unwrap();
        let err = build(chunks.clone(), light, layout.clone()).unwrap_err();
        assert!(err.to_string().contains("decode to"), "{err}");

        // A non-final group leaving more than a block of its budget unused.
        let mut loose = groups.clone();
        loose[0] = BlobMetadataBlockGroup::new_dense(
            0,
            4,
            0,
            5140,
            crc32c::crc32c(&pack_bytes),
            0,
            0,
            false,
            4000,
        )
        .unwrap();
        loose[1] = BlobMetadataBlockGroup::new_dense(
            4,
            2,
            5140,
            6000,
            crc32c::crc32c(&chunk_bytes),
            0,
            0,
            false,
            7140,
        )
        .unwrap();
        let err = build(chunks.clone(), loose, layout.clone()).unwrap_err();
        assert!(err.to_string().contains("unused"), "{err}");

        // Trailing pack layout bytes.
        let mut trailing = layout.clone();
        trailing.push(0);
        let err = build(chunks.clone(), groups.clone(), trailing).unwrap_err();
        assert!(err.to_string().contains("trailing"), "{err}");

        // A padded blob must not carry a pack layout or dense sizes.
        let err = BlobMetadata::new_with_flags(
            BlobMetadataCompressor::None,
            BlobMetadataDigester::Blake3,
            1,
            Vec::new(),
            vec![groups[0]],
            false,
            BlobMetadataFlags::empty(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("dense size must be zero"), "{err}");
    }
}

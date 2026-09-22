use crate::blob::algorithm::{BlobMetadataCompressor, BlobMetadataDigester};
use crate::blob::flag::FeatureFlags;
use crate::erofs::EROFS_BLOCK_SIZE;
use crate::error::{Context, Error, Result};
use crate::utils::align_up_u64;
use crate::utils::le::{
    read_u32_at, read_u64_at, read_u8_at, write_u32_at, write_u64_at, write_u8_at,
};
use bitflags::bitflags;
use crc32c::{crc32c, crc32c_append};
use memmap2::{Mmap, MmapOptions};
use std::fs::File;
use std::io::Write;
use std::mem::{align_of, size_of};
use std::ops::Range;
use std::path::Path;

/// On-disk magic: 8 raw ASCII bytes ("NDBLMETA" = NyDus BLob META), written
/// as-is so a hexdump of the file starts with the readable string. Same
/// style and `magic + version + flags` header prefix as the blob footer
/// (`NDFOOTER`) and chunk group map (`NDGRPMAP`) sidecars.
pub const NYDUS_BLOB_METADATA_MAGIC: [u8; 8] = *b"NDBLMETA";

/// Format version of the dense-group layout; earlier experimental layouts
/// are unsupported.
pub const NYDUS_BLOB_METADATA_VERSION: u32 = 1;

/// The header's fixed on-disk size. The tables follow it back to back, each
/// starting 8-byte aligned, and the whole file is padded to a 4KiB block.
pub const NYDUS_BLOB_METADATA_HEADER_SIZE: usize = 32;

/// On-disk size of one chunk group table entry (see
/// [`BlobMetadataChunkGroup`]).
pub const NYDUS_BLOB_METADATA_CHUNK_GROUP_ENTRY_SIZE: usize = 24;

/// On-disk size of one digest entry, see [`BlobMetadataDigest`].
pub const NYDUS_BLOB_METADATA_DIGEST_ENTRY_SIZE: usize = 32;

/// On-disk size of one GranuleIndexTable entry.
pub const NYDUS_BLOB_METADATA_GRANULE_INDEX_ENTRY_SIZE: usize = 4;

/// On-disk size of one redirect entry, see [`BlobMetadataRedirect`].
pub const NYDUS_BLOB_METADATA_REDIRECT_ENTRY_SIZE: usize = 8;

/// Default file chunk size: the largest chunk a file is cut into, 2 MiB.
/// The builder controls chunk group sizes separately, so changing the file
/// chunk size does not change the default chunk group minimum size.
pub const DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE: u32 = 2 * 1024 * 1024;

/// The default chunk size in 4KiB blocks.
pub const DEFAULT_NYDUS_BLOB_METADATA_CHUNK_BLOCK_COUNT: u32 =
    DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE / EROFS_BLOCK_SIZE;

/// File-name suffix of a blob meta sidecar file (`<blob>.blob.meta`).
pub const NYDUS_BLOB_METADATA_SUFFIX: &str = ".blob.meta";

/// Largest allowed group span exponent (`maximum_group_span_block_shift`): keeps the
/// derived byte size (`4096 << bits`) within a `u32` (2 GiB at most).
const NYDUS_BLOB_METADATA_MAX_BLOCK_COUNT_BITS: u8 = 19;

/// Byte range of the crc32 field within the header.
const NYDUS_BLOB_METADATA_HEADER_CRC32_FIELD: Range<usize> = 16..20;

const BLOCK: u64 = EROFS_BLOCK_SIZE as u64;
/// log2 of the 4KiB block: byte exponents are block exponents plus this.
const EROFS_BLOCK_SIZE_BITS: u8 = EROFS_BLOCK_SIZE.trailing_zeros() as u8;

bitflags! {
    /// Feature bits, split EROFS-style (see [`crate::blob::flag`]): the low
    /// 16 bits are incompatible features (unknown bits reject the file), the
    /// high 16 bits are compatible features (unknown bits are ignored).
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct BlobMetadataFlags: u32 {
        /// Group payloads are zstd frames; no compressor bit means stored
        /// plain.
        const COMPRESSOR_ZSTD = 1 << 0;
        /// Group payloads are LZ4 blocks.
        const COMPRESSOR_LZ4 = 1 << 1;
        /// Every chunk group has a BLAKE3 digest in the digest table (see
        /// [`BlobMetadataDigest::of_group`]); no digester bit means the
        /// table is empty (`nydus build --digester none`).
        const DIGESTER_BLAKE3 = 1 << 2;
        /// The blob is an `optimize` output: every chunk group is a copy of
        /// a chunk group of another blob of the image, named by the redirect
        /// table, and the runtime prefetches it into those source blobs'
        /// caches under `prefetch.scope: ondemand`. Incompatible: a reader
        /// that does not fill the sources from it gains nothing from it.
        const REDIRECT = 1 << 3;
    }
}

/// Every defined incompat bit is supported (unknown incompat bits reject the
/// file); the compat half is masked off by the validation itself.
const NYDUS_BLOB_METADATA_SUPPORTED_INCOMPAT: u32 = BlobMetadataFlags::all().bits() & 0xffff;

/// Header sealed with CRC32C over the complete metadata. Table offsets are
/// derived from the header and GroupTable terminator, never stored separately.
/// `total_blocks` and `chunk_count` below are validated, derived scalars,
/// not on-disk header fields or an allocated runtime index.
///
/// The header's 32 bytes (integers little-endian). Counts outside the
/// header are recovered from the GroupTable terminator before table access.
///
/// ```text
/// offset  size  field
///      0     8  magic                   b"NDBLMETA"
///      8     4  version                 1; other generations are rejected
///     12     4  flags                   low 16 incompat / high 16 compat
///     16     4  crc32                   crc32c of the whole serialized
///                                       metadata with this field zero
///     20     4  chunk_group_count       excludes the terminator
///     24     1  maximum_group_span_block_shift         log2 of maximum 4KiB block span
///     25     1  lookup_granule_byte_shift            log2 of lookup granule bytes
///     26     6  reserved                zero
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlobMetadataHeader {
    magic: [u8; 8],
    version: u32,
    flags: u32,
    crc32: u32,
    maximum_group_span_block_shift: u8,
    lookup_granule_byte_shift: u8,
    chunk_group_count: u32,
    total_blocks: u32,
    chunk_count: u32,
}

impl BlobMetadataHeader {
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < NYDUS_BLOB_METADATA_HEADER_SIZE {
            return Err(Error::InvalidImage(
                "blob meta header is truncated".to_string(),
            ));
        }
        if bytes[26..32].iter().any(|byte| *byte != 0) {
            return Err(Error::InvalidImage(
                "blob meta reserved header bytes must be zero".to_string(),
            ));
        }
        let mut header = Self {
            magic: bytes[0..8].try_into().unwrap(),
            version: read_u32_at(bytes, 8),
            flags: read_u32_at(bytes, 12),
            crc32: read_u32_at(bytes, 16),
            maximum_group_span_block_shift: read_u8_at(bytes, 24),
            lookup_granule_byte_shift: read_u8_at(bytes, 25),
            chunk_group_count: read_u32_at(bytes, 20),
            total_blocks: 0,
            chunk_count: 0,
        };
        let terminator_offset = NYDUS_BLOB_METADATA_HEADER_SIZE as u64
            + u64::from(header.chunk_group_count)
                * NYDUS_BLOB_METADATA_CHUNK_GROUP_ENTRY_SIZE as u64;
        let end = terminator_offset + NYDUS_BLOB_METADATA_CHUNK_GROUP_ENTRY_SIZE as u64;
        if end > bytes.len() as u64 {
            return Err(Error::InvalidImage(
                "blob meta GroupTable is truncated".to_string(),
            ));
        }
        let terminator = terminator_offset as usize;
        header.chunk_count = read_u32_at(bytes, terminator + 12);
        header.total_blocks = read_u32_at(bytes, terminator + 8);
        header.validate()?;
        Ok(header)
    }

    fn to_bytes(self) -> [u8; NYDUS_BLOB_METADATA_HEADER_SIZE] {
        let mut data = [0u8; NYDUS_BLOB_METADATA_HEADER_SIZE];
        data[0..8].copy_from_slice(&self.magic);
        write_u32_at(&mut data, 8, self.version);
        write_u32_at(&mut data, 12, self.flags);
        write_u32_at(&mut data, 16, self.crc32);
        write_u32_at(&mut data, 20, self.chunk_group_count);
        write_u8_at(&mut data, 24, self.maximum_group_span_block_shift);
        write_u8_at(&mut data, 25, self.lookup_granule_byte_shift);
        data
    }

    /// Validate the intrinsic field invariants. The entry counts are
    /// anchored against the actual bytes by [`BlobMetadata::validate_bytes`]
    /// and against each other by [`BlobMetadata::validate_tables`].
    fn validate(&self) -> Result<()> {
        if self.magic != NYDUS_BLOB_METADATA_MAGIC {
            return Err(Error::InvalidImage("invalid blob meta magic".to_string()));
        }
        if self.version != NYDUS_BLOB_METADATA_VERSION {
            return Err(Error::InvalidImage(format!(
                "unsupported blob meta version {} (expected {NYDUS_BLOB_METADATA_VERSION})",
                self.version
            )));
        }
        if self.maximum_group_span_block_shift > NYDUS_BLOB_METADATA_MAX_BLOCK_COUNT_BITS {
            return Err(Error::InvalidImage(format!(
                "blob meta group span bits too large: {}",
                self.maximum_group_span_block_shift
            )));
        }
        let span_bits = self.maximum_group_span_block_shift + EROFS_BLOCK_SIZE_BITS;
        if !(EROFS_BLOCK_SIZE_BITS..=span_bits).contains(&self.lookup_granule_byte_shift) {
            return Err(Error::InvalidImage(format!(
                "blob meta lookup granule bits {} must lie between one block and the {}-byte group span",
                self.lookup_granule_byte_shift,
                self.group_span()
            )));
        }
        let flags = BlobMetadataFlags::from_bits_truncate(self.flags);
        if flags.contains(BlobMetadataFlags::COMPRESSOR_ZSTD | BlobMetadataFlags::COMPRESSOR_LZ4) {
            return Err(Error::InvalidImage(
                "blob meta declares more than one compressor".to_string(),
            ));
        }
        FeatureFlags::from_bits(self.flags)
            .validate_incompat(NYDUS_BLOB_METADATA_SUPPORTED_INCOMPAT)?;
        let empty = self.chunk_group_count == 0;
        if empty != (self.chunk_count == 0) || empty != (self.total_blocks == 0) {
            return Err(Error::InvalidImage(format!(
                "blob meta has {} chunk groups, {} chunks and {} blocks",
                self.chunk_group_count, self.chunk_count, self.total_blocks
            )));
        }
        if self.chunk_group_count > self.chunk_count {
            return Err(Error::InvalidImage(format!(
                "blob meta names {} groups among {} chunks",
                self.chunk_group_count, self.chunk_count
            )));
        }
        self.used_size_checked()?;
        Ok(())
    }

    /// On-disk format generation, always [`NYDUS_BLOB_METADATA_VERSION`].
    pub fn version(&self) -> u32 {
        self.version
    }

    /// The known feature bits as a typed view.
    pub fn flags(&self) -> BlobMetadataFlags {
        BlobMetadataFlags::from_bits_truncate(self.flags)
    }

    /// crc32c sealing the whole serialized metadata, exactly as stored.
    pub fn crc32(&self) -> u32 {
        self.crc32
    }

    /// The chunk group payload compressor, per the flags.
    pub fn compressor(&self) -> BlobMetadataCompressor {
        BlobMetadataCompressor::from(self.flags())
    }

    /// The digest algorithm, per the flags.
    pub fn digester(&self) -> BlobMetadataDigester {
        BlobMetadataDigester::from(self.flags())
    }

    /// Whether the blob is an `optimize` output (see
    /// [`BlobMetadataFlags::REDIRECT`]).
    pub fn is_redirect(&self) -> bool {
        self.flags().contains(BlobMetadataFlags::REDIRECT)
    }

    /// log2 of the most 4KiB blocks a chunk group spans.
    pub fn maximum_group_span_block_shift(&self) -> u8 {
        self.maximum_group_span_block_shift
    }

    /// The most 4KiB blocks a chunk group spans (`1 << maximum_group_span_block_shift`).
    pub fn group_span_blocks(&self) -> u32 {
        1u32 << self.maximum_group_span_block_shift
    }

    /// The most bytes of the address space a chunk group spans: a lone
    /// chunk is at most a file chunk, a pack may span more.
    pub fn group_span(&self) -> u32 {
        EROFS_BLOCK_SIZE << self.maximum_group_span_block_shift
    }

    /// log2 of the mandatory lookup granule in bytes.
    pub fn lookup_granule_byte_shift(&self) -> u8 {
        self.lookup_granule_byte_shift
    }

    /// Lookup granule bytes; every non-final group spans at least this much.
    pub fn lookup_granule(&self) -> u32 {
        1u32 << self.lookup_granule_byte_shift
    }

    /// log2 of the lookup granule in 4KiB blocks.
    fn granule_block_bits(&self) -> u32 {
        u32::from(
            self.lookup_granule_byte_shift
                .saturating_sub(EROFS_BLOCK_SIZE_BITS),
        )
    }

    /// 4KiB blocks per GranuleIndexTable entry.
    fn granule_blocks(&self) -> u64 {
        1u64 << self.granule_block_bits()
    }

    /// Number of chunk groups (the table holds one more entry, the
    /// terminator).
    pub fn chunk_group_count(&self) -> u32 {
        self.chunk_group_count
    }

    /// Size of the address space in 4KiB blocks.
    pub fn total_blocks(&self) -> u32 {
        self.total_blocks
    }

    /// Number of chunks, lone chunks included.
    pub fn chunk_count(&self) -> u32 {
        self.chunk_count
    }

    /// Number of digest entries: the chunk group count with a digester,
    /// else zero.
    pub fn digest_count(&self) -> u32 {
        match self.digester() {
            BlobMetadataDigester::Blake3 => self.chunk_group_count,
            BlobMetadataDigester::None => 0,
        }
    }

    /// Number of entries in GranuleIndexTable, one per lookup granule.
    pub fn granule_index_count(&self) -> u32 {
        (u64::from(self.total_blocks)).div_ceil(self.granule_blocks()) as u32
    }

    /// Number of redirect entries: the chunk group count of a redirect
    /// blob, else zero.
    pub fn redirect_count(&self) -> u32 {
        if self.is_redirect() {
            self.chunk_group_count
        } else {
            0
        }
    }

    /// Byte offset of the chunk group table, right after the header.
    pub fn chunk_groups_offset(&self) -> u64 {
        NYDUS_BLOB_METADATA_HEADER_SIZE as u64
    }

    /// Byte offset of ChunkTable.
    pub fn chunks_offset(&self) -> u64 {
        self.chunk_groups_offset()
            + (self.chunk_group_count as u64 + 1)
                * NYDUS_BLOB_METADATA_CHUNK_GROUP_ENTRY_SIZE as u64
    }

    /// Byte offset of DigestTable. The tables of a validated header
    /// fit a `u32` ([`Self::used_size_checked`]), so the alignments cannot
    /// overflow.
    pub fn digests_offset(&self) -> u64 {
        align_up_u64(
            self.granule_index_offset()
                + self.granule_index_count() as u64
                    * NYDUS_BLOB_METADATA_GRANULE_INDEX_ENTRY_SIZE as u64,
            8,
        )
        .expect("blob meta table offsets fit u32")
    }

    /// Byte offset of GranuleIndexTable.
    pub fn granule_index_offset(&self) -> u64 {
        align_up_u64(self.chunks_offset() + self.chunk_count as u64 * 4, 8)
            .expect("blob meta table offsets fit u32")
    }

    /// Byte offset of the redirect table.
    pub fn redirects_offset(&self) -> u64 {
        align_up_u64(
            self.digests_offset()
                + self.digest_count() as u64 * NYDUS_BLOB_METADATA_DIGEST_ENTRY_SIZE as u64,
            8,
        )
        .expect("blob meta table offsets fit u32")
    }

    /// Bytes the header and the tables actually use, before the tail padding.
    pub fn used_size(&self) -> u64 {
        self.redirects_offset()
            + self.redirect_count() as u64 * NYDUS_BLOB_METADATA_REDIRECT_ENTRY_SIZE as u64
    }

    fn used_size_checked(&self) -> Result<u64> {
        let overflow = || Error::Overflow("blob meta table size overflow".to_string());
        let counts = [
            (
                self.chunk_group_count as u64 + 1,
                NYDUS_BLOB_METADATA_CHUNK_GROUP_ENTRY_SIZE as u64,
            ),
            (self.chunk_count as u64, 4),
            (
                self.granule_index_count() as u64,
                NYDUS_BLOB_METADATA_GRANULE_INDEX_ENTRY_SIZE as u64,
            ),
            (
                self.digest_count() as u64,
                NYDUS_BLOB_METADATA_DIGEST_ENTRY_SIZE as u64,
            ),
            (
                self.redirect_count() as u64,
                NYDUS_BLOB_METADATA_REDIRECT_ENTRY_SIZE as u64,
            ),
        ];
        let mut size = NYDUS_BLOB_METADATA_HEADER_SIZE as u64;
        for (count, entry) in counts {
            size = align_up_u64(size, 8)
                .and_then(|size| size.checked_add(count.checked_mul(entry)?))
                .ok_or_else(overflow)?;
        }
        if size > u32::MAX as u64 {
            return Err(overflow());
        }
        Ok(size)
    }

    /// The full serialized size: [`Self::used_size`] aligned up to one
    /// 4KiB block.
    pub fn padded_size(&self) -> u64 {
        align_up_u64(self.used_size(), BLOCK).expect("blob meta size overflowed")
    }
}

/// One raw chunk group table entry. The table holds `chunk_group_count + 1`
/// entries: entry `i` names where group `i` starts in the data region, the
/// address space and ChunkTable, and entry `i + 1` is where it ends,
/// so the last entry is a terminator holding the data region's size, the
/// address space's block count and the chunk count.
///
/// ```text
/// offset  size  field
///      0     8  compressed_offset   bytes into the data region where the
///                                   group's encoded payload starts
///      8     4  uncompressed_start_block  first 4KiB block of the group in the
///                                   address space
///     12     4  first_chunk_index        index of the group's first entry in
///                                   ChunkTable
///     16     4  uncompressed_size   bytes the group decodes to (zero in
///                                   the terminator)
///     20     4  uncompressed_crc32  CRC32C of the decoded payload (zero in
///                                   the terminator)
/// ```
///
/// The Rust layout is pinned to the on-disk layout (`repr(C)` plus the const
/// size assert) so a mapped table is readable in place, zero-copy.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ChunkGroupEntry {
    compressed_offset: u64,
    uncompressed_start_block: u32,
    first_chunk_index: u32,
    uncompressed_size: u32,
    uncompressed_crc32: u32,
}

const _: () = assert!(size_of::<ChunkGroupEntry>() == NYDUS_BLOB_METADATA_CHUNK_GROUP_ENTRY_SIZE);

impl ChunkGroupEntry {
    fn from_bytes(bytes: &[u8; NYDUS_BLOB_METADATA_CHUNK_GROUP_ENTRY_SIZE]) -> Self {
        Self {
            compressed_offset: read_u64_at(bytes, 0),
            uncompressed_start_block: read_u32_at(bytes, 8),
            first_chunk_index: read_u32_at(bytes, 12),
            uncompressed_size: read_u32_at(bytes, 16),
            uncompressed_crc32: read_u32_at(bytes, 20),
        }
    }

    fn to_bytes(self) -> [u8; NYDUS_BLOB_METADATA_CHUNK_GROUP_ENTRY_SIZE] {
        let mut data = [0u8; NYDUS_BLOB_METADATA_CHUNK_GROUP_ENTRY_SIZE];
        write_u64_at(&mut data, 0, self.compressed_offset);
        write_u32_at(&mut data, 8, self.uncompressed_start_block);
        write_u32_at(&mut data, 12, self.first_chunk_index);
        write_u32_at(&mut data, 16, self.uncompressed_size);
        write_u32_at(&mut data, 20, self.uncompressed_crc32);
        data
    }
}

/// A GranuleIndexTable entry: the group covering this granule's first block.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct GranuleIndexEntry {
    group_index: u32,
}

const _: () =
    assert!(size_of::<GranuleIndexEntry>() == NYDUS_BLOB_METADATA_GRANULE_INDEX_ENTRY_SIZE);

impl GranuleIndexEntry {
    fn from_bytes(bytes: &[u8; NYDUS_BLOB_METADATA_GRANULE_INDEX_ENTRY_SIZE]) -> Self {
        Self {
            group_index: read_u32_at(bytes, 0),
        }
    }

    fn to_bytes(self) -> [u8; NYDUS_BLOB_METADATA_GRANULE_INDEX_ENTRY_SIZE] {
        self.group_index.to_le_bytes()
    }
}

/// One redirect table entry: the chunk group of another blob of the image
/// that the chunk group at the same index copies. Present only in a
/// REDIRECT blob (an `optimize` output), one entry per chunk group.
///
/// ```text
/// offset  size  field
///      0     4  source_blob_index         nonzero source device index,
///                                         within the EROFS u16 range
///      4     4  source_chunk_group_index  the copied group within it
/// ```
///
/// The Rust layout is pinned to the on-disk layout (`repr(C)` plus the const
/// size assert) so a mapped table is readable in place, zero-copy.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlobMetadataRedirect {
    source_blob_index: u32,
    source_chunk_group_index: u32,
}

const _: () = assert!(size_of::<BlobMetadataRedirect>() == NYDUS_BLOB_METADATA_REDIRECT_ENTRY_SIZE);

impl BlobMetadataRedirect {
    /// Names chunk group `source_chunk_group_index` of blob
    /// `source_blob_index` (a device index, never zero) as the source.
    pub fn new(source_blob_index: u16, source_chunk_group_index: u32) -> Result<Self> {
        if source_blob_index == 0 {
            return Err(Error::InvalidParameter(
                "blob meta redirect source blob index must be non-zero".to_string(),
            ));
        }
        Ok(Self {
            source_blob_index: u32::from(source_blob_index),
            source_chunk_group_index,
        })
    }

    fn from_bytes(bytes: &[u8; NYDUS_BLOB_METADATA_REDIRECT_ENTRY_SIZE]) -> Self {
        Self {
            source_blob_index: read_u32_at(bytes, 0),
            source_chunk_group_index: read_u32_at(bytes, 4),
        }
    }

    fn to_bytes(self) -> [u8; NYDUS_BLOB_METADATA_REDIRECT_ENTRY_SIZE] {
        let mut data = [0u8; NYDUS_BLOB_METADATA_REDIRECT_ENTRY_SIZE];
        write_u32_at(&mut data, 0, self.source_blob_index);
        write_u32_at(&mut data, 4, self.source_chunk_group_index);
        data
    }

    fn validate(&self) -> Result<()> {
        if self.source_blob_index == 0 || self.source_blob_index > u32::from(u16::MAX) {
            return Err(Error::InvalidImage(
                "blob meta redirect entry must name a non-zero 16-bit source device".to_string(),
            ));
        }
        Ok(())
    }

    /// Device index of the source blob.
    pub fn source_blob_index(&self) -> u16 {
        self.source_blob_index as u16
    }

    /// The copied chunk group within the source blob.
    pub fn source_chunk_group_index(&self) -> u32 {
        self.source_chunk_group_index
    }
}

/// One group of one or more chunks: the compression, decode, cache fill,
/// readiness and trace unit. Groups tile the padded address space.
///
/// ```text
/// uncompressed address space: the groups back to back, block aligned
/// ┌──────────┬──────────────┬──────────┐
/// │ group 0  │   group 1    │ group 2  │   group i spans
/// │c0│c1│c2│ │      c3      │c4│ c5 │  │   each group spans its chunks' blocks
/// └──┴──┴──┴─┴──────────────┴──┴────┴──┘
///     ▼             ▼            ▼
/// ┌────────┬───────────────────┬──────┐
/// │   p0   │        p1         │  p2  │           encoded payloads: the
/// └────────┴───────────────────┴──────┘           chunks' bytes back to
///                                                 back, no padding, then
///                                                 compressed; packed in
///                                                 order, byte-exact
/// ```
///
/// A writer describes a group with [`Self::new`]; [`BlobMetadata::new`] then
/// lays the groups out back to back, which is when the index, the offsets
/// and the first member become known. Groups read back from a table
/// ([`BlobMetadata::chunk_group`]) carry every field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlobMetadataChunkGroup {
    index: u32,
    compressed_offset: u64,
    compressed_size: u32,
    uncompressed_start_block: u32,
    blocks: u32,
    first_chunk_index: u32,
    chunk_count: u32,
    payload_size: u32,
    crc32: u32,
    redirect: Option<BlobMetadataRedirect>,
}

impl BlobMetadataChunkGroup {
    /// Describes a group for a writer: `compressed_size` bytes of encoded
    /// payload decoding to `payload_size` bytes whose crc32c is `crc32`,
    /// holding `chunk_count` nonempty chunks, including a single chunk.
    /// Every length is listed in ChunkTable. `redirect` names the source
    /// when the blob is an optimize output.
    /// Index, offsets and blocks are assigned by [`BlobMetadata::new`].
    pub fn new(
        compressed_size: u32,
        payload_size: u32,
        chunk_count: u32,
        crc32: u32,
        redirect: Option<BlobMetadataRedirect>,
    ) -> Result<Self> {
        if compressed_size == 0 || payload_size == 0 {
            return Err(Error::InvalidParameter(
                "blob meta chunk group must decode to at least one byte from at least one encoded byte"
                    .to_string(),
            ));
        }
        if chunk_count == 0 {
            return Err(Error::InvalidParameter(
                "blob meta group must contain at least one chunk".to_string(),
            ));
        }
        Ok(Self {
            index: 0,
            compressed_offset: 0,
            compressed_size,
            uncompressed_start_block: 0,
            blocks: 0,
            first_chunk_index: 0,
            chunk_count,
            payload_size,
            crc32,
            redirect,
        })
    }

    /// The group's index in the table.
    pub fn index(&self) -> u32 {
        self.index
    }

    /// Byte offset of the encoded payload within the data region.
    pub fn compressed_offset(&self) -> u64 {
        self.compressed_offset
    }

    /// Byte size of the encoded payload, never zero.
    pub fn compressed_size(&self) -> u32 {
        self.compressed_size
    }

    /// Byte range of the encoded payload within the data region.
    pub fn compressed_range(&self) -> Range<u64> {
        self.compressed_offset..self.compressed_offset + self.compressed_size as u64
    }

    /// Bytes the encoded payload decodes to: the chunks' bytes back to
    /// back, never zero.
    pub fn payload_size(&self) -> u32 {
        self.payload_size
    }

    /// Whether the group packs several chunks (else it is one chunk).
    pub fn is_pack(&self) -> bool {
        self.chunk_count > 1
    }

    /// Number of chunks the group holds, always at least one.
    pub fn chunk_count(&self) -> u32 {
        self.chunk_count
    }

    /// The group's first entry in ChunkTable, including single-chunk groups.
    pub fn first_chunk_index(&self) -> u32 {
        self.first_chunk_index
    }

    /// The group's ChunkTable indexes.
    pub fn chunk_range(&self) -> Range<usize> {
        self.first_chunk_index as usize..(self.first_chunk_index + self.chunk_count) as usize
    }

    /// crc32c of the decoded payload, checked after decode.
    pub fn crc32(&self) -> u32 {
        self.crc32
    }

    /// The source this group copies, in a REDIRECT blob.
    pub fn redirect(&self) -> Option<BlobMetadataRedirect> {
        self.redirect
    }

    /// First 4KiB block of the group in the uncompressed address space.
    pub fn uncompressed_block_offset(&self) -> u64 {
        self.uncompressed_start_block as u64
    }

    /// 4KiB blocks the group spans: its chunks, each block aligned.
    pub fn uncompressed_block_count(&self) -> u32 {
        self.blocks
    }

    /// Start of the group in bytes.
    pub fn uncompressed_offset(&self) -> u64 {
        self.uncompressed_block_offset() * BLOCK
    }

    /// Length of the group in bytes.
    pub fn uncompressed_size(&self) -> u64 {
        self.uncompressed_block_count() as u64 * BLOCK
    }

    /// Byte range of the group in the uncompressed address space.
    pub fn uncompressed_range(&self) -> Range<u64> {
        self.uncompressed_offset()..self.uncompressed_offset() + self.uncompressed_size()
    }
}

/// One digest entry: the content digest of the chunk group at the same
/// index in the chunk group table (see [`BlobMetadataDigest::of_group`]).
/// On disk: `digest [u8; 32]`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlobMetadataDigest {
    digest: [u8; 32],
}

const _: () = assert!(size_of::<BlobMetadataDigest>() == NYDUS_BLOB_METADATA_DIGEST_ENTRY_SIZE);

/// Context separating multi-chunk group digests from plain content digests.
const NYDUS_BLOB_METADATA_GROUP_DIGEST_CONTEXT: &str = "nydus blob meta chunk group digest v1";

impl BlobMetadataDigest {
    /// Creates an entry for the chunk group at the same index in the group
    /// table.
    pub fn new(digest: [u8; 32]) -> Self {
        Self { digest }
    }

    /// The digest of a chunk group from the BLAKE3 digests of its chunks'
    /// exact bytes, in group order. A group of one chunk is named by that
    /// chunk's digest itself, so a content-addressed cache serves it by the
    /// chunk's content digest; a group of several chunks is named by a
    /// domain-separated BLAKE3 (`derive_key`) over the member digests, which
    /// costs no second pass over the bytes and separates group identity from
    /// plain content hashing. Collision resistance relies on BLAKE3.
    /// `None` for an empty slice.
    pub fn of_group(chunk_digests: &[[u8; 32]]) -> Option<Self> {
        match chunk_digests {
            [] => None,
            [only] => Some(Self::new(*only)),
            many => {
                let mut hasher =
                    blake3::Hasher::new_derive_key(NYDUS_BLOB_METADATA_GROUP_DIGEST_CONTEXT);
                for digest in many {
                    hasher.update(digest);
                }
                Some(Self::new(*hasher.finalize().as_bytes()))
            }
        }
    }

    fn to_bytes(self) -> [u8; NYDUS_BLOB_METADATA_DIGEST_ENTRY_SIZE] {
        self.digest
    }

    /// The digest, algorithm per the header's digester flag.
    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
}

/// In-memory backing of the tables: owned vectors on the write side (and
/// for in-memory parses), a shared file mapping read in place on the read
/// side.
#[derive(Debug)]
enum BlobMetadataStorage {
    Owned {
        chunk_groups: Vec<ChunkGroupEntry>,
        chunk_lengths: Vec<u32>,
        digests: Vec<BlobMetadataDigest>,
        granule_indices: Vec<GranuleIndexEntry>,
        redirects: Vec<BlobMetadataRedirect>,
    },
    Mapped(Mmap),
}

/// A nydus blob's metadata: how the blob's uncompressed address space —
/// what the EROFS chunk indexes point into and the cache file mirrors —
/// maps onto its encoded payload, sealed with a crc32c in the header.
///
/// Serialized, it is the `.blob.meta` sidecar file — and, embedded verbatim,
/// the blob meta region of a full blob (see [`super::footer::BlobFooter`]):
///
/// ```text
/// Header (32 B)
/// GroupTable ((groups + 1) * 24 B, including the terminator)
/// ChunkTable (chunks * 4 B, all chunk lengths)
/// GranuleIndexTable (ceil(total_bytes / granule) * 4 B)
/// DigestTable (groups * 32 B with BLAKE3, otherwise absent)
/// RedirectTable (groups * 8 B with REDIRECT, otherwise absent)
/// Zero padding to a 4 KiB multiple; each table starts 8-byte aligned.
/// ```
///
/// The groups tile the address space back to back: group `i` spans the
/// blocks `[uncompressed_start_block(i), uncompressed_start_block(i + 1))`,
/// its chunks (whole files,
/// or chunk-sized slices of larger files) sit back to back inside it, each
/// starting on its own 4KiB block. ChunkTable lists every chunk length,
/// including groups of one chunk. The encoded stream
/// is dense too: a group's payload is its chunks' bytes back to back
/// without the block padding, compressed as one unit (or stored plain when
/// compression does not shrink it, which the reader recognizes by
/// `compressed_size == payload_size`).
///
/// GranuleIndexTable names the group covering each granule's first block.
/// A direct lookup and comparison with the next group's start resolve any
/// address with at most one forward correction. Every non-final group spans
/// at least a granule. There is no bitmap, binary search or runtime index.
///
/// A REDIRECT blob (an `optimize` output) is laid out the same way, but
/// every group is a byte-exact copy of a chunk group of another blob of the
/// image, named by the redirect table; the runtime decodes it into that
/// source blob's cache instead of its own. It has its own GranuleIndexTable,
/// sized using the smallest non-final copied group's span.
///
/// In memory the tables are either owned (the write side and
/// [`Self::from_bytes`]) or a shared file mapping read in place
/// ([`Self::from_path`]); no lookup structure is built at load.
#[derive(Debug)]
pub struct BlobMetadata {
    header: BlobMetadataHeader,
    storage: BlobMetadataStorage,
}

impl BlobMetadata {
    /// Creates validated version-1 metadata. `group_span_blocks` bounds the
    /// group span in 4KiB blocks; `lookup_granule` is a power-of-two byte
    /// size between one block and that bound. Every non-final group must
    /// span at least a granule. Payloads and padded spans tile their spaces
    /// from zero. `chunk_lengths` lists every chunk, including lone ones,
    /// in group order. `digests` is one entry per group with BLAKE3, else
    /// empty. Redirect sources must be present for all groups or none.
    /// Returns an error for invalid geometry, inconsistent tables or overflow.
    pub fn new(
        compressor: BlobMetadataCompressor,
        digester: BlobMetadataDigester,
        group_span_blocks: u32,
        lookup_granule: u32,
        chunk_groups: Vec<BlobMetadataChunkGroup>,
        chunk_lengths: Vec<u32>,
        digests: Vec<BlobMetadataDigest>,
    ) -> Result<Self> {
        let redirected = chunk_groups
            .iter()
            .filter(|group| group.redirect.is_some())
            .count();
        let is_redirect = redirected > 0;
        if is_redirect && redirected != chunk_groups.len() {
            return Err(Error::InvalidParameter(
                "blob meta chunk groups must either all redirect or none".to_string(),
            ));
        }
        let mut flags = compressor.flag() | digester.flag();
        flags.set(BlobMetadataFlags::REDIRECT, is_redirect);
        let count = |len: usize, what: &str| {
            u32::try_from(len)
                .map_err(|_| Error::Overflow(format!("blob meta {what} count exceeds u32")))
        };
        let expected_digests = match digester {
            BlobMetadataDigester::Blake3 => chunk_groups.len(),
            BlobMetadataDigester::None => 0,
        };
        if digests.len() != expected_digests {
            return Err(Error::InvalidParameter(format!(
                "blob meta digest count {} does not match {} chunk groups (digester: {digester})",
                digests.len(),
                chunk_groups.len()
            )));
        }
        let maximum_group_span_block_shift = block_count_to_bits(group_span_blocks)?;
        if !lookup_granule.is_power_of_two() {
            return Err(Error::InvalidParameter(
                "lookup granule must be a power of two".to_string(),
            ));
        }
        let lookup_granule_byte_shift = lookup_granule.trailing_zeros() as u8;

        // Lay the groups out back to back in the data region, the address
        // space and ChunkTable, and end with the terminator.
        let mut entries = Vec::with_capacity(chunk_groups.len() + 1);
        let mut redirects = Vec::with_capacity(redirected);
        let mut compressed_offset = 0u64;
        let mut uncompressed_start_block = 0u64;
        let mut first_chunk_index = 0u32;
        let mut chunk_count = 0u64;
        for (index, group) in chunk_groups.iter().enumerate() {
            let end_member = first_chunk_index
                .checked_add(group.chunk_count)
                .ok_or_else(|| Error::Overflow("blob meta chunk count overflow".to_string()))?;
            let blocks: u64 = {
                let run = chunk_lengths
                    .get(first_chunk_index as usize..end_member as usize)
                    .ok_or_else(|| {
                        Error::InvalidParameter(format!(
                            "blob meta chunk group {index} names chunks past ChunkTable"
                        ))
                    })?;
                let payload: u64 = run.iter().map(|len| *len as u64).sum();
                if payload != group.payload_size as u64 {
                    return Err(Error::InvalidParameter(format!(
                        "blob meta chunk group {index} chunk_lengths add up to {payload} bytes, not its {}-byte payload",
                        group.payload_size
                    )));
                }
                run.iter().map(|len| (*len as u64).div_ceil(BLOCK)).sum()
            };
            entries.push(ChunkGroupEntry {
                compressed_offset,
                uncompressed_start_block: u32::try_from(uncompressed_start_block).map_err(
                    |_| {
                        Error::Overflow(format!(
                            "blob meta chunk group {index} starts past the 32-bit block space"
                        ))
                    },
                )?,
                first_chunk_index,
                uncompressed_size: group.payload_size,
                uncompressed_crc32: group.crc32,
            });
            redirects.extend(group.redirect);
            compressed_offset = compressed_offset
                .checked_add(group.compressed_size as u64)
                .ok_or_else(|| {
                    Error::Overflow(format!(
                        "blob meta chunk group {index} compressed range overflow"
                    ))
                })?;
            uncompressed_start_block += blocks;
            first_chunk_index = first_chunk_index
                .checked_add(group.chunk_count)
                .ok_or_else(|| {
                    Error::Overflow(format!(
                        "blob meta chunk group {index} member range overflow"
                    ))
                })?;
            chunk_count += group.chunk_count() as u64;
        }
        if first_chunk_index as usize != chunk_lengths.len() {
            return Err(Error::InvalidParameter(format!(
                "blob meta ChunkTable holds {} entries, the chunk groups name {first_chunk_index}",
                chunk_lengths.len()
            )));
        }
        let total_blocks = u32::try_from(uncompressed_start_block).map_err(|_| {
            Error::Overflow("blob meta address space exceeds the 32-bit block space".to_string())
        })?;
        entries.push(ChunkGroupEntry {
            compressed_offset,
            uncompressed_start_block: total_blocks,
            first_chunk_index,
            uncompressed_size: 0,
            uncompressed_crc32: 0,
        });
        let header = BlobMetadataHeader {
            magic: NYDUS_BLOB_METADATA_MAGIC,
            version: NYDUS_BLOB_METADATA_VERSION,
            flags: flags.bits(),
            crc32: 0,
            maximum_group_span_block_shift,
            lookup_granule_byte_shift,
            chunk_group_count: count(chunk_groups.len(), "chunk group")?,
            total_blocks,
            chunk_count: u32::try_from(chunk_count)
                .map_err(|_| Error::Overflow("blob meta chunk count exceeds u32".to_string()))?,
        };
        header.validate()?;
        let granule_indices = Vec::new();
        let mut storage = BlobMetadataStorage::Owned {
            chunk_groups: entries,
            chunk_lengths,
            digests,
            granule_indices,
            redirects,
        };
        Self::validate_tables(&header, &storage)?;
        let index = Self::build_granule_index(&header, Self::entries_of(&header, &storage));
        if let BlobMetadataStorage::Owned {
            granule_indices, ..
        } = &mut storage
        {
            *granule_indices = index;
        }
        Self::validate_index(&header, &storage)?;
        let mut blob_metadata = Self { header, storage };
        blob_metadata.header.crc32 = blob_metadata.compute_crc32_from_parts();
        Ok(blob_metadata)
    }

    /// Build the on-disk GranuleIndexTable on the writer side only.
    fn build_granule_index(
        header: &BlobMetadataHeader,
        entries: &[ChunkGroupEntry],
    ) -> Vec<GranuleIndexEntry> {
        let granule_index_count = header.granule_index_count() as usize;
        let mut granule_indices = Vec::with_capacity(granule_index_count);
        let groups = entries.len() - 1;
        let granule_blocks = header.granule_blocks();
        let mut group = 0usize;
        for cell in 0..granule_index_count as u64 {
            let cell_start = cell * granule_blocks;
            // The group covering the cell's first block; the terminator's
            // start is the address space's end, past every cell.
            while group + 1 < groups
                && entries[group + 1].uncompressed_start_block as u64 <= cell_start
            {
                group += 1;
            }
            granule_indices.push(GranuleIndexEntry {
                group_index: group as u32,
            });
        }
        granule_indices
    }

    /// Read blob metadata from an in-memory byte slice, optionally verifying
    /// the header crc32 over the full metadata.
    pub fn from_bytes(bytes: &[u8], verify_crc32: bool) -> Result<Self> {
        let header = BlobMetadataHeader::from_bytes(bytes)?;
        Self::validate_bytes(bytes, &header, verify_crc32)?;
        let table = |offset: u64, count: u64, entry: usize| -> &[u8] {
            &bytes[offset as usize..offset as usize + count as usize * entry]
        };
        let chunk_groups = table(
            header.chunk_groups_offset(),
            header.chunk_group_count as u64 + 1,
            NYDUS_BLOB_METADATA_CHUNK_GROUP_ENTRY_SIZE,
        )
        .chunks_exact(NYDUS_BLOB_METADATA_CHUNK_GROUP_ENTRY_SIZE)
        .map(|entry| ChunkGroupEntry::from_bytes(entry.try_into().unwrap()))
        .collect();
        let chunk_lengths = table(header.chunks_offset(), header.chunk_count as u64, 4)
            .chunks_exact(4)
            .map(|entry| u32::from_le_bytes(entry.try_into().unwrap()))
            .collect();
        let digests = table(
            header.digests_offset(),
            header.digest_count() as u64,
            NYDUS_BLOB_METADATA_DIGEST_ENTRY_SIZE,
        )
        .chunks_exact(NYDUS_BLOB_METADATA_DIGEST_ENTRY_SIZE)
        .map(|entry| BlobMetadataDigest::new(entry.try_into().unwrap()))
        .collect();
        let granule_indices = table(
            header.granule_index_offset(),
            header.granule_index_count() as u64,
            NYDUS_BLOB_METADATA_GRANULE_INDEX_ENTRY_SIZE,
        )
        .chunks_exact(NYDUS_BLOB_METADATA_GRANULE_INDEX_ENTRY_SIZE)
        .map(|entry| GranuleIndexEntry::from_bytes(entry.try_into().unwrap()))
        .collect();
        let redirects = table(
            header.redirects_offset(),
            header.redirect_count() as u64,
            NYDUS_BLOB_METADATA_REDIRECT_ENTRY_SIZE,
        )
        .chunks_exact(NYDUS_BLOB_METADATA_REDIRECT_ENTRY_SIZE)
        .map(|entry| BlobMetadataRedirect::from_bytes(entry.try_into().unwrap()))
        .collect();
        let storage = BlobMetadataStorage::Owned {
            chunk_groups,
            chunk_lengths,
            digests,
            granule_indices,
            redirects,
        };
        Self::validate_tables(&header, &storage)?;
        Self::validate_index(&header, &storage)?;
        Ok(Self { header, storage })
    }

    /// Read blob metadata from a file (mmap-backed), optionally verifying
    /// the header crc32 over the full metadata. The tables are validated in
    /// place; the mapping is kept and read zero-copy.
    pub fn from_path(path: &Path, verify_crc32: bool) -> Result<Self> {
        let file = File::open(path)
            .with_context(|| format!("failed to open blob meta: {}", path.display()))?;
        // SAFETY: the sidecar is written once and then only read; a
        // concurrent truncation would surface as SIGBUS, which is the
        // accepted trade-off for zero-copy tables (same as the other
        // mapped sidecars).
        let mmap = unsafe { MmapOptions::new().map(&file) }
            .with_context(|| format!("failed to mmap blob meta: {}", path.display()))?;
        let header = BlobMetadataHeader::from_bytes(&mmap)?;
        Self::validate_bytes(&mmap, &header, verify_crc32)?;
        let storage = BlobMetadataStorage::Mapped(mmap);
        Self::validate_tables(&header, &storage)?;
        Self::validate_index(&header, &storage)?;
        Ok(Self { header, storage })
    }

    /// View a table of the mapping in place.
    fn mapped_table<T>(mmap: &Mmap, offset: u64, count: usize) -> &[T] {
        let start = offset as usize;
        let bytes = &mmap[start..start + count * size_of::<T>()];
        debug_assert_eq!(bytes.as_ptr() as usize % align_of::<T>(), 0);
        // SAFETY: the entry types are `repr(C)` plain integers with a pinned
        // size and 8-byte-or-less alignment; every table starts 8-byte
        // aligned inside a page-aligned mapping, and `validate_bytes`
        // bounded the tables against the file, so the slice is in bounds and
        // aligned, and any bit pattern is a valid value (entries are
        // validated separately).
        unsafe { std::slice::from_raw_parts(bytes.as_ptr().cast(), count) }
    }

    fn entries_of<'a>(
        header: &BlobMetadataHeader,
        storage: &'a BlobMetadataStorage,
    ) -> &'a [ChunkGroupEntry] {
        match storage {
            BlobMetadataStorage::Owned { chunk_groups, .. } => chunk_groups,
            BlobMetadataStorage::Mapped(mmap) => Self::mapped_table(
                mmap,
                header.chunk_groups_offset(),
                header.chunk_group_count as usize + 1,
            ),
        }
    }

    /// ChunkTable entry `index`; the caller keeps the index below chunk_count.
    fn chunk_length_of(
        header: &BlobMetadataHeader,
        storage: &BlobMetadataStorage,
        index: usize,
    ) -> u32 {
        match storage {
            BlobMetadataStorage::Owned { chunk_lengths, .. } => chunk_lengths[index],
            BlobMetadataStorage::Mapped(mmap) => {
                let at = header.chunks_offset() as usize + index * 4;
                read_u32_at(mmap, at)
            }
        }
    }

    fn digests_of<'a>(
        header: &BlobMetadataHeader,
        storage: &'a BlobMetadataStorage,
    ) -> &'a [BlobMetadataDigest] {
        match storage {
            BlobMetadataStorage::Owned { digests, .. } => digests,
            BlobMetadataStorage::Mapped(mmap) => Self::mapped_table(
                mmap,
                header.digests_offset(),
                header.digest_count() as usize,
            ),
        }
    }

    fn granule_indices_of<'a>(
        header: &BlobMetadataHeader,
        storage: &'a BlobMetadataStorage,
    ) -> &'a [GranuleIndexEntry] {
        match storage {
            BlobMetadataStorage::Owned {
                granule_indices, ..
            } => granule_indices,
            BlobMetadataStorage::Mapped(mmap) => Self::mapped_table(
                mmap,
                header.granule_index_offset(),
                header.granule_index_count() as usize,
            ),
        }
    }

    fn redirects_of<'a>(
        header: &BlobMetadataHeader,
        storage: &'a BlobMetadataStorage,
    ) -> &'a [BlobMetadataRedirect] {
        match storage {
            BlobMetadataStorage::Owned { redirects, .. } => redirects,
            BlobMetadataStorage::Mapped(mmap) => Self::mapped_table(
                mmap,
                header.redirects_offset(),
                header.redirect_count() as usize,
            ),
        }
    }

    /// Anchor a serialized buffer against its header: exactly the padded
    /// size with a zeroed tail, and with `verify_crc32` the stored seal must
    /// match the raw bytes.
    fn validate_bytes(bytes: &[u8], header: &BlobMetadataHeader, verify_crc32: bool) -> Result<()> {
        if bytes.len() as u64 != header.padded_size() {
            return Err(Error::InvalidImage(format!(
                "blob meta size mismatch: expected {}, got {}",
                header.padded_size(),
                bytes.len()
            )));
        }
        for padding in [
            header.chunks_offset() + u64::from(header.chunk_count) * 4
                ..header.granule_index_offset(),
            header.granule_index_offset() + u64::from(header.granule_index_count()) * 4
                ..header.digests_offset(),
            header.used_size()..header.padded_size(),
        ] {
            if bytes[padding.start as usize..padding.end as usize]
                .iter()
                .any(|byte| *byte != 0)
            {
                return Err(Error::InvalidImage(
                    "blob meta padding must be zero".to_string(),
                ));
            }
        }
        if verify_crc32 {
            let expected = header.crc32();
            let actual = Self::compute_crc32(bytes);
            if expected != actual {
                return Err(Error::InvalidImage(format!(
                    "blob meta crc32 mismatch: expected {expected:#010x}, got {actual:#010x}"
                )));
            }
        }
        Ok(())
    }

    /// Validate contiguous data, block and chunk ranges, nonzero lengths,
    /// payload sums, span bounds, encoding sizes and redirect sources.
    fn validate_tables(header: &BlobMetadataHeader, storage: &BlobMetadataStorage) -> Result<()> {
        let entries = Self::entries_of(header, storage);
        let redirects = Self::redirects_of(header, storage);
        let span_blocks = header.group_span_blocks() as u64;
        let granule_blocks = u64::from(header.lookup_granule()) / BLOCK;
        let Some(terminator) = entries.last() else {
            return Err(Error::InvalidImage(
                "blob meta chunk group table lacks its terminator".to_string(),
            ));
        };
        if terminator.first_chunk_index != header.chunk_count
            || terminator.uncompressed_start_block != header.total_blocks
            || terminator.uncompressed_size != 0
            || terminator.uncompressed_crc32 != 0
        {
            return Err(Error::InvalidImage(format!(
                "blob meta chunk group terminator names {} chunk_lengths and {} blocks (payload {}, crc {}) for a header of {} chunk_lengths and {} blocks",
                terminator.first_chunk_index,
                terminator.uncompressed_start_block,
                terminator.uncompressed_size,
                terminator.uncompressed_crc32,
                header.chunk_count,
                header.total_blocks
            )));
        }
        if entries[0].compressed_offset != 0
            || entries[0].uncompressed_start_block != 0
            || entries[0].first_chunk_index != 0
        {
            return Err(Error::InvalidImage(
                "blob meta chunk groups must start at offset zero, block zero and member zero"
                    .to_string(),
            ));
        }
        for redirect in redirects {
            redirect.validate()?;
        }
        let groups = entries.len() - 1;
        let mut total_chunk_count = 0u64;
        for (index, pair) in entries.windows(2).enumerate() {
            let (start, end) = (pair[0], pair[1]);
            if end.compressed_offset <= start.compressed_offset {
                return Err(Error::InvalidImage(format!(
                    "blob meta chunk group {index} has an empty or overlapping compressed range"
                )));
            }
            let compressed_size = end.compressed_offset - start.compressed_offset;
            if compressed_size > u32::MAX as u64 {
                return Err(Error::Overflow(format!(
                    "blob meta chunk group {index} compressed size exceeds u32"
                )));
            }
            if end.uncompressed_start_block <= start.uncompressed_start_block {
                return Err(Error::InvalidImage(format!(
                    "blob meta chunk group {index} spans no blocks or overlaps its successor"
                )));
            }
            let blocks = u64::from(end.uncompressed_start_block - start.uncompressed_start_block);
            if end.first_chunk_index <= start.first_chunk_index
                || end.first_chunk_index > header.chunk_count
            {
                return Err(Error::InvalidImage(format!(
                    "blob meta chunk group {index} owns an out-of-range member run"
                )));
            }
            let chunk_count = end.first_chunk_index - start.first_chunk_index;
            let payload = u64::from(start.uncompressed_size);
            if payload == 0 {
                return Err(Error::InvalidImage(format!(
                    "blob meta chunk group {index} decodes to nothing"
                )));
            }
            let expected_blocks = {
                let mut sum = 0u64;
                let mut member_blocks = 0u64;
                for member in start.first_chunk_index..end.first_chunk_index {
                    let len = Self::chunk_length_of(header, storage, member as usize);
                    if len == 0 {
                        return Err(Error::InvalidImage(
                            "blob meta pack chunk_lengths must be non-empty".to_string(),
                        ));
                    }
                    sum += u64::from(len);
                    member_blocks += u64::from(len).div_ceil(BLOCK);
                }
                if sum != payload {
                    return Err(Error::InvalidImage(format!(
                        "blob meta chunk group {index} chunk_lengths add up to {sum} bytes, not its {payload}-byte payload"
                    )));
                }
                total_chunk_count += u64::from(chunk_count);
                member_blocks
            };
            if blocks != expected_blocks {
                return Err(Error::InvalidImage(format!(
                    "blob meta chunk group {index} spans {blocks} blocks, its chunks {expected_blocks}"
                )));
            }
            if blocks > span_blocks {
                return Err(Error::InvalidImage(format!(
                    "blob meta chunk group {index} spans {blocks} blocks, more than the {span_blocks}-block group span"
                )));
            }
            if index + 1 < groups && blocks < granule_blocks {
                return Err(Error::InvalidImage(format!(
                        "blob meta chunk group {index} spans {blocks} blocks, under the {granule_blocks}-block lookup granule"
                    )));
            }
            if compressed_size > payload {
                return Err(Error::InvalidImage(format!(
                    "blob meta chunk group {index} encoded payload exceeds its {payload}-byte payload"
                )));
            }
            if header.compressor() == BlobMetadataCompressor::None && compressed_size != payload {
                return Err(Error::InvalidImage(format!(
                    "blob meta plain chunk group {index} must store its full payload"
                )));
            }
        }
        if total_chunk_count != u64::from(header.chunk_count) {
            return Err(Error::InvalidImage(format!(
                "blob meta chunk groups hold {total_chunk_count} chunks, the header names {}",
                header.chunk_count
            )));
        }
        Ok(())
    }

    fn validate_index(header: &BlobMetadataHeader, storage: &BlobMetadataStorage) -> Result<()> {
        let entries = Self::entries_of(header, storage);
        let groups = header.chunk_group_count as usize;
        let mut group = 0usize;
        for (index, entry) in Self::granule_indices_of(header, storage).iter().enumerate() {
            let block = index as u64 * header.granule_blocks();
            while group + 1 < groups
                && u64::from(entries[group + 1].uncompressed_start_block) <= block
            {
                group += 1;
            }
            if entry.group_index as usize != group {
                return Err(Error::InvalidImage(
                    "blob meta GranuleIndexTable does not match GroupTable".to_string(),
                ));
            }
        }
        Ok(())
    }

    /// Write the serialized metadata (header, tables, zero padding) to
    /// `writer`, resealing the crc32 over the emitted bytes.
    pub fn write_to(&self, writer: &mut dyn Write) -> Result<()> {
        let mut header = self.header;
        header.crc32 = 0;
        let mut out = Vec::with_capacity(self.padded_size() as usize);
        self.serialize_into(&header, &mut out);
        let crc32 = Self::compute_crc32(&out);
        write_u32_at(
            &mut out,
            NYDUS_BLOB_METADATA_HEADER_CRC32_FIELD.start,
            crc32,
        );
        writer.write_all(&out)?;
        Ok(())
    }

    fn serialize_into(&self, header: &BlobMetadataHeader, out: &mut Vec<u8>) {
        out.extend_from_slice(&header.to_bytes());
        for entry in self.chunk_group_entries() {
            out.extend_from_slice(&entry.to_bytes());
        }
        for member in 0..header.chunk_count as usize {
            let len = Self::chunk_length_of(&self.header, &self.storage, member);
            out.extend_from_slice(&len.to_le_bytes());
        }
        out.resize(header.granule_index_offset() as usize, 0);
        for cell in Self::granule_indices_of(&self.header, &self.storage) {
            out.extend_from_slice(&cell.to_bytes());
        }
        out.resize(header.digests_offset() as usize, 0);
        for digest in self.digests() {
            out.extend_from_slice(&digest.to_bytes());
        }
        out.resize(header.redirects_offset() as usize, 0);
        for redirect in self.redirects() {
            out.extend_from_slice(&redirect.to_bytes());
        }
        out.resize(header.padded_size() as usize, 0);
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

    /// The raw chunk group table including its terminator.
    fn chunk_group_entries(&self) -> &[ChunkGroupEntry] {
        Self::entries_of(&self.header, &self.storage)
    }

    /// Byte length of a stored chunk, including lone chunks; `None` past ChunkTable.
    pub fn chunk_len(&self, index: usize) -> Option<u32> {
        (index < self.header.chunk_count as usize)
            .then(|| Self::chunk_length_of(&self.header, &self.storage, index))
    }

    /// The digest table, one entry per chunk group; empty without a
    /// digester.
    pub fn digests(&self) -> &[BlobMetadataDigest] {
        Self::digests_of(&self.header, &self.storage)
    }

    /// The redirect table, one entry per chunk group of a REDIRECT blob;
    /// empty otherwise.
    pub fn redirects(&self) -> &[BlobMetadataRedirect] {
        Self::redirects_of(&self.header, &self.storage)
    }

    /// The digest of chunk group `index`, `None` past the table or without
    /// a digester.
    pub fn digest(&self, index: usize) -> Option<&BlobMetadataDigest> {
        self.digests().get(index)
    }

    /// The chunk group at `index`, `None` past the table.
    pub fn chunk_group(&self, index: usize) -> Option<BlobMetadataChunkGroup> {
        if index >= self.chunk_group_count() {
            return None;
        }
        let entries = self.chunk_group_entries();
        let (start, end) = (entries[index], entries[index + 1]);
        Some(BlobMetadataChunkGroup {
            index: index as u32,
            compressed_offset: start.compressed_offset,
            compressed_size: (end.compressed_offset - start.compressed_offset) as u32,
            uncompressed_start_block: start.uncompressed_start_block,
            blocks: end.uncompressed_start_block - start.uncompressed_start_block,
            first_chunk_index: start.first_chunk_index,
            chunk_count: end.first_chunk_index - start.first_chunk_index,
            payload_size: start.uncompressed_size,
            crc32: start.uncompressed_crc32,
            redirect: self.redirects().get(index).copied(),
        })
    }

    /// The chunk groups in order.
    pub fn chunk_groups(&self) -> impl Iterator<Item = BlobMetadataChunkGroup> + '_ {
        (0..self.chunk_group_count()).map(move |index| {
            self.chunk_group(index)
                .expect("group index within the validated table")
        })
    }

    /// Number of chunk groups.
    pub fn chunk_group_count(&self) -> usize {
        self.header.chunk_group_count as usize
    }

    /// Number of chunks, lone chunks included.
    pub fn chunk_count(&self) -> usize {
        self.header.chunk_count as usize
    }

    /// Number of digest entries.
    pub fn digest_count(&self) -> usize {
        self.header.digest_count() as usize
    }

    /// Number of GranuleIndexTable entries.
    pub fn granule_index_count(&self) -> usize {
        self.header.granule_index_count() as usize
    }

    /// Number of redirect entries: every chunk group of a REDIRECT blob.
    pub fn redirect_count(&self) -> usize {
        self.header.redirect_count() as usize
    }

    /// log2 of the most 4KiB blocks a chunk group spans.
    pub fn maximum_group_span_block_shift(&self) -> u8 {
        self.header.maximum_group_span_block_shift
    }

    /// The most 4KiB blocks a chunk group spans.
    pub fn group_span_blocks(&self) -> u32 {
        self.header.group_span_blocks()
    }

    /// The most bytes of the address space a chunk group spans: a lone
    /// chunk is at most a file chunk, a pack may span more. Bounds the
    /// decode scratch a reader needs for any group.
    pub fn group_span(&self) -> u32 {
        self.header.group_span()
    }

    /// The mandatory lookup granule in bytes (see
    /// [`BlobMetadataHeader::lookup_granule`]).
    pub fn lookup_granule(&self) -> u32 {
        self.header.lookup_granule()
    }

    /// The chunk group payload compressor.
    pub fn compressor(&self) -> BlobMetadataCompressor {
        self.header.compressor()
    }

    /// The digest algorithm.
    pub fn digester(&self) -> BlobMetadataDigester {
        self.header.digester()
    }

    /// Whether the blob is an `optimize` output whose chunk groups copy
    /// other blobs' groups (see [`BlobMetadataFlags::REDIRECT`]).
    pub fn is_redirect(&self) -> bool {
        self.header.is_redirect()
    }

    /// Total size of the uncompressed address space in 4KiB blocks: the
    /// groups' blocks back to back.
    pub fn uncompressed_block_count(&self) -> u64 {
        self.header.total_blocks as u64
    }

    /// Total size of the uncompressed address space in bytes.
    pub fn uncompressed_size(&self) -> u64 {
        self.uncompressed_block_count() * BLOCK
    }

    /// Bytes all chunk groups decode to: the chunks' bytes without padding.
    pub fn payload_total(&self) -> u64 {
        self.chunk_group_entries()
            .iter()
            .map(|entry| entry.uncompressed_size as u64)
            .sum()
    }

    /// End of the last chunk group's compressed range: the data region's
    /// size.
    pub fn compressed_end(&self) -> u64 {
        self.chunk_group_entries()
            .last()
            .map_or(0, |terminator| terminator.compressed_offset)
    }

    /// The full serialized size, 4KiB aligned.
    pub fn padded_size(&self) -> u64 {
        self.header.padded_size()
    }

    /// Bytes group `group`'s payload decodes to: its chunks' bytes back to
    /// back.
    pub fn payload_size(&self, group: &BlobMetadataChunkGroup) -> u64 {
        u64::from(group.payload_size)
    }

    /// Whether group `group` is stored plain: its encoded bytes are its
    /// payload (the builder stores a payload plain when encoding would not
    /// shrink it, so equal sizes mean plain).
    pub fn is_plain(&self, group: &BlobMetadataChunkGroup) -> bool {
        self.compressor() == BlobMetadataCompressor::None
            || group.compressed_size() == group.payload_size()
    }

    /// The group covering an address, or `None` beyond the blob. A direct
    /// granule lookup and at most one forward correction give worst-case
    /// O(1) lookup without a search or an allocated runtime index.
    pub fn chunk_group_index_of(&self, uncompressed_offset: u64) -> Option<usize> {
        let block = uncompressed_offset / BLOCK;
        if block >= u64::from(self.header.total_blocks) {
            return None;
        }
        let entries = self.chunk_group_entries();
        let granule_block_bits = self.header.granule_block_bits();
        let mut group = Self::granule_indices_of(&self.header, &self.storage)
            [(block >> granule_block_bits) as usize]
            .group_index as usize;
        if block >= u64::from(entries[group + 1].uncompressed_start_block) {
            group += 1;
        }
        Some(group)
    }

    /// The chunks of chunk group `group_index` in address order, as
    /// `(ordinal within the group, absolute byte offset, length)`. Empty
    /// past the table.
    pub fn chunk_group_chunks(
        &self,
        group_index: usize,
    ) -> impl Iterator<Item = (usize, u64, u32)> + '_ {
        let group = self.chunk_group(group_index);
        let (mut member, end, mut block) = match group {
            None => (0usize, 0usize, 0u64),
            Some(group) => {
                let range = group.chunk_range();
                (range.start, range.end, group.uncompressed_block_offset())
            }
        };
        let first = member;
        std::iter::from_fn(move || {
            if member >= end {
                return None;
            }
            let len = Self::chunk_length_of(&self.header, &self.storage, member);
            let offset = block * BLOCK;
            block += u64::from(len).div_ceil(BLOCK);
            let ordinal = member - first;
            member += 1;
            Some((ordinal, offset, len))
        })
    }

    /// Scatter chunk group `group_index`'s decoded payload back into the
    /// padded address space, calling `sink` with every chunk's absolute byte
    /// offset and bytes, in address order. Each chunk starts on its own
    /// block, so the bytes between chunks are tail padding the cache leaves
    /// zero.
    pub fn for_each_decoded_chunk<'payload>(
        &self,
        group_index: usize,
        payload: &'payload [u8],
        sink: &mut dyn FnMut(u64, &'payload [u8]) -> std::io::Result<()>,
    ) -> std::io::Result<()> {
        let invalid =
            |what: &str| std::io::Error::new(std::io::ErrorKind::InvalidData, what.to_string());
        let group = self.chunk_group(group_index).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "chunk group index out of range",
            )
        })?;
        if payload.len() as u64 != self.payload_size(&group) {
            return Err(invalid(
                "decoded chunk group length does not match its payload size",
            ));
        }
        let mut position = 0usize;
        for (_, offset, len) in self.chunk_group_chunks(group_index) {
            let len = len as usize;
            sink(offset, &payload[position..position + len])?;
            position += len;
        }
        Ok(())
    }

    /// crc32c over a serialized buffer with the header's crc32 field zeroed.
    fn compute_crc32(bytes: &[u8]) -> u32 {
        let (header, tail) = bytes.split_at(NYDUS_BLOB_METADATA_HEADER_SIZE);
        let mut zeroed: [u8; NYDUS_BLOB_METADATA_HEADER_SIZE] = header.try_into().unwrap();
        zeroed[NYDUS_BLOB_METADATA_HEADER_CRC32_FIELD].fill(0);
        crc32c_append(crc32c(&zeroed), tail)
    }

    fn compute_crc32_from_parts(&self) -> u32 {
        let mut header = self.header;
        header.crc32 = 0;
        let mut out = Vec::with_capacity(self.padded_size() as usize);
        self.serialize_into(&header, &mut out);
        Self::compute_crc32(&out)
    }
}

/// Encode a power-of-two 4KiB block count as the log2 stored in the
/// header's `maximum_group_span_block_shift` field.
fn block_count_to_bits(blocks: u32) -> Result<u8> {
    if !blocks.is_power_of_two() {
        return Err(Error::InvalidParameter(format!(
            "blob meta block count {blocks} must be a power of two"
        )));
    }
    let bits = blocks.trailing_zeros() as u8;
    if bits > NYDUS_BLOB_METADATA_MAX_BLOCK_COUNT_BITS {
        return Err(Error::InvalidParameter(format!(
            "blob meta block count {blocks} exceeds the supported range"
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

    /// A plain group with an explicit nonzero chunk count.
    fn plain_group(payload: &[u8], chunk_count: usize) -> BlobMetadataChunkGroup {
        BlobMetadataChunkGroup::new(
            payload.len() as u32,
            payload.len() as u32,
            chunk_count as u32,
            crc32c(payload),
            None,
        )
        .unwrap()
    }

    fn layered(
        span_blocks: u32,
        granule: Option<u32>,
        groups: Vec<BlobMetadataChunkGroup>,
        chunk_lengths: Vec<u32>,
        digests: Vec<BlobMetadataDigest>,
    ) -> Result<BlobMetadata> {
        let digester = if digests.is_empty() {
            BlobMetadataDigester::None
        } else {
            BlobMetadataDigester::Blake3
        };
        BlobMetadata::new(
            BlobMetadataCompressor::None,
            digester,
            span_blocks,
            granule.unwrap_or(EROFS_BLOCK_SIZE),
            groups,
            chunk_lengths,
            digests,
        )
    }

    /// Fixture: a 64 KiB group span (16 blocks), 4 KiB lookup granule.
    /// Groups: pack A [100, 5000] (3 blocks), pack B [40, 6000, 1] (4
    /// blocks), lone C 20000 (5 blocks), lone D 65536 (16 blocks), pack E
    /// [1, 1] (2 blocks): 30 blocks and 30 granule index entries.
    fn fixture() -> (BlobMetadata, Vec<Vec<u8>>) {
        let chunks_data = vec![
            vec![0xa1; 100],
            vec![0xb2; 5000],
            vec![0xc3; 40],
            vec![0xd4; 6000],
            vec![0xe5; 1],
            vec![0xf6; 20000],
            vec![0x07; 65536],
            vec![0x18; 1],
            vec![0x29; 1],
        ];
        let payloads: Vec<Vec<u8>> = vec![
            chunks_data[..2].concat(),
            chunks_data[2..5].concat(),
            chunks_data[5].clone(),
            chunks_data[6].clone(),
            chunks_data[7..].concat(),
        ];
        let groups = vec![
            plain_group(&payloads[0], 2),
            plain_group(&payloads[1], 3),
            plain_group(&payloads[2], 1),
            plain_group(&payloads[3], 1),
            plain_group(&payloads[4], 2),
        ];
        let chunk_lengths = vec![100, 5000, 40, 6000, 1, 20000, 65536, 1, 1];
        let digests = [
            &chunks_data[..2],
            &chunks_data[2..5],
            &chunks_data[5..6],
            &chunks_data[6..7],
            &chunks_data[7..],
        ]
        .iter()
        .map(|group| {
            let digests: Vec<[u8; 32]> = group.iter().map(|chunk| digest(chunk)).collect();
            BlobMetadataDigest::of_group(&digests).unwrap()
        })
        .collect();
        let meta = layered(16, Some(4096), groups, chunk_lengths, digests).unwrap();
        (meta, chunks_data)
    }

    #[test]
    fn metadata_uses_version_one_and_a_32_byte_header() {
        assert_eq!(NYDUS_BLOB_METADATA_VERSION, 1);
        assert_eq!(NYDUS_BLOB_METADATA_HEADER_SIZE, 32);
        let (meta, _) = fixture();
        let mut raw = Vec::new();
        meta.write_to(&mut raw).unwrap();
        assert_eq!(&raw[..8], b"NDBLMETA");
        assert_eq!(read_u32_at(&raw, 8), 1);
        assert_eq!(read_u32_at(&raw, 20), 5);
        assert_eq!(&raw[24..32], &[4, 12, 0, 0, 0, 0, 0, 0]);
        assert_eq!(read_u32_at(&raw, 32 + 5 * 24 + 8), 30);
        assert_eq!(read_u32_at(&raw, 32 + 5 * 24 + 12), 9);
        let first_group = meta.chunk_group_entries()[0];
        assert_eq!(read_u32_at(&raw, 32 + 24 + 8), 3);
        assert_eq!(
            read_u32_at(&raw, 32 + 24 + 8),
            meta.chunk_group_entries()[1].uncompressed_start_block
        );
        assert_eq!(read_u32_at(&raw, 32 + 16), first_group.uncompressed_size);
        assert_eq!(read_u32_at(&raw, 32 + 20), first_group.uncompressed_crc32);
        assert_eq!(meta.header().chunks_offset(), 176);
        assert_eq!(meta.header().granule_index_offset(), 216);
        assert_eq!(meta.header().digests_offset(), 336);
        assert_eq!(meta.header().redirects_offset(), 496);
        assert_eq!(read_u32_at(&raw, 176), 100);
        assert_eq!(read_u32_at(&raw, 216 + 3 * 4), 1);
        for offset in [212, 213, 214, 215, 496, 4095] {
            let mut invalid = raw.clone();
            invalid[offset] = 1;
            assert!(BlobMetadata::from_bytes(&invalid, false).is_err());
        }
    }

    #[test]
    fn round_trips_through_bytes_and_a_mapped_sidecar() {
        let (meta, chunks_data) = fixture();
        assert_eq!(meta.header().version(), 1);
        assert_eq!(meta.chunk_group_count(), 5);
        assert_eq!(meta.chunk_count(), 9);
        assert_eq!(meta.uncompressed_block_count(), 30);
        assert_eq!(meta.uncompressed_size(), 30 * BLOCK);
        assert_eq!(meta.payload_total(), 5100 + 6041 + 20000 + 65536 + 2);
        assert_eq!(meta.compressed_end(), 5100 + 6041 + 20000 + 65536 + 2);
        assert_eq!(meta.lookup_granule(), 4096);
        assert_eq!(meta.granule_index_count(), 30);
        assert_eq!(
            meta.header().used_size(),
            32 + 6 * 24 + 40 + 30 * 4 + 5 * 32
        );
        let mut raw = Vec::new();
        meta.write_to(&mut raw).unwrap();
        assert_eq!(raw.len(), 4096);
        let loaded = BlobMetadata::from_bytes(&raw, true).unwrap();
        assert_eq!(loaded.chunk_group_entries(), meta.chunk_group_entries());
        assert_eq!(loaded.digests(), meta.digests());
        assert_eq!(
            BlobMetadata::granule_indices_of(&loaded.header, &loaded.storage),
            BlobMetadata::granule_indices_of(&meta.header, &meta.storage)
        );
        assert!(loaded.redirects().is_empty());

        let group = loaded.chunk_group(1).unwrap();
        assert_eq!(group.compressed_range(), 5100..11141);
        assert!(group.is_pack());
        assert_eq!(group.chunk_count(), 3);
        assert_eq!(group.chunk_range(), 2..5);
        assert_eq!(group.uncompressed_range(), 3 * BLOCK..7 * BLOCK);
        assert_eq!(loaded.payload_size(&group), 6041);
        assert!(loaded.is_plain(&group));
        assert_eq!(group.crc32(), crc32c(&chunks_data[2..5].concat()));
        assert!(group.redirect().is_none());
        assert!(loaded.chunk_group(5).is_none());
        assert!(loaded.chunk_group(usize::MAX).is_none());
        assert_eq!(
            loaded.chunk_group_chunks(1).collect::<Vec<_>>(),
            vec![(0, 3 * BLOCK, 40), (1, 4 * BLOCK, 6000), (2, 6 * BLOCK, 1)]
        );
        let lone = loaded.chunk_group(2).unwrap();
        assert!(!lone.is_pack());
        assert_eq!(lone.chunk_count(), 1);
        assert_eq!(lone.chunk_range(), 5..6);
        assert_eq!(lone.uncompressed_range(), 7 * BLOCK..12 * BLOCK);
        assert_eq!(
            loaded.chunk_group_chunks(2).collect::<Vec<_>>(),
            vec![(0, 7 * BLOCK, 20000)]
        );
        assert_eq!(loaded.chunk_len(6), Some(65536));
        assert_eq!(loaded.chunk_len(9), None);

        let dir = tempdir().unwrap();
        let path = dir.path().join("m.blob.meta");
        meta.save(&path).unwrap();
        let mapped = BlobMetadata::from_path(&path, true).unwrap();
        assert_eq!(mapped.chunk_group_entries(), meta.chunk_group_entries());
        assert!(mapped.chunk_group(usize::MAX).is_none());
        assert_eq!(mapped.chunk_group_chunks(usize::MAX).count(), 0);
        assert_eq!(
            (0..9)
                .map(|i| mapped.chunk_len(i).unwrap())
                .collect::<Vec<_>>(),
            vec![100, 5000, 40, 6000, 1, 20000, 65536, 1, 1]
        );
        assert_eq!(mapped.digests().len(), 5);
        // Lone groups carry their chunk's digest, packs a derived one.
        assert_eq!(mapped.digest(2).unwrap().digest(), &digest(&chunks_data[5]));
        assert_eq!(
            mapped.digest(1).unwrap(),
            &BlobMetadataDigest::of_group(&[
                digest(&chunks_data[2]),
                digest(&chunks_data[3]),
                digest(&chunks_data[4])
            ])
            .unwrap()
        );
        assert!(!mapped.is_redirect());
        assert_eq!(
            mapped.chunk_group_chunks(4).collect::<Vec<_>>(),
            vec![(0, 28 * BLOCK, 1), (1, 29 * BLOCK, 1)]
        );

        // A flipped byte fails the seal; another generation is rejected.
        let mut dirty = raw.clone();
        dirty[100] ^= 1;
        assert!(BlobMetadata::from_bytes(&dirty, true).is_err());
        let mut unsupported = raw.clone();
        write_u32_at(&mut unsupported, 8, 2);
        assert!(BlobMetadata::from_bytes(&unsupported, false)
            .unwrap_err()
            .to_string()
            .contains("version"));
    }

    #[test]
    fn group_digest_is_the_chunk_digest_alone_and_derived_for_packs() {
        let (a, b) = (digest(b"a"), digest(b"b"));
        assert_eq!(BlobMetadataDigest::of_group(&[]), None);
        assert_eq!(BlobMetadataDigest::of_group(&[a]).unwrap().digest(), &a);
        let pack = BlobMetadataDigest::of_group(&[a, b]).unwrap();
        // Order matters, and a pack digest is not the plain hash of the
        // concatenated digests (domain-separated), nor a member digest.
        assert_ne!(pack, BlobMetadataDigest::of_group(&[b, a]).unwrap());
        assert_ne!(pack.digest(), &digest(&[a, b].concat()));
        assert_ne!(pack.digest(), &a);
        assert_eq!(pack, BlobMetadataDigest::of_group(&[a, b]).unwrap());
    }

    #[test]
    fn offsets_map_to_groups_through_the_granule_index_table() {
        let (meta, _) = fixture();
        // One index entry per block; group boundaries are 0, 3, 7, 12, 28.
        let granule_indices = BlobMetadata::granule_indices_of(&meta.header, &meta.storage);
        assert_eq!(granule_indices.len(), 30);
        assert_eq!(granule_indices[0].group_index, 0);
        assert_eq!(granule_indices[3].group_index, 1);
        assert_eq!(granule_indices[28].group_index, 4);
        let expect = [
            (0, 0),
            (2, 0),
            (3, 1),
            (6, 1),
            (7, 2),
            (11, 2),
            (12, 3),
            (15, 3),
            (16, 3),
            (27, 3),
            (28, 4),
            (29, 4),
        ];
        for (block, group) in expect {
            let offset = block * BLOCK;
            assert_eq!(
                meta.chunk_group_index_of(offset),
                Some(group),
                "block {block}"
            );
            assert_eq!(
                meta.chunk_group_index_of(offset + BLOCK - 1),
                Some(group),
                "block {block} tail"
            );
        }
        assert_eq!(meta.chunk_group_index_of(30 * BLOCK), None);

        // A tampered cell is caught at load.
        let mut raw = Vec::new();
        meta.write_to(&mut raw).unwrap();
        let mut tampered = raw.clone();
        let granule_index_offset = meta.header().granule_index_offset() as usize;
        write_u32_at(&mut tampered, granule_index_offset + 4, 1 << 3);
        assert!(BlobMetadata::from_bytes(&tampered, false)
            .unwrap_err()
            .to_string()
            .contains("GranuleIndexTable"));

        // The smallest legal granule also uses the direct table.
        let (groups, chunk_lengths): (Vec<_>, Vec<u32>) = {
            let (meta, _) = fixture();
            (
                meta.chunk_groups()
                    .map(|group| {
                        BlobMetadataChunkGroup::new(
                            group.compressed_size(),
                            group.payload_size(),
                            group.chunk_count(),
                            group.crc32(),
                            None,
                        )
                        .unwrap()
                    })
                    .collect(),
                (0..9).map(|i| meta.chunk_len(i).unwrap()).collect(),
            )
        };
        let plain = layered(16, None, groups, chunk_lengths, vec![]).unwrap();
        assert_eq!(plain.granule_index_count(), 30);
        assert_eq!(plain.lookup_granule(), 4096);
        for (block, group) in expect {
            assert_eq!(plain.chunk_group_index_of(block * BLOCK), Some(group));
        }
        assert_eq!(plain.chunk_group_index_of(30 * BLOCK), None);
    }

    #[test]
    fn granule_bounds_every_group_but_the_last() {
        // 8 KiB granule (2 blocks): a one-block group in the middle is
        // rejected, at the end it is fine.
        let big = vec![7u8; 8192];
        let small = vec![8u8; 100];
        let ok = vec![plain_group(&big, 1), plain_group(&small, 1)];
        let meta = layered(4, Some(8192), ok, vec![8192, 100], vec![]).unwrap();
        assert_eq!(meta.granule_index_count(), 2);
        assert_eq!(meta.chunk_group_index_of(2 * BLOCK), Some(1));
        let bad = vec![plain_group(&small, 1), plain_group(&big, 1)];
        assert!(layered(4, Some(8192), bad, vec![100, 8192], vec![])
            .unwrap_err()
            .to_string()
            .contains("lookup granule"));
        // The granule is a power of two between one block and the span.
        for granule in [3000, 2048, 32768] {
            let groups = vec![plain_group(&big, 1)];
            assert!(layered(4, Some(granule), groups, vec![8192], vec![]).is_err());
        }
    }

    #[test]
    fn chunk_table_uses_u32_for_all_lengths() {
        // Small and large chunks share the same four-byte encoding.
        let a = vec![1u8; 70000];
        let b = vec![2u8; 100];
        let payload = [a.clone(), b.clone()].concat();
        let groups = vec![plain_group(&payload, 2)];
        let meta = layered(64, Some(4096), groups, vec![70000, 100], vec![]).unwrap();
        let mut raw = Vec::new();
        meta.write_to(&mut raw).unwrap();
        let loaded = BlobMetadata::from_bytes(&raw, true).unwrap();
        assert_eq!(loaded.chunk_len(0), Some(70000));
        assert_eq!(
            loaded.chunk_group_chunks(0).collect::<Vec<_>>(),
            vec![(0, 0, 70000), (1, 18 * BLOCK, 100)]
        );
        let dir = tempdir().unwrap();
        let path = dir.path().join("w.blob.meta");
        meta.save(&path).unwrap();
        let mapped = BlobMetadata::from_path(&path, true).unwrap();
        assert_eq!(mapped.chunk_len(0), Some(70000));
        assert_eq!(mapped.chunk_len(1), Some(100));
    }

    #[test]
    fn scatter_puts_every_chunk_on_its_block() {
        let (meta, chunks) = fixture();
        let payloads: Vec<Vec<u8>> = vec![
            chunks[..2].concat(),
            chunks[2..5].concat(),
            chunks[5].clone(),
            chunks[6].clone(),
            chunks[7..].concat(),
        ];
        let mut padded = vec![0u8; 30 * BLOCK as usize];
        for (index, payload) in payloads.iter().enumerate() {
            meta.for_each_decoded_chunk(index, payload, &mut |offset, bytes| {
                padded[offset as usize..offset as usize + bytes.len()].copy_from_slice(bytes);
                Ok(())
            })
            .unwrap();
        }
        let mut chunk = 0;
        for group in 0..5 {
            for (_, offset, len) in meta.chunk_group_chunks(group) {
                let offset = offset as usize;
                assert_eq!(&padded[offset..offset + len as usize], &chunks[chunk]);
                chunk += 1;
            }
        }
        assert_eq!(chunk, 9);
        // Block tails stay zero.
        assert!(padded[100..BLOCK as usize].iter().all(|b| *b == 0));
        assert!(meta
            .for_each_decoded_chunk(0, &payloads[0][..10], &mut |_, _| Ok(()))
            .is_err());
        assert!(meta
            .for_each_decoded_chunk(5, &payloads[0][..1], &mut |_, _| Ok(()))
            .is_err());
    }

    #[test]
    fn empty_metadata_is_one_block() {
        let meta = layered(1, Some(4096), Vec::new(), Vec::new(), Vec::new()).unwrap();
        let mut raw = Vec::new();
        meta.write_to(&mut raw).unwrap();
        assert_eq!(raw.len(), 4096);
        let loaded = BlobMetadata::from_bytes(&raw, true).unwrap();
        assert_eq!(loaded.uncompressed_size(), 0);
        assert_eq!(loaded.compressed_end(), 0);
        assert_eq!(loaded.granule_index_count(), 0);
        assert_eq!(loaded.chunk_group_index_of(0), None);
        assert_eq!(loaded.chunk_group_entries().len(), 1);
    }

    #[test]
    fn redirect_blobs_carry_a_source_per_group() {
        let (source, chunks) = fixture();
        // Copy the source's groups 4 and 0, in that order, as blob 3's.
        let copied = [4usize, 0];
        let mut groups = Vec::new();
        let mut chunk_lengths = Vec::new();
        let mut digests = Vec::new();
        for &index in &copied {
            let group = source.chunk_group(index).unwrap();
            groups.push(
                BlobMetadataChunkGroup::new(
                    group.compressed_size(),
                    group.payload_size(),
                    group.chunk_count(),
                    group.crc32(),
                    Some(BlobMetadataRedirect::new(3, index as u32).unwrap()),
                )
                .unwrap(),
            );
            chunk_lengths.extend(group.chunk_range().map(|i| source.chunk_len(i).unwrap()));
            digests.push(*source.digest(index).unwrap());
        }
        let meta = BlobMetadata::new(
            BlobMetadataCompressor::None,
            BlobMetadataDigester::Blake3,
            16,
            4096,
            groups,
            chunk_lengths,
            digests,
        )
        .unwrap();
        assert!(meta.is_redirect());
        assert_eq!(meta.redirect_count(), 2);
        assert_eq!(meta.chunk_count(), 4);
        assert_eq!(meta.chunk_count(), 4);
        assert_eq!(meta.uncompressed_block_count(), 5);
        assert_eq!(
            meta.header().used_size(),
            32 + 3 * 24 + 16 + 24 + 2 * 32 + 2 * 8
        );

        let mut raw = Vec::new();
        meta.write_to(&mut raw).unwrap();
        let loaded = BlobMetadata::from_bytes(&raw, true).unwrap();
        assert!(loaded.is_redirect());
        let first = loaded.chunk_group(0).unwrap();
        let redirect = first.redirect().unwrap();
        assert_eq!(redirect.source_blob_index(), 3);
        assert_eq!(redirect.source_chunk_group_index(), 4);
        assert_eq!(first.compressed_range(), 0..2);
        assert_eq!(first.uncompressed_range(), 0..2 * BLOCK);
        assert_eq!(first.crc32(), crc32c(&chunks[7..].concat()));
        let second = loaded.chunk_group(1).unwrap();
        assert_eq!(second.redirect().unwrap().source_chunk_group_index(), 0);
        assert_eq!(second.uncompressed_range(), 2 * BLOCK..5 * BLOCK);
        let dir = tempdir().unwrap();
        let path = dir.path().join("r.blob.meta");
        meta.save(&path).unwrap();
        assert_eq!(
            BlobMetadata::from_path(&path, true).unwrap().redirects(),
            meta.redirects()
        );

        // REDIRECT is incompatible: clearing the flag leaves a table the
        // header does not account for, and a reader without the feature
        // rejects the bit.
        let mut stripped = raw.clone();
        write_u32_at(
            &mut stripped,
            12,
            meta.header().flags().bits() & !BlobMetadataFlags::REDIRECT.bits(),
        );
        assert!(BlobMetadata::from_bytes(&stripped, false).is_err());
        let mut incompat = raw.clone();
        write_u32_at(&mut incompat, 12, meta.header().flags().bits() | 1 << 8);
        assert!(BlobMetadata::from_bytes(&incompat, false).is_err());
        // A zeroed source blob index is rejected on both sides.
        assert!(BlobMetadataRedirect::new(0, 1).is_err());
        let mut zeroed = raw.clone();
        write_u32_at(&mut zeroed, meta.header().redirects_offset() as usize, 0);
        assert!(BlobMetadata::from_bytes(&zeroed, false).is_err());
        let mut oversized = raw.clone();
        write_u32_at(
            &mut oversized,
            meta.header().redirects_offset() as usize,
            65536,
        );
        assert!(BlobMetadata::from_bytes(&oversized, false).is_err());

        // Groups must all redirect or none.
        let payload = chunks[5].clone();
        let mixed = vec![
            plain_group(&payload, 1),
            BlobMetadataChunkGroup::new(
                20000,
                20000,
                1,
                crc32c(&payload),
                Some(BlobMetadataRedirect::new(1, 1).unwrap()),
            )
            .unwrap(),
        ];
        assert!(layered(16, None, mixed, vec![], vec![])
            .unwrap_err()
            .to_string()
            .contains("all redirect"));
    }

    #[test]
    fn compressed_groups_round_trip_and_unknown_flags_are_split() {
        let payload = vec![7u8; 100];
        let meta = BlobMetadata::new(
            BlobMetadataCompressor::Zstd,
            BlobMetadataDigester::None,
            1,
            4096,
            vec![BlobMetadataChunkGroup::new(10, 100, 1, crc32c(&payload), None).unwrap()],
            vec![100],
            vec![],
        )
        .unwrap();
        assert!(!meta.is_redirect());
        assert!(!meta.is_plain(&meta.chunk_group(0).unwrap()));
        let mut raw = Vec::new();
        meta.write_to(&mut raw).unwrap();
        assert!(!BlobMetadata::from_bytes(&raw, true).unwrap().is_redirect());
        // An unknown compat bit is ignored; an unknown incompat bit rejects.
        let mut compat = raw.clone();
        write_u32_at(&mut compat, 12, meta.header().flags().bits() | 1 << 20);
        assert!(BlobMetadata::from_bytes(&compat, false).is_ok());
        let mut incompat = raw.clone();
        write_u32_at(&mut incompat, 12, meta.header().flags().bits() | 1 << 8);
        assert!(BlobMetadata::from_bytes(&incompat, false).is_err());
    }

    #[test]
    fn granule_index_corrects_once_and_rejects_corruption() {
        let lengths = vec![3 * 4096, 4 * 4096, 100];
        let groups = lengths
            .iter()
            .map(|length| plain_group(&vec![1; *length as usize], 1))
            .collect();
        let meta = layered(8, Some(8192), groups, lengths, vec![]).unwrap();
        let mut raw = Vec::new();
        meta.write_to(&mut raw).unwrap();
        let directory = tempdir().unwrap();
        let path = directory.path().join("index.blob.meta");
        meta.save(&path).unwrap();
        let mapped = BlobMetadata::from_path(&path, true).unwrap();
        assert!(matches!(mapped.storage, BlobMetadataStorage::Mapped(_)));
        for offset in 0..meta.uncompressed_size() {
            let expected = if offset < 3 * BLOCK {
                0
            } else if offset < 7 * BLOCK {
                1
            } else {
                2
            };
            assert_eq!(mapped.chunk_group_index_of(offset), Some(expected));
        }
        assert_eq!(mapped.chunk_group_index_of(u64::MAX), None);
        drop(mapped);
        let padding = meta.header().granule_index_offset()
            + u64::from(meta.header().granule_index_count()) * 4;
        for offset in padding..meta.header().digests_offset() {
            let mut invalid = raw.clone();
            invalid[offset as usize] = 1;
            assert!(BlobMetadata::from_bytes(&invalid, false).is_err());
        }
        for offset in [8, 20, 24, 25, 26, 31] {
            let mut invalid = raw.clone();
            invalid[offset] = 255;
            assert!(BlobMetadata::from_bytes(&invalid, false).is_err());
        }
        for length in [0, 31, 32, 55, 127, 4095] {
            assert!(BlobMetadata::from_bytes(&raw[..length], false).is_err());
        }
        for value in [1, u32::MAX] {
            let mut invalid = raw.clone();
            write_u32_at(
                &mut invalid,
                meta.header().granule_index_offset() as usize,
                value,
            );
            assert!(BlobMetadata::from_bytes(&invalid, false).is_err());
            std::fs::write(&path, &invalid).unwrap();
            assert!(BlobMetadata::from_path(&path, false).is_err());
        }
    }

    #[test]
    fn inconsistent_tables_reject() {
        let (meta, chunks) = fixture();
        let payloads: Vec<Vec<u8>> = vec![
            chunks[..2].concat(),
            chunks[2..5].concat(),
            chunks[5].clone(),
            chunks[6].clone(),
            chunks[7..].concat(),
        ];
        let chunk_lengths = || vec![100u32, 5000, 40, 6000, 1, 20000, 65536, 1, 1];
        let groups = || {
            vec![
                plain_group(&payloads[0], 2),
                plain_group(&payloads[1], 3),
                plain_group(&payloads[2], 1),
                plain_group(&payloads[3], 1),
                plain_group(&payloads[4], 2),
            ]
        };
        let build = |groups: Vec<BlobMetadataChunkGroup>, chunk_lengths: Vec<u32>| {
            layered(16, Some(4096), groups, chunk_lengths, vec![])
                .expect_err("expected rejection")
                .to_string()
        };

        // Members left over, or a group naming chunk_lengths past the table.
        assert!(build(groups(), [chunk_lengths(), vec![5]].concat()).contains("ChunkTable holds"));
        let mut greedy = groups();
        greedy[4].chunk_count = 3;
        assert!(build(greedy, chunk_lengths()).contains("past ChunkTable"));
        // A group of exactly one member, an empty group or an empty member.
        assert!(BlobMetadataChunkGroup::new(10, 10, 0, 0, None).is_err());
        assert!(BlobMetadataChunkGroup::new(10, 0, 0, 0, None).is_err());
        assert!(BlobMetadataChunkGroup::new(0, 10, 0, 0, None).is_err());
        let mut zero = chunk_lengths();
        zero[0] = 0;
        zero[1] = 5100;
        assert!(build(groups(), zero).contains("non-empty"));
        // Members that do not add up to the payload.
        let mut short = chunk_lengths();
        short[1] = 4999;
        assert!(build(groups(), short).contains("add up"));
        // A lone chunk over the group span, or a pack over a span of blocks.
        let over = vec![plain_group(&vec![1u8; 65537], 1)];
        assert!(build(over, vec![65537]).contains("more than the"));
        let wide = vec![plain_group(&vec![1u8; 17 * 4096], 17)];
        assert!(build(wide, vec![4096; 17]).contains("more than the"));
        // An encoded payload larger than the payload, or a plain blob that
        // does not store payloads whole.
        let mut grown = groups();
        grown[0].compressed_size = 5101;
        assert!(build(grown, chunk_lengths()).contains("exceeds"));
        let mut partial = groups();
        partial[0].compressed_size = 5099;
        assert!(build(partial, chunk_lengths()).contains("full payload"));
        // A digest table that does not cover every group.
        assert!(layered(
            16,
            Some(4096),
            groups(),
            chunk_lengths(),
            vec![BlobMetadataDigest::new([0; 32])]
        )
        .unwrap_err()
        .to_string()
        .contains("digest count"));

        // Two compressors at once, or a digest table without a digester.
        let mut raw = Vec::new();
        meta.write_to(&mut raw).unwrap();
        for flags in [
            BlobMetadataFlags::DIGESTER_BLAKE3
                | BlobMetadataFlags::COMPRESSOR_LZ4
                | BlobMetadataFlags::COMPRESSOR_ZSTD,
            BlobMetadataFlags::empty(),
        ] {
            let mut invalid = raw.clone();
            write_u32_at(&mut invalid, 12, flags.bits());
            assert!(BlobMetadata::from_bytes(&invalid, false).is_err());
        }
        // A header whose totals disagree with the tables.
        for (offset, value) in [(160usize, 31u32), (164, 8), (168, 1)] {
            let mut invalid = raw.clone();
            write_u32_at(&mut invalid, offset, value);
            assert!(BlobMetadata::from_bytes(&invalid, false).is_err());
        }
        let mut invalid = raw.clone();
        invalid[25] = 0;
        assert!(BlobMetadata::from_bytes(&invalid, false).is_err());
    }
}

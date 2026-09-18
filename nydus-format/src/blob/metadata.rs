use crate::blob::algorithm::{BlobMetadataCompressor, BlobMetadataDigester};
use crate::blob::flag::FeatureFlags;
use crate::erofs::EROFS_BLOCK_SIZE;
use crate::error::{Context, Error, Result};
use crate::utils::align_up_u64;
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
/// (`LPFOOTER`) and chunk group map (`LPGRPMAP`) sidecars.
pub const NYDUS_BLOB_METADATA_MAGIC: [u8; 8] = *b"LPBLMETA";

/// Format version of the fixed-group layout; earlier experimental layouts
/// are unsupported.
pub const NYDUS_BLOB_METADATA_VERSION: u32 = 1;

/// The header's fixed on-disk size. The tables follow it back to back, each
/// starting 8-byte aligned, and the whole file is padded to a 4KiB block.
pub const NYDUS_BLOB_METADATA_HEADER_SIZE: usize = 32;

/// On-disk size of one chunk group table entry (see
/// [`BlobMetadataChunkGroup`]).
pub const NYDUS_BLOB_METADATA_CHUNK_GROUP_ENTRY_SIZE: usize = 16;

/// On-disk size of one chunk entry: a little-endian `u32` byte length.
pub const NYDUS_BLOB_METADATA_CHUNK_ENTRY_SIZE: usize = 4;

/// On-disk size of one digest entry, see [`BlobMetadataDigest`].
pub const NYDUS_BLOB_METADATA_DIGEST_ENTRY_SIZE: usize = 32;

/// On-disk size of one redirect entry, see [`BlobMetadataRedirect`].
pub const NYDUS_BLOB_METADATA_REDIRECT_ENTRY_SIZE: usize = 8;

/// Default chunk size: the largest chunk a file is cut into, and — since
/// every chunk group owns exactly one chunk-sized slot of the address space
/// — the size of a group. 1 MiB.
pub const DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE: u32 = 1024 * 1024;

/// The default chunk size in 4KiB blocks.
pub const DEFAULT_NYDUS_BLOB_METADATA_CHUNK_BLOCK_COUNT: u32 =
    DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE / EROFS_BLOCK_SIZE;

/// File-name suffix of a blob meta sidecar file (`<blob>.blob.meta`).
pub const NYDUS_BLOB_METADATA_SUFFIX: &str = ".blob.meta";

/// Largest allowed block-count exponent (`chunk_block_count_bits`): keeps
/// the derived byte size (`4096 << bits`) within a `u32` (2 GiB at most).
const NYDUS_BLOB_METADATA_MAX_BLOCK_COUNT_BITS: u8 = 19;

/// Byte range of the crc32 field within the header.
const NYDUS_BLOB_METADATA_HEADER_CRC32_FIELD: Range<usize> = 16..20;

const BLOCK: u64 = EROFS_BLOCK_SIZE as u64;

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
        /// Every chunk has a BLAKE3 digest in the digest table; no digester
        /// bit means the table is empty (`nydus build --digester none`).
        const DIGESTER_BLAKE3 = 1 << 2;
        /// The blob is an `optimize` output: every chunk group is a copy of
        /// a chunk group of another blob of the image, named by the redirect
        /// table, and the runtime prefetches it into those source blobs'
        /// caches under `prefetch.scope: ondemand`. Incompatible: a reader
        /// that does not fill the sources from it gains nothing from it.
        const REDIRECT = 1 << 3;
        /// Upper data produced by the incremental writer without an embedded bootstrap.
        const INCREMENTAL = 1 << 4;
    }
}

/// Every defined incompat bit is supported (unknown incompat bits reject the
/// file); the compat half is masked off by the validation itself.
const NYDUS_BLOB_METADATA_SUPPORTED_INCOMPAT: u32 = BlobMetadataFlags::all().bits() & 0xffff;

/// The fixed-size header leading the serialized metadata: the geometry and
/// entry counts, sealed with a crc32c over the whole file. Table offsets are
/// not stored: the tables follow the header in a fixed order, each 8-byte
/// aligned (see [`BlobMetadata`]).
///
/// The header's 32 bytes (integers little-endian):
///
/// ```text
/// offset  size  field
///      0     8  magic                   b"LPBLMETA"
///      8     4  version                 1; other generations are rejected
///     12     4  flags                   low 16 incompat / high 16 compat
///     16     4  crc32                   crc32c of the whole serialized
///                                       metadata with this field zero
///     20     1  chunk_block_count_bits  log2 of the chunk's 4KiB blocks:
///                                       the largest chunk of a file, and
///                                       the slot every group owns
///     21     3  reserved                must be zero
///     24     4  chunk_group_count
///     28     4  chunk_count
/// ```
///
/// The digest count is not stored: it is the chunk count with a digester
/// bit set, zero otherwise. Likewise the redirect count is the chunk group
/// count with the REDIRECT flag, zero otherwise.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlobMetadataHeader {
    magic: [u8; 8],
    version: u32,
    flags: u32,
    crc32: u32,
    chunk_block_count_bits: u8,
    chunk_group_count: u32,
    chunk_count: u32,
}

impl BlobMetadataHeader {
    /// Parse and validate the fixed-size metadata header.
    ///
    /// This does not verify the crc32 or tables because those require the
    /// complete metadata region; use [`BlobMetadata::from_bytes`] for full
    /// validation.
    pub fn from_bytes(bytes: &[u8; NYDUS_BLOB_METADATA_HEADER_SIZE]) -> Result<Self> {
        if bytes[21..24] != [0, 0, 0] {
            return Err(Error::InvalidImage(
                "blob meta header reserved field must be zero".to_string(),
            ));
        }
        let header = Self {
            magic: bytes[0..8].try_into().unwrap(),
            version: read_u32_at(bytes, 8),
            flags: read_u32_at(bytes, 12),
            crc32: read_u32_at(bytes, 16),
            chunk_block_count_bits: read_u8_at(bytes, 20),
            chunk_group_count: read_u32_at(bytes, 24),
            chunk_count: read_u32_at(bytes, 28),
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
        write_u8_at(&mut data, 20, self.chunk_block_count_bits);
        write_u32_at(&mut data, 24, self.chunk_group_count);
        write_u32_at(&mut data, 28, self.chunk_count);
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
        if self.chunk_block_count_bits > NYDUS_BLOB_METADATA_MAX_BLOCK_COUNT_BITS {
            return Err(Error::InvalidImage(format!(
                "blob meta chunk block count bits too large: {}",
                self.chunk_block_count_bits
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
        if flags.contains(BlobMetadataFlags::REDIRECT | BlobMetadataFlags::INCREMENTAL) {
            return Err(Error::InvalidImage(
                "blob meta cannot be both redirect and incremental".to_string(),
            ));
        }
        if (self.chunk_group_count == 0) != (self.chunk_count == 0) {
            return Err(Error::InvalidImage(format!(
                "blob meta has {} chunk groups for {} chunks",
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

    /// Whether the blob stores incremental upper data without an embedded
    /// bootstrap.
    pub fn is_incremental(&self) -> bool {
        self.flags().contains(BlobMetadataFlags::INCREMENTAL)
    }

    /// log2 of the chunk's 4KiB blocks.
    pub fn chunk_block_count_bits(&self) -> u8 {
        self.chunk_block_count_bits
    }

    /// 4KiB blocks per chunk (`1 << chunk_block_count_bits`).
    pub fn chunk_block_count(&self) -> u32 {
        1u32 << self.chunk_block_count_bits
    }

    /// Bytes per chunk: the largest chunk a file is cut into, and the slot
    /// every chunk group owns in the address space.
    pub fn chunk_size(&self) -> u32 {
        EROFS_BLOCK_SIZE << self.chunk_block_count_bits
    }

    /// Number of chunk groups (the table holds one more entry, the
    /// terminator).
    pub fn chunk_group_count(&self) -> u32 {
        self.chunk_group_count
    }

    /// Number of chunk entries.
    pub fn chunk_count(&self) -> u32 {
        self.chunk_count
    }

    /// Number of digest entries: the chunk count with a digester, else zero.
    pub fn digest_count(&self) -> u32 {
        match self.digester() {
            BlobMetadataDigester::Blake3 => self.chunk_count,
            BlobMetadataDigester::None => 0,
        }
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

    /// Byte offset of the chunk table.
    pub fn chunks_offset(&self) -> u64 {
        self.chunk_groups_offset()
            + (self.chunk_group_count as u64 + 1)
                * NYDUS_BLOB_METADATA_CHUNK_GROUP_ENTRY_SIZE as u64
    }

    /// Byte offset of the digest table. The tables of a validated header
    /// fit a `u32` ([`Self::used_size_checked`]), so the alignment cannot
    /// overflow.
    pub fn digests_offset(&self) -> u64 {
        align_up_u64(
            self.chunks_offset()
                + self.chunk_count as u64 * NYDUS_BLOB_METADATA_CHUNK_ENTRY_SIZE as u64,
            8,
        )
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
            (
                self.chunk_count as u64,
                NYDUS_BLOB_METADATA_CHUNK_ENTRY_SIZE as u64,
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
/// entries: entry `i` names where group `i` starts, and entry `i + 1` is
/// where it ends, so the last entry is a terminator holding the data
/// region's size and the chunk count.
///
/// ```text
/// offset  size  field
///      0     8  compressed_offset   bytes into the data region where the
///                                   group's encoded payload starts
///      8     4  first_chunk         index of the group's first chunk
///     12     4  crc32               crc32c of the decoded payload (zero in
///                                   the terminator)
/// ```
///
/// The Rust layout is pinned to the on-disk layout (`repr(C)` plus the const
/// size assert) so a mapped table is readable in place, zero-copy.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ChunkGroupEntry {
    compressed_offset: u64,
    first_chunk: u32,
    crc32: u32,
}

const _: () = assert!(size_of::<ChunkGroupEntry>() == NYDUS_BLOB_METADATA_CHUNK_GROUP_ENTRY_SIZE);

impl ChunkGroupEntry {
    fn from_bytes(bytes: &[u8; NYDUS_BLOB_METADATA_CHUNK_GROUP_ENTRY_SIZE]) -> Self {
        Self {
            compressed_offset: read_u64_at(bytes, 0),
            first_chunk: read_u32_at(bytes, 8),
            crc32: read_u32_at(bytes, 12),
        }
    }

    fn to_bytes(self) -> [u8; NYDUS_BLOB_METADATA_CHUNK_GROUP_ENTRY_SIZE] {
        let mut data = [0u8; NYDUS_BLOB_METADATA_CHUNK_GROUP_ENTRY_SIZE];
        write_u64_at(&mut data, 0, self.compressed_offset);
        write_u32_at(&mut data, 8, self.first_chunk);
        write_u32_at(&mut data, 12, self.crc32);
        data
    }
}

/// One redirect table entry: the chunk group of another blob of the image
/// that the chunk group at the same index copies. Present only in a
/// REDIRECT blob (an `optimize` output), one entry per chunk group.
///
/// ```text
/// offset  size  field
///      0     2  source_blob_index         device index of the source blob,
///                                         never zero
///      2     2  reserved                  must be zero
///      4     4  source_chunk_group_index  the copied group within it
/// ```
///
/// The Rust layout is pinned to the on-disk layout (`repr(C)` plus the const
/// size assert) so a mapped table is readable in place, zero-copy.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlobMetadataRedirect {
    source_blob_index: u16,
    reserved: u16,
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
            source_blob_index,
            reserved: 0,
            source_chunk_group_index,
        })
    }

    fn from_bytes(bytes: &[u8; NYDUS_BLOB_METADATA_REDIRECT_ENTRY_SIZE]) -> Self {
        Self {
            source_blob_index: read_u16_at(bytes, 0),
            reserved: read_u16_at(bytes, 2),
            source_chunk_group_index: read_u32_at(bytes, 4),
        }
    }

    fn to_bytes(self) -> [u8; NYDUS_BLOB_METADATA_REDIRECT_ENTRY_SIZE] {
        let mut data = [0u8; NYDUS_BLOB_METADATA_REDIRECT_ENTRY_SIZE];
        write_u16_at(&mut data, 0, self.source_blob_index);
        write_u16_at(&mut data, 2, self.reserved);
        write_u32_at(&mut data, 4, self.source_chunk_group_index);
        data
    }

    fn validate(&self) -> Result<()> {
        if self.source_blob_index == 0 || self.reserved != 0 {
            return Err(Error::InvalidImage(
                "blob meta redirect entry must name a non-zero source blob and keep its reserved field zero"
                    .to_string(),
            ));
        }
        Ok(())
    }

    /// Device index of the source blob.
    pub fn source_blob_index(&self) -> u16 {
        self.source_blob_index
    }

    /// The copied chunk group within the source blob.
    pub fn source_chunk_group_index(&self) -> u32 {
        self.source_chunk_group_index
    }
}

/// One chunk group: the unit of compression, backend read, decode, cache
/// fill, readiness and trace.
///
/// ```text
/// uncompressed address space: one chunk-sized slot per group
/// ┌──────────────┬──────────────┬──────────────┐
/// │   group 0    │   group 1    │   group 2    │   group i owns
/// │ c0 │c1│c2│   │      c3      │c4 │ c5 │     │   [i·S, (i+1)·S)
/// └────┴──┴──┴───┴──────────────┴───┴────┴─────┘
///       ▼               ▼              ▼
/// ┌─────────┬───────────────────┬──────┐
/// │   p0    │        p1         │  p2  │           encoded payloads: the
/// └─────────┴───────────────────┴──────┘           chunks' bytes back to
///                                                  back, no padding, then
///                                                  compressed; packed in
///                                                  order, byte-exact
/// ```
///
/// A writer describes a group with [`Self::new`]; [`BlobMetadata::new`] then
/// lays the groups out back to back, which is when the index, the payload
/// offset and the first chunk become known. Groups read back from a table
/// ([`BlobMetadata::chunk_group`]) carry every field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlobMetadataChunkGroup {
    index: u32,
    compressed_offset: u64,
    compressed_size: u32,
    first_chunk: u32,
    chunk_count: u32,
    crc32: u32,
    chunk_block_count_bits: u8,
    redirect: Option<BlobMetadataRedirect>,
}

impl BlobMetadataChunkGroup {
    /// Describes a group for a writer: `compressed_size` bytes of encoded
    /// payload holding `chunk_count` chunks whose decoded bytes crc32c to
    /// `crc32`, copied from `redirect` when the blob is a REDIRECT blob.
    /// Index, offsets and the slot geometry are assigned by
    /// [`BlobMetadata::new`].
    pub fn new(
        compressed_size: u32,
        chunk_count: u32,
        crc32: u32,
        redirect: Option<BlobMetadataRedirect>,
    ) -> Result<Self> {
        if compressed_size == 0 || chunk_count == 0 {
            return Err(Error::InvalidParameter(
                "blob meta chunk group must hold at least one chunk and one encoded byte"
                    .to_string(),
            ));
        }
        Ok(Self {
            index: 0,
            compressed_offset: 0,
            compressed_size,
            first_chunk: 0,
            chunk_count,
            crc32,
            chunk_block_count_bits: 0,
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

    /// The group's first chunk.
    pub fn first_chunk(&self) -> u32 {
        self.first_chunk
    }

    /// Chunks the group holds, never zero.
    pub fn chunk_count(&self) -> u32 {
        self.chunk_count
    }

    /// The group's chunk indexes.
    pub fn chunk_range(&self) -> Range<usize> {
        self.first_chunk as usize..(self.first_chunk + self.chunk_count) as usize
    }

    /// crc32c of the decoded payload, checked after decode.
    pub fn crc32(&self) -> u32 {
        self.crc32
    }

    /// The source this group copies, in a REDIRECT blob.
    pub fn redirect(&self) -> Option<BlobMetadataRedirect> {
        self.redirect
    }

    /// Start of the group's slot, in 4KiB blocks of the uncompressed
    /// address space.
    pub fn uncompressed_block_offset(&self) -> u64 {
        (self.index as u64) << self.chunk_block_count_bits
    }

    /// Length of the slot in 4KiB blocks.
    pub fn uncompressed_block_count(&self) -> u32 {
        1u32 << self.chunk_block_count_bits
    }

    /// Start of the slot in bytes.
    pub fn uncompressed_offset(&self) -> u64 {
        self.uncompressed_block_offset() * BLOCK
    }

    /// Length of the slot in bytes: the chunk size.
    pub fn uncompressed_size(&self) -> u64 {
        self.uncompressed_block_count() as u64 * BLOCK
    }

    /// Byte range of the slot in the uncompressed address space.
    pub fn uncompressed_range(&self) -> Range<u64> {
        self.uncompressed_offset()..self.uncompressed_offset() + self.uncompressed_size()
    }
}

/// One digest entry: the content digest of the chunk at the same index in
/// the chunk table. On disk: `digest [u8; 32]`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlobMetadataDigest {
    digest: [u8; 32],
}

const _: () = assert!(size_of::<BlobMetadataDigest>() == NYDUS_BLOB_METADATA_DIGEST_ENTRY_SIZE);

impl BlobMetadataDigest {
    /// Creates an entry for the chunk at the same index in the chunk table.
    pub fn new(digest: [u8; 32]) -> Self {
        Self { digest }
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
        chunks: Vec<u32>,
        digests: Vec<BlobMetadataDigest>,
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
/// ┌────────┬─────────────────────┬──────────────┬───────────────┬────────────────┬─────────┐
/// │ header │ chunk group table   │ chunk table  │ digest table  │ redirect table │ padding │
/// │ 32 B   │ (groups + 1) × 16 B │ 4 B × chunks │ 32 B × chunks │ 8 B × groups   │         │
/// └────────┴─────────────────────┴──────────────┴───────────────┴────────────────┴─────────┘
/// 0        32                   each table 8-byte aligned       REDIRECT blobs only   4KiB×n
/// ```
///
/// The address space is cut into chunk-sized slots, one per chunk group:
/// group `i` owns bytes `[i·S, (i+1)·S)` for the chunk size `S`, so the
/// group of an address is a shift. Inside its slot a group's chunks (whole
/// files of at most `S` bytes, or `S`-sized slices of larger files) sit
/// back to back, each starting on its own 4KiB block; the slot's tail past
/// the last chunk is unused. The encoded stream is dense: a group's payload
/// is its chunks' bytes back to back without the block padding, compressed
/// as one unit (or stored plain when compression does not shrink it, which
/// the reader recognizes by `compressed_size == payload_size`). The chunk
/// table — one byte length per chunk, in group order — pins both positions
/// of every chunk as short prefix sums within its group, so a reader
/// decodes one group and scatters its chunks back onto their blocks on
/// cache fill.
///
/// A REDIRECT blob (an `optimize` output) is laid out the same way, but
/// every group is a byte-exact copy of a chunk group of another blob of the
/// image, named by the redirect table; the runtime decodes it into that
/// source blob's cache instead of its own.
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
    /// Creates validated, sealed metadata. `chunk_block_count` is the chunk
    /// size in 4KiB blocks (the largest chunk of a file and the slot of
    /// every group); `chunk_groups` are in order, their payloads packed
    /// back to back from offset zero of the data region; `chunks` are the
    /// chunk byte lengths in group order; `digests` hold one entry per
    /// chunk, or none with `BlobMetadataDigester::None`. The blob is a
    /// REDIRECT blob when every group names a redirect source, and a plain
    /// blob when none does; a mix is rejected.
    pub fn new(
        compressor: BlobMetadataCompressor,
        digester: BlobMetadataDigester,
        chunk_block_count: u32,
        chunk_groups: Vec<BlobMetadataChunkGroup>,
        chunks: Vec<u32>,
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
            BlobMetadataDigester::Blake3 => chunks.len(),
            BlobMetadataDigester::None => 0,
        };
        if digests.len() != expected_digests {
            return Err(Error::InvalidParameter(format!(
                "blob meta digest count {} does not match {} chunks (digester: {digester})",
                digests.len(),
                chunks.len()
            )));
        }
        let header = BlobMetadataHeader {
            magic: NYDUS_BLOB_METADATA_MAGIC,
            version: NYDUS_BLOB_METADATA_VERSION,
            flags: flags.bits(),
            crc32: 0,
            chunk_block_count_bits: block_count_to_bits(chunk_block_count)?,
            chunk_group_count: count(chunk_groups.len(), "chunk group")?,
            chunk_count: count(chunks.len(), "chunk")?,
        };
        header.validate()?;

        // Lay the groups out back to back and end with the terminator.
        let mut entries = Vec::with_capacity(chunk_groups.len() + 1);
        let mut redirects = Vec::with_capacity(redirected);
        let mut compressed_offset = 0u64;
        let mut first_chunk = 0u32;
        for (index, group) in chunk_groups.iter().enumerate() {
            entries.push(ChunkGroupEntry {
                compressed_offset,
                first_chunk,
                crc32: group.crc32,
            });
            redirects.extend(group.redirect);
            compressed_offset = compressed_offset
                .checked_add(group.compressed_size as u64)
                .ok_or_else(|| {
                    Error::Overflow(format!(
                        "blob meta chunk group {index} compressed range overflow"
                    ))
                })?;
            first_chunk = first_chunk.checked_add(group.chunk_count).ok_or_else(|| {
                Error::Overflow(format!(
                    "blob meta chunk group {index} chunk range overflow"
                ))
            })?;
        }
        entries.push(ChunkGroupEntry {
            compressed_offset,
            first_chunk,
            crc32: 0,
        });
        let storage = BlobMetadataStorage::Owned {
            chunk_groups: entries,
            chunks,
            digests,
            redirects,
        };
        Self::validate_tables(&header, &storage)?;
        let mut blob_metadata = Self { header, storage };
        blob_metadata.header.crc32 = blob_metadata.compute_crc32_from_parts();
        Ok(blob_metadata)
    }

    /// Creates metadata for an incremental upper blob.
    pub fn new_incremental(
        compressor: BlobMetadataCompressor,
        digester: BlobMetadataDigester,
        chunk_block_count: u32,
        chunk_groups: Vec<BlobMetadataChunkGroup>,
        chunks: Vec<u32>,
        digests: Vec<BlobMetadataDigest>,
    ) -> Result<Self> {
        let mut blob_metadata = Self::new(
            compressor,
            digester,
            chunk_block_count,
            chunk_groups,
            chunks,
            digests,
        )?;
        if blob_metadata.is_redirect() {
            return Err(Error::InvalidParameter(
                "redirect blob metadata cannot be incremental".to_string(),
            ));
        }
        blob_metadata.header.flags |= BlobMetadataFlags::INCREMENTAL.bits();
        blob_metadata.header.validate()?;
        blob_metadata.header.crc32 = 0;
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
        let chunks = table(
            header.chunks_offset(),
            header.chunk_count as u64,
            NYDUS_BLOB_METADATA_CHUNK_ENTRY_SIZE,
        )
        .chunks_exact(NYDUS_BLOB_METADATA_CHUNK_ENTRY_SIZE)
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
            chunks,
            digests,
            redirects,
        };
        Self::validate_tables(&header, &storage)?;
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
        let Some((header_bytes, _)) = mmap.split_first_chunk::<NYDUS_BLOB_METADATA_HEADER_SIZE>()
        else {
            return Err(Error::InvalidImage("blob meta file too small".to_string()));
        };
        let header = BlobMetadataHeader::from_bytes(header_bytes)?;
        Self::validate_bytes(&mmap, &header, verify_crc32)?;
        let storage = BlobMetadataStorage::Mapped(mmap);
        Self::validate_tables(&header, &storage)?;
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

    fn chunks_of<'a>(header: &BlobMetadataHeader, storage: &'a BlobMetadataStorage) -> &'a [u32] {
        match storage {
            BlobMetadataStorage::Owned { chunks, .. } => chunks,
            BlobMetadataStorage::Mapped(mmap) => {
                Self::mapped_table(mmap, header.chunks_offset(), header.chunk_count as usize)
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
        if bytes[header.used_size() as usize..]
            .iter()
            .any(|byte| *byte != 0)
        {
            return Err(Error::InvalidImage(
                "blob meta padding must be zero".to_string(),
            ));
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

    /// Validate the tables against each other: groups pack their payloads
    /// back to back from offset zero and own consecutive, non-empty chunk
    /// runs that together cover the chunk table; every chunk is non-empty
    /// and at most the chunk size; a group's chunks fit its slot; a payload
    /// never grows when encoded, and a plain blob stores every payload
    /// whole; the terminator carries zero crc; a redirect blob names a
    /// non-zero source blob per group.
    fn validate_tables(header: &BlobMetadataHeader, storage: &BlobMetadataStorage) -> Result<()> {
        let entries = Self::entries_of(header, storage);
        let chunks = Self::chunks_of(header, storage);
        let redirects = Self::redirects_of(header, storage);
        let slot_blocks = header.chunk_block_count() as u64;
        let chunk_size = header.chunk_size();
        let Some(terminator) = entries.last() else {
            return Err(Error::InvalidImage(
                "blob meta chunk group table lacks its terminator".to_string(),
            ));
        };
        if terminator.first_chunk as usize != chunks.len() || terminator.crc32 != 0 {
            return Err(Error::InvalidImage(format!(
                "blob meta chunk group terminator names {} chunks (crc {}) for a {}-chunk table",
                terminator.first_chunk,
                terminator.crc32,
                chunks.len()
            )));
        }
        if entries[0].compressed_offset != 0 || entries[0].first_chunk != 0 {
            return Err(Error::InvalidImage(
                "blob meta chunk groups must start at offset zero and chunk zero".to_string(),
            ));
        }
        for redirect in redirects {
            redirect.validate()?;
        }
        for (index, pair) in entries.windows(2).enumerate() {
            let (start, end) = (pair[0], pair[1]);
            if end.compressed_offset <= start.compressed_offset {
                return Err(Error::InvalidImage(format!(
                    "blob meta chunk group {index} has an empty or overlapping compressed range"
                )));
            }
            if end.first_chunk <= start.first_chunk || end.first_chunk as usize > chunks.len() {
                return Err(Error::InvalidImage(format!(
                    "blob meta chunk group {index} owns an empty or out-of-range chunk run"
                )));
            }
            let compressed_size = end.compressed_offset - start.compressed_offset;
            if compressed_size > u32::MAX as u64 {
                return Err(Error::Overflow(format!(
                    "blob meta chunk group {index} compressed size exceeds u32"
                )));
            }
            let mut payload = 0u64;
            let mut blocks = 0u64;
            for &len in &chunks[start.first_chunk as usize..end.first_chunk as usize] {
                if len == 0 {
                    return Err(Error::InvalidImage(
                        "blob meta chunk lengths must be non-zero".to_string(),
                    ));
                }
                if len > chunk_size {
                    return Err(Error::InvalidImage(
                        "blob meta chunk length exceeds the chunk size".to_string(),
                    ));
                }
                payload += len as u64;
                blocks += (len as u64).div_ceil(BLOCK);
            }
            if blocks > slot_blocks {
                return Err(Error::InvalidImage(format!(
                    "blob meta chunk group {index} holds {blocks} blocks of chunks in a \
                     {slot_blocks}-block slot"
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
        for chunk in self.chunks() {
            out.extend_from_slice(&chunk.to_le_bytes());
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

    /// The chunk table: byte lengths in group order.
    pub fn chunks(&self) -> &[u32] {
        Self::chunks_of(&self.header, &self.storage)
    }

    /// The digest table, one entry per chunk; empty without a digester.
    pub fn digests(&self) -> &[BlobMetadataDigest] {
        Self::digests_of(&self.header, &self.storage)
    }

    /// The redirect table, one entry per chunk group of a REDIRECT blob;
    /// empty otherwise.
    pub fn redirects(&self) -> &[BlobMetadataRedirect] {
        Self::redirects_of(&self.header, &self.storage)
    }

    /// The digest of chunk `chunk_index`, `None` past the table or without
    /// a digester.
    pub fn digest(&self, chunk_index: usize) -> Option<&BlobMetadataDigest> {
        self.digests().get(chunk_index)
    }

    /// The chunk group at `index`, `None` past the table.
    pub fn chunk_group(&self, index: usize) -> Option<BlobMetadataChunkGroup> {
        let entries = self.chunk_group_entries();
        if index + 1 >= entries.len() {
            return None;
        }
        let (start, end) = (entries[index], entries[index + 1]);
        Some(BlobMetadataChunkGroup {
            index: index as u32,
            compressed_offset: start.compressed_offset,
            compressed_size: (end.compressed_offset - start.compressed_offset) as u32,
            first_chunk: start.first_chunk,
            chunk_count: end.first_chunk - start.first_chunk,
            crc32: start.crc32,
            chunk_block_count_bits: self.header.chunk_block_count_bits,
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

    /// Number of chunk entries.
    pub fn chunk_count(&self) -> usize {
        self.header.chunk_count as usize
    }

    /// Number of digest entries.
    pub fn digest_count(&self) -> usize {
        self.header.digest_count() as usize
    }

    /// Number of redirect entries: every chunk group of a REDIRECT blob.
    pub fn redirect_count(&self) -> usize {
        self.header.redirect_count() as usize
    }

    /// log2 of the chunk's 4KiB blocks.
    pub fn chunk_block_count_bits(&self) -> u8 {
        self.header.chunk_block_count_bits
    }

    /// 4KiB blocks per chunk.
    pub fn chunk_block_count(&self) -> u32 {
        self.header.chunk_block_count()
    }

    /// Bytes per chunk: the largest chunk of a file, and every group's slot.
    pub fn chunk_size(&self) -> u32 {
        self.header.chunk_size()
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

    /// Whether the blob stores incremental upper data without an embedded
    /// bootstrap.
    pub fn is_incremental(&self) -> bool {
        self.header.is_incremental()
    }

    /// Total size of the uncompressed address space in 4KiB blocks: one
    /// slot per group.
    pub fn uncompressed_block_count(&self) -> u64 {
        (self.header.chunk_group_count as u64) << self.header.chunk_block_count_bits
    }

    /// Total size of the uncompressed address space in bytes.
    pub fn uncompressed_size(&self) -> u64 {
        self.uncompressed_block_count() * BLOCK
    }

    /// Bytes all chunk groups decode to: the chunks' bytes without padding.
    pub fn payload_total(&self) -> u64 {
        self.chunks().iter().map(|len| *len as u64).sum()
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
        self.chunks()[group.chunk_range()]
            .iter()
            .map(|len| *len as u64)
            .sum()
    }

    /// Whether group `group` is stored plain: its encoded bytes are its
    /// payload (the builder stores a payload plain when encoding would not
    /// shrink it, so equal sizes mean plain).
    pub fn is_plain(&self, group: &BlobMetadataChunkGroup) -> bool {
        self.compressor() == BlobMetadataCompressor::None
            || u64::from(group.compressed_size()) == self.payload_size(group)
    }

    /// The chunk group covering `uncompressed_offset`, `None` past the end
    /// of the blob: a shift, since every group owns one chunk-sized slot.
    pub fn chunk_group_index_of(&self, uncompressed_offset: u64) -> Option<usize> {
        let index = uncompressed_offset >> (self.header.chunk_block_count_bits as u32 + 12);
        (index < self.header.chunk_group_count as u64).then_some(index as usize)
    }

    /// The chunks of chunk group `group_index` in address order, as
    /// `(chunk_index, absolute byte offset, length)`. Empty past the table.
    pub fn chunk_group_chunks(
        &self,
        group_index: usize,
    ) -> impl Iterator<Item = (usize, u64, u32)> + '_ {
        let chunks = self.chunks();
        let group = self.chunk_group(group_index);
        let range = group.map_or(0..0, |group| group.chunk_range());
        let mut block = group.map_or(0, |group| group.uncompressed_block_offset());
        range.map(move |chunk| {
            let len = chunks[chunk];
            let offset = block * BLOCK;
            block += (len as u64).div_ceil(BLOCK);
            (chunk, offset, len)
        })
    }

    /// The group holding chunk `chunk_index` and the chunk's absolute byte
    /// offset in the uncompressed address space, `None` past the chunk
    /// table. A binary search over the group table, for the offline paths
    /// (`check`); the read path never maps chunks to groups.
    pub fn chunk_location(&self, chunk_index: usize) -> Option<(usize, u64)> {
        if chunk_index >= self.chunk_count() {
            return None;
        }
        let entries = self.chunk_group_entries();
        let group_index =
            entries.partition_point(|entry| entry.first_chunk as usize <= chunk_index) - 1;
        self.chunk_group_chunks(group_index)
            .find(|(chunk, _, _)| *chunk == chunk_index)
            .map(|(_, offset, _)| (group_index, offset))
    }

    /// The chunks of group `group_index` overlapping the byte range
    /// `[offset, end)` of the uncompressed address space, as an index range;
    /// empty when the range misses the group's chunks (the slot's unused
    /// tail) or the group.
    pub fn chunks_in_range(&self, group_index: usize, offset: u64, end: u64) -> Range<usize> {
        let mut first = None;
        let mut last = 0usize;
        for (chunk, chunk_offset, len) in self.chunk_group_chunks(group_index) {
            let chunk_end = chunk_offset + len as u64;
            if chunk_end <= offset {
                continue;
            }
            if chunk_offset >= end {
                break;
            }
            first.get_or_insert(chunk);
            last = chunk + 1;
        }
        first.map_or(0..0, |first| first..last)
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
/// header's `chunk_block_count_bits` field.
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

    fn plain_group(payload: &[u8], chunk_count: u32) -> BlobMetadataChunkGroup {
        BlobMetadataChunkGroup::new(payload.len() as u32, chunk_count, crc32c(payload), None)
            .unwrap()
    }

    fn layered(
        chunk_blocks: u32,
        groups: Vec<BlobMetadataChunkGroup>,
        chunks: Vec<u32>,
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
            chunk_blocks,
            groups,
            chunks,
            digests,
        )
    }

    /// Fixture: 16 KiB slots (four blocks), chunks 100 | 5000 | 40 | 6000 | 1
    /// bytes, so group 0 = [100, 5000] (blocks 0..3 of slot 0), group 1 =
    /// [40, 6000] (blocks 4..7 of slot 1), group 2 = [1] (block 8 of slot 2).
    fn fixture() -> (BlobMetadata, Vec<Vec<u8>>) {
        let chunks_data = vec![
            vec![0xa1; 100],
            vec![0xb2; 5000],
            vec![0xc3; 40],
            vec![0xd4; 6000],
            vec![0xe5; 1],
        ];
        let stream: Vec<u8> = chunks_data.concat();
        let groups = vec![
            plain_group(&stream[..5100], 2),
            plain_group(&stream[5100..11140], 2),
            plain_group(&stream[11140..], 1),
        ];
        let meta = layered(
            4,
            groups,
            vec![100, 5000, 40, 6000, 1],
            chunks_data
                .iter()
                .map(|chunk| BlobMetadataDigest::new(digest(chunk)))
                .collect(),
        )
        .unwrap();
        (meta, chunks_data)
    }

    #[test]
    fn round_trips_through_bytes_and_a_mapped_sidecar() {
        let (meta, chunks_data) = fixture();
        assert_eq!(meta.header().version(), 1);
        assert_eq!(meta.chunk_group_count(), 3);
        assert_eq!(meta.uncompressed_block_count(), 12);
        assert_eq!(meta.uncompressed_size(), 12 * BLOCK);
        assert_eq!(meta.payload_total(), 11141);
        assert_eq!(meta.compressed_end(), 11141);
        assert_eq!(meta.header().used_size(), 32 + 4 * 16 + 5 * 4 + 4 + 5 * 32);
        let mut raw = Vec::new();
        meta.write_to(&mut raw).unwrap();
        assert_eq!(raw.len(), 4096);
        let loaded = BlobMetadata::from_bytes(&raw, true).unwrap();
        assert_eq!(loaded.chunk_group_entries(), meta.chunk_group_entries());
        assert_eq!(loaded.chunks(), meta.chunks());
        assert_eq!(loaded.digests(), meta.digests());
        assert!(loaded.redirects().is_empty());

        let group = loaded.chunk_group(1).unwrap();
        assert_eq!(group.compressed_range(), 5100..11140);
        assert_eq!(group.chunk_range(), 2..4);
        assert_eq!(group.uncompressed_range(), 4 * BLOCK..8 * BLOCK);
        assert_eq!(loaded.payload_size(&group), 6040);
        assert!(loaded.is_plain(&group));
        assert_eq!(group.crc32(), crc32c(&chunks_data[2..4].concat()));
        assert!(group.redirect().is_none());
        assert!(loaded.chunk_group(3).is_none());
        assert_eq!(
            loaded.chunk_group_chunks(1).collect::<Vec<_>>(),
            vec![(2, 4 * BLOCK, 40), (3, 5 * BLOCK, 6000)]
        );

        let dir = tempdir().unwrap();
        let path = dir.path().join("m.blob.meta");
        meta.save(&path).unwrap();
        let mapped = BlobMetadata::from_path(&path, true).unwrap();
        assert_eq!(mapped.chunk_group_entries(), meta.chunk_group_entries());
        assert_eq!(mapped.chunks(), &[100, 5000, 40, 6000, 1]);
        assert_eq!(mapped.digests().len(), 5);
        assert_eq!(mapped.digest(3).unwrap().digest(), &digest(&chunks_data[3]));
        assert!(!mapped.is_redirect());

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
    fn offsets_map_to_groups_by_shift() {
        let (meta, _) = fixture();
        let expect = [0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2];
        for (block, group) in expect.iter().enumerate() {
            let offset = block as u64 * BLOCK;
            assert_eq!(
                meta.chunk_group_index_of(offset),
                Some(*group),
                "block {block}"
            );
            assert_eq!(meta.chunk_group_index_of(offset + BLOCK - 1), Some(*group));
        }
        assert_eq!(meta.chunk_group_index_of(12 * BLOCK), None);
        assert_eq!(meta.chunk_location(0), Some((0, 0)));
        assert_eq!(meta.chunk_location(1), Some((0, BLOCK)));
        assert_eq!(meta.chunk_location(3), Some((1, 5 * BLOCK)));
        assert_eq!(meta.chunk_location(4), Some((2, 8 * BLOCK)));
        assert_eq!(meta.chunk_location(5), None);
        assert_eq!(meta.chunks_in_range(0, 0, 10), 0..1);
        assert_eq!(meta.chunks_in_range(0, 50, BLOCK + 1), 0..2);
        assert_eq!(meta.chunks_in_range(1, 5 * BLOCK, 5 * BLOCK + 1), 3..4);
        // The unused tail of slot 2 holds no chunk.
        assert_eq!(meta.chunks_in_range(2, 9 * BLOCK, 12 * BLOCK), 0..0);
        assert_eq!(meta.chunks_in_range(7, 0, 1), 0..0);
    }

    #[test]
    fn scatter_puts_every_chunk_on_its_block() {
        let (meta, chunks) = fixture();
        let stream: Vec<u8> = chunks.concat();
        let mut padded = vec![0u8; 12 * BLOCK as usize];
        let ranges = [(0usize, 5100usize), (5100, 11140), (11140, 11141)];
        for (index, (start, end)) in ranges.iter().enumerate() {
            meta.for_each_decoded_chunk(index, &stream[*start..*end], &mut |offset, bytes| {
                padded[offset as usize..offset as usize + bytes.len()].copy_from_slice(bytes);
                Ok(())
            })
            .unwrap();
        }
        for group in 0..3 {
            for (chunk, offset, len) in meta.chunk_group_chunks(group) {
                let offset = offset as usize;
                assert_eq!(&padded[offset..offset + len as usize], &chunks[chunk]);
            }
        }
        // Slot tails stay zero.
        assert!(padded[3 * BLOCK as usize..4 * BLOCK as usize]
            .iter()
            .all(|b| *b == 0));
        assert!(meta
            .for_each_decoded_chunk(0, &stream[..10], &mut |_, _| Ok(()))
            .is_err());
        assert!(meta
            .for_each_decoded_chunk(3, &stream[..1], &mut |_, _| Ok(()))
            .is_err());
    }

    #[test]
    fn empty_metadata_is_one_block() {
        let meta = layered(1, Vec::new(), Vec::new(), Vec::new()).unwrap();
        let mut raw = Vec::new();
        meta.write_to(&mut raw).unwrap();
        assert_eq!(raw.len(), 4096);
        let loaded = BlobMetadata::from_bytes(&raw, true).unwrap();
        assert_eq!(loaded.uncompressed_size(), 0);
        assert_eq!(loaded.compressed_end(), 0);
        assert_eq!(loaded.chunk_group_index_of(0), None);
        assert_eq!(loaded.chunk_group_entries().len(), 1);
    }

    #[test]
    fn incremental_metadata_round_trips_and_is_not_redirect() {
        let (source, _) = fixture();
        let meta = BlobMetadata::new_incremental(
            source.compressor(),
            source.digester(),
            source.chunk_block_count(),
            source.chunk_groups().collect(),
            source.chunks().to_vec(),
            source.digests().to_vec(),
        )
        .unwrap();
        assert!(meta.is_incremental());
        assert!(!meta.is_redirect());

        let mut raw = Vec::new();
        meta.write_to(&mut raw).unwrap();
        let loaded = BlobMetadata::from_bytes(&raw, true).unwrap();
        assert!(loaded.is_incremental());
        assert!(!loaded.is_redirect());
        assert_eq!(loaded.chunk_group_entries(), source.chunk_group_entries());
        assert_eq!(loaded.chunks(), source.chunks());
        assert_eq!(loaded.digests(), source.digests());
    }

    #[test]
    fn redirect_blobs_carry_a_source_per_group() {
        let (source, chunks) = fixture();
        let stream: Vec<u8> = chunks.concat();
        // Copy the source's groups 2 and 0, in that order, as blob 3's.
        let copied = [2usize, 0];
        let mut groups = Vec::new();
        let mut lens = Vec::new();
        let mut digests = Vec::new();
        for &index in &copied {
            let group = source.chunk_group(index).unwrap();
            groups.push(
                BlobMetadataChunkGroup::new(
                    group.compressed_size(),
                    group.chunk_count(),
                    group.crc32(),
                    Some(BlobMetadataRedirect::new(3, index as u32).unwrap()),
                )
                .unwrap(),
            );
            lens.extend_from_slice(&source.chunks()[group.chunk_range()]);
            digests.extend_from_slice(&source.digests()[group.chunk_range()]);
        }
        let meta = BlobMetadata::new(
            BlobMetadataCompressor::None,
            BlobMetadataDigester::Blake3,
            4,
            groups,
            lens,
            digests,
        )
        .unwrap();
        assert!(meta.is_redirect());
        assert_eq!(meta.redirect_count(), 2);
        assert_eq!(meta.chunks(), &[1, 100, 5000]);
        assert_eq!(
            meta.header().used_size(),
            32 + 3 * 16 + 3 * 4 + 4 + 3 * 32 + 2 * 8
        );

        let mut raw = Vec::new();
        meta.write_to(&mut raw).unwrap();
        let loaded = BlobMetadata::from_bytes(&raw, true).unwrap();
        assert!(loaded.is_redirect());
        let first = loaded.chunk_group(0).unwrap();
        let redirect = first.redirect().unwrap();
        assert_eq!(redirect.source_blob_index(), 3);
        assert_eq!(redirect.source_chunk_group_index(), 2);
        assert_eq!(first.compressed_range(), 0..1);
        assert_eq!(first.crc32(), crc32c(&stream[11140..]));
        assert_eq!(
            loaded
                .chunk_group(1)
                .unwrap()
                .redirect()
                .unwrap()
                .source_chunk_group_index(),
            0
        );
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
        write_u16_at(&mut zeroed, meta.header().redirects_offset() as usize, 0);
        assert!(BlobMetadata::from_bytes(&zeroed, false).is_err());

        // Groups must all redirect or none.
        let mixed = vec![
            plain_group(&stream[..5100], 2),
            BlobMetadataChunkGroup::new(
                6040,
                2,
                crc32c(&stream[5100..11140]),
                Some(BlobMetadataRedirect::new(1, 1).unwrap()),
            )
            .unwrap(),
        ];
        assert!(layered(4, mixed, vec![100, 5000, 40, 6000], vec![])
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
            vec![BlobMetadataChunkGroup::new(10, 1, crc32c(&payload), None).unwrap()],
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
    fn inconsistent_tables_reject() {
        let (meta, chunks) = fixture();
        let stream: Vec<u8> = chunks.concat();
        let ok_chunks = meta.chunks().to_vec();
        let build = |groups: Vec<BlobMetadataChunkGroup>, chunks: Vec<u32>| {
            layered(4, groups, chunks, vec![])
                .expect_err("expected rejection")
                .to_string()
        };
        let groups = || {
            vec![
                plain_group(&stream[..5100], 2),
                plain_group(&stream[5100..11140], 2),
                plain_group(&stream[11140..], 1),
            ]
        };

        // Chunks left over after the last group, or a group past the chunks.
        assert!(build(groups(), vec![100, 5000, 40, 6000, 1, 5]).contains("terminator"));
        let mut greedy = groups();
        greedy[2].chunk_count = 2;
        assert!(build(greedy, ok_chunks.clone()).contains("terminator"));

        // A zero-length chunk, or one over the chunk size.
        let mut zero = groups();
        zero[2].chunk_count = 2;
        assert!(build(zero, vec![100, 5000, 40, 6000, 1, 0]).contains("non-zero"));
        assert!(build(vec![plain_group(&[0; 16385], 1)], vec![16385]).contains("chunk size"));

        // A group whose chunks overflow its slot (four blocks).
        let overflow = vec![plain_group(&stream[..11141], 5)];
        assert!(build(overflow, ok_chunks.clone()).contains("slot"));

        // An empty group or an encoded payload larger than the payload.
        let mut empty = groups();
        empty[0].chunk_count = 0;
        empty[1].chunk_count = 4;
        assert!(build(empty, ok_chunks.clone()).contains("empty"));
        let mut grown = groups();
        grown[0].compressed_size = 5101;
        assert!(build(grown, ok_chunks.clone()).contains("exceeds"));

        // A plain blob must store payloads whole.
        let mut short = groups();
        short[0].compressed_size = 5099;
        assert!(build(short, ok_chunks.clone()).contains("full payload"));

        // A digest table that does not cover every chunk.
        assert!(layered(
            4,
            groups(),
            ok_chunks,
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
    }
}

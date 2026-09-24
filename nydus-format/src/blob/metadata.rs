use crate::blob::algorithm::{BlobMetadataCompressor, BlobMetadataDigester};
use crate::blob::flag::FeatureFlags;
use crate::erofs::EROFS_BLOCK_SIZE;
use crate::error::{Context, Error, Result};
use crate::utils::align_up_u64;
use crate::utils::le::{
    read_bytes_at, read_u16_at, read_u32_at, read_u64_at, read_u8_at, write_u16_at, write_u32_at,
};
use crc32c::{crc32c, crc32c_append};
use memmap2::{Mmap, MmapOptions};
use std::fmt;
use std::fs::File;
use std::io::Write;
use std::ops::Range;
use std::path::Path;

/// The `type` field of a table header: which table follows. Not an enum:
/// a reader keeps and skips tables of types it does not know, so any value
/// round-trips; the known ones are the constants below.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlobMetadataTableType(u16);

impl BlobMetadataTableType {
    /// ChunkGroupTable, entries [`BlobMetadataChunkGroup`].
    pub const CHUNK_GROUP: Self = Self(1);

    /// ChunkLengthTable, entries [`BlobMetadataChunkLength`].
    pub const CHUNK_LENGTH: Self = Self(2);

    /// ChunkGroupIndexTable, entries [`BlobMetadataChunkGroupIndex`].
    pub const CHUNK_GROUP_INDEX: Self = Self(3);

    /// ChunkGroupDigestTable, entries [`BlobMetadataChunkGroupDigest`].
    pub const CHUNK_GROUP_DIGEST: Self = Self(4);

    /// ChunkGroupRedirectTable, entries [`BlobMetadataChunkGroupRedirect`].
    pub const CHUNK_GROUP_REDIRECT: Self = Self(5);

    /// The raw on-disk value.
    pub fn get(self) -> u16 {
        self.0
    }

    /// Whether this reader parses tables of this type; the others are kept
    /// verbatim and skipped.
    fn is_supported(self) -> bool {
        (Self::CHUNK_GROUP.0..=Self::CHUNK_GROUP_REDIRECT.0).contains(&self.0)
    }
}

impl fmt::Display for BlobMetadataTableType {
    /// The table's name, or the raw value in hex for a type this reader
    /// does not know.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::CHUNK_GROUP => f.write_str("ChunkGroupTable"),
            Self::CHUNK_LENGTH => f.write_str("ChunkLengthTable"),
            Self::CHUNK_GROUP_INDEX => f.write_str("ChunkGroupIndexTable"),
            Self::CHUNK_GROUP_DIGEST => f.write_str("ChunkGroupDigestTable"),
            Self::CHUNK_GROUP_REDIRECT => f.write_str("ChunkGroupRedirectTable"),
            Self(other) => write!(f, "{other:#x}"),
        }
    }
}

/// One table of the blob meta, at the next 8-byte boundary behind the
/// previous one. Every table starts with the same 16-byte header. A table
/// type may define an optional header extension behind it, so `header_size`
/// is 16 without one and more with one; the entries start at `header_size`:
///
/// ```text
/// ┌──────────────┬─────────────────────────────┬─────────┬─────────┬─────┬─────────┐
/// │ header, 16 B │ header extension (optional) │ entry 0 │ entry 1 │ ... │ entry n │
/// └──────────────┴─────────────────────────────┴─────────┴─────────┴─────┴─────────┘
/// 0              16                            header_size         + entry_size each
///
/// offset  size  field
///      0     2  type                    see BlobMetadataTableType; 0x8000
///                                       and above are private
///      2     2  header_size             at least 16, a multiple of 8
///      4     2  feature_compat          unknown bits are ignored
///      6     2  feature_incompat        unknown bits reject the file; a
///                                       table of unknown type is skipped
///                                       when zero, rejected otherwise
///      8     4  entry_size              bytes per entry
///     12     4  entry_count
///
/// table                    header extension
/// ChunkGroupTable          ChunkGroupTableHeaderExtension, 8 B
/// ChunkLengthTable         none
/// ChunkGroupIndexTable     ChunkGroupIndexTableHeaderExtension, 8 B
/// ChunkGroupDigestTable    ChunkGroupDigestTableHeaderExtension, 8 B
/// ChunkGroupRedirectTable  none
/// ```
///
/// A newer writer appends extension or entry fields and declares the larger
/// `header_size` or `entry_size`; an older reader reads through the declared
/// sizes and never sees them (qcow2 header extensions, ext4 `i_extra_isize`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlobMetadataTable {
    table_type: BlobMetadataTableType,
    feature_compat: u16,
    feature_incompat: u16,
    offset: usize,
    header_size: usize,
    entry_size: usize,
    entry_count: usize,
}

impl BlobMetadataTable {
    /// On-disk size of the header every table starts with, and the whole
    /// `header_size` of a table type without a header extension.
    pub const HEADER_SIZE: usize = 16;

    /// Every incompat bit this reader understands for a known table, none
    /// so far. A table setting a bit outside this mask was written by a
    /// newer nydus and is rejected by [`Self::validate_layout`].
    const INCOMPAT_SUPPORTED: u16 = 0;

    /// Parse the table header at `offset`, checking that the table fits in
    /// `bytes`.
    fn from_bytes(bytes: &[u8], offset: usize) -> Result<Self> {
        if offset + Self::HEADER_SIZE > bytes.len() {
            return Err(Error::InvalidImage(format!(
                "blob meta table header at {offset:#x} is truncated"
            )));
        }
        let table = Self {
            table_type: BlobMetadataTableType(read_u16_at(bytes, offset)),
            header_size: read_u16_at(bytes, offset + 2) as usize,
            feature_compat: read_u16_at(bytes, offset + 4),
            feature_incompat: read_u16_at(bytes, offset + 6),
            entry_size: read_u32_at(bytes, offset + 8) as usize,
            entry_count: read_u32_at(bytes, offset + 12) as usize,
            offset,
        };
        let kind = table.table_type;
        if table.header_size < Self::HEADER_SIZE || table.header_size % 8 != 0 {
            return Err(Error::InvalidImage(format!(
                "blob meta table {kind} header size {} is not a multiple of 8 of at least {}",
                table.header_size,
                Self::HEADER_SIZE
            )));
        }
        // Both factors come from u32 fields, so the product fits in a u64.
        let size = table.header_size as u64 + table.entry_size as u64 * table.entry_count as u64;
        if offset as u64 + size > bytes.len() as u64 {
            return Err(Error::InvalidImage(format!(
                "blob meta table {kind} extends past the {}-byte file",
                bytes.len()
            )));
        }
        Ok(table)
    }

    /// The table type.
    pub fn table_type(&self) -> BlobMetadataTableType {
        self.table_type
    }

    /// Compatible feature bits of the table, exactly as stored.
    pub fn feature_compat(&self) -> u16 {
        self.feature_compat
    }

    /// Incompatible feature bits of the table, exactly as stored.
    pub fn feature_incompat(&self) -> u16 {
        self.feature_incompat
    }

    /// Byte range of the whole table, its header included.
    pub fn range(&self) -> Range<usize> {
        self.offset..self.offset + self.header_size + self.entry_size * self.entry_count
    }

    /// Byte offset of the first entry.
    fn entries_offset(&self) -> usize {
        self.offset + self.header_size
    }

    /// Byte offset of entry `index`; the caller keeps it below the count.
    fn entry_offset(&self, index: usize) -> usize {
        self.entries_offset() + index * self.entry_size
    }

    /// Validate a known table against the layout this reader knows: its
    /// declared header and entry sizes must cover it (a newer writer may
    /// append fields, which are then skipped), and its incompat bits must
    /// be supported.
    fn validate_layout(&self, header_size: usize, entry_size: usize) -> Result<()> {
        if self.header_size < header_size {
            return Err(Error::InvalidImage(format!(
                "blob meta {} header size {} is below {header_size}",
                self.table_type, self.header_size
            )));
        }

        if self.entry_size < entry_size {
            return Err(Error::InvalidImage(format!(
                "blob meta {} entry size {} is below {entry_size}",
                self.table_type, self.entry_size
            )));
        }

        let unknown = self.feature_incompat & !Self::INCOMPAT_SUPPORTED;
        if unknown != 0 {
            return Err(Error::Unsupported(format!(
                "unsupported blob meta {} incompat flags {unknown:#x} (image is newer than this reader)",
                self.table_type
            )));
        }

        Ok(())
    }

    /// Encode one table: the header, its optional `extension` bytes (empty
    /// for a table type without one), then `entry_count` entries of
    /// `entry_size` bytes.
    fn encode(
        table_type: BlobMetadataTableType,
        extension: &[u8],
        entry_size: usize,
        entry_count: usize,
        write_entries: impl FnOnce(&mut Vec<u8>),
    ) -> Result<Vec<u8>> {
        let count = u32::try_from(entry_count)
            .map_err(|_| Error::Overflow("blob meta table entry count exceeds u32".to_string()))?;
        let header_size = Self::HEADER_SIZE + extension.len();
        debug_assert_eq!(header_size % 8, 0);
        let mut table = vec![0u8; Self::HEADER_SIZE];
        write_u16_at(&mut table, 0, table_type.0);
        write_u16_at(&mut table, 2, header_size as u16);
        write_u32_at(&mut table, 8, entry_size as u32);
        write_u32_at(&mut table, 12, count);
        table.extend_from_slice(extension);
        write_entries(&mut table);
        debug_assert_eq!(table.len(), header_size + entry_size * entry_count);
        Ok(table)
    }
}

/// The ChunkGroupTable header extension.
///
/// ```text
/// offset  size  field
///     16     1  max_group_span_bits     log2 of the most blocks a group
///                                       spans, at most 19
///     17     1  compressor              0 none, 1 zstd, 2 lz4
///     18     6  reserved                writers zero it, readers ignore it
/// ```
#[derive(Clone, Copy, Debug)]
struct ChunkGroupTableHeaderExtension {
    max_group_span_bits: u8,
    compressor: u8,
    reserved: [u8; 6],
}

impl ChunkGroupTableHeaderExtension {
    /// On-disk size, behind the header.
    const SIZE: usize = 8;

    fn read(bytes: &[u8], table: &BlobMetadataTable) -> Self {
        Self {
            max_group_span_bits: read_u8_at(bytes, table.offset + 16),
            compressor: read_u8_at(bytes, table.offset + 17),
            reserved: read_bytes_at(bytes, table.offset + 18),
        }
    }

    fn to_bytes(self) -> [u8; Self::SIZE] {
        let mut header = [0u8; Self::SIZE];
        header[0] = self.max_group_span_bits;
        header[1] = self.compressor;
        header[2..8].copy_from_slice(&self.reserved);
        header
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
///
/// On disk ChunkGroupTable holds `chunk_group_count + 1` rows of
/// [`Self::SIZE`] bytes: row `i` names where group `i` starts in the data
/// region, the address space and ChunkLengthTable, and row `i + 1` where it
/// ends, so the last row is a terminator holding the data region's size,
/// the address space's block count and the chunk count.
///
/// ```text
/// offset  size  field
///      0     8  compressed_offset          bytes into the data region where
///                                          the group's encoded payload starts
///      8     4  uncompressed_block_offset  first 4KiB block of the group in
///                                          the address space
///     12     4  first_chunk_index          index of the group's first entry
///                                          in ChunkLengthTable
///     16     4  payload_size               bytes the group decodes to (zero
///                                          in the terminator)
///     20     4  payload_crc32              CRC32C of the decoded payload
///                                          (zero in the terminator)
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlobMetadataChunkGroup {
    index: u32,
    compressed_offset: u64,
    compressed_size: u32,
    uncompressed_block_offset: u32,
    blocks: u32,
    first_chunk_index: u32,
    chunk_count: u32,
    payload_size: u32,
    payload_crc32: u32,
    redirect: Option<BlobMetadataChunkGroupRedirect>,
}

impl BlobMetadataChunkGroup {
    /// On-disk size of one row.
    pub const SIZE: usize = 24;

    /// Describes a group for a writer: `compressed_size` bytes of encoded
    /// payload decoding to `payload_size` bytes whose crc32c is `payload_crc32`,
    /// holding `chunk_count` nonempty chunks, including a single chunk.
    /// Every length is listed in ChunkLengthTable. `redirect` names the source
    /// when the blob is an optimize output.
    /// Index, offsets and blocks are assigned by [`BlobMetadata::new`].
    pub fn new(
        compressed_size: u32,
        payload_size: u32,
        chunk_count: u32,
        payload_crc32: u32,
        redirect: Option<BlobMetadataChunkGroupRedirect>,
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
            uncompressed_block_offset: 0,
            blocks: 0,
            first_chunk_index: 0,
            chunk_count,
            payload_size,
            payload_crc32,
            redirect,
        })
    }

    /// One row as stored: the start of a group, the derived fields left
    /// zero for [`BlobMetadata::chunk_group`] to fill from the next row.
    fn row(
        compressed_offset: u64,
        uncompressed_block_offset: u32,
        first_chunk_index: u32,
        payload_size: u32,
        payload_crc32: u32,
    ) -> Self {
        Self {
            index: 0,
            compressed_offset,
            compressed_size: 0,
            uncompressed_block_offset,
            blocks: 0,
            first_chunk_index,
            chunk_count: 0,
            payload_size,
            payload_crc32,
            redirect: None,
        }
    }

    fn read(bytes: &[u8], at: usize) -> Self {
        Self::row(
            read_u64_at(bytes, at),
            read_u32_at(bytes, at + 8),
            read_u32_at(bytes, at + 12),
            read_u32_at(bytes, at + 16),
            read_u32_at(bytes, at + 20),
        )
    }

    fn write(self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.compressed_offset.to_le_bytes());
        out.extend_from_slice(&self.uncompressed_block_offset.to_le_bytes());
        out.extend_from_slice(&self.first_chunk_index.to_le_bytes());
        out.extend_from_slice(&self.payload_size.to_le_bytes());
        out.extend_from_slice(&self.payload_crc32.to_le_bytes());
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

    /// The group's first entry in ChunkLengthTable, including single-chunk groups.
    pub fn first_chunk_index(&self) -> u32 {
        self.first_chunk_index
    }

    /// The group's ChunkLengthTable indexes.
    pub fn chunk_range(&self) -> Range<usize> {
        self.first_chunk_index as usize..(self.first_chunk_index + self.chunk_count) as usize
    }

    /// crc32c of the decoded payload, checked after decode.
    pub fn payload_crc32(&self) -> u32 {
        self.payload_crc32
    }

    /// The source this group copies, in a redirect blob.
    pub fn redirect(&self) -> Option<BlobMetadataChunkGroupRedirect> {
        self.redirect
    }

    /// First 4KiB block of the group in the uncompressed address space.
    pub fn uncompressed_block_offset(&self) -> u64 {
        self.uncompressed_block_offset as u64
    }

    /// 4KiB blocks the group spans: its chunks, each block aligned.
    pub fn uncompressed_block_count(&self) -> u32 {
        self.blocks
    }

    /// Start of the group in bytes.
    pub fn uncompressed_offset(&self) -> u64 {
        self.uncompressed_block_offset() * EROFS_BLOCK_SIZE as u64
    }

    /// Length of the group in bytes.
    pub fn uncompressed_size(&self) -> u64 {
        self.uncompressed_block_count() as u64 * EROFS_BLOCK_SIZE as u64
    }

    /// Byte range of the group in the uncompressed address space.
    pub fn uncompressed_range(&self) -> Range<u64> {
        self.uncompressed_offset()..self.uncompressed_offset() + self.uncompressed_size()
    }
}

/// One ChunkLengthTable entry: the byte length of one chunk, never zero.
/// Every chunk of the blob has one, lone chunks included, in group order.
///
/// ```text
/// offset  size  field
///      0     4  length                     bytes of the chunk
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlobMetadataChunkLength(u32);

impl BlobMetadataChunkLength {
    /// On-disk size of one entry.
    pub const SIZE: usize = 4;

    fn read(bytes: &[u8], at: usize) -> Self {
        Self(read_u32_at(bytes, at))
    }

    fn write(self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.0.to_le_bytes());
    }

    /// The chunk's length in bytes.
    pub fn get(self) -> u32 {
        self.0
    }
}

/// The ChunkGroupIndexTable header extension.
///
/// ```text
/// offset  size  field
///     16     1  index_span_bits         log2 of the blocks one entry
///                                       covers, at most max_group_span_bits
///     17     7  reserved                writers zero it, readers ignore it
/// ```
#[derive(Clone, Copy, Debug)]
struct ChunkGroupIndexTableHeaderExtension {
    index_span_bits: u8,
    reserved: [u8; 7],
}

impl ChunkGroupIndexTableHeaderExtension {
    /// On-disk size, behind the header.
    const SIZE: usize = 8;

    fn read(bytes: &[u8], table: &BlobMetadataTable) -> Self {
        Self {
            index_span_bits: read_u8_at(bytes, table.offset + 16),
            reserved: read_bytes_at(bytes, table.offset + 17),
        }
    }

    fn to_bytes(self) -> [u8; Self::SIZE] {
        let mut header = [0u8; Self::SIZE];
        header[0] = self.index_span_bits;
        header[1..8].copy_from_slice(&self.reserved);
        header
    }
}

/// One ChunkGroupIndexTable entry: the chunk group covering the first
/// block of one index span. The table has one entry per index span of the
/// address space; see [`BlobMetadata::chunk_group_index_of`] for the
/// lookup it serves.
///
/// ```text
/// offset  size  field
///      0     4  chunk_group_index          index into ChunkGroupTable
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlobMetadataChunkGroupIndex(u32);

impl BlobMetadataChunkGroupIndex {
    /// On-disk size of one entry.
    pub const SIZE: usize = 4;

    fn read(bytes: &[u8], at: usize) -> Self {
        Self(read_u32_at(bytes, at))
    }

    fn write(self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.0.to_le_bytes());
    }

    /// The chunk group's index in ChunkGroupTable.
    pub fn get(self) -> u32 {
        self.0
    }
}

/// The ChunkGroupDigestTable header extension.
///
/// ```text
/// offset  size  field
///     16     1  algorithm               1 BLAKE3; an unknown value leaves
///                                       the blob undigested for this reader
///     17     7  reserved                writers zero it, readers ignore it
/// ```
#[derive(Clone, Copy, Debug)]
struct ChunkGroupDigestTableHeaderExtension {
    algorithm: u8,
    reserved: [u8; 7],
}

impl ChunkGroupDigestTableHeaderExtension {
    /// On-disk size, behind the header.
    const SIZE: usize = 8;

    fn read(bytes: &[u8], table: &BlobMetadataTable) -> Self {
        Self {
            algorithm: read_u8_at(bytes, table.offset + 16),
            reserved: read_bytes_at(bytes, table.offset + 17),
        }
    }

    fn to_bytes(self) -> [u8; Self::SIZE] {
        let mut header = [0u8; Self::SIZE];
        header[0] = self.algorithm;
        header[1..8].copy_from_slice(&self.reserved);
        header
    }
}

/// One ChunkGroupDigestTable entry: the content digest of the chunk group
/// at the same index in ChunkGroupTable (see [`Self::of_group`]).
///
/// ```text
/// offset  size  field
///      0    32  digest                     algorithm per the table header
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlobMetadataChunkGroupDigest {
    digest: [u8; 32],
}

impl BlobMetadataChunkGroupDigest {
    /// On-disk size of one entry.
    pub const SIZE: usize = 32;

    /// Context separating multi-chunk group digests from plain content digests.
    const GROUP_CONTEXT: &str = "nydus blob meta chunk group digest v1";

    /// Creates an entry for the chunk group at the same index in the group
    /// table.
    pub fn new(digest: [u8; 32]) -> Self {
        Self { digest }
    }

    fn read(bytes: &[u8], at: usize) -> Self {
        Self {
            digest: read_bytes_at(bytes, at),
        }
    }

    fn write(self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.digest);
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
                let mut hasher = blake3::Hasher::new_derive_key(Self::GROUP_CONTEXT);
                for digest in many {
                    hasher.update(digest);
                }
                Some(Self::new(*hasher.finalize().as_bytes()))
            }
        }
    }

    /// The digest, algorithm per the ChunkGroupDigestTable header.
    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
}

/// One ChunkGroupRedirectTable entry: the chunk group of another blob of
/// the image that the chunk group at the same index copies. Present only
/// in a redirect blob (an `optimize` output), one entry per chunk group.
///
/// ```text
/// offset  size  field
///      0     2  source_blob_index         nonzero source device index
///      2     2  reserved                  writers zero it, readers ignore it
///      4     4  source_chunk_group_index  the copied group within it
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlobMetadataChunkGroupRedirect {
    source_blob_index: u16,
    reserved: [u8; 2],
    source_chunk_group_index: u32,
}

impl BlobMetadataChunkGroupRedirect {
    /// On-disk size of one entry.
    pub const SIZE: usize = 8;

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
            reserved: [0; 2],
            source_chunk_group_index,
        })
    }

    fn read(bytes: &[u8], at: usize) -> Self {
        Self {
            source_blob_index: read_u16_at(bytes, at),
            reserved: read_bytes_at(bytes, at + 2),
            source_chunk_group_index: read_u32_at(bytes, at + 4),
        }
    }

    fn write(self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.source_blob_index.to_le_bytes());
        out.extend_from_slice(&self.reserved);
        out.extend_from_slice(&self.source_chunk_group_index.to_le_bytes());
    }

    /// Validate the intrinsic field invariants.
    fn validate_fields(&self) -> Result<()> {
        if self.source_blob_index == 0 {
            return Err(Error::InvalidImage(
                "blob meta redirect entry must name a non-zero source device".to_string(),
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

/// The serialized metadata a [`BlobMetadata`] reads its tables from: owned
/// bytes on the write side and for in-memory parses, a shared file mapping
/// read in place on the read side.
#[derive(Debug)]
enum BlobMetadataBytes {
    Owned(Vec<u8>),
    Mapped(Mmap),
}

impl AsRef<[u8]> for BlobMetadataBytes {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Owned(bytes) => bytes,
            Self::Mapped(mmap) => mmap,
        }
    }
}

/// A nydus blob's metadata: how the blob's uncompressed address space maps
/// onto its encoded payload, sealed with a crc32c in the header. Serialized
/// it is the `.blob.meta` sidecar file, and verbatim the blob meta region
/// of a full blob (see [`super::footer::BlobFooter`]).
///
/// The header, [`Self::HEADER_SIZE`] bytes (integers little-endian):
///
/// ```text
/// offset  size  field
///      0     8  magic                   b"NDBLMETA"
///      8     4  feature_compat          unknown bits are ignored
///     12     4  feature_incompat        unknown bits reject the file
///     16     4  crc32                   crc32c of the whole serialized
///                                       metadata with this field zero
///     20     2  table_count             tables following this header
///     22     2  reserved                writers zero it, readers ignore it
/// ```
///
/// The file, every table at the next 8-byte boundary, zero padded to a
/// 4 KiB multiple:
///
/// ```text
/// ┌────────┬─────────────────┬──────────────────┬──────────────────────┬───────────────────────┬─────────────────────────┬─────┐
/// │ header │ ChunkGroupTable │ ChunkLengthTable │ ChunkGroupIndexTable │ ChunkGroupDigestTable │ ChunkGroupRedirectTable │ pad │
/// └────────┴─────────────────┴──────────────────┴──────────────────────┴───────────────────────┴─────────────────────────┴─────┘
/// 0        24                                                           optional                redirect blobs only
///
/// table                    type  header extension                        entries
/// ChunkGroupTable             1  ChunkGroupTableHeaderExtension          (groups + 1) * 24 B, the last
///                                                                        one a terminator
/// ChunkLengthTable            2  none                                    chunks * 4 B
/// ChunkGroupIndexTable        3  ChunkGroupIndexTableHeaderExtension     ceil(blocks / index span
///                                                                        blocks) * 4 B
/// ChunkGroupDigestTable       4  ChunkGroupDigestTableHeaderExtension    groups * 32 B
/// ChunkGroupRedirectTable     5  none                                    groups * 8 B
/// ```
///
/// The table headers are the compatibility contract: a reader skips a table
/// of unknown type unless it has incompat bits, reads known tables through
/// their declared header and entry sizes so fields a newer writer appends
/// are ignored, rejects unknown incompat bits of the file or of a known
/// table, and keeps the bytes verbatim so [`Self::write_to`] preserves what
/// it does not know.
///
/// The groups tile the address space back to back, each chunk on its own
/// block (see [`BlobMetadataChunkGroup`]). ChunkGroupIndexTable names the group
/// covering each index span's first block, the coarse cousin of EROFS's `z_erofs_lcluster_index`: an
/// address resolves with one table read and at most one forward correction; every non-final group spans
/// at least a index span. A redirect blob (an `optimize` output) copies chunk
/// groups of other blobs of the image byte for byte and names their
/// sources in ChunkGroupRedirectTable.
#[derive(Debug)]
pub struct BlobMetadata {
    bytes: BlobMetadataBytes,
    feature_compat: u32,
    feature_incompat: u32,
    crc32: u32,
    table_count: u16,
    _reserved: [u8; 2],
    tables: Vec<BlobMetadataTable>,
    groups: BlobMetadataTable,
    chunks: BlobMetadataTable,
    indexes: BlobMetadataTable,
    digests: Option<BlobMetadataTable>,
    redirects: Option<BlobMetadataTable>,
    compressor: BlobMetadataCompressor,
    unsupported_digest_algorithm: Option<u8>,
    max_group_span_blocks: u32,
    index_span_blocks: u32,
    chunk_group_count: u32,
    chunk_count: u32,
    total_blocks: u32,
}

impl BlobMetadata {
    /// On-disk magic: 8 raw ASCII bytes ("NDBLMETA" = Nydus BLob META), written
    /// as-is so a hexdump of the file starts with the readable string. Same
    /// frozen `magic + feature_compat + feature_incompat + crc32` prefix as the
    /// blob footer (`NDFOOTER`), see [`crate::blob::flag`].
    pub const MAGIC: [u8; 8] = *b"NDBLMETA";

    /// The header's fixed on-disk size; the first table follows it.
    pub const HEADER_SIZE: usize = 24;

    /// Byte range of the crc32 field within the header.
    const CRC32_FIELD: Range<usize> = 16..20;

    /// Every incompat bit this reader understands, none so far. A file
    /// setting a bit outside this mask was written by a newer nydus and is
    /// rejected by [`FeatureFlags::validate_incompat`].
    const INCOMPAT_SUPPORTED: u32 = 0;

    /// Default file chunk size: the largest chunk a file is cut into, 2 MiB.
    /// The builder controls chunk group sizes separately, so changing the file
    /// chunk size does not change the default chunk group minimum size.
    pub const DEFAULT_CHUNK_SIZE: u32 = 2 * 1024 * 1024;

    /// File-name suffix of a blob meta sidecar file (`<blob>.blob.meta`).
    pub const SUFFIX: &str = ".blob.meta";

    /// Largest group span in blocks: 2 GiB keeps byte sizes within a `u32`.
    const MAX_GROUP_SPAN_BLOCKS: u32 = 1 << 19;

    /// Creates validated metadata. `group_span` bounds the group span in
    /// bytes and `index_span` is the index span in bytes, both powers
    /// of two of at least one block, the index span at most the group span. Every
    /// non-final group must span at least a index span. Payloads and padded
    /// spans tile their spaces from zero. `chunk_lengths` lists every chunk,
    /// including lone ones, in group order. `digests` is one entry per group
    /// with BLAKE3, else empty. Redirect sources must be present for all
    /// groups or none. Returns an error for invalid geometry, inconsistent
    /// tables or overflow.
    pub fn new(
        compressor: BlobMetadataCompressor,
        digester: BlobMetadataDigester,
        group_span: u32,
        index_span: u32,
        chunk_groups: Vec<BlobMetadataChunkGroup>,
        chunk_lengths: Vec<u32>,
        digests: Vec<BlobMetadataChunkGroupDigest>,
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
        if !group_span.is_power_of_two() || group_span < EROFS_BLOCK_SIZE {
            return Err(Error::InvalidParameter(format!(
                "blob meta group span {group_span} must be a power of two of at least one block"
            )));
        }
        if !index_span.is_power_of_two() || index_span < EROFS_BLOCK_SIZE {
            return Err(Error::InvalidParameter(format!(
                "blob meta index span {index_span} must be a power of two of at least one block"
            )));
        }
        let max_group_span_blocks = group_span / EROFS_BLOCK_SIZE;
        let index_span_blocks = index_span / EROFS_BLOCK_SIZE;

        // Lay the groups out back to back in the data region, the address
        // space and ChunkLengthTable, and end with the terminator.
        let mut entries = Vec::with_capacity(chunk_groups.len() + 1);
        let mut redirects = Vec::with_capacity(redirected);
        let mut compressed_offset = 0u64;
        let mut uncompressed_block_offset = 0u64;
        let mut first_chunk_index = 0u32;
        for (index, group) in chunk_groups.iter().enumerate() {
            let end_member = first_chunk_index
                .checked_add(group.chunk_count)
                .ok_or_else(|| Error::Overflow("blob meta chunk count overflow".to_string()))?;
            let blocks: u64 = {
                let run = chunk_lengths
                    .get(first_chunk_index as usize..end_member as usize)
                    .ok_or_else(|| {
                        Error::InvalidParameter(format!(
                            "blob meta chunk group {index} names chunks past ChunkLengthTable"
                        ))
                    })?;
                let payload: u64 = run.iter().map(|len| *len as u64).sum();
                if payload != group.payload_size as u64 {
                    return Err(Error::InvalidParameter(format!(
                        "blob meta chunk group {index} chunk_lengths add up to {payload} bytes, not its {}-byte payload",
                        group.payload_size
                    )));
                }
                run.iter()
                    .map(|len| (*len as u64).div_ceil(EROFS_BLOCK_SIZE as u64))
                    .sum()
            };
            entries.push(BlobMetadataChunkGroup::row(
                compressed_offset,
                u32::try_from(uncompressed_block_offset).map_err(|_| {
                    Error::Overflow(format!(
                        "blob meta chunk group {index} starts past the 32-bit block space"
                    ))
                })?,
                first_chunk_index,
                group.payload_size,
                group.payload_crc32,
            ));
            redirects.extend(group.redirect);
            compressed_offset = compressed_offset
                .checked_add(group.compressed_size as u64)
                .ok_or_else(|| {
                    Error::Overflow(format!(
                        "blob meta chunk group {index} compressed range overflow"
                    ))
                })?;
            uncompressed_block_offset += blocks;
            first_chunk_index = end_member;
        }
        if first_chunk_index as usize != chunk_lengths.len() {
            return Err(Error::InvalidParameter(format!(
                "blob meta ChunkLengthTable holds {} entries, the chunk groups name {first_chunk_index}",
                chunk_lengths.len()
            )));
        }
        let total_blocks = u32::try_from(uncompressed_block_offset).map_err(|_| {
            Error::Overflow("blob meta address space exceeds the 32-bit block space".to_string())
        })?;
        entries.push(BlobMetadataChunkGroup::row(
            compressed_offset,
            total_blocks,
            first_chunk_index,
            0,
            0,
        ));
        let chunk_group_indexes =
            Self::build_chunk_group_index(&entries, total_blocks, index_span_blocks);

        let mut tables = vec![
            BlobMetadataTable::encode(
                BlobMetadataTableType::CHUNK_GROUP,
                &ChunkGroupTableHeaderExtension {
                    max_group_span_bits: max_group_span_blocks.ilog2() as u8,
                    compressor: compressor.code(),
                    reserved: [0; 6],
                }
                .to_bytes(),
                BlobMetadataChunkGroup::SIZE,
                entries.len(),
                |out| entries.iter().for_each(|entry| entry.write(out)),
            )?,
            BlobMetadataTable::encode(
                BlobMetadataTableType::CHUNK_LENGTH,
                &[],
                BlobMetadataChunkLength::SIZE,
                chunk_lengths.len(),
                |out| {
                    chunk_lengths
                        .iter()
                        .for_each(|len| BlobMetadataChunkLength(*len).write(out))
                },
            )?,
            BlobMetadataTable::encode(
                BlobMetadataTableType::CHUNK_GROUP_INDEX,
                &ChunkGroupIndexTableHeaderExtension {
                    index_span_bits: index_span_blocks.ilog2() as u8,
                    reserved: [0; 7],
                }
                .to_bytes(),
                BlobMetadataChunkGroupIndex::SIZE,
                chunk_group_indexes.len(),
                |out| {
                    chunk_group_indexes
                        .iter()
                        .for_each(|index| index.write(out))
                },
            )?,
        ];
        if let Some(algorithm) = digester.code() {
            tables.push(BlobMetadataTable::encode(
                BlobMetadataTableType::CHUNK_GROUP_DIGEST,
                &ChunkGroupDigestTableHeaderExtension {
                    algorithm,
                    reserved: [0; 7],
                }
                .to_bytes(),
                BlobMetadataChunkGroupDigest::SIZE,
                digests.len(),
                |out| digests.iter().for_each(|digest| digest.write(out)),
            )?);
        }
        if is_redirect {
            tables.push(BlobMetadataTable::encode(
                BlobMetadataTableType::CHUNK_GROUP_REDIRECT,
                &[],
                BlobMetadataChunkGroupRedirect::SIZE,
                redirects.len(),
                |out| redirects.iter().for_each(|redirect| redirect.write(out)),
            )?);
        }
        Self::parse(BlobMetadataBytes::Owned(Self::assemble(&tables)?))
    }

    /// Read blob metadata from an in-memory byte slice: the raw bytes are
    /// checked first (`validate_bytes`), then the tables are walked and the
    /// decoded fields checked against each other (`validate_fields`).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Self::validate_bytes(bytes)?;
        Self::parse(BlobMetadataBytes::Owned(bytes.to_vec()))
    }

    /// Read blob metadata from a file, with the same checks as
    /// [`Self::from_bytes`] over a shared mapping that is kept and read
    /// zero-copy.
    pub fn from_path(path: &Path) -> Result<Self> {
        let file = File::open(path)
            .with_context(|| format!("failed to open blob meta: {}", path.display()))?;
        // SAFETY: the sidecar is written once and then only read; a
        // concurrent truncation would surface as SIGBUS, which is the
        // accepted trade-off for zero-copy tables (same as the other
        // mapped sidecars).
        let mmap = unsafe { MmapOptions::new().map(&file) }
            .with_context(|| format!("failed to mmap blob meta: {}", path.display()))?;
        Self::validate_bytes(&mmap)?;
        Self::parse(BlobMetadataBytes::Mapped(mmap))
    }

    /// Validate the raw on-disk bytes before decoding them: a whole number
    /// of blocks holding at least the header, the magic, and the stored
    /// crc32 against [`Self::compute_crc32`] over the whole file.
    fn validate_bytes(bytes: &[u8]) -> Result<()> {
        if bytes.len() < Self::HEADER_SIZE || bytes.len() % EROFS_BLOCK_SIZE as usize != 0 {
            return Err(Error::InvalidImage(format!(
                "blob meta size {} is not a whole number of 4 KiB blocks",
                bytes.len()
            )));
        }
        if bytes[..8] != Self::MAGIC {
            return Err(Error::InvalidImage("invalid blob meta magic".to_string()));
        }
        let stored = read_u32_at(bytes, Self::CRC32_FIELD.start);
        let actual = Self::compute_crc32(bytes);
        if stored != actual {
            return Err(Error::InvalidImage(format!(
                "blob meta crc32 mismatch: expected {stored:#010x}, got {actual:#010x}"
            )));
        }
        Ok(())
    }

    /// Parse bytes whose seal [`Self::validate_bytes`] accepted, or the
    /// writer just produced: walk the tables, resolve the known ones, read
    /// their header fields, then validate the fields, the entries and the
    /// lookup table.
    fn parse(bytes: BlobMetadataBytes) -> Result<Self> {
        let raw = bytes.as_ref();
        let feature_compat = read_u32_at(raw, 8);
        let feature_incompat = read_u32_at(raw, 12);
        let crc32 = read_u32_at(raw, Self::CRC32_FIELD.start);
        let table_count = read_u16_at(raw, 20);
        let _reserved = read_bytes_at(raw, 22);
        // Unknown incompat bits may change the table walk itself, so they
        // reject before anything behind the header is trusted.
        FeatureFlags::from_bits(feature_incompat).validate_incompat(Self::INCOMPAT_SUPPORTED)?;

        // The tables follow the header back to back, each at the next
        // 8-byte boundary, and the last one ends at the padded file end.
        let mut tables: Vec<BlobMetadataTable> = Vec::with_capacity(table_count as usize);
        let mut end = Self::HEADER_SIZE;
        for _ in 0..table_count {
            let table = BlobMetadataTable::from_bytes(raw, end.next_multiple_of(8))?;
            let kind = table.table_type;
            if kind.0 == 0 || tables.iter().any(|seen| seen.table_type == kind) {
                return Err(Error::InvalidImage(format!(
                    "blob meta table at {:#x} has a zero or duplicate type {kind}",
                    table.offset
                )));
            }
            if !kind.is_supported() && table.feature_incompat != 0 {
                return Err(Error::Unsupported(format!(
                    "unsupported incompat blob meta table {kind} (image is newer than this reader)"
                )));
            }
            end = table.range().end;
            tables.push(table);
        }
        if align_up_u64(end as u64, EROFS_BLOCK_SIZE as u64) != Some(raw.len() as u64) {
            return Err(Error::InvalidImage(format!(
                "blob meta size mismatch: the tables end at {end}, the file holds {} bytes",
                raw.len()
            )));
        }

        // Resolve the known tables against the layout this reader knows.
        let supported = |kind: BlobMetadataTableType,
                         header_size: usize,
                         entry_size: usize|
         -> Result<Option<BlobMetadataTable>> {
            let Some(table) = tables.iter().find(|table| table.table_type == kind) else {
                return Ok(None);
            };
            table.validate_layout(header_size, entry_size)?;
            Ok(Some(*table))
        };
        let required = |kind: BlobMetadataTableType,
                        header_size: usize,
                        entry_size: usize|
         -> Result<BlobMetadataTable> {
            supported(kind, header_size, entry_size)?
                .ok_or_else(|| Error::InvalidImage(format!("blob meta lacks its {kind}")))
        };

        let groups = required(
            BlobMetadataTableType::CHUNK_GROUP,
            BlobMetadataTable::HEADER_SIZE + ChunkGroupTableHeaderExtension::SIZE,
            BlobMetadataChunkGroup::SIZE,
        )?;
        let chunks = required(
            BlobMetadataTableType::CHUNK_LENGTH,
            BlobMetadataTable::HEADER_SIZE,
            BlobMetadataChunkLength::SIZE,
        )?;
        let indexes = required(
            BlobMetadataTableType::CHUNK_GROUP_INDEX,
            BlobMetadataTable::HEADER_SIZE + ChunkGroupIndexTableHeaderExtension::SIZE,
            BlobMetadataChunkGroupIndex::SIZE,
        )?;
        let digests = supported(
            BlobMetadataTableType::CHUNK_GROUP_DIGEST,
            BlobMetadataTable::HEADER_SIZE + ChunkGroupDigestTableHeaderExtension::SIZE,
            BlobMetadataChunkGroupDigest::SIZE,
        )?;
        let redirects = supported(
            BlobMetadataTableType::CHUNK_GROUP_REDIRECT,
            BlobMetadataTable::HEADER_SIZE,
            BlobMetadataChunkGroupRedirect::SIZE,
        )?;

        // Read the header extensions. The two `_bits` fields are log2
        // block counts; one past the u32 block space is no span at all.
        let group_header = ChunkGroupTableHeaderExtension::read(raw, &groups);
        let max_group_span_blocks = 1u32
            .checked_shl(u32::from(group_header.max_group_span_bits))
            .ok_or_else(|| {
                Error::InvalidImage(
                    "blob meta maximum group span exceeds the 32-bit block space".to_string(),
                )
            })?;
        let compressor = BlobMetadataCompressor::from_code(group_header.compressor)?;
        let index_header = ChunkGroupIndexTableHeaderExtension::read(raw, &indexes);
        let index_span_blocks = 1u32
            .checked_shl(u32::from(index_header.index_span_bits))
            .ok_or_else(|| {
                Error::InvalidImage(
                    "blob meta index span exceeds the 32-bit block space".to_string(),
                )
            })?;
        let (digests, unsupported_digest_algorithm) = match digests {
            None => (None, None),
            Some(table) => {
                let algorithm = ChunkGroupDigestTableHeaderExtension::read(raw, &table).algorithm;
                if BlobMetadataDigester::from_code(algorithm).is_some() {
                    (Some(table), None)
                } else {
                    (None, Some(algorithm))
                }
            }
        };

        // Read the group terminator: the totals live in its offsets.
        let Some(chunk_group_count) = groups.entry_count.checked_sub(1) else {
            return Err(Error::InvalidImage(
                "blob meta chunk group table lacks its terminator".to_string(),
            ));
        };
        let terminator = groups.entry_offset(chunk_group_count);
        let total_blocks = read_u32_at(raw, terminator + 8);
        let chunk_count = read_u32_at(raw, terminator + 12);

        let blob_metadata = Self {
            bytes,
            feature_compat,
            feature_incompat,
            crc32,
            table_count,
            _reserved,
            tables,
            groups,
            chunks,
            indexes,
            digests,
            redirects,
            compressor,
            unsupported_digest_algorithm,
            max_group_span_blocks,
            index_span_blocks,
            chunk_group_count: chunk_group_count as u32,
            chunk_count,
            total_blocks,
        };
        blob_metadata.validate_fields()?;
        blob_metadata.validate_tables()?;
        blob_metadata.validate_index()?;
        Ok(blob_metadata)
    }

    /// Validate the intrinsic field invariants, needing nothing beyond the
    /// table header fields and the table sizes.
    fn validate_fields(&self) -> Result<()> {
        // Geometry: the group span is bounded so byte sizes fit a u32, and
        // the index span is at most a group span.
        if self.max_group_span_blocks > Self::MAX_GROUP_SPAN_BLOCKS {
            return Err(Error::InvalidImage(format!(
                "blob meta maximum group span of {} blocks exceeds {}",
                self.max_group_span_blocks,
                Self::MAX_GROUP_SPAN_BLOCKS
            )));
        }

        if self.index_span_blocks > self.max_group_span_blocks {
            return Err(Error::InvalidImage(format!(
                "blob meta index span of {} blocks exceeds the group span of {} blocks",
                self.index_span_blocks, self.max_group_span_blocks
            )));
        }

        // Counts: an empty blob has no groups, chunks or blocks, any other
        // blob has all three, with at most one group per chunk.
        if self.chunk_group_count == 0 {
            if self.chunk_count != 0 || self.total_blocks != 0 {
                return Err(Error::InvalidImage(format!(
                    "blob meta has no chunk groups but {} chunks and {} blocks",
                    self.chunk_count, self.total_blocks
                )));
            }
        } else if self.chunk_count == 0 || self.total_blocks == 0 {
            return Err(Error::InvalidImage(format!(
                "blob meta has {} chunk groups but {} chunks and {} blocks",
                self.chunk_group_count, self.chunk_count, self.total_blocks
            )));
        }
        if self.chunk_group_count > self.chunk_count {
            return Err(Error::InvalidImage(format!(
                "blob meta names {} groups among {} chunks",
                self.chunk_group_count, self.chunk_count
            )));
        }

        // Tables: each holds exactly one entry per chunk, index span or group.
        if self.chunks.entry_count != self.chunk_count as usize {
            return Err(Error::InvalidImage(format!(
                "blob meta ChunkLengthTable holds {} entries, the chunk groups name {}",
                self.chunks.entry_count, self.chunk_count
            )));
        }

        let chunk_group_index_count =
            u64::from(self.total_blocks).div_ceil(u64::from(self.index_span_blocks));
        if self.indexes.entry_count as u64 != chunk_group_index_count {
            return Err(Error::InvalidImage(format!(
                "blob meta ChunkGroupIndexTable holds {} entries for {chunk_group_index_count} index spans",
                self.indexes.entry_count
            )));
        }

        if self
            .digests
            .is_some_and(|table| table.entry_count != self.chunk_group_count as usize)
        {
            return Err(Error::InvalidImage(
                "blob meta ChunkGroupDigestTable does not hold one entry per chunk group"
                    .to_string(),
            ));
        }

        if self
            .redirects
            .is_some_and(|table| table.entry_count != self.chunk_group_count as usize)
        {
            return Err(Error::InvalidImage(
                "blob meta ChunkGroupRedirectTable does not hold one entry per chunk group"
                    .to_string(),
            ));
        }

        Ok(())
    }

    /// Lay out the header and the encoded `tables` in order, each at the next
    /// 8-byte boundary, zero-pad to a 4 KiB multiple and seal the crc32.
    fn assemble(tables: &[Vec<u8>]) -> Result<Vec<u8>> {
        let table_count = u16::try_from(tables.len())
            .map_err(|_| Error::Overflow("blob meta holds more than 65535 tables".to_string()))?;
        let mut out = vec![0u8; Self::HEADER_SIZE];
        out[..8].copy_from_slice(&Self::MAGIC);
        write_u16_at(&mut out, 20, table_count);
        for table in tables {
            out.resize(out.len().next_multiple_of(8), 0);
            out.extend_from_slice(table);
        }
        out.resize(out.len().next_multiple_of(EROFS_BLOCK_SIZE as usize), 0);
        let crc32 = Self::compute_crc32(&out);
        write_u32_at(&mut out, Self::CRC32_FIELD.start, crc32);
        Ok(out)
    }

    /// Build ChunkGroupIndexTable: the group covering each index span's
    /// first block.
    fn build_chunk_group_index(
        rows: &[BlobMetadataChunkGroup],
        total_blocks: u32,
        index_span_blocks: u32,
    ) -> Vec<BlobMetadataChunkGroupIndex> {
        let index_span_blocks = u64::from(index_span_blocks);
        let count = u64::from(total_blocks).div_ceil(index_span_blocks);
        let groups = rows.len() - 1;
        let mut group = 0usize;
        (0..count)
            .map(|span| {
                let start = span * index_span_blocks;
                // The terminator's start is the address space's end, past every span.
                while group + 1 < groups
                    && u64::from(rows[group + 1].uncompressed_block_offset) <= start
                {
                    group += 1;
                }
                BlobMetadataChunkGroupIndex(group as u32)
            })
            .collect()
    }

    /// crc32c over a serialized buffer with the header's crc32 field zeroed:
    /// the writer seals the assembled file with it, the reader verifies the
    /// raw incoming bytes against it.
    fn compute_crc32(bytes: &[u8]) -> u32 {
        let field = Self::CRC32_FIELD;
        let crc32 = crc32c_append(crc32c(&bytes[..field.start]), &[0; 4]);
        crc32c_append(crc32, &bytes[field.end..])
    }

    /// Row `index` of ChunkGroupTable, the terminator for `chunk_group_count`.
    fn chunk_group_entry(&self, index: usize) -> BlobMetadataChunkGroup {
        BlobMetadataChunkGroup::read(self.bytes.as_ref(), self.groups.entry_offset(index))
    }

    /// First block of group `index`, the terminator's for `chunk_group_count`.
    fn block_offset_of(&self, index: usize) -> u32 {
        read_u32_at(self.bytes.as_ref(), self.groups.entry_offset(index) + 8)
    }

    /// ChunkLengthTable entry `index`; the caller keeps the index below chunk_count.
    fn chunk_length_entry(&self, index: usize) -> BlobMetadataChunkLength {
        BlobMetadataChunkLength::read(self.bytes.as_ref(), self.chunks.entry_offset(index))
    }

    /// ChunkGroupIndexTable entry `index`; the caller keeps it below the count.
    fn chunk_group_index_entry(&self, index: usize) -> BlobMetadataChunkGroupIndex {
        BlobMetadataChunkGroupIndex::read(self.bytes.as_ref(), self.indexes.entry_offset(index))
    }

    fn redirect_entry(&self, index: usize) -> Option<BlobMetadataChunkGroupRedirect> {
        self.redirects
            .filter(|table| index < table.entry_count)
            .map(|table| {
                BlobMetadataChunkGroupRedirect::read(self.bytes.as_ref(), table.entry_offset(index))
            })
    }

    /// Validate contiguous data, block and chunk ranges, nonzero lengths,
    /// payload sums, span bounds, encoding sizes and redirect sources.
    fn validate_tables(&self) -> Result<()> {
        let span_blocks = u64::from(self.group_span_blocks());
        let index_span_blocks = u64::from(self.index_span_blocks);
        let chunk_count = self.chunk_count;
        let terminator = self.chunk_group_entry(self.chunk_group_count as usize);
        if terminator.payload_size != 0 || terminator.payload_crc32 != 0 {
            return Err(Error::InvalidImage(format!(
                "blob meta chunk group terminator carries payload {} and crc {}",
                terminator.payload_size, terminator.payload_crc32
            )));
        }
        let first = self.chunk_group_entry(0);
        if first.compressed_offset != 0
            || first.uncompressed_block_offset != 0
            || first.first_chunk_index != 0
        {
            return Err(Error::InvalidImage(
                "blob meta chunk groups must start at offset zero, block zero and member zero"
                    .to_string(),
            ));
        }
        for index in 0..self.redirect_count() {
            self.redirect_entry(index)
                .expect("redirect index within the table")
                .validate_fields()?;
        }
        let groups = self.chunk_group_count as usize;
        let mut total_chunk_count = 0u64;
        let mut start = first;
        for index in 0..groups {
            let end = self.chunk_group_entry(index + 1);
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
            if end.uncompressed_block_offset <= start.uncompressed_block_offset {
                return Err(Error::InvalidImage(format!(
                    "blob meta chunk group {index} spans no blocks or overlaps its successor"
                )));
            }
            let blocks = u64::from(end.uncompressed_block_offset - start.uncompressed_block_offset);
            if end.first_chunk_index <= start.first_chunk_index
                || end.first_chunk_index > chunk_count
            {
                return Err(Error::InvalidImage(format!(
                    "blob meta chunk group {index} owns an out-of-range member run"
                )));
            }
            let chunk_count = end.first_chunk_index - start.first_chunk_index;
            let payload = u64::from(start.payload_size);
            if payload == 0 {
                return Err(Error::InvalidImage(format!(
                    "blob meta chunk group {index} decodes to nothing"
                )));
            }
            let expected_blocks = {
                let mut sum = 0u64;
                let mut member_blocks = 0u64;
                for member in start.first_chunk_index..end.first_chunk_index {
                    let len = self.chunk_length_entry(member as usize).get();
                    if len == 0 {
                        return Err(Error::InvalidImage(
                            "blob meta pack chunk_lengths must be non-empty".to_string(),
                        ));
                    }
                    sum += u64::from(len);
                    member_blocks += u64::from(len).div_ceil(EROFS_BLOCK_SIZE as u64);
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
            if index + 1 < groups && blocks < index_span_blocks {
                return Err(Error::InvalidImage(format!(
                    "blob meta chunk group {index} spans {blocks} blocks, under the {index_span_blocks}-block index span"
                )));
            }
            if compressed_size > payload {
                return Err(Error::InvalidImage(format!(
                    "blob meta chunk group {index} encoded payload exceeds its {payload}-byte payload"
                )));
            }
            if self.compressor == BlobMetadataCompressor::None && compressed_size != payload {
                return Err(Error::InvalidImage(format!(
                    "blob meta plain chunk group {index} must store its full payload"
                )));
            }
            start = end;
        }
        if total_chunk_count != u64::from(chunk_count) {
            return Err(Error::InvalidImage(format!(
                "blob meta chunk groups hold {total_chunk_count} chunks, the terminator names {chunk_count}"
            )));
        }
        Ok(())
    }

    fn validate_index(&self) -> Result<()> {
        let groups = self.chunk_group_count as usize;
        let mut group = 0usize;
        for index in 0..self.indexes.entry_count {
            let block = index as u64 * u64::from(self.index_span_blocks);
            while group + 1 < groups && u64::from(self.block_offset_of(group + 1)) <= block {
                group += 1;
            }
            if self.chunk_group_index_entry(index).get() as usize != group {
                return Err(Error::InvalidImage(
                    "blob meta ChunkGroupIndexTable does not match ChunkGroupTable".to_string(),
                ));
            }
        }
        Ok(())
    }

    /// Write the serialized metadata verbatim, including tables this reader
    /// does not know.
    pub fn write_to(&self, writer: &mut dyn Write) -> Result<()> {
        writer.write_all(self.bytes.as_ref())?;
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

    /// Compatible feature bits, exactly as stored.
    pub fn feature_compat(&self) -> u32 {
        self.feature_compat
    }

    /// Incompatible feature bits, exactly as stored.
    pub fn feature_incompat(&self) -> u32 {
        self.feature_incompat
    }

    /// crc32c sealing the whole serialized metadata, exactly as stored.
    pub fn crc32(&self) -> u32 {
        self.crc32
    }

    /// Number of tables following the header.
    pub fn table_count(&self) -> u16 {
        self.table_count
    }

    /// The tables, in file order.
    pub fn tables(&self) -> &[BlobMetadataTable] {
        &self.tables
    }

    /// The raw bytes of the table of type `table_type`, its header included,
    /// `None` when there is no such table.
    pub fn table_bytes(&self, table_type: BlobMetadataTableType) -> Option<&[u8]> {
        self.tables
            .iter()
            .find(|table| table.table_type == table_type)
            .map(|table| &self.bytes.as_ref()[table.range()])
    }

    /// The algorithm code of a ChunkGroupDigestTable this reader does not know, which
    /// leaves the blob undigested for it; a reader that must verify digests
    /// fails on it instead of skipping the verification.
    pub fn unsupported_digest_algorithm(&self) -> Option<u8> {
        self.unsupported_digest_algorithm
    }

    /// Byte length of a stored chunk, including lone chunks; `None` past ChunkLengthTable.
    pub fn chunk_len(&self, index: usize) -> Option<u32> {
        (index < self.chunk_count as usize).then(|| self.chunk_length_entry(index).get())
    }

    /// The digest table, one entry per chunk group; empty without a
    /// supported digester.
    pub fn digests(&self) -> Vec<BlobMetadataChunkGroupDigest> {
        (0..self.digest_count())
            .filter_map(|index| self.digest(index))
            .collect()
    }

    /// The redirect table, one entry per chunk group of a redirect blob;
    /// empty otherwise.
    pub fn redirects(&self) -> Vec<BlobMetadataChunkGroupRedirect> {
        (0..self.redirect_count())
            .filter_map(|index| self.redirect_entry(index))
            .collect()
    }

    /// The digest of chunk group `index`, `None` past the table or without
    /// a supported digester.
    pub fn digest(&self, index: usize) -> Option<BlobMetadataChunkGroupDigest> {
        let table = self.digests.filter(|table| index < table.entry_count)?;
        Some(BlobMetadataChunkGroupDigest::read(
            self.bytes.as_ref(),
            table.entry_offset(index),
        ))
    }

    /// The chunk group at `index`, `None` past the table.
    pub fn chunk_group(&self, index: usize) -> Option<BlobMetadataChunkGroup> {
        if index >= self.chunk_group_count() {
            return None;
        }
        let (start, end) = (
            self.chunk_group_entry(index),
            self.chunk_group_entry(index + 1),
        );
        Some(BlobMetadataChunkGroup {
            index: index as u32,
            compressed_size: (end.compressed_offset - start.compressed_offset) as u32,
            blocks: end.uncompressed_block_offset - start.uncompressed_block_offset,
            chunk_count: end.first_chunk_index - start.first_chunk_index,
            redirect: self.redirect_entry(index),
            ..start
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
        self.chunk_group_count as usize
    }

    /// Number of chunks, lone chunks included.
    pub fn chunk_count(&self) -> usize {
        self.chunk_count as usize
    }

    /// Number of digest entries: every chunk group with a supported
    /// digester, else zero.
    pub fn digest_count(&self) -> usize {
        self.digests.map_or(0, |view| view.entry_count)
    }

    /// Number of ChunkGroupIndexTable entries.
    pub fn chunk_group_index_count(&self) -> usize {
        self.indexes.entry_count
    }

    /// Number of redirect entries: every chunk group of a redirect blob.
    pub fn redirect_count(&self) -> usize {
        self.redirects.map_or(0, |view| view.entry_count)
    }

    /// The most 4KiB blocks a chunk group spans.
    pub fn group_span_blocks(&self) -> u32 {
        self.max_group_span_blocks
    }

    /// The most bytes of the address space a chunk group spans: a lone
    /// chunk is at most a file chunk, a pack may span more. Bounds the
    /// decode scratch a reader needs for any group.
    pub fn group_span(&self) -> u32 {
        self.max_group_span_blocks * EROFS_BLOCK_SIZE
    }

    /// 4KiB blocks per ChunkGroupIndexTable entry.
    pub fn index_span_blocks(&self) -> u32 {
        self.index_span_blocks
    }

    /// The index span in bytes; every non-final group spans at least
    /// this much.
    pub fn index_span(&self) -> u32 {
        self.index_span_blocks * EROFS_BLOCK_SIZE
    }

    /// The chunk group payload compressor.
    pub fn compressor(&self) -> BlobMetadataCompressor {
        self.compressor
    }

    /// The digest algorithm, `None` without a ChunkGroupDigestTable this reader
    /// supports.
    pub fn digester(&self) -> BlobMetadataDigester {
        if self.digests.is_some() {
            BlobMetadataDigester::Blake3
        } else {
            BlobMetadataDigester::None
        }
    }

    /// Whether the blob is an `optimize` output whose chunk groups copy
    /// other blobs' groups, named by its ChunkGroupRedirectTable.
    pub fn is_redirect(&self) -> bool {
        self.redirects.is_some()
    }

    /// Total size of the uncompressed address space in 4KiB blocks: the
    /// groups' blocks back to back.
    pub fn uncompressed_block_count(&self) -> u64 {
        u64::from(self.total_blocks)
    }

    /// Total size of the uncompressed address space in bytes.
    pub fn uncompressed_size(&self) -> u64 {
        self.uncompressed_block_count() * EROFS_BLOCK_SIZE as u64
    }

    /// Bytes all chunk groups decode to: the chunks' bytes without padding.
    pub fn payload_total(&self) -> u64 {
        (0..self.chunk_group_count())
            .map(|index| u64::from(self.chunk_group_entry(index).payload_size))
            .sum()
    }

    /// End of the last chunk group's compressed range: the data region's
    /// size.
    pub fn compressed_end(&self) -> u64 {
        self.chunk_group_entry(self.chunk_group_count())
            .compressed_offset
    }

    /// The full serialized size, 4KiB aligned.
    pub fn padded_size(&self) -> u64 {
        self.bytes.as_ref().len() as u64
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
    /// one table read and at most one forward correction give worst-case
    /// O(1) lookup without a search or an allocated runtime index.
    pub fn chunk_group_index_of(&self, uncompressed_offset: u64) -> Option<usize> {
        let block = uncompressed_offset / EROFS_BLOCK_SIZE as u64;
        if block >= u64::from(self.total_blocks) {
            return None;
        }
        let span = (block / u64::from(self.index_span_blocks)) as usize;
        let mut group = self.chunk_group_index_entry(span).get() as usize;
        if block >= u64::from(self.block_offset_of(group + 1)) {
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
            let len = self.chunk_length_entry(member).get();
            let offset = block * EROFS_BLOCK_SIZE as u64;
            block += u64::from(len).div_ceil(EROFS_BLOCK_SIZE as u64);
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn digest(bytes: &[u8]) -> [u8; 32] {
        *blake3::hash(bytes).as_bytes()
    }

    fn reseal(mut bytes: Vec<u8>) -> Vec<u8> {
        let crc32 = BlobMetadata::compute_crc32(&bytes);
        write_u32_at(&mut bytes, BlobMetadata::CRC32_FIELD.start, crc32);
        bytes
    }

    fn raw(meta: &BlobMetadata) -> Vec<u8> {
        let mut raw = Vec::new();
        meta.write_to(&mut raw).unwrap();
        raw
    }

    /// The encoded tables of `meta`, to reassemble a mutated file with.
    fn split(meta: &BlobMetadata) -> Vec<Vec<u8>> {
        meta.tables()
            .iter()
            .map(|table| meta.table_bytes(table.table_type()).unwrap().to_vec())
            .collect()
    }

    /// Byte offset of the header of table `table_type`.
    fn table_offset(meta: &BlobMetadata, table_type: BlobMetadataTableType) -> usize {
        meta.tables()
            .iter()
            .find(|table| table.table_type() == table_type)
            .unwrap()
            .range()
            .start
    }

    /// Byte offset of the first entry of table `table_type`.
    fn entries_offset(meta: &BlobMetadata, table_type: BlobMetadataTableType) -> usize {
        table_offset(meta, table_type)
            + read_u16_at(meta.table_bytes(table_type).unwrap(), 2) as usize
    }

    fn entries(meta: &BlobMetadata) -> Vec<BlobMetadataChunkGroup> {
        (0..=meta.chunk_group_count())
            .map(|index| meta.chunk_group_entry(index))
            .collect()
    }

    fn chunk_group_indexes(meta: &BlobMetadata) -> Vec<usize> {
        (0..meta.chunk_group_index_count())
            .map(|index| meta.chunk_group_index_entry(index).get() as usize)
            .collect()
    }

    /// Re-encode `table` as a newer writer would that appends `extra`
    /// header bytes and `extra` bytes to every entry, filled with 0xab.
    fn widen(table: &[u8], extra: usize) -> Vec<u8> {
        let header_size = read_u16_at(table, 2) as usize;
        let entry_size = read_u32_at(table, 8) as usize;
        let count = read_u32_at(table, 12) as usize;
        let mut out = table[..header_size].to_vec();
        out.resize(header_size + extra, 0xab);
        write_u16_at(&mut out, 2, (header_size + extra) as u16);
        write_u32_at(&mut out, 8, (entry_size + extra) as u32);
        for index in 0..count {
            let at = header_size + index * entry_size;
            out.extend_from_slice(&table[at..at + entry_size]);
            out.resize(out.len() + extra, 0xab);
        }
        out
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
        span: u32,
        index_span: Option<u32>,
        groups: Vec<BlobMetadataChunkGroup>,
        chunk_lengths: Vec<u32>,
        digests: Vec<BlobMetadataChunkGroupDigest>,
    ) -> Result<BlobMetadata> {
        let digester = if digests.is_empty() {
            BlobMetadataDigester::None
        } else {
            BlobMetadataDigester::Blake3
        };
        BlobMetadata::new(
            BlobMetadataCompressor::None,
            digester,
            span,
            index_span.unwrap_or(EROFS_BLOCK_SIZE),
            groups,
            chunk_lengths,
            digests,
        )
    }

    /// Fixture: a 64 KiB group span (16 blocks), 4 KiB index span.
    /// Groups: pack A [100, 5000] (3 blocks), pack B [40, 6000, 1] (4
    /// blocks), lone C 20000 (5 blocks), lone D 65536 (16 blocks), pack E
    /// [1, 1] (2 blocks): 30 blocks and 30 index span entries.
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
            BlobMetadataChunkGroupDigest::of_group(&digests).unwrap()
        })
        .collect();
        let meta = layered(64 * 1024, Some(4096), groups, chunk_lengths, digests).unwrap();
        (meta, chunks_data)
    }

    #[test]
    fn layout_places_the_header_and_tables_back_to_back() {
        let (meta, _) = fixture();
        let raw = raw(&meta);
        assert_eq!(raw.len(), 4096);
        assert_eq!(&raw[..8], b"NDBLMETA");
        assert_eq!(read_u32_at(&raw, 8), 0);
        assert_eq!(read_u32_at(&raw, 12), 0);
        assert_eq!(read_u16_at(&raw, 20), 4);
        // Tables back to back from 24, each at the next 8-byte boundary:
        // (offset, type, header_size, compat, incompat, entry_size, count).
        let headers: Vec<_> = [24, 192, 248, 392]
            .into_iter()
            .map(|at| {
                (
                    at,
                    read_u16_at(&raw, at),
                    read_u16_at(&raw, at + 2),
                    read_u16_at(&raw, at + 4),
                    read_u16_at(&raw, at + 6),
                    read_u32_at(&raw, at + 8),
                    read_u32_at(&raw, at + 12),
                )
            })
            .collect();
        assert_eq!(
            headers,
            vec![
                (24, 1, 24, 0, 0, 24, 6),
                (192, 2, 16, 0, 0, 4, 9),
                (248, 3, 24, 0, 0, 4, 30),
                (392, 4, 24, 0, 0, 32, 5),
            ]
        );
        // ChunkGroupTable header fields: 64 KiB span is 16 blocks (bits 4), no
        // compressor; ChunkGroupIndexTable: a one-block index span (bits 0);
        // ChunkGroupDigestTable: BLAKE3.
        assert_eq!(&raw[24 + 16..24 + 18], &[4, 0]);
        assert_eq!(raw[248 + 16], 0);
        assert_eq!(raw[392 + 16], 1);
        // Entries: the second group starts at block 3; the terminator holds
        // 30 blocks and 9 chunks.
        let first_group = entries(&meta)[0];
        assert_eq!(read_u32_at(&raw, 48 + 24 + 8), 3);
        assert_eq!(read_u32_at(&raw, 48 + 5 * 24 + 8), 30);
        assert_eq!(read_u32_at(&raw, 48 + 5 * 24 + 12), 9);
        assert_eq!(read_u32_at(&raw, 48 + 16), first_group.payload_size);
        assert_eq!(read_u32_at(&raw, 48 + 20), first_group.payload_crc32);
        assert_eq!(read_u32_at(&raw, 208), 100);
        assert_eq!(read_u32_at(&raw, 272 + 3 * 4), 1);
        assert_eq!(meta.group_span_blocks(), 16);
        assert_eq!(meta.index_span_blocks(), 1);

        // Reserved fields and padding are ignored but sealed: the header
        // reserved field, the ChunkGroupTable header reserved bytes, table
        // alignment padding and the tail.
        for offset in [22, 24 + 18, 24 + 23, 244, 4095] {
            let mut ignored = raw.clone();
            ignored[offset] = 1;
            assert!(BlobMetadata::from_bytes(&ignored).is_err());
            assert!(
                BlobMetadata::from_bytes(&reseal(ignored)).is_ok(),
                "{offset}"
            );
        }
    }

    #[test]
    fn feature_words_ignore_compat_and_reject_incompat_bits() {
        let (meta, _) = fixture();
        let raw = raw(&meta);
        for bit in [1u32, 1 << 31] {
            let mut compat = raw.clone();
            write_u32_at(&mut compat, 8, bit);
            assert!(BlobMetadata::from_bytes(&reseal(compat)).is_ok());
            let mut incompat = raw.clone();
            write_u32_at(&mut incompat, 12, bit);
            let err = BlobMetadata::from_bytes(&reseal(incompat)).unwrap_err();
            assert!(err.to_string().contains("incompat"), "{err}");
        }
        // The same rules hold within a table header.
        let group_table = table_offset(&meta, BlobMetadataTableType::CHUNK_GROUP);
        let mut compat = raw.clone();
        write_u16_at(&mut compat, group_table + 4, 1 << 15);
        assert!(BlobMetadata::from_bytes(&reseal(compat)).is_ok());
        let mut incompat = raw.clone();
        write_u16_at(&mut incompat, group_table + 6, 1);
        let err = BlobMetadata::from_bytes(&reseal(incompat)).unwrap_err();
        assert!(
            err.to_string().contains("ChunkGroupTable incompat"),
            "{err}"
        );
    }

    #[test]
    fn unknown_tables_follow_their_incompat_bits() {
        let (meta, _) = fixture();
        let tables = split(&meta);
        let unknown = |kind: u16, incompat: u16| {
            let mut table =
                BlobMetadataTable::encode(BlobMetadataTableType(kind), &[], 4, 5, |out| {
                    out.extend([0x5a; 20])
                })
                .unwrap();
            write_u16_at(&mut table, 6, incompat);
            table
        };
        let with = |extra: Vec<u8>| {
            let mut tables = tables.clone();
            tables.push(extra);
            BlobMetadata::assemble(&tables).unwrap()
        };

        // An unknown table without incompat bits is skipped and kept
        // verbatim.
        let extension = unknown(0x100, 0);
        let bytes = with(extension.clone());
        let loaded = BlobMetadata::from_bytes(&bytes).unwrap();
        assert_eq!(entries(&loaded), entries(&meta));
        assert_eq!(
            loaded.table_bytes(BlobMetadataTableType(0x100)),
            Some(&extension[..])
        );
        assert_eq!(raw(&loaded), bytes);
        let dir = tempdir().unwrap();
        let path = dir.path().join("x.blob.meta");
        loaded.save(&path).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        assert_eq!(
            BlobMetadata::from_path(&path)
                .unwrap()
                .table_bytes(BlobMetadataTableType(0x100)),
            Some(&extension[..])
        );

        // Any incompat bit of an unknown table rejects.
        let err = BlobMetadata::from_bytes(&with(unknown(0x100, 1 << 15))).unwrap_err();
        assert!(
            err.to_string().contains("incompat blob meta table 0x100"),
            "{err}"
        );

        let rejects = |bytes: Vec<u8>, expected: &str| {
            let err = BlobMetadata::from_bytes(&bytes).unwrap_err();
            assert!(err.to_string().contains(expected), "{expected}: {err}");
        };
        rejects(with(unknown(1, 0)), "duplicate");
        rejects(with(unknown(0, 0)), "zero or duplicate");
        let mut without_chunks = tables.clone();
        without_chunks.remove(1);
        rejects(
            BlobMetadata::assemble(&without_chunks).unwrap(),
            "lacks its ChunkLengthTable",
        );

        let raw = raw(&meta);
        let digest_table = table_offset(&meta, BlobMetadataTableType::CHUNK_GROUP_DIGEST);
        let mut past = raw.clone();
        write_u32_at(&mut past, digest_table + 12, 1000);
        rejects(reseal(past), "past the");
        let mut grown = raw.clone();
        grown.resize(8192, 0);
        rejects(reseal(grown), "size mismatch");
        // A table count beyond the tables reads the zero padding as a table.
        let mut overcounted = raw.clone();
        write_u16_at(&mut overcounted, 20, 5);
        rejects(reseal(overcounted), "header size 0");
    }

    #[test]
    fn wider_tables_are_read_through_their_declared_sizes() {
        let (meta, _) = fixture();
        let widened: Vec<_> = split(&meta)
            .into_iter()
            .map(|bytes| widen(&bytes, 8))
            .collect();
        let loaded = BlobMetadata::from_bytes(&BlobMetadata::assemble(&widened).unwrap()).unwrap();
        assert_eq!(entries(&loaded), entries(&meta));
        assert_eq!(chunk_group_indexes(&loaded), chunk_group_indexes(&meta));
        assert_eq!(loaded.digests(), meta.digests());
        assert_eq!(loaded.group_span_blocks(), 16);
        assert_eq!(loaded.index_span_blocks(), 1);
        for index in 0..9 {
            assert_eq!(loaded.chunk_len(index), meta.chunk_len(index));
        }
        for offset in (0..meta.uncompressed_size()).step_by(1000) {
            assert_eq!(
                loaded.chunk_group_index_of(offset),
                meta.chunk_group_index_of(offset)
            );
        }
        // A table narrower than this reader knows rejects; the last table
        // is narrowed so that no other table moves.
        let digest_table = table_offset(&meta, BlobMetadataTableType::CHUNK_GROUP_DIGEST);
        let mut narrow = raw(&meta);
        write_u32_at(&mut narrow, digest_table + 8, 16);
        let err = BlobMetadata::from_bytes(&reseal(narrow)).unwrap_err();
        assert!(
            err.to_string()
                .contains("ChunkGroupDigestTable entry size 16"),
            "{err}"
        );
    }

    #[test]
    fn table_header_fields_are_validated() {
        let (meta, _) = fixture();
        let raw = raw(&meta);
        let group_table = table_offset(&meta, BlobMetadataTableType::CHUNK_GROUP);
        let chunk_group_index_table = table_offset(&meta, BlobMetadataTableType::CHUNK_GROUP_INDEX);
        let digest_table = table_offset(&meta, BlobMetadataTableType::CHUNK_GROUP_DIGEST);
        let mutate = |offset: usize, value: u8| {
            let mut bytes = raw.clone();
            bytes[offset] = value;
            BlobMetadata::from_bytes(&reseal(bytes))
        };
        let err = mutate(group_table + 16, 20).unwrap_err();
        assert!(
            err.to_string()
                .contains("group span of 1048576 blocks exceeds"),
            "{err}"
        );
        let err = mutate(group_table + 17, 9).unwrap_err();
        assert!(err.to_string().contains("compressor 9"), "{err}");
        let err = mutate(chunk_group_index_table + 16, 5).unwrap_err();
        assert!(
            err.to_string().contains("index span of 32 blocks exceeds"),
            "{err}"
        );
        let err = mutate(group_table + 2, 20).unwrap_err();
        assert!(err.to_string().contains("header size 20"), "{err}");
        let err = mutate(digest_table + 2, 16).unwrap_err();
        assert!(
            err.to_string()
                .contains("ChunkGroupDigestTable header size 16 is below 24"),
            "{err}"
        );

        // An unknown digest algorithm leaves the blob undigested.
        let loaded = mutate(digest_table + 16, 9).unwrap();
        assert_eq!(loaded.digester(), BlobMetadataDigester::None);
        assert_eq!(loaded.digest_count(), 0);
        assert!(loaded.digests().is_empty());
        assert_eq!(loaded.unsupported_digest_algorithm(), Some(9));
        assert_eq!(meta.unsupported_digest_algorithm(), None);
    }

    #[test]
    fn round_trips_through_bytes_and_a_mapped_sidecar() {
        let (meta, chunks_data) = fixture();
        assert_eq!(meta.chunk_group_count(), 5);
        assert_eq!(meta.chunk_count(), 9);
        assert_eq!(meta.uncompressed_block_count(), 30);
        assert_eq!(meta.uncompressed_size(), 30 * EROFS_BLOCK_SIZE as u64);
        assert_eq!(meta.payload_total(), 5100 + 6041 + 20000 + 65536 + 2);
        assert_eq!(meta.compressed_end(), 5100 + 6041 + 20000 + 65536 + 2);
        assert_eq!(meta.index_span(), 4096);
        assert_eq!(meta.group_span(), 64 * 1024);
        assert_eq!(meta.chunk_group_index_count(), 30);
        let raw = raw(&meta);
        assert_eq!(raw.len(), 4096);
        let loaded = BlobMetadata::from_bytes(&raw).unwrap();
        assert_eq!(entries(&loaded), entries(&meta));
        assert_eq!(loaded.digests(), meta.digests());
        assert_eq!(chunk_group_indexes(&loaded), chunk_group_indexes(&meta));
        assert!(loaded.redirects().is_empty());

        let group = loaded.chunk_group(1).unwrap();
        assert_eq!(group.compressed_range(), 5100..11141);
        assert!(group.is_pack());
        assert_eq!(group.chunk_count(), 3);
        assert_eq!(group.chunk_range(), 2..5);
        assert_eq!(
            group.uncompressed_range(),
            3 * EROFS_BLOCK_SIZE as u64..7 * EROFS_BLOCK_SIZE as u64
        );
        assert_eq!(loaded.payload_size(&group), 6041);
        assert!(loaded.is_plain(&group));
        assert_eq!(group.payload_crc32(), crc32c(&chunks_data[2..5].concat()));
        assert!(group.redirect().is_none());
        assert!(loaded.chunk_group(5).is_none());
        assert!(loaded.chunk_group(usize::MAX).is_none());
        assert_eq!(
            loaded.chunk_group_chunks(1).collect::<Vec<_>>(),
            vec![
                (0, 3 * EROFS_BLOCK_SIZE as u64, 40),
                (1, 4 * EROFS_BLOCK_SIZE as u64, 6000),
                (2, 6 * EROFS_BLOCK_SIZE as u64, 1)
            ]
        );
        let lone = loaded.chunk_group(2).unwrap();
        assert!(!lone.is_pack());
        assert_eq!(lone.chunk_count(), 1);
        assert_eq!(lone.chunk_range(), 5..6);
        assert_eq!(
            lone.uncompressed_range(),
            7 * EROFS_BLOCK_SIZE as u64..12 * EROFS_BLOCK_SIZE as u64
        );
        assert_eq!(
            loaded.chunk_group_chunks(2).collect::<Vec<_>>(),
            vec![(0, 7 * EROFS_BLOCK_SIZE as u64, 20000)]
        );
        assert_eq!(loaded.chunk_len(6), Some(65536));
        assert_eq!(loaded.chunk_len(9), None);

        let dir = tempdir().unwrap();
        let path = dir.path().join("m.blob.meta");
        meta.save(&path).unwrap();
        let mapped = BlobMetadata::from_path(&path).unwrap();
        assert_eq!(entries(&mapped), entries(&meta));
        assert!(matches!(mapped.bytes, BlobMetadataBytes::Mapped(_)));
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
            BlobMetadataChunkGroupDigest::of_group(&[
                digest(&chunks_data[2]),
                digest(&chunks_data[3]),
                digest(&chunks_data[4])
            ])
            .unwrap()
        );
        assert!(!mapped.is_redirect());
        assert_eq!(
            mapped.chunk_group_chunks(4).collect::<Vec<_>>(),
            vec![
                (0, 28 * EROFS_BLOCK_SIZE as u64, 1),
                (1, 29 * EROFS_BLOCK_SIZE as u64, 1)
            ]
        );

        // A flipped byte fails the seal.
        let mut dirty = raw.clone();
        dirty[100] ^= 1;
        assert!(BlobMetadata::from_bytes(&dirty)
            .unwrap_err()
            .to_string()
            .contains("crc32"));
    }

    #[test]
    fn group_digest_is_the_chunk_digest_alone_and_derived_for_packs() {
        let (a, b) = (digest(b"a"), digest(b"b"));
        assert_eq!(BlobMetadataChunkGroupDigest::of_group(&[]), None);
        assert_eq!(
            BlobMetadataChunkGroupDigest::of_group(&[a])
                .unwrap()
                .digest(),
            &a
        );
        let pack = BlobMetadataChunkGroupDigest::of_group(&[a, b]).unwrap();
        // Order matters, and a pack digest is not the plain hash of the
        // concatenated digests (domain-separated), nor a member digest.
        assert_ne!(
            pack,
            BlobMetadataChunkGroupDigest::of_group(&[b, a]).unwrap()
        );
        assert_ne!(pack.digest(), &digest(&[a, b].concat()));
        assert_ne!(pack.digest(), &a);
        assert_eq!(
            pack,
            BlobMetadataChunkGroupDigest::of_group(&[a, b]).unwrap()
        );
    }

    #[test]
    fn offsets_map_to_groups_through_the_chunk_group_index_table() {
        let (meta, _) = fixture();
        // One index entry per block; group boundaries are 0, 3, 7, 12, 28.
        let groups_by_span = chunk_group_indexes(&meta);
        assert_eq!(groups_by_span.len(), 30);
        assert_eq!(groups_by_span[0], 0);
        assert_eq!(groups_by_span[3], 1);
        assert_eq!(groups_by_span[28], 4);
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
            let offset = block * EROFS_BLOCK_SIZE as u64;
            assert_eq!(
                meta.chunk_group_index_of(offset),
                Some(group),
                "block {block}"
            );
            assert_eq!(
                meta.chunk_group_index_of(offset + EROFS_BLOCK_SIZE as u64 - 1),
                Some(group),
                "block {block} tail"
            );
        }
        assert_eq!(
            meta.chunk_group_index_of(30 * EROFS_BLOCK_SIZE as u64),
            None
        );

        // A tampered cell is caught at load.
        let mut tampered = raw(&meta);
        let chunk_group_index_offset =
            entries_offset(&meta, BlobMetadataTableType::CHUNK_GROUP_INDEX);
        write_u32_at(&mut tampered, chunk_group_index_offset + 4, 1 << 3);
        assert!(BlobMetadata::from_bytes(&reseal(tampered))
            .unwrap_err()
            .to_string()
            .contains("ChunkGroupIndexTable"));

        // The smallest legal index span also uses the direct table.
        let (groups, chunk_lengths): (Vec<_>, Vec<u32>) = {
            let (meta, _) = fixture();
            (
                meta.chunk_groups()
                    .map(|group| {
                        BlobMetadataChunkGroup::new(
                            group.compressed_size(),
                            group.payload_size(),
                            group.chunk_count(),
                            group.payload_crc32(),
                            None,
                        )
                        .unwrap()
                    })
                    .collect(),
                (0..9).map(|i| meta.chunk_len(i).unwrap()).collect(),
            )
        };
        let plain = layered(64 * 1024, None, groups, chunk_lengths, vec![]).unwrap();
        assert_eq!(plain.chunk_group_index_count(), 30);
        assert_eq!(plain.index_span(), 4096);
        for (block, group) in expect {
            assert_eq!(
                plain.chunk_group_index_of(block * EROFS_BLOCK_SIZE as u64),
                Some(group)
            );
        }
        assert_eq!(
            plain.chunk_group_index_of(30 * EROFS_BLOCK_SIZE as u64),
            None
        );
    }

    #[test]
    fn index_span_bounds_every_group_but_the_last() {
        // 8 KiB index span (2 blocks): a one-block group in the middle is
        // rejected, at the end it is fine.
        let big = vec![7u8; 8192];
        let small = vec![8u8; 100];
        let ok = vec![plain_group(&big, 1), plain_group(&small, 1)];
        let meta = layered(16384, Some(8192), ok, vec![8192, 100], vec![]).unwrap();
        assert_eq!(meta.chunk_group_index_count(), 2);
        assert_eq!(
            meta.chunk_group_index_of(2 * EROFS_BLOCK_SIZE as u64),
            Some(1)
        );
        let bad = vec![plain_group(&small, 1), plain_group(&big, 1)];
        assert!(layered(16384, Some(8192), bad, vec![100, 8192], vec![])
            .unwrap_err()
            .to_string()
            .contains("index span"));
        // The index span is a power of two between one block and the span.
        for index_span in [3000, 2048, 32768] {
            let groups = vec![plain_group(&big, 1)];
            assert!(layered(16384, Some(index_span), groups, vec![8192], vec![]).is_err());
        }
    }

    #[test]
    fn chunk_table_uses_u32_for_all_lengths() {
        // Small and large chunks share the same four-byte encoding.
        let a = vec![1u8; 70000];
        let b = vec![2u8; 100];
        let payload = [a.clone(), b.clone()].concat();
        let groups = vec![plain_group(&payload, 2)];
        let meta = layered(256 * 1024, Some(4096), groups, vec![70000, 100], vec![]).unwrap();
        let mut raw = Vec::new();
        meta.write_to(&mut raw).unwrap();
        let loaded = BlobMetadata::from_bytes(&raw).unwrap();
        assert_eq!(loaded.chunk_len(0), Some(70000));
        assert_eq!(
            loaded.chunk_group_chunks(0).collect::<Vec<_>>(),
            vec![(0, 0, 70000), (1, 18 * EROFS_BLOCK_SIZE as u64, 100)]
        );
        let dir = tempdir().unwrap();
        let path = dir.path().join("w.blob.meta");
        meta.save(&path).unwrap();
        let mapped = BlobMetadata::from_path(&path).unwrap();
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
        let mut padded = vec![0u8; 30 * EROFS_BLOCK_SIZE as u64 as usize];
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
        assert!(padded[100..EROFS_BLOCK_SIZE as u64 as usize]
            .iter()
            .all(|b| *b == 0));
        assert!(meta
            .for_each_decoded_chunk(0, &payloads[0][..10], &mut |_, _| Ok(()))
            .is_err());
        assert!(meta
            .for_each_decoded_chunk(5, &payloads[0][..1], &mut |_, _| Ok(()))
            .is_err());
    }

    #[test]
    fn empty_metadata_is_one_block() {
        let meta = layered(4096, Some(4096), Vec::new(), Vec::new(), Vec::new()).unwrap();
        let mut raw = Vec::new();
        meta.write_to(&mut raw).unwrap();
        assert_eq!(raw.len(), 4096);
        let loaded = BlobMetadata::from_bytes(&raw).unwrap();
        assert_eq!(loaded.uncompressed_size(), 0);
        assert_eq!(loaded.compressed_end(), 0);
        assert_eq!(loaded.chunk_group_index_count(), 0);
        assert_eq!(loaded.chunk_group_index_of(0), None);
        assert_eq!(entries(&loaded).len(), 1);
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
                    group.payload_crc32(),
                    Some(BlobMetadataChunkGroupRedirect::new(3, index as u32).unwrap()),
                )
                .unwrap(),
            );
            chunk_lengths.extend(group.chunk_range().map(|i| source.chunk_len(i).unwrap()));
            digests.push(source.digest(index).unwrap());
        }
        let meta = BlobMetadata::new(
            BlobMetadataCompressor::None,
            BlobMetadataDigester::Blake3,
            64 * 1024,
            4096,
            groups,
            chunk_lengths,
            digests,
        )
        .unwrap();
        assert!(meta.is_redirect());
        assert_eq!(meta.redirect_count(), 2);
        assert_eq!(meta.chunk_count(), 4);
        assert_eq!(meta.uncompressed_block_count(), 5);
        assert_eq!(
            meta.tables()
                .iter()
                .map(|table| (table.table_type().get(), table.feature_incompat()))
                .collect::<Vec<_>>(),
            vec![(1, 0), (2, 0), (3, 0), (4, 0), (5, 0)]
        );

        let raw = raw(&meta);
        let loaded = BlobMetadata::from_bytes(&raw).unwrap();
        assert!(loaded.is_redirect());
        let first = loaded.chunk_group(0).unwrap();
        let redirect = first.redirect().unwrap();
        assert_eq!(redirect.source_blob_index(), 3);
        assert_eq!(redirect.source_chunk_group_index(), 4);
        assert_eq!(first.compressed_range(), 0..2);
        assert_eq!(first.uncompressed_range(), 0..2 * EROFS_BLOCK_SIZE as u64);
        assert_eq!(first.payload_crc32(), crc32c(&chunks[7..].concat()));
        let second = loaded.chunk_group(1).unwrap();
        assert_eq!(second.redirect().unwrap().source_chunk_group_index(), 0);
        assert_eq!(
            second.uncompressed_range(),
            2 * EROFS_BLOCK_SIZE as u64..5 * EROFS_BLOCK_SIZE as u64
        );
        let dir = tempdir().unwrap();
        let path = dir.path().join("r.blob.meta");
        meta.save(&path).unwrap();
        assert_eq!(
            BlobMetadata::from_path(&path).unwrap().redirects(),
            meta.redirects()
        );

        // A zeroed source blob index is rejected on both sides; the
        // reserved half of an entry is ignored.
        assert!(BlobMetadataChunkGroupRedirect::new(0, 1).is_err());
        let redirects = entries_offset(&meta, BlobMetadataTableType::CHUNK_GROUP_REDIRECT);
        assert_eq!(read_u16_at(&raw, redirects), 3);
        assert_eq!(read_u32_at(&raw, redirects + 4), 4);
        let mut zeroed = raw.clone();
        write_u16_at(&mut zeroed, redirects, 0);
        assert!(BlobMetadata::from_bytes(&reseal(zeroed)).is_err());
        let mut reserved = raw.clone();
        write_u16_at(&mut reserved, redirects + 2, 0xffff);
        assert!(BlobMetadata::from_bytes(&reseal(reserved)).is_ok());
        // ChunkGroupRedirectTable holds one entry per chunk group.
        let mut short = split(&meta);
        let table = &mut short[4];
        write_u32_at(table, 12, 1);
        table.truncate(table.len() - 8);
        let err = BlobMetadata::from_bytes(&BlobMetadata::assemble(&short).unwrap()).unwrap_err();
        assert!(err.to_string().contains("ChunkGroupRedirectTable"), "{err}");

        // Groups must all redirect or none.
        let payload = chunks[5].clone();
        let mixed = vec![
            plain_group(&payload, 1),
            BlobMetadataChunkGroup::new(
                20000,
                20000,
                1,
                crc32c(&payload),
                Some(BlobMetadataChunkGroupRedirect::new(1, 1).unwrap()),
            )
            .unwrap(),
        ];
        assert!(layered(64 * 1024, None, mixed, vec![], vec![])
            .unwrap_err()
            .to_string()
            .contains("all redirect"));
    }

    #[test]
    fn compressed_groups_round_trip() {
        let payload = vec![7u8; 100];
        let meta = BlobMetadata::new(
            BlobMetadataCompressor::Zstd,
            BlobMetadataDigester::None,
            4096,
            4096,
            vec![BlobMetadataChunkGroup::new(10, 100, 1, crc32c(&payload), None).unwrap()],
            vec![100],
            vec![],
        )
        .unwrap();
        assert!(!meta.is_redirect());
        assert!(!meta.is_plain(&meta.chunk_group(0).unwrap()));
        assert_eq!(meta.tables().len(), 3);
        let loaded = BlobMetadata::from_bytes(&raw(&meta)).unwrap();
        assert_eq!(loaded.compressor(), BlobMetadataCompressor::Zstd);
        assert_eq!(loaded.digester(), BlobMetadataDigester::None);
        assert!(!loaded.is_redirect());
    }

    #[test]
    fn chunk_group_index_corrects_once_and_rejects_corruption() {
        let lengths = vec![3 * 4096, 4 * 4096, 100];
        let groups = lengths
            .iter()
            .map(|length| plain_group(&vec![1; *length as usize], 1))
            .collect();
        let meta = layered(32768, Some(8192), groups, lengths, vec![]).unwrap();
        let raw = raw(&meta);
        let directory = tempdir().unwrap();
        let path = directory.path().join("index.blob.meta");
        meta.save(&path).unwrap();
        let mapped = BlobMetadata::from_path(&path).unwrap();
        assert!(matches!(mapped.bytes, BlobMetadataBytes::Mapped(_)));
        for offset in 0..meta.uncompressed_size() {
            let expected = if offset < 3 * EROFS_BLOCK_SIZE as u64 {
                0
            } else if offset < 7 * EROFS_BLOCK_SIZE as u64 {
                1
            } else {
                2
            };
            assert_eq!(mapped.chunk_group_index_of(offset), Some(expected));
        }
        assert_eq!(mapped.chunk_group_index_of(u64::MAX), None);
        drop(mapped);
        for offset in [0, 12, 20, 21] {
            let mut invalid = raw.clone();
            invalid[offset] = 255;
            assert!(
                BlobMetadata::from_bytes(&reseal(invalid)).is_err(),
                "{offset}"
            );
        }
        for length in [0, 23, 24, 55, 127, 4095] {
            assert!(BlobMetadata::from_bytes(&raw[..length]).is_err());
        }
        let chunk_group_index_offset =
            entries_offset(&meta, BlobMetadataTableType::CHUNK_GROUP_INDEX);
        for value in [1, u32::MAX] {
            let mut invalid = raw.clone();
            write_u32_at(&mut invalid, chunk_group_index_offset, value);
            let invalid = reseal(invalid);
            assert!(BlobMetadata::from_bytes(&invalid).is_err());
            std::fs::write(&path, &invalid).unwrap();
            assert!(BlobMetadata::from_path(&path).is_err());
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
            layered(64 * 1024, Some(4096), groups, chunk_lengths, vec![])
                .expect_err("expected rejection")
                .to_string()
        };

        // Members left over, or a group naming chunk_lengths past the table.
        assert!(
            build(groups(), [chunk_lengths(), vec![5]].concat()).contains("ChunkLengthTable holds")
        );
        let mut greedy = groups();
        greedy[4].chunk_count = 3;
        assert!(build(greedy, chunk_lengths()).contains("past ChunkLengthTable"));
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
            64 * 1024,
            Some(4096),
            groups(),
            chunk_lengths(),
            vec![BlobMetadataChunkGroupDigest::new([0; 32])]
        )
        .unwrap_err()
        .to_string()
        .contains("digest count"));

        // Tables whose counts disagree with the terminator.
        let raw = raw(&meta);
        let terminator = entries_offset(&meta, BlobMetadataTableType::CHUNK_GROUP) + 5 * 24;
        for (offset, value) in [
            (terminator + 8, 31u32),
            (terminator + 12, 8),
            (terminator + 16, 1),
        ] {
            let mut invalid = raw.clone();
            write_u32_at(&mut invalid, offset, value);
            assert!(BlobMetadata::from_bytes(&reseal(invalid)).is_err());
        }
        let mut invalid = raw.clone();
        invalid[table_offset(&meta, BlobMetadataTableType::CHUNK_GROUP_INDEX) + 16] = 1;
        assert!(BlobMetadata::from_bytes(&reseal(invalid)).is_err());
    }
}

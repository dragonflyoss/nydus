use crate::blob::algorithm::{BlobMetadataCompressor, BlobMetadataDigester};
use crate::blob::flag::FeatureFlags;
use crate::erofs::EROFS_BLOCK_SIZE;
use crate::error::{Context, Error, Result};
use crate::utils::align_up_u64;
use crate::utils::le::{
    read_bytes_at, read_u16_at, read_u32_at, read_u64_at, read_u8_at, write_bytes_at, write_u16_at,
    write_u32_at, write_u64_at, write_u8_at,
};
use crc32c::{crc32c, crc32c_append};
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Write};
use std::marker::PhantomData;
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

    /// Size of the header extension this reader reads for the type, `None`
    /// for a type without one or one it does not parse.
    fn header_extension_size(self) -> Option<usize> {
        match self {
            Self::CHUNK_GROUP => Some(BlobMetadataChunkGroupTableHeaderExtension::SIZE),
            Self::CHUNK_GROUP_INDEX => Some(BlobMetadataChunkGroupIndexTableHeaderExtension::SIZE),
            Self::CHUNK_GROUP_DIGEST => {
                Some(BlobMetadataChunkGroupDigestTableHeaderExtension::SIZE)
            }
            _ => None,
        }
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
/// ChunkGroupTable          BlobMetadataChunkGroupTableHeaderExtension, 8 B
/// ChunkLengthTable         none
/// ChunkGroupIndexTable     BlobMetadataChunkGroupIndexTableHeaderExtension, 8 B
/// ChunkGroupDigestTable    BlobMetadataChunkGroupDigestTableHeaderExtension, 8 B
/// ChunkGroupRedirectTable  none
/// ```
///
/// A newer writer appends header extension or entry fields and declares the larger
/// `header_size` or `entry_size`; an older reader reads through the declared
/// sizes and never sees them (qcow2 header extensions, ext4 `i_extra_isize`).
///
/// Decoded, `header_size` is the optional header extension's size behind
/// the [`Self::HEADER_SIZE`] every table starts with.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlobMetadataTable {
    // Where the table starts in the file, then its header in on-disk order.
    offset: usize,
    table_type: BlobMetadataTableType,
    header_extension_size: Option<usize>,
    feature_compat: u16,
    feature_incompat: u16,
    entry_size: usize,
    entry_count: usize,
}

impl BlobMetadataTable {
    /// On-disk size of the header every table starts with, and the whole
    /// `header_size` of a table type without a header extension.
    pub const HEADER_SIZE: usize = 16;

    /// Every incompat bit this reader understands for a known table, none
    /// so far. A table setting a bit outside this mask was written by a
    /// newer nydus and is rejected by `validate_fields`.
    const INCOMPAT_SUPPORTED: u16 = 0;

    /// Creates the header of a table a writer lays out: `table_type`, a
    /// header extension of `header_extension_size` bytes when the table
    /// type has one, the given feature words, then `entry_count` entries of
    /// `entry_size` bytes. The fields are checked, so a constructed header
    /// is valid by definition. The table's offset in the file is not known
    /// here; [`BlobMetadata::from_tables`] places it.
    fn new(
        table_type: BlobMetadataTableType,
        header_extension_size: Option<usize>,
        feature_compat: u16,
        feature_incompat: u16,
        entry_size: usize,
        entry_count: usize,
    ) -> Result<Self> {
        let table = Self {
            offset: 0,
            table_type,
            header_extension_size,
            feature_compat,
            feature_incompat,
            entry_size,
            entry_count: u32::try_from(entry_count).map_err(|_| {
                Error::Overflow("blob meta table entry count exceeds u32".to_string())
            })? as usize,
        };

        table.validate_fields()?;
        Ok(table)
    }

    /// Parse the table header at `offset` in the file `bytes`: the raw
    /// bytes are checked first (`validate_bytes`), then the decoded fields
    /// (`validate_fields`). Whether the table fits in the file is settled
    /// by the walk over all tables, which must end at the file's end.
    fn from_bytes(bytes: &[u8], offset: usize) -> Result<Self> {
        Self::validate_bytes(bytes, offset)?;
        let header_size = read_u16_at(bytes, offset + 2) as usize;
        let table = Self {
            offset,
            table_type: BlobMetadataTableType(read_u16_at(bytes, offset)),
            header_extension_size: header_size
                .checked_sub(Self::HEADER_SIZE)
                .filter(|size| *size != 0),
            feature_compat: read_u16_at(bytes, offset + 4),
            feature_incompat: read_u16_at(bytes, offset + 6),
            entry_size: read_u32_at(bytes, offset + 8) as usize,
            entry_count: read_u32_at(bytes, offset + 12) as usize,
        };

        table.validate_fields()?;
        Ok(table)
    }

    /// Serialize the table into its on-disk bytes: this header, the
    /// `header_extension` behind it when the table type has one, then the
    /// `entries`, whose size and count the header was created with.
    fn to_bytes<T: BlobMetadataEntry>(
        self,
        header_extension: Option<&[u8]>,
        entries: &[T],
    ) -> Vec<u8> {
        let mut data = vec![0u8; Self::HEADER_SIZE];
        write_u16_at(&mut data, 0, self.table_type.0);
        write_u16_at(&mut data, 2, self.header_size() as u16);
        write_u16_at(&mut data, 4, self.feature_compat);
        write_u16_at(&mut data, 6, self.feature_incompat);
        write_u32_at(&mut data, 8, self.entry_size as u32);
        write_u32_at(&mut data, 12, self.entry_count as u32);

        if let Some(header_extension) = header_extension {
            data.extend_from_slice(header_extension);
        }

        for entry in entries {
            entry.write_to(&mut data);
        }
        data
    }

    /// Validate the raw bytes before decoding them: a whole header lies at
    /// `offset`.
    fn validate_bytes(bytes: &[u8], offset: usize) -> Result<()> {
        if offset + Self::HEADER_SIZE > bytes.len() {
            return Err(Error::InvalidImage(format!(
                "blob meta table header at {offset:#x} is truncated"
            )));
        }

        let header_size = read_u16_at(bytes, offset + 2) as usize;
        if header_size < Self::HEADER_SIZE || header_size % 8 != 0 {
            return Err(Error::InvalidImage(format!(
                "blob meta table at {offset:#x} header size {header_size} is not a multiple of 8 of at least {}",
                Self::HEADER_SIZE
            )));
        }

        Ok(())
    }

    /// Validate the intrinsic field invariants, needing nothing beyond the
    /// fields themselves. Run once per table by [`Self::from_bytes`].
    fn validate_fields(&self) -> Result<()> {
        FeatureFlags::from_bits(u32::from(self.feature_incompat))
            .validate_incompat(u32::from(Self::INCOMPAT_SUPPORTED))
            .with_context(|| format!("blob meta table {} incompat flags", self.table_type))?;

        if let Some(required) = self.table_type.header_extension_size() {
            if !self
                .header_extension_size
                .is_some_and(|size| size >= required)
            {
                return Err(Error::InvalidImage(format!(
                    "blob meta table {} header extension is shorter than its {required} bytes",
                    self.table_type
                )));
            }
        }

        Ok(())
    }

    /// Byte range of the whole table, its header included.
    pub fn range(&self) -> Range<usize> {
        self.offset..self.offset + self.header_size() + self.entry_size * self.entry_count
    }

    /// The table type.
    pub fn table_type(&self) -> BlobMetadataTableType {
        self.table_type
    }

    /// The on-disk `header_size`: the header and its extension, if any.
    fn header_size(&self) -> usize {
        match self.header_extension_size {
            None => Self::HEADER_SIZE,
            Some(size) => Self::HEADER_SIZE + size,
        }
    }

    /// Byte range of the header extension of `size` bytes, behind the
    /// header.
    fn header_extension_range(&self, size: usize) -> Range<usize> {
        let start = self.offset + Self::HEADER_SIZE;
        start..start + size
    }

    /// Compatible feature bits of the table, exactly as stored.
    pub fn feature_compat(&self) -> u16 {
        self.feature_compat
    }

    /// Incompatible feature bits of the table, exactly as stored.
    pub fn feature_incompat(&self) -> u16 {
        self.feature_incompat
    }

    /// Byte offset of entry `index`; the caller keeps it below the count.
    fn entry_offset(&self, index: usize) -> usize {
        self.offset + self.header_size() + index * self.entry_size
    }

    /// Read this table as entries of `T`; the view is checked before use.
    fn entries_of<T: BlobMetadataEntry>(self) -> Result<BlobMetadataEntries<T>> {
        let entries = BlobMetadataEntries {
            table: self,
            entry: PhantomData,
        };

        entries.validate()?;
        Ok(entries)
    }
}

/// One entry of a blob meta table as stored on disk.
trait BlobMetadataEntry: Sized {
    /// On-disk size of one entry.
    const SIZE: usize;

    /// Decode an entry from exactly its [`Self::SIZE`] bytes.
    fn from_bytes(bytes: &[u8]) -> Self;

    /// Append the entry's on-disk bytes to `out`.
    fn write_to(&self, out: &mut Vec<u8>);
}

/// A table whose declared sizes were checked against `T` and its header
/// header extension, so its entries can be read as `T`.
#[derive(Clone, Copy, Debug)]
struct BlobMetadataEntries<T> {
    table: BlobMetadataTable,
    entry: PhantomData<T>,
}

impl<T: BlobMetadataEntry> BlobMetadataEntries<T> {
    /// Entry `index` of the file `bytes`; the caller keeps it below
    /// [`Self::len`].
    fn get(&self, bytes: &[u8], index: usize) -> T {
        let at = self.table.entry_offset(index);
        T::from_bytes(&bytes[at..at + T::SIZE])
    }

    /// Number of entries.
    fn len(&self) -> usize {
        self.table.entry_count
    }

    /// Validate that the declared entry size covers `T`, so fields a newer
    /// writer appended are skipped rather than read past.
    fn validate(&self) -> Result<()> {
        if self.table.entry_size < T::SIZE {
            return Err(Error::InvalidImage(format!(
                "blob meta {} entry size {} is below {}",
                self.table.table_type,
                self.table.entry_size,
                T::SIZE
            )));
        }

        Ok(())
    }
}

// ChunkGroupTable

/// The ChunkGroupTable header extension.
///
/// ```text
/// offset  size  field
///     16     1  max_blocks_per_chunk_group_bits  log2 of the most blocks a
///                                                 group covers, at most 19
///     17     1  compressor              0 none, 1 zstd, 2 lz4
///     18     6  reserved                writers zero it, readers ignore it
/// ```
#[derive(Clone, Copy, Debug)]
struct BlobMetadataChunkGroupTableHeaderExtension {
    max_blocks_per_chunk_group_bits: u8,
    compressor: u8,
    reserved: [u8; 6],
}

impl BlobMetadataChunkGroupTableHeaderExtension {
    /// On-disk size, behind the header.
    const SIZE: usize = 8;

    /// Creates the extension of a table whose groups span at most
    /// `max_blocks_per_chunk_group` blocks, rounded down to a power of two
    /// since only its log2 is stored.
    fn new(max_blocks_per_chunk_group: u32, compressor: BlobMetadataCompressor) -> Result<Self> {
        Ok(Self {
            max_blocks_per_chunk_group_bits: max_blocks_per_chunk_group.checked_ilog2().ok_or(
                Error::InvalidParameter("blob meta max blocks per chunk group is zero".to_string()),
            )? as u8,
            compressor: compressor.code(),
            reserved: [0; 6],
        })
    }

    /// Read the extension behind the header of `table` in the file `bytes`.
    fn from_bytes(bytes: &[u8], table: &BlobMetadataTable) -> Self {
        let bytes = &bytes[table.header_extension_range(Self::SIZE)];
        Self {
            max_blocks_per_chunk_group_bits: read_u8_at(bytes, 0),
            compressor: read_u8_at(bytes, 1),
            reserved: read_bytes_at(bytes, 2),
        }
    }

    fn to_bytes(self) -> [u8; Self::SIZE] {
        let mut data = [0u8; Self::SIZE];
        write_u8_at(&mut data, 0, self.max_blocks_per_chunk_group_bits);
        write_u8_at(&mut data, 1, self.compressor);
        write_bytes_at(&mut data, 2, &self.reserved);
        data
    }

    /// The most blocks a group covers; a log2 past the u32 block space
    /// saturates, over every bound.
    fn max_blocks_per_chunk_group(&self) -> u32 {
        2u32.saturating_pow(self.max_blocks_per_chunk_group_bits.into())
    }

    /// The compressor every group is stored with.
    fn compressor(&self) -> Result<BlobMetadataCompressor> {
        BlobMetadataCompressor::from_code(self.compressor)
    }
}

/// One ChunkGroupTable entry: where a chunk group starts. The table holds
/// `chunk_group_count + 1` entries; entry `i` names where group `i` starts
/// in the data region, the logical address space and ChunkLengthTable, and
/// entry `i + 1` where it ends, so the last entry is a terminator holding
/// the data region's size, the address space's block count and the chunk
/// count. [`BlobMetadata::chunk_group`] joins two neighbouring entries into
/// a [`BlobMetadataChunkGroupExtent`], the group with its lengths. A writer
/// lays its groups out back to back and hands [`BlobMetadata::new`] the
/// entries, the terminator included.
///
/// ```text
/// offset  size  field
///      0     8  compressed_offset          bytes into the data region where
///                                          the group's compressed bytes start
///      8     4  logical_block_offset       first 4KiB block of the group in
///                                          the address space
///     12     4  first_chunk_index          index of the group's first entry
///                                          in ChunkLengthTable
///     16     4  uncompressed_size          bytes the group decompresses to
///                                          (zero in the terminator)
///     20     4  uncompressed_crc32         CRC32C of the uncompressed bytes
///                                          (zero in the terminator)
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlobMetadataChunkGroup {
    compressed_offset: u64,
    logical_block_offset: u32,
    first_chunk_index: u32,
    uncompressed_size: u32,
    uncompressed_crc32: u32,
}

impl BlobMetadataEntry for BlobMetadataChunkGroup {
    const SIZE: usize = 24;

    fn from_bytes(bytes: &[u8]) -> Self {
        Self {
            compressed_offset: read_u64_at(bytes, 0),
            logical_block_offset: read_u32_at(bytes, 8),
            first_chunk_index: read_u32_at(bytes, 12),
            uncompressed_size: read_u32_at(bytes, 16),
            uncompressed_crc32: read_u32_at(bytes, 20),
        }
    }

    fn write_to(&self, out: &mut Vec<u8>) {
        let mut data = [0u8; Self::SIZE];
        write_u64_at(&mut data, 0, self.compressed_offset);
        write_u32_at(&mut data, 8, self.logical_block_offset);
        write_u32_at(&mut data, 12, self.first_chunk_index);
        write_u32_at(&mut data, 16, self.uncompressed_size);
        write_u32_at(&mut data, 20, self.uncompressed_crc32);
        out.extend_from_slice(&data);
    }
}

impl BlobMetadataChunkGroup {
    /// Names where a group starts in the data region, the address space
    /// and ChunkLengthTable, and what it decompresses to; the terminator
    /// carries the totals and zero for both.
    pub fn new(
        compressed_offset: u64,
        logical_block_offset: u32,
        first_chunk_index: u32,
        uncompressed_size: u32,
        uncompressed_crc32: u32,
    ) -> Self {
        Self {
            compressed_offset,
            logical_block_offset,
            first_chunk_index,
            uncompressed_size,
            uncompressed_crc32,
        }
    }
}

/// One chunk group with its extent in every layer: where it starts and how
/// far it reaches, joined from its ChunkGroupTable entry and the next. A
/// group of one or more chunks is the compression, decode, cache fill,
/// readiness and trace unit, and lives in three layers:
///
/// ```text
/// logical: the address space the cache mirrors, groups back to back,
///          every chunk on its own 4 KiB blocks (logical_block_offset,
///          logical_block_count)
/// ┌──────────┬──────────────┬──────────┐
/// │ group 0  │   group 1    │ group 2  │
/// │c0│c1│c2│ │      c3      │c4│ c5 │  │
/// └──┴──┴──┴─┴──────────────┴──┴────┴──┘
///     ▼             ▼            ▼
/// uncompressed: the chunks' bytes back to back, no padding
///               (uncompressed_size, uncompressed_crc32)
/// ┌──────┬────────────────┬─────┐
/// │ u0   │       u1       │ u2  │
/// └──────┴────────────────┴─────┘
///     ▼             ▼            ▼
/// compressed: each group's bytes compressed as one unit, packed in order
///             in the data region (compressed_offset, compressed_size)
/// ┌───┬───────┬──┐
/// │c0 │  c1   │c2│
/// └───┴───────┴──┘
/// ```
///
/// [`BlobMetadata::chunk_group`] reads a group as its extent; a writer
/// describes groups by their [`BlobMetadataChunkGroup`] entries instead.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlobMetadataChunkGroupExtent {
    index: u32,
    compressed_offset: u64,
    compressed_size: u32,
    logical_block_offset: u32,
    logical_block_count: u32,
    first_chunk_index: u32,
    chunk_count: u32,
    uncompressed_size: u32,
    uncompressed_crc32: u32,
    redirect: Option<BlobMetadataChunkGroupRedirect>,
}

impl BlobMetadataChunkGroupExtent {
    /// The extent of group `index`, which starts at its ChunkGroupTable
    /// entry `start` and ends where the next entry `end` starts, copying
    /// `redirect`'s source in a redirect blob. The entries already advance
    /// in every layer ([`BlobMetadata::validate_tables`]).
    fn new(
        index: usize,
        start: BlobMetadataChunkGroup,
        end: BlobMetadataChunkGroup,
        redirect: Option<BlobMetadataChunkGroupRedirect>,
    ) -> Self {
        Self {
            index: index as u32,
            compressed_offset: start.compressed_offset,
            compressed_size: (end.compressed_offset - start.compressed_offset) as u32,
            logical_block_offset: start.logical_block_offset,
            logical_block_count: end.logical_block_offset - start.logical_block_offset,
            first_chunk_index: start.first_chunk_index,
            chunk_count: end.first_chunk_index - start.first_chunk_index,
            uncompressed_size: start.uncompressed_size,
            uncompressed_crc32: start.uncompressed_crc32,
            redirect,
        }
    }

    /// The group's index in the table.
    pub fn index(&self) -> u32 {
        self.index
    }

    /// Byte offset of the compressed bytes within the data region.
    pub fn compressed_offset(&self) -> u64 {
        self.compressed_offset
    }

    /// Byte size of the compressed bytes, never zero.
    pub fn compressed_size(&self) -> u32 {
        self.compressed_size
    }

    /// Byte range of the compressed bytes within the data region.
    pub fn compressed_range(&self) -> Range<u64> {
        self.compressed_offset..self.compressed_offset + self.compressed_size as u64
    }

    /// Bytes the group decompresses to: the chunks' bytes back to back,
    /// never zero.
    pub fn uncompressed_size(&self) -> u32 {
        self.uncompressed_size
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

    /// crc32c of the uncompressed bytes, checked after decompression.
    pub fn uncompressed_crc32(&self) -> u32 {
        self.uncompressed_crc32
    }

    /// The source this group copies, in a redirect blob.
    pub fn redirect(&self) -> Option<BlobMetadataChunkGroupRedirect> {
        self.redirect
    }

    /// First 4KiB block of the group in the logical address space.
    pub fn logical_block_offset(&self) -> u64 {
        self.logical_block_offset as u64
    }

    /// 4KiB blocks the group spans: its chunks, each block aligned.
    pub fn logical_block_count(&self) -> u32 {
        self.logical_block_count
    }

    /// Start of the group in the logical address space, in bytes.
    pub fn logical_offset(&self) -> u64 {
        self.logical_block_offset() * EROFS_BLOCK_SIZE as u64
    }

    /// Bytes the group occupies in the logical address space: its blocks,
    /// padding included; [`Self::uncompressed_size`] is the bytes it decodes
    /// to.
    pub fn logical_size(&self) -> u64 {
        self.logical_block_count() as u64 * EROFS_BLOCK_SIZE as u64
    }

    /// Byte range of the group in the logical address space.
    pub fn logical_range(&self) -> Range<u64> {
        self.logical_offset()..self.logical_offset() + self.logical_size()
    }
}

// ChunkLengthTable

/// One ChunkLengthTable entry: the byte length of one chunk, never zero.
/// Every chunk of the blob has one, lone chunks included, in group order.
///
/// ```text
/// offset  size  field
///      0     4  length                     bytes of the chunk
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlobMetadataChunkLength(u32);

impl BlobMetadataEntry for BlobMetadataChunkLength {
    const SIZE: usize = 4;

    fn from_bytes(bytes: &[u8]) -> Self {
        Self(read_u32_at(bytes, 0))
    }

    fn write_to(&self, out: &mut Vec<u8>) {
        let mut data = [0u8; Self::SIZE];
        write_u32_at(&mut data, 0, self.0);
        out.extend_from_slice(&data);
    }
}

impl BlobMetadataChunkLength {
    /// Creates the entry of a chunk of `length` bytes.
    pub fn new(length: u32) -> Self {
        Self(length)
    }

    /// The chunk's length in bytes.
    pub fn get(self) -> u32 {
        self.0
    }
}

// ChunkGroupIndexTable

/// The ChunkGroupIndexTable header extension.
///
/// ```text
/// offset  size  field
///     16     1  blocks_per_chunk_group_index_bits    log2 of the blocks one entry covers,
///                                        at most max_blocks_per_chunk_group_bits
///     17     7  reserved                writers zero it, readers ignore it
/// ```
#[derive(Clone, Copy, Debug)]
struct BlobMetadataChunkGroupIndexTableHeaderExtension {
    blocks_per_chunk_group_index_bits: u8,
    reserved: [u8; 7],
}

impl BlobMetadataChunkGroupIndexTableHeaderExtension {
    /// On-disk size, behind the header.
    const SIZE: usize = 8;

    /// Creates the extension of a table whose entries each cover
    /// `blocks_per_chunk_group_index` blocks, rounded down to a power of two
    /// since only its log2 is stored.
    fn new(blocks_per_chunk_group_index: u32) -> Result<Self> {
        Ok(Self {
            blocks_per_chunk_group_index_bits: blocks_per_chunk_group_index.checked_ilog2().ok_or(
                Error::InvalidParameter(
                    "blob meta blocks per chunk group index is zero".to_string(),
                ),
            )? as u8,
            reserved: [0; 7],
        })
    }

    /// Read the extension behind the header of `table` in the file `bytes`.
    fn from_bytes(bytes: &[u8], table: &BlobMetadataTable) -> Self {
        let bytes = &bytes[table.header_extension_range(Self::SIZE)];
        Self {
            blocks_per_chunk_group_index_bits: read_u8_at(bytes, 0),
            reserved: read_bytes_at(bytes, 1),
        }
    }

    fn to_bytes(self) -> [u8; Self::SIZE] {
        let mut data = [0u8; Self::SIZE];
        write_u8_at(&mut data, 0, self.blocks_per_chunk_group_index_bits);
        write_bytes_at(&mut data, 1, &self.reserved);
        data
    }

    /// The blocks one index entry covers; a log2 past the u32 block space
    /// saturates, over every bound.
    fn blocks_per_chunk_group_index(&self) -> u32 {
        2u32.saturating_pow(self.blocks_per_chunk_group_index_bits.into())
    }
}

/// One ChunkGroupIndexTable entry: the chunk group covering the first
/// block of one index entry. The table has one entry per `bytes_per_chunk_group_index` of the
/// address space; see [`BlobMetadata::chunk_group_index_of`] for the
/// lookup it serves.
///
/// ```text
/// offset  size  field
///      0     4  chunk_group_index          index into ChunkGroupTable
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlobMetadataChunkGroupIndex(u32);

impl BlobMetadataEntry for BlobMetadataChunkGroupIndex {
    const SIZE: usize = 4;

    fn from_bytes(bytes: &[u8]) -> Self {
        Self(read_u32_at(bytes, 0))
    }

    fn write_to(&self, out: &mut Vec<u8>) {
        let mut data = [0u8; Self::SIZE];
        write_u32_at(&mut data, 0, self.0);
        out.extend_from_slice(&data);
    }
}

impl BlobMetadataChunkGroupIndex {
    /// The ChunkGroupIndexTable of the ChunkGroupTable `chunk_groups`,
    /// terminator included: the group covering the first block of each
    /// `blocks_per_chunk_group_index` blocks of the address space, which the
    /// terminator's start ends.
    fn from_chunk_group_table(
        chunk_groups: &[BlobMetadataChunkGroup],
        blocks_per_chunk_group_index: u32,
    ) -> Vec<Self> {
        let blocks_per_chunk_group_index = u64::from(blocks_per_chunk_group_index);
        let logical_block_count = chunk_groups
            .last()
            .map_or(0, |terminator| terminator.logical_block_offset);
        let count = u64::from(logical_block_count).div_ceil(blocks_per_chunk_group_index);
        let chunk_group_count = chunk_groups.len().saturating_sub(1);
        let mut chunk_group = 0usize;
        (0..count)
            .map(|index| {
                let start = index * blocks_per_chunk_group_index;
                while chunk_group + 1 < chunk_group_count
                    && u64::from(chunk_groups[chunk_group + 1].logical_block_offset) <= start
                {
                    chunk_group += 1;
                }
                Self(chunk_group as u32)
            })
            .collect()
    }

    /// The chunk group's index in ChunkGroupTable.
    pub fn get(self) -> u32 {
        self.0
    }
}

// ChunkGroupDigestTable

/// The ChunkGroupDigestTable header extension.
///
/// ```text
/// offset  size  field
///     16     1  algorithm               1 BLAKE3; an unknown value leaves
///                                       the blob undigested for this reader
///     17     7  reserved                writers zero it, readers ignore it
/// ```
#[derive(Clone, Copy, Debug)]
struct BlobMetadataChunkGroupDigestTableHeaderExtension {
    algorithm: u8,
    reserved: [u8; 7],
}

impl BlobMetadataChunkGroupDigestTableHeaderExtension {
    /// On-disk size, behind the header.
    const SIZE: usize = 8;

    /// Creates the extension of a table of [`BlobMetadataChunkGroupDigest`]
    /// entries, which are BLAKE3 by construction.
    fn new() -> Self {
        Self {
            algorithm: BlobMetadataDigester::BLAKE3_CODE,
            reserved: [0; 7],
        }
    }

    /// Read the extension behind the header of `table` in the file `bytes`.
    fn from_bytes(bytes: &[u8], table: &BlobMetadataTable) -> Self {
        let bytes = &bytes[table.header_extension_range(Self::SIZE)];
        Self {
            algorithm: read_u8_at(bytes, 0),
            reserved: read_bytes_at(bytes, 1),
        }
    }

    fn to_bytes(self) -> [u8; Self::SIZE] {
        let mut data = [0u8; Self::SIZE];
        write_u8_at(&mut data, 0, self.algorithm);
        write_bytes_at(&mut data, 1, &self.reserved);
        data
    }
}

/// One ChunkGroupDigestTable entry: the content digest of the chunk group
/// at the same index in ChunkGroupTable (see [`Self::from_chunk_digests`]).
///
/// ```text
/// offset  size  field
///      0    32  digest                     algorithm per the table header
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlobMetadataChunkGroupDigest([u8; Self::SIZE]);

impl BlobMetadataEntry for BlobMetadataChunkGroupDigest {
    const SIZE: usize = Self::SIZE;

    fn from_bytes(bytes: &[u8]) -> Self {
        Self(read_bytes_at(bytes, 0))
    }

    fn write_to(&self, out: &mut Vec<u8>) {
        let mut data = [0u8; Self::SIZE];
        write_bytes_at(&mut data, 0, &self.0);
        out.extend_from_slice(&data);
    }
}

impl BlobMetadataChunkGroupDigest {
    /// On-disk size of one entry: a BLAKE3 digest.
    pub const SIZE: usize = 32;

    /// BLAKE3 `derive_key` context separating multi-chunk group digests from
    /// plain content digests.
    const DERIVE_KEY_CONTEXT: &str = "nydus blob meta chunk group digest v1";

    /// Creates an entry for the chunk group at the same index in the group
    /// table.
    pub fn new(digest: [u8; Self::SIZE]) -> Self {
        Self(digest)
    }

    /// The digest, algorithm per the ChunkGroupDigestTable header.
    pub fn get(self) -> [u8; Self::SIZE] {
        self.0
    }

    /// The digest of a chunk group from the BLAKE3 digests of its chunks'
    /// exact bytes, in group order. A group of one chunk is named by that
    /// chunk's digest itself, so a content-addressed cache serves it by the
    /// chunk's content digest; a group of several chunks is named by a
    /// domain-separated BLAKE3 (`derive_key`) over the member digests, which
    /// costs no second pass over the bytes and separates group identity from
    /// plain content hashing. Collision resistance relies on BLAKE3. An
    /// empty slice is an error: a chunk group holds at least one chunk.
    pub fn from_chunk_digests(chunk_digests: &[[u8; Self::SIZE]]) -> Result<Self> {
        match chunk_digests {
            [] => Err(Error::InvalidParameter(
                "blob meta chunk group digest needs at least one chunk digest".to_string(),
            )),
            [only] => Ok(Self(*only)),
            many => {
                let mut hasher = blake3::Hasher::new_derive_key(Self::DERIVE_KEY_CONTEXT);
                for digest in many {
                    hasher.update(digest);
                }

                Ok(Self(hasher.finalize().into()))
            }
        }
    }
}

// ChunkGroupRedirectTable

/// One ChunkGroupRedirectTable entry: the chunk group of another blob of
/// the image that the chunk group at the same index copies. Present only
/// in a redirect blob (an `optimize` output), one entry per chunk group.
///
/// ```text
/// offset  size  field
///      0     2  source_blob_index         EROFS device slot of the source
///                                          blob, as wide as a chunk index
///                                          device_id; never zero, slot zero
///                                          is the bootstrap itself
///      2     2  reserved                  writers zero it, readers ignore it
///      4     4  source_chunk_group_index  the copied group within it
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlobMetadataChunkGroupRedirect {
    source_blob_index: u16,
    reserved: [u8; 2],
    source_chunk_group_index: u32,
}

impl BlobMetadataEntry for BlobMetadataChunkGroupRedirect {
    const SIZE: usize = 8;

    fn from_bytes(bytes: &[u8]) -> Self {
        Self {
            source_blob_index: read_u16_at(bytes, 0),
            reserved: read_bytes_at(bytes, 2),
            source_chunk_group_index: read_u32_at(bytes, 4),
        }
    }

    fn write_to(&self, out: &mut Vec<u8>) {
        let mut data = [0u8; Self::SIZE];
        write_u16_at(&mut data, 0, self.source_blob_index);
        write_bytes_at(&mut data, 2, &self.reserved);
        write_u32_at(&mut data, 4, self.source_chunk_group_index);
        out.extend_from_slice(&data);
    }
}

impl BlobMetadataChunkGroupRedirect {
    /// Names chunk group `source_chunk_group_index` of the blob in EROFS
    /// device slot `source_blob_index` (never zero) as the source.
    pub fn new(source_blob_index: u16, source_chunk_group_index: u32) -> Result<Self> {
        let redirect = Self {
            source_blob_index,
            reserved: [0; 2],
            source_chunk_group_index,
        };

        redirect.validate()?;
        Ok(redirect)
    }

    /// Validate that the source blob index is a device slot: slot zero is
    /// the bootstrap itself.
    fn validate(&self) -> Result<()> {
        if self.source_blob_index == 0 {
            return Err(Error::InvalidImage(
                "blob meta redirect source blob index must be non-zero".to_string(),
            ));
        }

        Ok(())
    }

    /// EROFS device slot of the source blob.
    pub fn source_blob_index(&self) -> u16 {
        self.source_blob_index
    }

    /// The copied chunk group within the source blob.
    pub fn source_chunk_group_index(&self) -> u32 {
        self.source_chunk_group_index
    }
}

/// The header every blob meta starts with, sealed with a crc32c over the
/// whole serialized metadata. It holds only what concerns the whole file;
/// each table's parameters live in that table's own header extension.
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
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlobMetadataHeader {
    feature_compat: u32,
    feature_incompat: u32,
    crc32: u32,
    table_count: u16,
    reserved: [u8; 2],
}

impl BlobMetadataHeader {
    /// On-disk magic: 8 raw ASCII bytes ("NDBLMETA" = Nydus BLob META), written
    /// as-is so a hexdump of the file starts with the readable string. Same
    /// frozen `magic + feature_compat + feature_incompat + crc32` prefix as the
    /// blob footer (`NDFOOTER`), see [`crate::blob::flag`].
    pub const MAGIC: [u8; 8] = *b"NDBLMETA";

    /// The header's fixed on-disk size; the first table follows it.
    pub const SIZE: usize = 24;

    /// Byte range of the crc32 field within the header.
    const CRC32_FIELD: Range<usize> = 16..20;

    /// Every incompat bit this reader understands, none so far. A file
    /// setting a bit outside this mask was written by a newer nydus and is
    /// rejected by [`FeatureFlags::validate_incompat`].
    const INCOMPAT_SUPPORTED: u32 = 0;

    /// Creates the header sealing a blob meta whose `table_count` tables
    /// serialize, padded to the block, to `tables` right behind it.
    fn new(feature_compat: u32, feature_incompat: u32, table_count: u16, tables: &[u8]) -> Self {
        let mut header = Self {
            feature_compat,
            feature_incompat,
            crc32: 0,
            table_count,
            reserved: [0; 2],
        };

        header.crc32 = Self::compute_crc32(&header.to_bytes(), tables);
        header
    }

    /// Parse the header from the start of the file `bytes`: the raw bytes
    /// are checked first (`validate_bytes`), then the decoded fields
    /// (`validate_fields`).
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Self::validate_bytes(bytes)?;
        let header = Self {
            feature_compat: read_u32_at(bytes, 8),
            feature_incompat: read_u32_at(bytes, 12),
            crc32: read_u32_at(bytes, Self::CRC32_FIELD.start),
            table_count: read_u16_at(bytes, 20),
            reserved: read_bytes_at(bytes, 22),
        };

        header.validate_fields()?;
        Ok(header)
    }

    /// Serialize the header into its on-disk bytes.
    fn to_bytes(self) -> [u8; Self::SIZE] {
        let mut data = [0u8; Self::SIZE];
        write_bytes_at(&mut data, 0, &Self::MAGIC);
        write_u32_at(&mut data, 8, self.feature_compat);
        write_u32_at(&mut data, 12, self.feature_incompat);
        write_u32_at(&mut data, Self::CRC32_FIELD.start, self.crc32);
        write_u16_at(&mut data, 20, self.table_count);
        write_bytes_at(&mut data, 22, &self.reserved);
        data
    }

    /// Validate the raw on-disk bytes before decoding them: a whole number
    /// of blocks holding at least the header, the magic, and the stored
    /// crc32 against [`Self::compute_crc32`] over the whole file.
    fn validate_bytes(bytes: &[u8]) -> Result<()> {
        if !Self::has_magic(bytes) {
            return Err(Error::InvalidImage("invalid blob meta magic".to_string()));
        }

        if bytes.len() < Self::SIZE || bytes.len() % EROFS_BLOCK_SIZE as usize != 0 {
            return Err(Error::InvalidImage(format!(
                "blob meta size {} is not a whole number of 4 KiB blocks",
                bytes.len()
            )));
        }

        let (header, tables) = bytes.split_at(Self::SIZE);
        if read_u32_at(header, Self::CRC32_FIELD.start)
            != Self::compute_crc32(&read_bytes_at(header, 0), tables)
        {
            return Err(Error::InvalidImage("blob meta crc32 mismatch".to_string()));
        }

        Ok(())
    }

    /// Validate the intrinsic field invariants: unknown incompat bits
    /// reject, before anything behind the header is trusted, since they may
    /// change the table walk itself.
    fn validate_fields(&self) -> Result<()> {
        FeatureFlags::from_bits(self.feature_incompat).validate_incompat(Self::INCOMPAT_SUPPORTED)
    }

    /// Whether `bytes` starts with the blob meta magic.
    pub fn has_magic(bytes: &[u8]) -> bool {
        bytes.starts_with(&Self::MAGIC)
    }

    /// crc32c over the header bytes with the crc32 field treated as zero,
    /// continued over the `tables` behind it: the writer seals `to_bytes()`
    /// with it, the reader verifies the raw incoming bytes against it.
    fn compute_crc32(header: &[u8; Self::SIZE], tables: &[u8]) -> u32 {
        let mut zeroed = *header;
        zeroed[Self::CRC32_FIELD].fill(0);
        crc32c_append(crc32c(&zeroed), tables)
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
}

/// A nydus blob's metadata: how the blob's logical address space maps onto
/// its compressed data, sealed with a crc32c in the header. Serialized
/// it is the `.blob.meta` sidecar file, and verbatim the blob meta region
/// of a full blob (see [`super::footer::BlobFooter`]).
///
/// The file: the [`BlobMetadataHeader`], then every table at the next
/// 8-byte boundary, zero padded to a
/// 4 KiB multiple:
///
/// ```text
/// ┌────────┬─────────────────┬──────────────────┬──────────────────────┬───────────────────────┬─────────────────────────┬─────┐
/// │ header │ ChunkGroupTable │ ChunkLengthTable │ ChunkGroupIndexTable │ ChunkGroupDigestTable │ ChunkGroupRedirectTable │ pad │
/// └────────┴─────────────────┴──────────────────┴──────────────────────┴───────────────────────┴─────────────────────────┴─────┘
/// 0        24                                                           optional                redirect blobs only
///
/// table                    type  presence             header extension                                  entries
/// ChunkGroupTable             1  required             BlobMetadataChunkGroupTableHeaderExtension        (groups + 1) * 24 B,
///                                                                                                       the last one a terminator
/// ChunkLengthTable            2  required             none                                              chunks * 4 B
/// ChunkGroupIndexTable        3  required             BlobMetadataChunkGroupIndexTableHeaderExtension   ceil(blocks / blocks per
///                                                                                                       index) * 4 B
/// ChunkGroupDigestTable       4  optional             BlobMetadataChunkGroupDigestTableHeaderExtension  groups * 32 B
/// ChunkGroupRedirectTable     5  redirect blobs only  none                                              groups * 8 B
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
/// block (see [`BlobMetadataChunkGroupExtent`]). ChunkGroupIndexTable names the
/// group covering each index entry's first block, the coarse cousin of
/// EROFS's `z_erofs_lcluster_index`: an address resolves with one table read
/// and at most one forward correction; every non-final group covers at
/// least one index entry. A redirect blob (an `optimize` output) copies chunk
/// groups of other blobs of the image byte for byte and names their
/// sources in ChunkGroupRedirectTable.
#[derive(Debug)]
pub struct BlobMetadata {
    // The header, and the compressor every chunk group is stored with.
    header: BlobMetadataHeader,
    compressor: BlobMetadataCompressor,
    // Every table in file order, then the supported ones as typed entries,
    // in type order.
    tables: Vec<BlobMetadataTable>,
    chunk_groups: BlobMetadataEntries<BlobMetadataChunkGroup>,
    chunk_lengths: BlobMetadataEntries<BlobMetadataChunkLength>,
    chunk_group_indexes: BlobMetadataEntries<BlobMetadataChunkGroupIndex>,
    chunk_group_digests: Option<BlobMetadataEntries<BlobMetadataChunkGroupDigest>>,
    chunk_group_redirects: Option<BlobMetadataEntries<BlobMetadataChunkGroupRedirect>>,
    // The geometry and the counts, from the header extensions and the
    // ChunkGroupTable terminator.
    chunk_group_count: u32,
    max_blocks_per_chunk_group: u32,
    blocks_per_chunk_group_index: u32,
    chunk_count: u32,
    logical_block_count: u32,
    // The ChunkGroupDigestTable algorithm when this reader does not know it.
    unsupported_digest_algorithm: Option<u8>,
    // The bytes every table above is read from.
    bytes: Vec<u8>,
}

impl BlobMetadata {
    /// Default file chunk size: the largest chunk a file is cut into, 2 MiB.
    /// The builder controls chunk group sizes separately, so changing the file
    /// chunk size does not change the default chunk group minimum size.
    pub const DEFAULT_CHUNK_SIZE: u32 = 2 * 1024 * 1024;

    /// File-name suffix of a blob meta sidecar file (`<blob>.blob.meta`).
    pub const SUFFIX: &str = ".blob.meta";

    /// Largest `max_blocks_per_chunk_group`: 2 GiB keeps byte sizes within a `u32`.
    const MAX_BLOCKS_PER_CHUNK_GROUP: u32 = 1 << 19;

    /// Creates validated metadata from a writer's tables: serializes them,
    /// builds ChunkGroupIndexTable, and parses the result back with every
    /// check of [`Self::from_bytes`]. `max_blocks_per_chunk_group` bounds a
    /// group in blocks and `blocks_per_chunk_group_index` is the blocks one
    /// index entry covers, both stored as their log2, the index entry at
    /// most the group, every non-final group covering at least one index
    /// entry. `chunk_groups` is ChunkGroupTable, laid out back to back from
    /// zero and ending in its terminator; `chunk_lengths` lists every chunk,
    /// lone ones included, in group order; `chunk_group_digests` is one
    /// BLAKE3 entry per group, or empty for a blob without a
    /// ChunkGroupDigestTable; `chunk_group_redirects` is one entry per
    /// group of a redirect blob, else empty.
    pub fn new(
        max_blocks_per_chunk_group: u32,
        blocks_per_chunk_group_index: u32,
        compressor: BlobMetadataCompressor,
        chunk_groups: Vec<BlobMetadataChunkGroup>,
        chunk_lengths: Vec<BlobMetadataChunkLength>,
        chunk_group_digests: Vec<BlobMetadataChunkGroupDigest>,
        chunk_group_redirects: Vec<BlobMetadataChunkGroupRedirect>,
    ) -> Result<Self> {
        let chunk_group_header_extension = BlobMetadataChunkGroupTableHeaderExtension::new(
            max_blocks_per_chunk_group,
            compressor,
        )?
        .to_bytes();
        let chunk_group_index_header_extension =
            BlobMetadataChunkGroupIndexTableHeaderExtension::new(blocks_per_chunk_group_index)?
                .to_bytes();
        let chunk_group_indexes = BlobMetadataChunkGroupIndex::from_chunk_group_table(
            &chunk_groups,
            blocks_per_chunk_group_index,
        );

        let mut tables = vec![
            BlobMetadataTable::new(
                BlobMetadataTableType::CHUNK_GROUP,
                Some(chunk_group_header_extension.len()),
                0,
                0,
                BlobMetadataChunkGroup::SIZE,
                chunk_groups.len(),
            )?
            .to_bytes(Some(&chunk_group_header_extension), &chunk_groups),
            BlobMetadataTable::new(
                BlobMetadataTableType::CHUNK_LENGTH,
                None,
                0,
                0,
                BlobMetadataChunkLength::SIZE,
                chunk_lengths.len(),
            )?
            .to_bytes(None, &chunk_lengths),
            BlobMetadataTable::new(
                BlobMetadataTableType::CHUNK_GROUP_INDEX,
                Some(chunk_group_index_header_extension.len()),
                0,
                0,
                BlobMetadataChunkGroupIndex::SIZE,
                chunk_group_indexes.len(),
            )?
            .to_bytes(
                Some(&chunk_group_index_header_extension),
                &chunk_group_indexes,
            ),
        ];
        if !chunk_group_digests.is_empty() {
            let header_extension =
                BlobMetadataChunkGroupDigestTableHeaderExtension::new().to_bytes();
            tables.push(
                BlobMetadataTable::new(
                    BlobMetadataTableType::CHUNK_GROUP_DIGEST,
                    Some(header_extension.len()),
                    0,
                    0,
                    BlobMetadataChunkGroupDigest::SIZE,
                    chunk_group_digests.len(),
                )?
                .to_bytes(Some(&header_extension), &chunk_group_digests),
            );
        }
        if !chunk_group_redirects.is_empty() {
            tables.push(
                BlobMetadataTable::new(
                    BlobMetadataTableType::CHUNK_GROUP_REDIRECT,
                    None,
                    0,
                    0,
                    BlobMetadataChunkGroupRedirect::SIZE,
                    chunk_group_redirects.len(),
                )?
                .to_bytes(None, &chunk_group_redirects),
            );
        }

        Self::from_tables(&tables)
    }

    /// Parse a blob meta from its bytes, which it keeps and reads its tables
    /// from: the header, which seals the whole file, then the table walk,
    /// the supported tables as typed entries, their header extensions and
    /// the ChunkGroupTable terminator, then the field and table checks.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        let raw = bytes.as_slice();
        let header = BlobMetadataHeader::from_bytes(raw)?;
        let tables = Self::tables_from_bytes(raw, header.table_count)?;
        let table = |table_type: BlobMetadataTableType| {
            tables
                .iter()
                .find(|table| table.table_type == table_type)
                .copied()
        };
        let required = |table_type: BlobMetadataTableType| {
            table(table_type)
                .ok_or_else(|| Error::InvalidImage(format!("blob meta lacks its {table_type}")))
        };

        let chunk_groups =
            required(BlobMetadataTableType::CHUNK_GROUP)?.entries_of::<BlobMetadataChunkGroup>()?;
        let chunk_lengths = required(BlobMetadataTableType::CHUNK_LENGTH)?
            .entries_of::<BlobMetadataChunkLength>()?;
        let chunk_group_indexes = required(BlobMetadataTableType::CHUNK_GROUP_INDEX)?
            .entries_of::<BlobMetadataChunkGroupIndex>()?;
        let chunk_group_digests = table(BlobMetadataTableType::CHUNK_GROUP_DIGEST)
            .map(BlobMetadataTable::entries_of::<BlobMetadataChunkGroupDigest>)
            .transpose()?;
        let chunk_group_redirects = table(BlobMetadataTableType::CHUNK_GROUP_REDIRECT)
            .map(BlobMetadataTable::entries_of::<BlobMetadataChunkGroupRedirect>)
            .transpose()?;

        let chunk_group_header_extension =
            BlobMetadataChunkGroupTableHeaderExtension::from_bytes(raw, &chunk_groups.table);
        let chunk_group_index_header_extension =
            BlobMetadataChunkGroupIndexTableHeaderExtension::from_bytes(
                raw,
                &chunk_group_indexes.table,
            );
        // A ChunkGroupDigestTable of an algorithm this reader does not know
        // leaves the blob undigested for it.
        let (chunk_group_digests, unsupported_digest_algorithm) = match chunk_group_digests {
            None => (None, None),
            Some(entries) => {
                let algorithm = BlobMetadataChunkGroupDigestTableHeaderExtension::from_bytes(
                    raw,
                    &entries.table,
                )
                .algorithm;
                match BlobMetadataDigester::from_code(algorithm) {
                    None => (None, Some(algorithm)),
                    Some(_) => (Some(entries), None),
                }
            }
        };
        // The terminator names the data region's size, the address space's
        // block count and the chunk count.
        let Some(chunk_group_count) = chunk_groups.len().checked_sub(1) else {
            return Err(Error::InvalidImage(
                "blob meta ChunkGroupTable lacks its terminator".to_string(),
            ));
        };
        let terminator = chunk_groups.get(raw, chunk_group_count);

        let blob_metadata = Self {
            header,
            compressor: chunk_group_header_extension.compressor()?,
            tables,
            chunk_groups,
            chunk_lengths,
            chunk_group_indexes,
            chunk_group_digests,
            chunk_group_redirects,
            chunk_group_count: chunk_group_count as u32,
            max_blocks_per_chunk_group: chunk_group_header_extension.max_blocks_per_chunk_group(),
            blocks_per_chunk_group_index: chunk_group_index_header_extension
                .blocks_per_chunk_group_index(),
            chunk_count: terminator.first_chunk_index,
            logical_block_count: terminator.logical_block_offset,
            unsupported_digest_algorithm,
            bytes,
        };

        blob_metadata.validate_fields()?;
        blob_metadata.validate_tables()?;
        Ok(blob_metadata)
    }

    /// Read a blob meta from a file, with the same checks as
    /// [`Self::from_bytes`].
    pub fn from_path(path: &Path) -> Result<Self> {
        let bytes = fs::read(path)
            .with_context(|| format!("failed to read blob meta: {}", path.display()))?;
        Self::from_bytes(bytes)
    }

    /// Lay out the header and the serialized `tables` in order, each at the
    /// next 8-byte boundary, zero-pad to a 4 KiB multiple, seal the crc32,
    /// then parse the result with the same checks as [`Self::from_bytes`].
    fn from_tables(tables: &[Vec<u8>]) -> Result<Self> {
        let table_count = u16::try_from(tables.len())
            .map_err(|_| Error::Overflow("blob meta holds more than 65535 tables".to_string()))?;
        let mut bytes = vec![0u8; BlobMetadataHeader::SIZE];
        for table in tables {
            bytes.resize(bytes.len().next_multiple_of(8), 0);
            bytes.extend_from_slice(table);
        }
        bytes.resize(bytes.len().next_multiple_of(EROFS_BLOCK_SIZE as usize), 0);
        let header = BlobMetadataHeader::new(0, 0, table_count, &bytes[BlobMetadataHeader::SIZE..]);
        write_bytes_at(&mut bytes, 0, &header.to_bytes());
        Self::from_bytes(bytes)
    }

    /// The `table_count` table headers behind the blob meta header in the
    /// file `bytes`: back to back, each at the next 8-byte boundary, of
    /// distinct nonzero types, the last ending at the padded file end.
    fn tables_from_bytes(bytes: &[u8], table_count: u16) -> Result<Vec<BlobMetadataTable>> {
        let mut tables: Vec<BlobMetadataTable> = Vec::with_capacity(usize::from(table_count));
        let mut end = BlobMetadataHeader::SIZE;
        for _ in 0..table_count {
            let table = BlobMetadataTable::from_bytes(bytes, end.next_multiple_of(8))?;
            if table.table_type.0 == 0
                || tables
                    .iter()
                    .any(|seen| seen.table_type == table.table_type)
            {
                return Err(Error::InvalidImage(format!(
                    "blob meta table at {:#x} has a zero or duplicate type {}",
                    table.offset, table.table_type
                )));
            }
            end = table.range().end;
            tables.push(table);
        }
        if align_up_u64(end as u64, EROFS_BLOCK_SIZE as u64) != Some(bytes.len() as u64) {
            return Err(Error::InvalidImage(format!(
                "blob meta size mismatch: the tables end at {end}, the file holds {} bytes",
                bytes.len()
            )));
        }
        Ok(tables)
    }

    /// Write the serialized metadata verbatim, including tables this reader
    /// does not know.
    pub fn write_to(&self, writer: &mut dyn Write) -> Result<()> {
        writer.write_all(&self.bytes)?;
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

    /// Validate the intrinsic field invariants: the geometry, the counts
    /// and every table's entry count, needing nothing beyond the header
    /// extensions, the terminator and the table headers.
    fn validate_fields(&self) -> Result<()> {
        // Geometry: a chunk group is bounded so byte sizes fit a u32, and an
        // index entry covers at most a chunk group.
        if self.max_blocks_per_chunk_group > Self::MAX_BLOCKS_PER_CHUNK_GROUP {
            return Err(Error::InvalidImage(format!(
                "blob meta max blocks per chunk group {} exceeds {}",
                self.max_blocks_per_chunk_group,
                Self::MAX_BLOCKS_PER_CHUNK_GROUP
            )));
        }
        if self.blocks_per_chunk_group_index > self.max_blocks_per_chunk_group {
            return Err(Error::InvalidImage(format!(
                "blob meta blocks per chunk group index {} exceeds the max blocks per chunk group {}",
                self.blocks_per_chunk_group_index, self.max_blocks_per_chunk_group
            )));
        }

        // Counts: an empty blob has no groups, chunks or blocks, any other
        // blob has all three, with at most one group per chunk.
        if self.chunk_group_count == 0 {
            if self.chunk_count != 0 || self.logical_block_count != 0 {
                return Err(Error::InvalidImage(format!(
                    "blob meta has no chunk groups but {} chunks and {} blocks",
                    self.chunk_count, self.logical_block_count
                )));
            }
        } else if self.chunk_count == 0 || self.logical_block_count == 0 {
            return Err(Error::InvalidImage(format!(
                "blob meta has {} chunk groups but {} chunks and {} blocks",
                self.chunk_group_count, self.chunk_count, self.logical_block_count
            )));
        }
        if self.chunk_group_count > self.chunk_count {
            return Err(Error::InvalidImage(format!(
                "blob meta names {} chunk groups among {} chunks",
                self.chunk_group_count, self.chunk_count
            )));
        }

        // Tables: one entry per chunk, per index entry, or per chunk group.
        if self.chunk_lengths.len() != self.chunk_count as usize {
            return Err(Error::InvalidImage(format!(
                "blob meta ChunkLengthTable holds {} entries, the chunk groups name {}",
                self.chunk_lengths.len(),
                self.chunk_count
            )));
        }
        let chunk_group_index_count = u64::from(self.logical_block_count)
            .div_ceil(u64::from(self.blocks_per_chunk_group_index));
        if self.chunk_group_indexes.len() as u64 != chunk_group_index_count {
            return Err(Error::InvalidImage(format!(
                "blob meta ChunkGroupIndexTable holds {} entries for {chunk_group_index_count} index entries",
                self.chunk_group_indexes.len()
            )));
        }
        if self
            .chunk_group_digests
            .is_some_and(|entries| entries.len() != self.chunk_group_count as usize)
        {
            return Err(Error::InvalidImage(
                "blob meta ChunkGroupDigestTable does not hold one entry per chunk group"
                    .to_string(),
            ));
        }
        if self
            .chunk_group_redirects
            .is_some_and(|entries| entries.len() != self.chunk_group_count as usize)
        {
            return Err(Error::InvalidImage(
                "blob meta ChunkGroupRedirectTable does not hold one entry per chunk group"
                    .to_string(),
            ));
        }

        Ok(())
    }

    /// Validate the tables against each other: ChunkGroupTable starts at
    /// zero, advances in every layer and ends at a terminator without
    /// payload, then every chunk group against its chunks, its redirect and
    /// its index entries ([`Self::validate_chunk_group`]).
    fn validate_tables(&self) -> Result<()> {
        let first = self.chunk_group_entry(0);
        if first.compressed_offset != 0
            || first.logical_block_offset != 0
            || first.first_chunk_index != 0
        {
            return Err(Error::InvalidImage(
                "blob meta chunk groups must start at offset zero, block zero and chunk zero"
                    .to_string(),
            ));
        }
        let terminator = self.chunk_group_entry(self.chunk_group_count());
        if terminator.uncompressed_size != 0 || terminator.uncompressed_crc32 != 0 {
            return Err(Error::InvalidImage(format!(
                "blob meta chunk group terminator carries payload {} and crc {}",
                terminator.uncompressed_size, terminator.uncompressed_crc32
            )));
        }
        for index in 0..self.chunk_group_count() {
            let (start, end) = (
                self.chunk_group_entry(index),
                self.chunk_group_entry(index + 1),
            );
            if end.compressed_offset <= start.compressed_offset
                || end.logical_block_offset <= start.logical_block_offset
                || end.first_chunk_index <= start.first_chunk_index
            {
                return Err(Error::InvalidImage(format!(
                    "blob meta chunk group {index} is empty or overlaps its successor"
                )));
            }
        }

        for index in 0..self.chunk_group_count() {
            self.validate_chunk_group(index)?;
        }
        Ok(())
    }

    /// Validate chunk group `index`, whose entries already advance: its
    /// chunks are nonempty, add up to its uncompressed size and fill its
    /// blocks, which stay within the group bound and, but for the last
    /// group, cover an index entry; its compressed bytes fit a `u32` and
    /// never exceed the uncompressed, and equal them in a plain blob; its
    /// redirect names a device slot; and every index entry whose first
    /// block it holds names it.
    fn validate_chunk_group(&self, index: usize) -> Result<()> {
        let (start, end) = (
            self.chunk_group_entry(index),
            self.chunk_group_entry(index + 1),
        );
        let compressed_size = end.compressed_offset - start.compressed_offset;
        let uncompressed_size = u64::from(start.uncompressed_size);
        let logical_block_count = u64::from(end.logical_block_offset - start.logical_block_offset);
        let blocks_per_chunk_group_index = u64::from(self.blocks_per_chunk_group_index);

        let mut chunk_bytes = 0u64;
        let mut chunk_blocks = 0u64;
        for chunk in start.first_chunk_index..end.first_chunk_index {
            let length = u64::from(self.chunk_length_entry(chunk as usize).get());
            if length == 0 {
                return Err(Error::InvalidImage(format!(
                    "blob meta chunk group {index} chunk_lengths must be non-empty"
                )));
            }
            chunk_bytes += length;
            chunk_blocks += length.div_ceil(EROFS_BLOCK_SIZE as u64);
        }
        if chunk_bytes != uncompressed_size {
            return Err(Error::InvalidImage(format!(
                "blob meta chunk group {index} chunk_lengths add up to {chunk_bytes} bytes, not its {uncompressed_size}-byte payload"
            )));
        }
        if chunk_blocks != logical_block_count {
            return Err(Error::InvalidImage(format!(
                "blob meta chunk group {index} spans {logical_block_count} blocks, its chunks {chunk_blocks}"
            )));
        }
        if logical_block_count > u64::from(self.max_blocks_per_chunk_group) {
            return Err(Error::InvalidImage(format!(
                "blob meta chunk group {index} spans {logical_block_count} blocks, more than the {} allowed per chunk group",
                self.max_blocks_per_chunk_group
            )));
        }
        if index + 1 < self.chunk_group_count()
            && logical_block_count < blocks_per_chunk_group_index
        {
            return Err(Error::InvalidImage(format!(
                "blob meta chunk group {index} spans {logical_block_count} blocks, under the {blocks_per_chunk_group_index} per chunk group index entry"
            )));
        }

        if compressed_size > u64::from(u32::MAX) {
            return Err(Error::Overflow(format!(
                "blob meta chunk group {index} compressed size exceeds u32"
            )));
        }
        if compressed_size > uncompressed_size {
            return Err(Error::InvalidImage(format!(
                "blob meta chunk group {index} encoded payload exceeds its {uncompressed_size}-byte payload"
            )));
        }
        if self.compressor == BlobMetadataCompressor::None && compressed_size != uncompressed_size {
            return Err(Error::InvalidImage(format!(
                "blob meta plain chunk group {index} must store its full payload"
            )));
        }

        if let Some(redirect) = self.chunk_group_redirect_entry(index) {
            redirect.validate()?;
        }

        let first_index =
            u64::from(start.logical_block_offset).div_ceil(blocks_per_chunk_group_index);
        let end_index = u64::from(end.logical_block_offset).div_ceil(blocks_per_chunk_group_index);
        for entry in first_index..end_index {
            if self.chunk_group_index_entry(entry as usize).get() as usize != index {
                return Err(Error::InvalidImage(format!(
                    "blob meta ChunkGroupIndexTable entry {entry} does not name chunk group {index}"
                )));
            }
        }
        Ok(())
    }

    /// The header, exactly as stored.
    pub fn header(&self) -> &BlobMetadataHeader {
        &self.header
    }

    /// The compressor every chunk group is stored with.
    pub fn compressor(&self) -> BlobMetadataCompressor {
        self.compressor
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
            .map(|table| &self.bytes[table.range()])
    }

    /// The chunk group at `index`, `None` past the table.
    pub fn chunk_group(&self, index: usize) -> Option<BlobMetadataChunkGroupExtent> {
        if index >= self.chunk_group_count() {
            return None;
        }
        Some(BlobMetadataChunkGroupExtent::new(
            index,
            self.chunk_group_entry(index),
            self.chunk_group_entry(index + 1),
            self.chunk_group_redirect_entry(index),
        ))
    }

    /// The chunk groups in order.
    pub fn chunk_groups(&self) -> impl Iterator<Item = BlobMetadataChunkGroupExtent> + '_ {
        (0..self.chunk_group_count()).filter_map(move |index| self.chunk_group(index))
    }

    /// Number of chunk groups.
    pub fn chunk_group_count(&self) -> usize {
        self.chunk_group_count as usize
    }

    /// The chunk group covering the address `logical_offset`, `None` beyond
    /// the blob: one ChunkGroupIndexTable read and at most one forward
    /// correction, without a search or an allocated runtime index.
    pub fn chunk_group_index_of(&self, logical_offset: u64) -> Option<usize> {
        let block = logical_offset / EROFS_BLOCK_SIZE as u64;
        if block >= u64::from(self.logical_block_count) {
            return None;
        }
        let index = (block / u64::from(self.blocks_per_chunk_group_index)) as usize;
        let mut chunk_group = self.chunk_group_index_entry(index).get() as usize;
        if block >= u64::from(self.chunk_group_entry(chunk_group + 1).logical_block_offset) {
            chunk_group += 1;
        }
        Some(chunk_group)
    }

    /// The most 4KiB blocks a chunk group covers.
    pub fn max_blocks_per_chunk_group(&self) -> u32 {
        self.max_blocks_per_chunk_group
    }

    /// The most bytes of the address space a chunk group covers: a lone
    /// chunk is at most a file chunk, a pack may cover more. Bounds the
    /// decode scratch a reader needs for any group.
    pub fn max_bytes_per_chunk_group(&self) -> u32 {
        self.max_blocks_per_chunk_group * EROFS_BLOCK_SIZE
    }

    /// Byte length of chunk `index`, lone chunks included; `None` past
    /// ChunkLengthTable.
    pub fn chunk_length(&self, index: usize) -> Option<u32> {
        (index < self.chunk_count()).then(|| self.chunk_length_entry(index).get())
    }

    /// Number of chunks, lone chunks included.
    pub fn chunk_count(&self) -> usize {
        self.chunk_count as usize
    }

    /// Number of ChunkGroupIndexTable entries.
    pub fn chunk_group_index_count(&self) -> usize {
        self.chunk_group_indexes.len()
    }

    /// 4KiB blocks per ChunkGroupIndexTable entry.
    pub fn blocks_per_chunk_group_index(&self) -> u32 {
        self.blocks_per_chunk_group_index
    }

    /// Bytes of the address space one ChunkGroupIndexTable entry covers;
    /// every non-final group covers at least this much.
    pub fn bytes_per_chunk_group_index(&self) -> u32 {
        self.blocks_per_chunk_group_index * EROFS_BLOCK_SIZE
    }

    /// The digest of chunk group `index`, `None` past the table or without
    /// a supported digester.
    pub fn chunk_group_digest(&self, index: usize) -> Option<BlobMetadataChunkGroupDigest> {
        let entries = self
            .chunk_group_digests
            .filter(|entries| index < entries.len())?;
        Some(entries.get(&self.bytes, index))
    }

    /// The digest table, one entry per chunk group; empty without a
    /// supported digester.
    pub fn chunk_group_digests(&self) -> Vec<BlobMetadataChunkGroupDigest> {
        (0..self.chunk_group_digest_count())
            .filter_map(|index| self.chunk_group_digest(index))
            .collect()
    }

    /// Number of digest entries: every chunk group with a supported
    /// digester, else zero.
    pub fn chunk_group_digest_count(&self) -> usize {
        self.chunk_group_digests.map_or(0, |entries| entries.len())
    }

    /// The digest algorithm, `None` without a ChunkGroupDigestTable this
    /// reader supports.
    pub fn digester(&self) -> BlobMetadataDigester {
        if self.chunk_group_digests.is_some() {
            BlobMetadataDigester::Blake3
        } else {
            BlobMetadataDigester::None
        }
    }

    /// The algorithm code of a ChunkGroupDigestTable this reader does not
    /// know, which leaves the blob undigested for it; a reader that must
    /// verify digests fails on it instead of skipping the verification.
    pub fn unsupported_digest_algorithm(&self) -> Option<u8> {
        self.unsupported_digest_algorithm
    }

    /// The redirect table, one entry per chunk group of a redirect blob;
    /// empty otherwise.
    pub fn chunk_group_redirects(&self) -> Vec<BlobMetadataChunkGroupRedirect> {
        (0..self.chunk_group_redirect_count())
            .filter_map(|index| self.chunk_group_redirect_entry(index))
            .collect()
    }

    /// Number of redirect entries: every chunk group of a redirect blob.
    pub fn chunk_group_redirect_count(&self) -> usize {
        self.chunk_group_redirects
            .map_or(0, |entries| entries.len())
    }

    /// Whether the blob is an `optimize` output whose chunk groups copy
    /// other blobs' groups, named by its ChunkGroupRedirectTable.
    pub fn is_redirect(&self) -> bool {
        self.chunk_group_redirects.is_some()
    }

    /// Total size of the logical address space in 4KiB blocks: the groups'
    /// blocks back to back.
    pub fn logical_block_count(&self) -> u64 {
        u64::from(self.logical_block_count)
    }

    /// Total size of the logical address space in bytes, every group's
    /// blocks back to back.
    pub fn logical_size(&self) -> u64 {
        self.logical_block_count() * EROFS_BLOCK_SIZE as u64
    }

    /// Bytes all chunk groups decode to: the chunks' bytes without padding.
    pub fn uncompressed_size(&self) -> u64 {
        (0..self.chunk_group_count())
            .map(|index| u64::from(self.chunk_group_entry(index).uncompressed_size))
            .sum()
    }

    /// End of the last chunk group's compressed range: the data region's
    /// size.
    pub fn compressed_size(&self) -> u64 {
        self.chunk_group_entry(self.chunk_group_count())
            .compressed_offset
    }

    /// The full serialized size, 4KiB aligned.
    pub fn size(&self) -> u64 {
        self.bytes.len() as u64
    }

    /// Whether `chunk_group` is stored plain: its compressed bytes are its
    /// uncompressed bytes. The builder stores a group plain when compression
    /// would not shrink it, so equal sizes mean plain.
    pub fn is_plain(&self, chunk_group: &BlobMetadataChunkGroupExtent) -> bool {
        self.compressor == BlobMetadataCompressor::None
            || chunk_group.compressed_size() == chunk_group.uncompressed_size()
    }

    /// The chunks of chunk group `chunk_group_index` in address order, as
    /// `(ordinal within the group, absolute byte offset, length)`. Empty
    /// past the table.
    pub fn chunk_group_chunks(
        &self,
        chunk_group_index: usize,
    ) -> impl Iterator<Item = (usize, u64, u32)> + '_ {
        let (chunks, mut block) = match self.chunk_group(chunk_group_index) {
            None => (0..0, 0),
            Some(chunk_group) => (
                chunk_group.chunk_range(),
                chunk_group.logical_block_offset(),
            ),
        };
        let first = chunks.start;
        chunks.map(move |chunk| {
            let length = self.chunk_length_entry(chunk).get();
            let offset = block * EROFS_BLOCK_SIZE as u64;
            block += u64::from(length).div_ceil(EROFS_BLOCK_SIZE as u64);
            (chunk - first, offset, length)
        })
    }

    /// Scatter chunk group `chunk_group_index`'s uncompressed `payload` back
    /// into the padded address space, calling `sink` with every chunk's
    /// absolute byte offset and bytes, in address order. Each chunk starts
    /// on its own block, so the bytes between chunks are tail padding the
    /// cache leaves zero.
    pub fn for_each_decoded_chunk<'payload>(
        &self,
        chunk_group_index: usize,
        payload: &'payload [u8],
        sink: &mut dyn FnMut(u64, &'payload [u8]) -> io::Result<()>,
    ) -> io::Result<()> {
        let chunk_group = self.chunk_group(chunk_group_index).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "chunk group index out of range",
            )
        })?;
        if payload.len() != chunk_group.uncompressed_size() as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "decoded chunk group length does not match its payload size",
            ));
        }
        let mut position = 0usize;
        for (_, offset, length) in self.chunk_group_chunks(chunk_group_index) {
            let end = position + length as usize;
            sink(offset, &payload[position..end])?;
            position = end;
        }
        Ok(())
    }

    /// ChunkGroupTable entry `index`, the terminator for `chunk_group_count`.
    fn chunk_group_entry(&self, index: usize) -> BlobMetadataChunkGroup {
        self.chunk_groups.get(&self.bytes, index)
    }

    /// ChunkLengthTable entry `index`; the caller keeps it below `chunk_count`.
    fn chunk_length_entry(&self, index: usize) -> BlobMetadataChunkLength {
        self.chunk_lengths.get(&self.bytes, index)
    }

    /// ChunkGroupIndexTable entry `index`; the caller keeps it below the count.
    fn chunk_group_index_entry(&self, index: usize) -> BlobMetadataChunkGroupIndex {
        self.chunk_group_indexes.get(&self.bytes, index)
    }

    /// ChunkGroupRedirectTable entry `index`, `None` past the table or
    /// without one.
    fn chunk_group_redirect_entry(&self, index: usize) -> Option<BlobMetadataChunkGroupRedirect> {
        self.chunk_group_redirects
            .filter(|entries| index < entries.len())
            .map(|entries| entries.get(&self.bytes, index))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn digest(bytes: &[u8]) -> [u8; BlobMetadataChunkGroupDigest::SIZE] {
        *blake3::hash(bytes).as_bytes()
    }

    /// A group as a writer knows it before laying it out: its lengths, the
    /// crc of its payload and, in a redirect blob, its source.
    #[derive(Clone, Copy)]
    struct Spec {
        compressed_size: u32,
        chunk_count: u32,
        uncompressed_size: u32,
        uncompressed_crc32: u32,
        redirect: Option<BlobMetadataChunkGroupRedirect>,
    }

    fn spec(
        compressed_size: u32,
        chunk_count: u32,
        uncompressed_size: u32,
        uncompressed_crc32: u32,
        redirect: Option<BlobMetadataChunkGroupRedirect>,
    ) -> Spec {
        Spec {
            compressed_size,
            chunk_count,
            uncompressed_size,
            uncompressed_crc32,
            redirect,
        }
    }

    /// Lay `specs` out back to back into ChunkGroupTable, terminator
    /// included, and ChunkGroupRedirectTable; `chunk_lengths` lists every
    /// chunk in group order.
    fn layout(
        specs: &[Spec],
        chunk_lengths: &[u32],
    ) -> (
        Vec<BlobMetadataChunkGroup>,
        Vec<BlobMetadataChunkGroupRedirect>,
    ) {
        let mut chunk_groups = Vec::with_capacity(specs.len() + 1);
        let mut redirects = Vec::new();
        let (mut compressed_offset, mut logical_block_offset, mut first_chunk_index) = (0, 0, 0);
        for spec in specs {
            chunk_groups.push(BlobMetadataChunkGroup::new(
                compressed_offset,
                logical_block_offset,
                first_chunk_index,
                spec.uncompressed_size,
                spec.uncompressed_crc32,
            ));
            redirects.extend(spec.redirect);
            compressed_offset += u64::from(spec.compressed_size);
            let chunks =
                first_chunk_index as usize..(first_chunk_index + spec.chunk_count) as usize;
            logical_block_offset += chunk_lengths.get(chunks).map_or(0, |run| {
                run.iter().map(|len| len.div_ceil(EROFS_BLOCK_SIZE)).sum()
            });
            first_chunk_index += spec.chunk_count;
        }
        chunk_groups.push(BlobMetadataChunkGroup::new(
            compressed_offset,
            logical_block_offset,
            first_chunk_index,
            0,
            0,
        ));
        (chunk_groups, redirects)
    }

    fn reseal(mut bytes: Vec<u8>) -> Vec<u8> {
        let (header, tables) = bytes.split_at(BlobMetadataHeader::SIZE);
        let crc32 = BlobMetadataHeader::compute_crc32(&read_bytes_at(header, 0), tables);
        write_u32_at(&mut bytes, BlobMetadataHeader::CRC32_FIELD.start, crc32);
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
    fn plain_chunk_group(payload: &[u8], chunk_count: usize) -> Spec {
        spec(
            payload.len() as u32,
            chunk_count as u32,
            payload.len() as u32,
            crc32c(payload),
            None,
        )
    }

    fn layered(
        max_bytes_per_chunk_group: u32,
        bytes_per_chunk_group_index: Option<u32>,
        specs: Vec<Spec>,
        chunk_lengths: Vec<u32>,
        digests: Vec<BlobMetadataChunkGroupDigest>,
    ) -> Result<BlobMetadata> {
        let (chunk_groups, redirects) = layout(&specs, &chunk_lengths);
        BlobMetadata::new(
            max_bytes_per_chunk_group / EROFS_BLOCK_SIZE,
            bytes_per_chunk_group_index.unwrap_or(EROFS_BLOCK_SIZE) / EROFS_BLOCK_SIZE,
            BlobMetadataCompressor::None,
            chunk_groups,
            chunk_lengths
                .into_iter()
                .map(BlobMetadataChunkLength::new)
                .collect(),
            digests,
            redirects,
        )
    }

    /// Fixture: 64 KiB (16 blocks) per chunk group at most, 4 KiB per chunk
    /// group index entry.
    /// Groups: pack A [100, 5000] (3 blocks), pack B [40, 6000, 1] (4
    /// blocks), lone C 20000 (5 blocks), lone D 65536 (16 blocks), pack E
    /// [1, 1] (2 blocks): 30 blocks and 30 index entries.
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
        let chunk_groups = vec![
            plain_chunk_group(&payloads[0], 2),
            plain_chunk_group(&payloads[1], 3),
            plain_chunk_group(&payloads[2], 1),
            plain_chunk_group(&payloads[3], 1),
            plain_chunk_group(&payloads[4], 2),
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
        .map(|chunk_group| {
            let digests: Vec<[u8; BlobMetadataChunkGroupDigest::SIZE]> =
                chunk_group.iter().map(|chunk| digest(chunk)).collect();
            BlobMetadataChunkGroupDigest::from_chunk_digests(&digests).unwrap()
        })
        .collect();
        let meta = layered(64 * 1024, Some(4096), chunk_groups, chunk_lengths, digests).unwrap();
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
        // ChunkGroupTable header fields: 64 KiB per group is 16 blocks (bits 4), no
        // compressor; ChunkGroupIndexTable: one block per index (bits 0);
        // ChunkGroupDigestTable: BLAKE3.
        assert_eq!(&raw[24 + 16..24 + 18], &[4, 0]);
        assert_eq!(raw[248 + 16], 0);
        assert_eq!(raw[392 + 16], 1);
        // Entries: the second group starts at block 3; the terminator holds
        // 30 blocks and 9 chunks.
        let first_chunk_group = entries(&meta)[0];
        assert_eq!(read_u32_at(&raw, 48 + 24 + 8), 3);
        assert_eq!(read_u32_at(&raw, 48 + 5 * 24 + 8), 30);
        assert_eq!(read_u32_at(&raw, 48 + 5 * 24 + 12), 9);
        assert_eq!(
            read_u32_at(&raw, 48 + 16),
            first_chunk_group.uncompressed_size
        );
        assert_eq!(
            read_u32_at(&raw, 48 + 20),
            first_chunk_group.uncompressed_crc32
        );
        assert_eq!(read_u32_at(&raw, 208), 100);
        assert_eq!(read_u32_at(&raw, 272 + 3 * 4), 1);
        assert_eq!(meta.max_blocks_per_chunk_group(), 16);
        assert_eq!(meta.blocks_per_chunk_group_index(), 1);

        // Reserved fields and padding are ignored but sealed: the header
        // reserved field, the ChunkGroupTable header reserved bytes, table
        // alignment padding and the tail.
        for offset in [22, 24 + 18, 24 + 23, 244, 4095] {
            let mut ignored = raw.clone();
            ignored[offset] = 1;
            assert!(BlobMetadata::from_bytes(ignored.clone()).is_err());
            assert!(
                BlobMetadata::from_bytes(reseal(ignored)).is_ok(),
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
            assert!(BlobMetadata::from_bytes(reseal(compat)).is_ok());
            let mut incompat = raw.clone();
            write_u32_at(&mut incompat, 12, bit);
            let err = BlobMetadata::from_bytes(reseal(incompat)).unwrap_err();
            assert!(err.to_string().contains("incompat"), "{err}");
        }
        // The same rules hold within a table header.
        let chunk_group_table = table_offset(&meta, BlobMetadataTableType::CHUNK_GROUP);
        let mut compat = raw.clone();
        write_u16_at(&mut compat, chunk_group_table + 4, 1 << 15);
        assert!(BlobMetadata::from_bytes(reseal(compat)).is_ok());
        let mut incompat = raw.clone();
        write_u16_at(&mut incompat, chunk_group_table + 6, 1);
        let err = BlobMetadata::from_bytes(reseal(incompat)).unwrap_err();
        assert!(
            err.to_string().contains("table ChunkGroupTable incompat"),
            "{err}"
        );
    }

    #[test]
    fn unknown_tables_follow_their_incompat_bits() {
        let (meta, _) = fixture();
        let tables = split(&meta);
        let unknown = |kind: u16, incompat: u16| {
            let entries = [BlobMetadataChunkLength(0x5a5a_5a5a); 5];
            let mut table = BlobMetadataTable::new(
                BlobMetadataTableType(kind),
                None,
                0,
                0,
                BlobMetadataChunkLength::SIZE,
                entries.len(),
            )
            .unwrap()
            .to_bytes(None, &entries);
            write_u16_at(&mut table, 6, incompat);
            table
        };
        let with = |extra: Vec<u8>| {
            let mut tables = tables.clone();
            tables.push(extra);
            BlobMetadata::from_tables(&tables)
        };

        // An unknown table without incompat bits is skipped and kept
        // verbatim.
        let extension = unknown(0x100, 0);
        let loaded = with(extension.clone()).unwrap();
        assert_eq!(entries(&loaded), entries(&meta));
        assert_eq!(
            loaded.table_bytes(BlobMetadataTableType(0x100)),
            Some(&extension[..])
        );
        let bytes = raw(&loaded);
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
        let err = with(unknown(0x100, 1 << 15)).unwrap_err();
        assert!(
            err.to_string().contains("blob meta table 0x100 incompat"),
            "{err}"
        );

        let rejects = |parsed: Result<BlobMetadata>, expected: &str| {
            let err = parsed.unwrap_err();
            assert!(err.to_string().contains(expected), "{expected}: {err}");
        };
        rejects(with(unknown(2, 0)), "duplicate");
        rejects(with(unknown(0, 0)), "zero or duplicate");
        let mut without_chunks = tables.clone();
        without_chunks.remove(1);
        rejects(
            BlobMetadata::from_tables(&without_chunks),
            "lacks its ChunkLengthTable",
        );

        let raw = raw(&meta);
        let digest_table = table_offset(&meta, BlobMetadataTableType::CHUNK_GROUP_DIGEST);
        let mut past = raw.clone();
        write_u32_at(&mut past, digest_table + 12, 1000);
        rejects(BlobMetadata::from_bytes(reseal(past)), "size mismatch");
        let mut grown = raw.clone();
        grown.resize(8192, 0);
        rejects(BlobMetadata::from_bytes(reseal(grown)), "size mismatch");
        // A table count beyond the tables reads the zero padding as a table.
        let mut overcounted = raw.clone();
        write_u16_at(&mut overcounted, 20, 5);
        rejects(
            BlobMetadata::from_bytes(reseal(overcounted)),
            "header size 0",
        );
    }

    #[test]
    fn wider_tables_are_read_through_their_declared_sizes() {
        let (meta, _) = fixture();
        let widened: Vec<_> = split(&meta)
            .into_iter()
            .map(|bytes| widen(&bytes, 8))
            .collect();
        let loaded = BlobMetadata::from_tables(&widened).unwrap();
        assert_eq!(entries(&loaded), entries(&meta));
        assert_eq!(chunk_group_indexes(&loaded), chunk_group_indexes(&meta));
        assert_eq!(loaded.chunk_group_digests(), meta.chunk_group_digests());
        assert_eq!(loaded.max_blocks_per_chunk_group(), 16);
        assert_eq!(loaded.blocks_per_chunk_group_index(), 1);
        for index in 0..9 {
            assert_eq!(loaded.chunk_length(index), meta.chunk_length(index));
        }
        for offset in (0..meta.logical_size()).step_by(1000) {
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
        let err = BlobMetadata::from_bytes(reseal(narrow)).unwrap_err();
        assert!(
            err.to_string()
                .contains("ChunkGroupDigestTable entry size 16 is below 32"),
            "{err}"
        );
    }

    #[test]
    fn table_header_fields_are_validated() {
        let (meta, _) = fixture();
        let raw = raw(&meta);
        let chunk_group_table = table_offset(&meta, BlobMetadataTableType::CHUNK_GROUP);
        let chunk_group_index_table = table_offset(&meta, BlobMetadataTableType::CHUNK_GROUP_INDEX);
        let digest_table = table_offset(&meta, BlobMetadataTableType::CHUNK_GROUP_DIGEST);
        let mutate = |offset: usize, value: u8| {
            let mut bytes = raw.clone();
            bytes[offset] = value;
            BlobMetadata::from_bytes(reseal(bytes))
        };
        let err = mutate(chunk_group_table + 16, 20).unwrap_err();
        assert!(
            err.to_string()
                .contains("max blocks per chunk group 1048576 exceeds"),
            "{err}"
        );
        let err = mutate(chunk_group_table + 17, 9).unwrap_err();
        assert!(err.to_string().contains("compressor 9"), "{err}");
        let err = mutate(chunk_group_index_table + 16, 5).unwrap_err();
        assert!(
            err.to_string()
                .contains("blocks per chunk group index 32 exceeds"),
            "{err}"
        );
        let err = mutate(chunk_group_table + 2, 20).unwrap_err();
        assert!(err.to_string().contains("header size 20"), "{err}");
        let err = mutate(digest_table + 2, 16).unwrap_err();
        assert!(
            err.to_string()
                .contains("ChunkGroupDigestTable header extension is shorter than its 8 bytes"),
            "{err}"
        );

        // An unknown digest algorithm leaves the blob undigested.
        let loaded = mutate(digest_table + 16, 9).unwrap();
        assert_eq!(loaded.digester(), BlobMetadataDigester::None);
        assert_eq!(loaded.chunk_group_digest_count(), 0);
        assert!(loaded.chunk_group_digests().is_empty());
        assert_eq!(loaded.unsupported_digest_algorithm(), Some(9));
        assert_eq!(meta.unsupported_digest_algorithm(), None);
    }

    #[test]
    fn round_trips_through_bytes_and_a_saved_sidecar() {
        let (meta, chunks_data) = fixture();
        assert_eq!(meta.chunk_group_count(), 5);
        assert_eq!(meta.chunk_count(), 9);
        assert_eq!(meta.logical_block_count(), 30);
        assert_eq!(meta.logical_size(), 30 * EROFS_BLOCK_SIZE as u64);
        assert_eq!(meta.uncompressed_size(), 5100 + 6041 + 20000 + 65536 + 2);
        assert_eq!(meta.compressed_size(), 5100 + 6041 + 20000 + 65536 + 2);
        assert_eq!(meta.bytes_per_chunk_group_index(), 4096);
        assert_eq!(meta.max_bytes_per_chunk_group(), 64 * 1024);
        assert_eq!(meta.chunk_group_index_count(), 30);
        let raw = raw(&meta);
        assert_eq!(raw.len(), 4096);
        let loaded = BlobMetadata::from_bytes(raw.clone()).unwrap();
        assert_eq!(entries(&loaded), entries(&meta));
        assert_eq!(loaded.chunk_group_digests(), meta.chunk_group_digests());
        assert_eq!(chunk_group_indexes(&loaded), chunk_group_indexes(&meta));
        assert!(loaded.chunk_group_redirects().is_empty());

        let chunk_group = loaded.chunk_group(1).unwrap();
        assert_eq!(chunk_group.compressed_range(), 5100..11141);
        assert!(chunk_group.chunk_count() > 1);
        assert_eq!(chunk_group.chunk_count(), 3);
        assert_eq!(chunk_group.chunk_range(), 2..5);
        assert_eq!(
            chunk_group.logical_range(),
            3 * EROFS_BLOCK_SIZE as u64..7 * EROFS_BLOCK_SIZE as u64
        );
        assert_eq!(chunk_group.uncompressed_size(), 6041);
        assert!(loaded.is_plain(&chunk_group));
        assert_eq!(
            chunk_group.uncompressed_crc32(),
            crc32c(&chunks_data[2..5].concat())
        );
        assert!(chunk_group.redirect().is_none());
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
        assert_eq!(lone.chunk_count(), 1);
        assert_eq!(lone.chunk_count(), 1);
        assert_eq!(lone.chunk_range(), 5..6);
        assert_eq!(
            lone.logical_range(),
            7 * EROFS_BLOCK_SIZE as u64..12 * EROFS_BLOCK_SIZE as u64
        );
        assert_eq!(
            loaded.chunk_group_chunks(2).collect::<Vec<_>>(),
            vec![(0, 7 * EROFS_BLOCK_SIZE as u64, 20000)]
        );
        assert_eq!(loaded.chunk_length(6), Some(65536));
        assert_eq!(loaded.chunk_length(9), None);

        let dir = tempdir().unwrap();
        let path = dir.path().join("m.blob.meta");
        meta.save(&path).unwrap();
        let saved = BlobMetadata::from_path(&path).unwrap();
        assert_eq!(entries(&saved), entries(&meta));
        assert!(saved.chunk_group(usize::MAX).is_none());
        assert_eq!(saved.chunk_group_chunks(usize::MAX).count(), 0);
        assert_eq!(
            (0..9)
                .map(|i| saved.chunk_length(i).unwrap())
                .collect::<Vec<_>>(),
            vec![100, 5000, 40, 6000, 1, 20000, 65536, 1, 1]
        );
        assert_eq!(saved.chunk_group_digests().len(), 5);
        // Lone groups carry their chunk's digest, packs a derived one.
        assert_eq!(
            saved.chunk_group_digest(2).unwrap().get(),
            digest(&chunks_data[5])
        );
        assert_eq!(
            saved.chunk_group_digest(1).unwrap(),
            BlobMetadataChunkGroupDigest::from_chunk_digests(&[
                digest(&chunks_data[2]),
                digest(&chunks_data[3]),
                digest(&chunks_data[4])
            ])
            .unwrap()
        );
        assert!(!saved.is_redirect());
        assert_eq!(
            saved.chunk_group_chunks(4).collect::<Vec<_>>(),
            vec![
                (0, 28 * EROFS_BLOCK_SIZE as u64, 1),
                (1, 29 * EROFS_BLOCK_SIZE as u64, 1)
            ]
        );

        // A flipped byte fails the seal.
        let mut dirty = raw.clone();
        dirty[100] ^= 1;
        assert!(BlobMetadata::from_bytes(dirty.clone())
            .unwrap_err()
            .to_string()
            .contains("crc32"));
    }

    #[test]
    fn chunk_group_digest_is_the_chunk_digest_alone_and_derived_for_packs() {
        let (a, b) = (digest(b"a"), digest(b"b"));
        assert!(BlobMetadataChunkGroupDigest::from_chunk_digests(&[]).is_err());
        assert_eq!(
            BlobMetadataChunkGroupDigest::from_chunk_digests(&[a])
                .unwrap()
                .get(),
            a
        );
        let pack = BlobMetadataChunkGroupDigest::from_chunk_digests(&[a, b]).unwrap();
        // Order matters, and a pack digest is not the plain hash of the
        // concatenated digests (domain-separated), nor a member digest.
        assert_ne!(
            pack,
            BlobMetadataChunkGroupDigest::from_chunk_digests(&[b, a]).unwrap()
        );
        assert_ne!(pack.get(), digest(&[a, b].concat()));
        assert_ne!(pack.get(), a);
        assert_eq!(
            pack,
            BlobMetadataChunkGroupDigest::from_chunk_digests(&[a, b]).unwrap()
        );
    }

    #[test]
    fn offsets_map_to_groups_through_the_chunk_group_index_table() {
        let (meta, _) = fixture();
        // One index entry per block; group boundaries are 0, 3, 7, 12, 28.
        let chunk_groups_by_index = chunk_group_indexes(&meta);
        assert_eq!(chunk_groups_by_index.len(), 30);
        assert_eq!(chunk_groups_by_index[0], 0);
        assert_eq!(chunk_groups_by_index[3], 1);
        assert_eq!(chunk_groups_by_index[28], 4);
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
        for (block, chunk_group) in expect {
            let offset = block * EROFS_BLOCK_SIZE as u64;
            assert_eq!(
                meta.chunk_group_index_of(offset),
                Some(chunk_group),
                "block {block}"
            );
            assert_eq!(
                meta.chunk_group_index_of(offset + EROFS_BLOCK_SIZE as u64 - 1),
                Some(chunk_group),
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
        assert!(BlobMetadata::from_bytes(reseal(tampered))
            .unwrap_err()
            .to_string()
            .contains("ChunkGroupIndexTable"));

        // The smallest legal blocks per chunk group index also uses the direct table.
        let (chunk_groups, chunk_lengths): (Vec<_>, Vec<u32>) = {
            let (meta, _) = fixture();
            (
                meta.chunk_groups()
                    .map(|chunk_group| {
                        spec(
                            chunk_group.compressed_size(),
                            chunk_group.chunk_count(),
                            chunk_group.uncompressed_size(),
                            chunk_group.uncompressed_crc32(),
                            None,
                        )
                    })
                    .collect(),
                (0..9).map(|i| meta.chunk_length(i).unwrap()).collect(),
            )
        };
        let plain = layered(64 * 1024, None, chunk_groups, chunk_lengths, vec![]).unwrap();
        assert_eq!(plain.chunk_group_index_count(), 30);
        assert_eq!(plain.bytes_per_chunk_group_index(), 4096);
        for (block, chunk_group) in expect {
            assert_eq!(
                plain.chunk_group_index_of(block * EROFS_BLOCK_SIZE as u64),
                Some(chunk_group)
            );
        }
        assert_eq!(
            plain.chunk_group_index_of(30 * EROFS_BLOCK_SIZE as u64),
            None
        );
    }

    #[test]
    fn blocks_per_chunk_group_index_bound_every_chunk_group_but_the_last() {
        // 8 KiB per index (2 blocks): a one-block group in the middle is
        // rejected, at the end it is fine.
        let big = vec![7u8; 8192];
        let small = vec![8u8; 100];
        let ok = vec![plain_chunk_group(&big, 1), plain_chunk_group(&small, 1)];
        let meta = layered(16384, Some(8192), ok, vec![8192, 100], vec![]).unwrap();
        assert_eq!(meta.chunk_group_index_count(), 2);
        assert_eq!(
            meta.chunk_group_index_of(2 * EROFS_BLOCK_SIZE as u64),
            Some(1)
        );
        let bad = vec![plain_chunk_group(&small, 1), plain_chunk_group(&big, 1)];
        assert!(layered(16384, Some(8192), bad, vec![100, 8192], vec![])
            .unwrap_err()
            .to_string()
            .contains("per chunk group index entry"));
        // The blocks per chunk group index is at least one block and at most the group bound.
        for bytes_per_chunk_group_index in [3000, 2048, 32768] {
            let chunk_groups = vec![plain_chunk_group(&big, 1)];
            assert!(layered(
                16384,
                Some(bytes_per_chunk_group_index),
                chunk_groups,
                vec![8192],
                vec![]
            )
            .is_err());
        }
    }

    #[test]
    fn chunk_table_uses_u32_for_all_lengths() {
        // Small and large chunks share the same four-byte encoding.
        let a = vec![1u8; 70000];
        let b = vec![2u8; 100];
        let payload = [a.clone(), b.clone()].concat();
        let chunk_groups = vec![plain_chunk_group(&payload, 2)];
        let meta = layered(
            256 * 1024,
            Some(4096),
            chunk_groups,
            vec![70000, 100],
            vec![],
        )
        .unwrap();
        let mut raw = Vec::new();
        meta.write_to(&mut raw).unwrap();
        let loaded = BlobMetadata::from_bytes(raw.clone()).unwrap();
        assert_eq!(loaded.chunk_length(0), Some(70000));
        assert_eq!(
            loaded.chunk_group_chunks(0).collect::<Vec<_>>(),
            vec![(0, 0, 70000), (1, 18 * EROFS_BLOCK_SIZE as u64, 100)]
        );
        let dir = tempdir().unwrap();
        let path = dir.path().join("w.blob.meta");
        meta.save(&path).unwrap();
        let saved = BlobMetadata::from_path(&path).unwrap();
        assert_eq!(saved.chunk_length(0), Some(70000));
        assert_eq!(saved.chunk_length(1), Some(100));
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
        for chunk_group in 0..5 {
            for (_, offset, len) in meta.chunk_group_chunks(chunk_group) {
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
        let loaded = BlobMetadata::from_bytes(raw.clone()).unwrap();
        assert_eq!(loaded.logical_size(), 0);
        assert_eq!(loaded.compressed_size(), 0);
        assert_eq!(loaded.chunk_group_index_count(), 0);
        assert_eq!(loaded.chunk_group_index_of(0), None);
        assert_eq!(entries(&loaded).len(), 1);
    }

    #[test]
    fn redirect_blobs_carry_a_source_per_chunk_group() {
        let (source, chunks) = fixture();
        // Copy the source's groups 4 and 0, in that order, as blob 3's.
        let copied = [4usize, 0];
        let mut specs = Vec::new();
        let mut chunk_lengths = Vec::new();
        let mut digests = Vec::new();
        for &index in &copied {
            let chunk_group = source.chunk_group(index).unwrap();
            specs.push(spec(
                chunk_group.compressed_size(),
                chunk_group.chunk_count(),
                chunk_group.uncompressed_size(),
                chunk_group.uncompressed_crc32(),
                Some(BlobMetadataChunkGroupRedirect::new(3, index as u32).unwrap()),
            ));
            chunk_lengths.extend(
                chunk_group
                    .chunk_range()
                    .map(|i| source.chunk_length(i).unwrap()),
            );
            digests.push(source.chunk_group_digest(index).unwrap());
        }
        let meta = layered(64 * 1024, None, specs, chunk_lengths, digests).unwrap();
        assert!(meta.is_redirect());
        assert_eq!(meta.chunk_group_redirect_count(), 2);
        assert_eq!(meta.chunk_count(), 4);
        assert_eq!(meta.logical_block_count(), 5);
        assert_eq!(
            meta.tables()
                .iter()
                .map(|table| (table.table_type().get(), table.feature_incompat()))
                .collect::<Vec<_>>(),
            vec![(1, 0), (2, 0), (3, 0), (4, 0), (5, 0)]
        );

        let raw = raw(&meta);
        let loaded = BlobMetadata::from_bytes(raw.clone()).unwrap();
        assert!(loaded.is_redirect());
        let first = loaded.chunk_group(0).unwrap();
        let redirect = first.redirect().unwrap();
        assert_eq!(redirect.source_blob_index(), 3);
        assert_eq!(redirect.source_chunk_group_index(), 4);
        assert_eq!(first.compressed_range(), 0..2);
        assert_eq!(first.logical_range(), 0..2 * EROFS_BLOCK_SIZE as u64);
        assert_eq!(first.uncompressed_crc32(), crc32c(&chunks[7..].concat()));
        let second = loaded.chunk_group(1).unwrap();
        assert_eq!(second.redirect().unwrap().source_chunk_group_index(), 0);
        assert_eq!(
            second.logical_range(),
            2 * EROFS_BLOCK_SIZE as u64..5 * EROFS_BLOCK_SIZE as u64
        );
        let dir = tempdir().unwrap();
        let path = dir.path().join("r.blob.meta");
        meta.save(&path).unwrap();
        assert_eq!(
            BlobMetadata::from_path(&path)
                .unwrap()
                .chunk_group_redirects(),
            meta.chunk_group_redirects()
        );

        // A zeroed source blob index is rejected on both sides; the
        // reserved half of an entry is ignored.
        assert!(BlobMetadataChunkGroupRedirect::new(0, 1).is_err());
        let redirects = entries_offset(&meta, BlobMetadataTableType::CHUNK_GROUP_REDIRECT);
        assert_eq!(read_u16_at(&raw, redirects), 3);
        assert_eq!(read_u32_at(&raw, redirects + 4), 4);
        let mut zeroed = raw.clone();
        write_u16_at(&mut zeroed, redirects, 0);
        assert!(BlobMetadata::from_bytes(reseal(zeroed)).is_err());
        let mut reserved = raw.clone();
        write_u16_at(&mut reserved, redirects + 2, 0xffff);
        assert!(BlobMetadata::from_bytes(reseal(reserved)).is_ok());
        // ChunkGroupRedirectTable holds one entry per chunk group.
        let mut short = split(&meta);
        let table = &mut short[4];
        write_u32_at(table, 12, 1);
        table.truncate(table.len() - 8);
        let err = BlobMetadata::from_tables(&short).unwrap_err();
        assert!(err.to_string().contains("ChunkGroupRedirectTable"), "{err}");

        // ChunkGroupRedirectTable covers every group or none.
        let payload = chunks[5].clone();
        let mixed = vec![
            plain_chunk_group(&payload, 1),
            spec(
                20000,
                1,
                20000,
                crc32c(&payload),
                Some(BlobMetadataChunkGroupRedirect::new(1, 1).unwrap()),
            ),
        ];
        assert!(layered(64 * 1024, None, mixed, vec![20000, 20000], vec![])
            .unwrap_err()
            .to_string()
            .contains("ChunkGroupRedirectTable"));
    }

    #[test]
    fn compressed_chunk_groups_round_trip() {
        let payload = vec![7u8; 100];
        let meta = BlobMetadata::new(
            1,
            1,
            BlobMetadataCompressor::Zstd,
            vec![
                BlobMetadataChunkGroup::new(0, 0, 0, 100, crc32c(&payload)),
                BlobMetadataChunkGroup::new(10, 1, 1, 0, 0),
            ],
            vec![BlobMetadataChunkLength::new(100)],
            vec![],
            vec![],
        )
        .unwrap();
        assert!(!meta.is_redirect());
        assert!(!meta.is_plain(&meta.chunk_group(0).unwrap()));
        assert_eq!(meta.tables().len(), 3);
        let loaded = BlobMetadata::from_bytes(raw(&meta)).unwrap();
        assert_eq!(loaded.compressor(), BlobMetadataCompressor::Zstd);
        assert_eq!(loaded.digester(), BlobMetadataDigester::None);
        assert!(!loaded.is_redirect());
    }

    #[test]
    fn chunk_group_index_corrects_once_and_rejects_corruption() {
        let lengths = vec![3 * 4096, 4 * 4096, 100];
        let chunk_groups = lengths
            .iter()
            .map(|length| plain_chunk_group(&vec![1; *length as usize], 1))
            .collect();
        let meta = layered(32768, Some(8192), chunk_groups, lengths, vec![]).unwrap();
        let raw = raw(&meta);
        let directory = tempdir().unwrap();
        let path = directory.path().join("index.blob.meta");
        meta.save(&path).unwrap();
        let saved = BlobMetadata::from_path(&path).unwrap();
        for offset in 0..meta.logical_size() {
            let expected = if offset < 3 * EROFS_BLOCK_SIZE as u64 {
                0
            } else if offset < 7 * EROFS_BLOCK_SIZE as u64 {
                1
            } else {
                2
            };
            assert_eq!(saved.chunk_group_index_of(offset), Some(expected));
        }
        assert_eq!(saved.chunk_group_index_of(u64::MAX), None);
        drop(saved);
        for offset in [0, 12, 20, 21] {
            let mut invalid = raw.clone();
            invalid[offset] = 255;
            assert!(
                BlobMetadata::from_bytes(reseal(invalid)).is_err(),
                "{offset}"
            );
        }
        for length in [0, 23, 24, 55, 127, 4095] {
            assert!(BlobMetadata::from_bytes(raw[..length].to_vec()).is_err());
        }
        let chunk_group_index_offset =
            entries_offset(&meta, BlobMetadataTableType::CHUNK_GROUP_INDEX);
        for value in [1, u32::MAX] {
            let mut invalid = raw.clone();
            write_u32_at(&mut invalid, chunk_group_index_offset, value);
            let invalid = reseal(invalid);
            assert!(BlobMetadata::from_bytes(invalid.clone()).is_err());
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
        let chunk_groups = || {
            vec![
                plain_chunk_group(&payloads[0], 2),
                plain_chunk_group(&payloads[1], 3),
                plain_chunk_group(&payloads[2], 1),
                plain_chunk_group(&payloads[3], 1),
                plain_chunk_group(&payloads[4], 2),
            ]
        };
        let build = |chunk_groups: Vec<Spec>, chunk_lengths: Vec<u32>| {
            layered(64 * 1024, Some(4096), chunk_groups, chunk_lengths, vec![])
                .expect_err("expected rejection")
                .to_string()
        };

        // Members left over, or a group naming chunk_lengths past the table.
        assert!(build(chunk_groups(), [chunk_lengths(), vec![5]].concat())
            .contains("ChunkLengthTable holds"));
        let mut greedy = chunk_groups();
        greedy[4].chunk_count = 3;
        assert!(build(greedy, chunk_lengths()).contains("ChunkLengthTable holds"));
        // An empty group, or one that decodes to or from nothing.
        let mut empty = chunk_groups();
        empty[4].chunk_count = 0;
        assert!(build(empty, chunk_lengths()[..7].to_vec()).contains("empty or overlaps"));
        let mut nothing = chunk_groups();
        nothing[4].uncompressed_size = 0;
        assert!(build(nothing, chunk_lengths()).contains("add up"));
        let mut hollow = chunk_groups();
        hollow[4].compressed_size = 0;
        assert!(build(hollow, chunk_lengths()).contains("empty or overlaps"));
        let mut zero = chunk_lengths();
        zero[0] = 0;
        zero[1] = 5100;
        assert!(build(chunk_groups(), zero).contains("non-empty"));
        // Members that do not add up to the uncompressed size.
        let mut short = chunk_lengths();
        short[1] = 4999;
        assert!(build(chunk_groups(), short).contains("add up"));
        // A lone chunk over the group bound, or a pack over it in blocks.
        let over = vec![plain_chunk_group(&vec![1u8; 65537], 1)];
        assert!(build(over, vec![65537]).contains("more than the"));
        let wide = vec![plain_chunk_group(&vec![1u8; 17 * 4096], 17)];
        assert!(build(wide, vec![4096; 17]).contains("more than the"));
        // Compressed bytes larger than the uncompressed, or a plain blob that
        // does not store groups whole.
        let mut grown = chunk_groups();
        grown[0].compressed_size = 5101;
        assert!(build(grown, chunk_lengths()).contains("exceeds"));
        let mut partial = chunk_groups();
        partial[0].compressed_size = 5099;
        assert!(build(partial, chunk_lengths()).contains("full payload"));
        // A digest table that does not cover every group.
        assert!(layered(
            64 * 1024,
            Some(4096),
            chunk_groups(),
            chunk_lengths(),
            vec![BlobMetadataChunkGroupDigest::new([0; 32])]
        )
        .unwrap_err()
        .to_string()
        .contains("ChunkGroupDigestTable"));

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
            assert!(BlobMetadata::from_bytes(reseal(invalid)).is_err());
        }
        let mut invalid = raw.clone();
        invalid[table_offset(&meta, BlobMetadataTableType::CHUNK_GROUP_INDEX) + 16] = 1;
        assert!(BlobMetadata::from_bytes(reseal(invalid)).is_err());
    }
}

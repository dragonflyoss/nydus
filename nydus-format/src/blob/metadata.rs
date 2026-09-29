use crate::blob::algorithm::{BlobMetadataCompressor, BlobMetadataDigester};
use crate::blob::flag::FeatureFlags;
use crate::erofs::EROFS_BLOCK_SIZE;
use crate::error::{Context, Error, Result};
use crate::utils::le::{
    read_bytes_at, read_u16_at, read_u32_at, read_u64_at, read_u8_at, write_bytes_at, write_u16_at,
    write_u32_at, write_u64_at, write_u8_at,
};
use crc32c::{crc32c, crc32c_append};
use std::fmt;
use std::fs;
use std::io::Write;
use std::marker::PhantomData;
use std::ops::Range;
use std::path::Path;

/// The `type` field of a table header. Not an enum, since a reader keeps
/// and skips tables of types it does not know, so any value round-trips.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlobMetadataTableType(u16);

/// The five table types this reader knows.
impl BlobMetadataTableType {
    /// ChunkGroupTable, where every chunk group starts in the data region,
    /// the address space and ChunkLengthTable, plus a last entry holding the
    /// totals. Entries are [`BlobMetadataChunkGroup`].
    pub const CHUNK_GROUP: Self = Self(1);

    /// ChunkLengthTable, the byte length of every chunk of the blob in group
    /// order. Entries are [`BlobMetadataChunkLength`].
    pub const CHUNK_LENGTH: Self = Self(2);

    /// ChunkGroupIndexTable, the chunk group covering each stride of blocks
    /// of the address space, which resolves an address to its group in one
    /// read. Entries are [`BlobMetadataChunkGroupIndex`].
    pub const CHUNK_GROUP_INDEX: Self = Self(3);

    /// ChunkGroupDigestTable, the content digest of every chunk group,
    /// present when the writer digested them. Entries are
    /// [`BlobMetadataChunkGroupDigest`].
    pub const CHUNK_GROUP_DIGEST: Self = Self(4);

    /// ChunkGroupRedirectTable, the chunk group of another blob that every
    /// chunk group copies, present in redirect blobs only. Entries are
    /// [`BlobMetadataChunkGroupRedirect`].
    pub const CHUNK_GROUP_REDIRECT: Self = Self(5);

    /// The raw on-disk value.
    pub fn get(self) -> u16 {
        self.0
    }
}

/// Names tables in error messages.
impl fmt::Display for BlobMetadataTableType {
    /// The table's name, or the raw value in hex for an unknown type.
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

/// One table of the blob meta, a 16-byte header followed by the type's
/// optional header extension and then the entries.
///
/// ```text
/// ┌──────────────┬─────────────────────────────┬─────────┬─────┬─────────┐
/// │ header, 16 B │ header extension (optional) │ entry 0 │ ... │ entry n │
/// └──────────────┴─────────────────────────────┴─────────┴─────┴─────────┘
/// 0              16                            header_size  + entry_size each
///
/// offset  size  field
///      0     2  type                    see BlobMetadataTableType
///      2     2  header_size             16 plus the extension, a multiple of 8
///      4     2  feature_compat          unknown bits are ignored
///      6     2  feature_incompat        unknown bits reject the file, an
///                                       unknown type is skipped when zero
///      8     4  entry_size              bytes per entry
///     12     4  entry_count
/// ```
///
/// A newer writer appends header extension or entry fields and declares the
/// larger `header_size` or `entry_size`, and an older reader reads through
/// the declared sizes and never sees them (qcow2 header extensions, ext4
/// `i_extra_isize`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlobMetadataTable {
    offset: usize,
    table_type: BlobMetadataTableType,
    header_extension_size: Option<usize>,
    feature_compat: u16,
    feature_incompat: u16,
    entry_size: usize,
    entry_count: usize,
}

/// Writes and reads a table header, and locates the header extension and the
/// entries behind it.
impl BlobMetadataTable {
    /// The table header's fixed on-disk size, 16 bytes every table starts
    /// with, ahead of its optional header extension and its entries.
    pub const HEADER_SIZE: usize = 16;

    /// Every table offset and `header_size` is a multiple of this, keeping the
    /// entries' `u64` fields aligned.
    pub const ALIGNMENT: usize = 8;

    /// Every incompat bit this reader understands for a table, none yet.
    const INCOMPAT_SUPPORTED: u16 = 0;

    /// The `feature_compat` word a writer declares, no table feature yet.
    pub const DEFAULT_FEATURE_COMPAT: u16 = 0;

    /// The `feature_incompat` word a writer declares, no table feature yet.
    pub const DEFAULT_FEATURE_INCOMPAT: u16 = 0;

    /// Creates the header of a table a writer lays out at `offset`. The fields
    /// are checked, so a constructed header is valid by definition.
    fn new(
        offset: usize,
        table_type: BlobMetadataTableType,
        header_extension_size: Option<usize>,
        feature_compat: u16,
        feature_incompat: u16,
        entry_size: usize,
        entry_count: usize,
    ) -> Result<Self> {
        let table = Self {
            offset,
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

    /// Parse the table header at the next [`Self::ALIGNMENT`] at or after
    /// `offset` in the file `bytes`, where the previous table ended. The
    /// raw bytes are checked first (`validate_bytes`), then the decoded
    /// fields (`validate_fields`), then that the table lies within the file.
    fn from_bytes(bytes: &[u8], offset: usize) -> Result<Self> {
        let offset = offset.next_multiple_of(Self::ALIGNMENT);
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
        if table.range().end > bytes.len() {
            return Err(Error::InvalidImage(format!(
                "blob meta table {} at {offset:#x} runs past the file",
                table.table_type
            )));
        }

        Ok(table)
    }

    /// Serialize the table as this header, the `header_extension` when the
    /// type has one, then the `entries`.
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

    /// Validate the raw bytes before decoding them, a whole header at
    /// `offset` with an aligned `header_size`.
    fn validate_bytes(bytes: &[u8], offset: usize) -> Result<()> {
        if offset + Self::HEADER_SIZE > bytes.len() {
            return Err(Error::InvalidImage(format!(
                "blob meta table header at {offset:#x} is truncated"
            )));
        }

        let header_size = read_u16_at(bytes, offset + 2) as usize;
        if header_size < Self::HEADER_SIZE || header_size % Self::ALIGNMENT != 0 {
            return Err(Error::InvalidImage(format!(
                "blob meta table at {offset:#x} header size {header_size} is not a multiple of {} of at least {}",
                Self::ALIGNMENT,
                Self::HEADER_SIZE
            )));
        }

        Ok(())
    }

    /// Validate the intrinsic field invariants. Unknown incompat bits reject,
    /// and a known type's header extension is at least as large as this
    /// reader parses.
    fn validate_fields(&self) -> Result<()> {
        FeatureFlags::from_bits(u32::from(self.feature_incompat))
            .validate_incompat(u32::from(Self::INCOMPAT_SUPPORTED))
            .with_context(|| format!("blob meta table {} incompat flags", self.table_type))?;

        let required = match self.table_type {
            BlobMetadataTableType::CHUNK_GROUP => BlobMetadataChunkGroupTableHeaderExtension::SIZE,
            BlobMetadataTableType::CHUNK_GROUP_INDEX => {
                BlobMetadataChunkGroupIndexTableHeaderExtension::SIZE
            }
            BlobMetadataTableType::CHUNK_GROUP_DIGEST => {
                BlobMetadataChunkGroupDigestTableHeaderExtension::SIZE
            }
            _ => return Ok(()),
        };
        if !self
            .header_extension_size
            .is_some_and(|size| size >= required)
        {
            return Err(Error::InvalidImage(format!(
                "blob meta table {} header extension is shorter than its {required} bytes",
                self.table_type
            )));
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

    /// The on-disk `header_size`, the header and its extension, if any.
    fn header_size(&self) -> usize {
        match self.header_extension_size {
            None => Self::HEADER_SIZE,
            Some(size) => Self::HEADER_SIZE + size,
        }
    }

    /// Byte range of the `size`-byte header extension behind the header.
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

    /// The table of `table_type` among `tables`, `None` without one.
    fn find(tables: &[Self], table_type: BlobMetadataTableType) -> Option<Self> {
        tables
            .iter()
            .find(|table| table.table_type == table_type)
            .copied()
    }

    /// The table of `table_type` among `tables`, which every blob meta holds.
    fn require(tables: &[Self], table_type: BlobMetadataTableType) -> Result<Self> {
        Self::find(tables, table_type)
            .ok_or_else(|| Error::InvalidImage(format!("blob meta lacks its {table_type}")))
    }

    /// Read this table as entries of `T`. The declared entry size must cover
    /// `T`, so fields a newer writer appended are skipped rather than read
    /// past.
    fn entries_of<T: BlobMetadataEntry>(self) -> Result<BlobMetadataEntries<T>> {
        if self.entry_size < T::SIZE {
            return Err(Error::InvalidImage(format!(
                "blob meta {} entry size {} is below {}",
                self.table_type,
                self.entry_size,
                T::SIZE
            )));
        }

        Ok(BlobMetadataEntries {
            table: self,
            entry: PhantomData,
        })
    }
}

/// One entry of a blob meta table as stored on disk.
trait BlobMetadataEntry: Sized {
    /// One entry's fixed on-disk size, what the table header declares as its
    /// entry size.
    const SIZE: usize;

    /// Decode an entry from exactly its [`Self::SIZE`] bytes.
    fn from_bytes(bytes: &[u8]) -> Self;

    /// Append the entry's on-disk bytes to `out`.
    fn write_to(&self, out: &mut Vec<u8>);
}

/// A table whose declared entry size covers `T`, read as entries of `T`.
#[derive(Clone, Copy, Debug)]
struct BlobMetadataEntries<T> {
    table: BlobMetadataTable,
    entry: PhantomData<T>,
}

/// Reads entries of `T` out of the file bytes.
impl<T: BlobMetadataEntry> BlobMetadataEntries<T> {
    /// Entry `index` of the file `bytes`, which the caller keeps below
    /// [`Self::len`].
    fn get(&self, bytes: &[u8], index: usize) -> T {
        let offset = self.table.offset + self.table.header_size() + index * self.table.entry_size;
        T::from_bytes(&bytes[offset..offset + T::SIZE])
    }

    /// Number of entries.
    fn len(&self) -> usize {
        self.table.entry_count
    }
}

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

/// Writes and reads the extension, and decodes the group bound and the
/// compressor it stores.
impl BlobMetadataChunkGroupTableHeaderExtension {
    /// The ChunkGroupTable header extension's fixed on-disk size, 8 bytes
    /// behind the table header holding the group bound and the compressor.
    const SIZE: usize = 8;

    /// Creates the extension of a table whose groups span at most
    /// `max_blocks_per_chunk_group` blocks, stored as its log2.
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

    /// Serialize the extension into the bytes behind the table header.
    fn to_bytes(self) -> [u8; Self::SIZE] {
        let mut data = [0u8; Self::SIZE];
        write_u8_at(&mut data, 0, self.max_blocks_per_chunk_group_bits);
        write_u8_at(&mut data, 1, self.compressor);
        write_bytes_at(&mut data, 2, &self.reserved);
        data
    }

    /// The most blocks a group covers. A log2 past the u32 block space
    /// saturates, over every bound.
    fn max_blocks_per_chunk_group(&self) -> u32 {
        2u32.saturating_pow(self.max_blocks_per_chunk_group_bits.into())
    }

    /// The compressor every group is stored with.
    fn compressor(&self) -> Result<BlobMetadataCompressor> {
        BlobMetadataCompressor::from_code(self.compressor)
    }
}

/// One ChunkGroupTable entry, where a chunk group starts in the data region,
/// the address space and ChunkLengthTable. The table holds one entry per
/// group plus a last entry. Group `i` spans entry `i` to entry `i + 1` in
/// every layer, so the last entry is where the groups end, the totals.
///
/// ```text
///                       entry 0       entry 1    entry 2             entry 3 (last)
///                       ▼             ▼          ▼                   ▼
/// data region           ┌─────────────┬──────────┬───────────────────┐
/// compressed_offset     │   group 0   │ group 1  │      group 2      │
///                       └─────────────┴──────────┴───────────────────┘
/// address space         ┌─────────────┬──────────┬───────────────────┐
/// logical_block_offset  │   group 0   │ group 1  │      group 2      │
///                       └─────────────┴──────────┴───────────────────┘
/// ChunkLengthTable      ┌─────────────┬──────────┬───────────────────┐
/// first_chunk_index     │   group 0   │ group 1  │      group 2      │
///                       └─────────────┴──────────┴───────────────────┘
///
/// offset  size  field
///      0     8  compressed_offset          bytes into the data region
///      8     4  logical_block_offset       first 4KiB block in the address space
///     12     4  first_chunk_index          first entry in ChunkLengthTable
///     16     4  uncompressed_size          bytes the group decompresses to,
///                                          zero in the last entry
///     20     4  uncompressed_crc32         crc32c of those bytes, zero in the
///                                          last entry
/// ```
///
/// [`BlobMetadata::chunk_group`] joins two neighbouring entries into a
/// [`BlobMetadataChunkGroupExtent`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlobMetadataChunkGroup {
    compressed_offset: u64,
    logical_block_offset: u32,
    first_chunk_index: u32,
    uncompressed_size: u32,
    uncompressed_crc32: u32,
}

/// On-disk encoding of a ChunkGroupTable entry, its five fields
/// little-endian in struct order.
impl BlobMetadataEntry for BlobMetadataChunkGroup {
    /// One ChunkGroupTable entry's fixed on-disk size, 24 bytes holding where
    /// the group starts in each layer, its uncompressed size and its crc32.
    const SIZE: usize = 24;

    /// Decode the three starts, the uncompressed size and its crc32 from the
    /// entry's 24 bytes.
    fn from_bytes(bytes: &[u8]) -> Self {
        Self {
            compressed_offset: read_u64_at(bytes, 0),
            logical_block_offset: read_u32_at(bytes, 8),
            first_chunk_index: read_u32_at(bytes, 12),
            uncompressed_size: read_u32_at(bytes, 16),
            uncompressed_crc32: read_u32_at(bytes, 20),
        }
    }

    /// Append the entry's 24 bytes, the three starts first, then the
    /// uncompressed size and its crc32.
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

/// A writer creates entries, a reader joins them into extents through
/// [`BlobMetadata::chunk_group`].
impl BlobMetadataChunkGroup {
    /// Creates an entry. The last entry carries the totals with zero size
    /// and crc.
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

/// One chunk group with its extent in every layer, joined from its
/// ChunkGroupTable entry and the next. A group of one or more chunks is the
/// compression, decode, cache fill, readiness and trace unit.
///
/// ```text
/// logical       the address space the cache mirrors, groups back to back,
///               every chunk on its own 4 KiB blocks (logical_block_offset,
///               logical_block_count)
/// ┌──────────┬──────────────┬──────────┐
/// │ group 0  │   group 1    │ group 2  │
/// │c0│c1│c2│ │      c3      │c4│ c5 │  │
/// └──┴──┴──┴─┴──────────────┴──┴────┴──┘
///     ▼             ▼            ▼
/// uncompressed  the chunks' bytes back to back, no padding
///               (uncompressed_size, uncompressed_crc32)
/// ┌──────┬────────────────┬─────┐
/// │ u0   │       u1       │ u2  │
/// └──────┴────────────────┴─────┘
///     ▼             ▼            ▼
/// compressed    each group's bytes compressed as one unit, packed in order
///               in the data region (compressed_offset, compressed_size)
/// ┌───┬───────┬──┐
/// │c0 │  c1   │c2│
/// └───┴───────┴──┘
/// ```
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

/// Joins two entries into a group, then answers where the group lies in each
/// layer and how to decode it.
impl BlobMetadataChunkGroupExtent {
    /// The extent of group `index` between its entry `start` and the next
    /// entry `end`, with its `redirect` in a redirect blob.
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

    /// Bytes the group decompresses to, the chunks' bytes back to back,
    /// never zero.
    pub fn uncompressed_size(&self) -> u32 {
        self.uncompressed_size
    }

    /// Number of chunks the group holds, always at least one.
    pub fn chunk_count(&self) -> u32 {
        self.chunk_count
    }

    /// The group's first entry in ChunkLengthTable.
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

    /// 4KiB blocks the group spans, its chunks each block aligned.
    pub fn logical_block_count(&self) -> u32 {
        self.logical_block_count
    }

    /// Start of the group in the logical address space, in bytes.
    pub fn logical_offset(&self) -> u64 {
        self.logical_block_offset() * EROFS_BLOCK_SIZE as u64
    }

    /// Bytes the group occupies in the address space, padding included.
    pub fn logical_size(&self) -> u64 {
        self.logical_block_count() as u64 * EROFS_BLOCK_SIZE as u64
    }

    /// Byte range of the group in the logical address space.
    pub fn logical_range(&self) -> Range<u64> {
        self.logical_offset()..self.logical_offset() + self.logical_size()
    }

    /// Whether the group is stored uncompressed in `blob_metadata`'s blob.
    /// The builder skips compression that would not shrink a group, so
    /// equal compressed and uncompressed sizes mean it is.
    pub fn is_uncompressed(&self, blob_metadata: &BlobMetadata) -> bool {
        blob_metadata.compressor() == BlobMetadataCompressor::None
            || self.compressed_size == self.uncompressed_size
    }

    /// The group's chunks as `(logical byte offset, length)`, in address
    /// order, each on its own block, their lengths read from
    /// `blob_metadata`'s ChunkLengthTable. [`Self::decoded_chunks`] pairs
    /// them with their bytes.
    pub fn chunks<'a>(
        &self,
        blob_metadata: &'a BlobMetadata,
    ) -> impl Iterator<Item = (u64, u32)> + 'a {
        let mut block = self.logical_block_offset();
        self.chunk_range().map(move |chunk| {
            let length = blob_metadata
                .chunk_lengths
                .get(&blob_metadata.bytes, chunk)
                .get();
            let offset = block * EROFS_BLOCK_SIZE as u64;
            block += u64::from(length).div_ceil(EROFS_BLOCK_SIZE as u64);
            (offset, length)
        })
    }

    /// The group's chunks as `(logical byte offset, bytes within payload)`,
    /// `payload` being the group's decoded bytes, the gaps between chunks
    /// block padding. `None` when `payload` is not the group's uncompressed
    /// size.
    pub fn decoded_chunks<'a>(
        &self,
        blob_metadata: &'a BlobMetadata,
        payload: &'a [u8],
    ) -> Option<impl Iterator<Item = (u64, &'a [u8])> + 'a> {
        if payload.len() != self.uncompressed_size as usize {
            return None;
        }

        let mut position = 0usize;
        Some(self.chunks(blob_metadata).map(move |(offset, length)| {
            let bytes = &payload[position..position + length as usize];
            position += length as usize;
            (offset, bytes)
        }))
    }
}

/// One ChunkLengthTable entry, the byte length of one chunk, never zero.
/// Every chunk of the blob has one, lone chunks included, in group order.
///
/// ```text
/// offset  size  field
///      0     4  length                     bytes of the chunk
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlobMetadataChunkLength(u32);

/// On-disk encoding of a ChunkLengthTable entry, one little-endian `u32`.
impl BlobMetadataEntry for BlobMetadataChunkLength {
    /// One ChunkLengthTable entry's fixed on-disk size, 4 bytes holding one
    /// chunk's byte length.
    const SIZE: usize = 4;

    /// Decode the length from the entry's 4 bytes.
    fn from_bytes(bytes: &[u8]) -> Self {
        Self(read_u32_at(bytes, 0))
    }

    /// Append the length as 4 bytes.
    fn write_to(&self, out: &mut Vec<u8>) {
        let mut data = [0u8; Self::SIZE];
        write_u32_at(&mut data, 0, self.0);
        out.extend_from_slice(&data);
    }
}

/// Wraps and unwraps the length.
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

/// Writes and reads the extension, and decodes the stride it stores.
impl BlobMetadataChunkGroupIndexTableHeaderExtension {
    /// The ChunkGroupIndexTable header extension's fixed on-disk size, 8 bytes
    /// behind the table header holding the stride.
    const SIZE: usize = 8;

    /// Creates the extension of a table whose entries each cover
    /// `blocks_per_chunk_group_index` blocks, stored as its log2.
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

    /// Serialize the extension into the bytes behind the table header.
    fn to_bytes(self) -> [u8; Self::SIZE] {
        let mut data = [0u8; Self::SIZE];
        write_u8_at(&mut data, 0, self.blocks_per_chunk_group_index_bits);
        write_bytes_at(&mut data, 1, &self.reserved);
        data
    }

    /// The blocks one index entry covers. A log2 past the u32 block space
    /// saturates, over every bound.
    fn blocks_per_chunk_group_index(&self) -> u32 {
        2u32.saturating_pow(self.blocks_per_chunk_group_index_bits.into())
    }
}

/// One ChunkGroupIndexTable entry, the chunk group covering the first block
/// of one stride of `blocks_per_chunk_group_index` blocks. An address
/// resolves with one table read and at most one forward correction
/// ([`BlobMetadata::chunk_group_index`]), the coarse cousin of EROFS's
/// `z_erofs_lcluster_index`. Below the stride is 4 blocks and every group
/// but the last spans at least one stride. Each arrow is one entry naming
/// the group at its stride's first block. Block 6 reads entry 1, group 0,
/// and steps forward to group 1 since group 0 ends at block 5.
///
/// ```text
/// block                 0         5       9             16
///                       ┌─────────┬───────┬─────────────┐
/// address space         │ group 0 │group 1│   group 2   │
///                       └─────────┴───────┴─────────────┘
///                        ▲       ▲       ▲       ▲
///                        │       │       │       │
///                       ┌───────┬───────┬───────┬───────┐
/// ChunkGroupIndexTable  │   0   │   0   │   1   │   2   │
///                       └───────┴───────┴───────┴───────┘
/// block                 0       4       8       12      16
///
/// offset  size  field
///      0     4  chunk_group_index          index into ChunkGroupTable
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlobMetadataChunkGroupIndex(u32);

/// On-disk encoding of a ChunkGroupIndexTable entry, one little-endian
/// `u32`.
impl BlobMetadataEntry for BlobMetadataChunkGroupIndex {
    /// One ChunkGroupIndexTable entry's fixed on-disk size, 4 bytes holding
    /// the index of the group at one stride's first block.
    const SIZE: usize = 4;

    /// Decode the chunk group index from the entry's 4 bytes.
    fn from_bytes(bytes: &[u8]) -> Self {
        Self(read_u32_at(bytes, 0))
    }

    /// Append the chunk group index as 4 bytes.
    fn write_to(&self, out: &mut Vec<u8>) {
        let mut data = [0u8; Self::SIZE];
        write_u32_at(&mut data, 0, self.0);
        out.extend_from_slice(&data);
    }
}

/// Derives the table from ChunkGroupTable for a writer, and unwraps an
/// entry for a reader.
impl BlobMetadataChunkGroupIndex {
    /// The ChunkGroupIndexTable of the ChunkGroupTable entries `chunk_groups`,
    /// last entry included. A group over blocks `s..e` covers the entries
    /// `ceil(s / n)..ceil(e / n)`, so the table is the groups' runs back to back.
    fn from_chunk_groups(
        chunk_groups: &[BlobMetadataChunkGroup],
        blocks_per_chunk_group_index: u32,
    ) -> Vec<Self> {
        let entries_before = |chunk_group: &BlobMetadataChunkGroup| {
            chunk_group
                .logical_block_offset
                .div_ceil(blocks_per_chunk_group_index)
        };

        chunk_groups
            .windows(2)
            .enumerate()
            .flat_map(|(index, pair)| {
                let entry_count = entries_before(&pair[1]) - entries_before(&pair[0]);
                std::iter::repeat(Self(index as u32)).take(entry_count as usize)
            })
            .collect()
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
///     16     1  algorithm               1 BLAKE3, an unknown value leaves
///                                       the blob undigested for this reader
///     17     7  reserved                writers zero it, readers ignore it
/// ```
#[derive(Clone, Copy, Debug)]
struct BlobMetadataChunkGroupDigestTableHeaderExtension {
    algorithm: u8,
    reserved: [u8; 7],
}

/// Writes and reads the extension, and decodes the digester it stores.
impl BlobMetadataChunkGroupDigestTableHeaderExtension {
    /// The ChunkGroupDigestTable header extension's fixed on-disk size, 8
    /// bytes behind the table header holding the algorithm.
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

    /// Serialize the extension into the bytes behind the table header.
    fn to_bytes(self) -> [u8; Self::SIZE] {
        let mut data = [0u8; Self::SIZE];
        write_u8_at(&mut data, 0, self.algorithm);
        write_bytes_at(&mut data, 1, &self.reserved);
        data
    }

    /// The digester the entries are made with, `None` for an algorithm
    /// this reader does not know.
    fn digester(&self) -> Option<BlobMetadataDigester> {
        BlobMetadataDigester::from_code(self.algorithm)
    }
}

/// One ChunkGroupDigestTable entry, the content digest of the chunk group
/// at the same index in ChunkGroupTable (see [`Self::from_chunk_digests`]).
///
/// ```text
/// offset  size  field
///      0    32  digest                     algorithm per the table header
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlobMetadataChunkGroupDigest([u8; Self::SIZE]);

/// On-disk encoding of a ChunkGroupDigestTable entry, the 32 digest bytes
/// verbatim.
impl BlobMetadataEntry for BlobMetadataChunkGroupDigest {
    /// One ChunkGroupDigestTable entry's fixed on-disk size, 32 bytes holding
    /// one group's digest.
    const SIZE: usize = Self::SIZE;

    /// Copy the digest out of the entry's 32 bytes.
    fn from_bytes(bytes: &[u8]) -> Self {
        Self(read_bytes_at(bytes, 0))
    }

    /// Append the digest's 32 bytes.
    fn write_to(&self, out: &mut Vec<u8>) {
        let mut data = [0u8; Self::SIZE];
        write_bytes_at(&mut data, 0, &self.0);
        out.extend_from_slice(&data);
    }
}

/// Computes a group's digest for a writer, and unwraps it for a reader.
impl BlobMetadataChunkGroupDigest {
    /// The digest's fixed on-disk size, 32 bytes, one BLAKE3 digest, also the
    /// ChunkGroupDigestTable entry size.
    pub const SIZE: usize = 32;

    /// BLAKE3 `derive_key` context separating multi-chunk group digests from
    /// plain content digests.
    const DERIVE_KEY_CONTEXT: &str = "nydus blob meta chunk group digest v1";

    /// Creates an entry for the group at the same index in ChunkGroupTable.
    pub fn new(digest: [u8; Self::SIZE]) -> Self {
        Self(digest)
    }

    /// The digest, algorithm per the ChunkGroupDigestTable header.
    pub fn get(self) -> [u8; Self::SIZE] {
        self.0
    }

    /// The digest of a chunk group from the BLAKE3 digests of its chunks. A lone
    /// chunk is named by its own digest, so a content-addressed cache serves it
    /// by content. A pack is named by a domain-separated BLAKE3 (`derive_key`)
    /// over the member digests, without a second pass over the bytes. An empty
    /// slice is an error, since a group holds at least one chunk.
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

/// One ChunkGroupRedirectTable entry, the chunk group of another blob of
/// the image that the chunk group at the same index copies. Present only
/// in a redirect blob (an `optimize` output), one entry per chunk group.
///
/// ```text
/// offset  size  field
///      0     2  source_blob_index         EROFS device slot of the source
///                                          blob, as wide as a chunk index
///                                          device_id, never zero since slot
///                                          zero is the bootstrap itself
///      2     2  reserved                  writers zero it, readers ignore it
///      4     4  source_chunk_group_index  the copied group within it
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlobMetadataChunkGroupRedirect {
    source_blob_index: u16,
    reserved: [u8; 2],
    source_chunk_group_index: u32,
}

/// On-disk encoding of a ChunkGroupRedirectTable entry, its fields
/// little-endian in struct order.
impl BlobMetadataEntry for BlobMetadataChunkGroupRedirect {
    /// One ChunkGroupRedirectTable entry's fixed on-disk size, 8 bytes holding
    /// the source blob slot, two reserved bytes and the source group.
    const SIZE: usize = 8;

    /// Decode the source blob slot, the reserved bytes and the source group
    /// from the entry's 8 bytes.
    fn from_bytes(bytes: &[u8]) -> Self {
        Self {
            source_blob_index: read_u16_at(bytes, 0),
            reserved: read_bytes_at(bytes, 2),
            source_chunk_group_index: read_u32_at(bytes, 4),
        }
    }

    /// Append the entry's 8 bytes, the source blob slot, the reserved bytes and
    /// the source group.
    fn write_to(&self, out: &mut Vec<u8>) {
        let mut data = [0u8; Self::SIZE];
        write_u16_at(&mut data, 0, self.source_blob_index);
        write_bytes_at(&mut data, 2, &self.reserved);
        write_u32_at(&mut data, 4, self.source_chunk_group_index);
        out.extend_from_slice(&data);
    }
}

/// Names a source for a writer, and reads it back for a reader.
impl BlobMetadataChunkGroupRedirect {
    /// Names chunk group `source_chunk_group_index` of the blob in EROFS
    /// device slot `source_blob_index` (never zero) as the source.
    pub fn new(source_blob_index: u16, source_chunk_group_index: u32) -> Result<Self> {
        let redirect = Self {
            source_blob_index,
            reserved: [0; 2],
            source_chunk_group_index,
        };

        redirect.validate_fields()?;
        Ok(redirect)
    }

    /// Validate that the source blob index is a device slot, since slot zero
    /// is the bootstrap itself.
    fn validate_fields(&self) -> Result<()> {
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

/// The file a writer lays out, the header's placeholder and then every
/// table pushed at the next [`BlobMetadataTable::ALIGNMENT`].
/// [`Self::finish`] pads it to the block and seals the header.
struct BlobMetadataWriter {
    bytes: Vec<u8>,
    tables: Vec<BlobMetadataTable>,
}

/// Lays the file out table by table.
impl BlobMetadataWriter {
    /// Starts a file with room for the header.
    fn new() -> Self {
        Self {
            bytes: vec![0u8; BlobMetadataHeader::SIZE],
            tables: Vec::new(),
        }
    }

    /// Append one table, its header and then `header_extension` when the
    /// table type has one and then `entries`. Returns the appended entries
    /// as a typed view over the bytes [`Self::finish`] hands over.
    fn push_table<T: BlobMetadataEntry>(
        &mut self,
        table_type: BlobMetadataTableType,
        header_extension: Option<&[u8]>,
        entries: &[T],
    ) -> Result<BlobMetadataEntries<T>> {
        self.bytes.resize(
            self.bytes
                .len()
                .next_multiple_of(BlobMetadataTable::ALIGNMENT),
            0,
        );

        let table = BlobMetadataTable::new(
            self.bytes.len(),
            table_type,
            header_extension.map(<[u8]>::len),
            BlobMetadataTable::DEFAULT_FEATURE_COMPAT,
            BlobMetadataTable::DEFAULT_FEATURE_INCOMPAT,
            T::SIZE,
            entries.len(),
        )?;

        self.bytes
            .extend_from_slice(&table.to_bytes(header_extension, entries));
        self.tables.push(table);
        table.entries_of()
    }

    /// Pad the file to a 4 KiB multiple and seal the header over it, handing
    /// over the header, the tables in file order and the bytes.
    fn finish(mut self) -> Result<(BlobMetadataHeader, Vec<BlobMetadataTable>, Vec<u8>)> {
        let table_count = u16::try_from(self.tables.len())
            .map_err(|_| Error::Overflow("blob meta holds more than 65535 tables".to_string()))?;
        self.bytes.resize(
            self.bytes.len().next_multiple_of(EROFS_BLOCK_SIZE as usize),
            0,
        );

        let header = BlobMetadataHeader::new(
            BlobMetadataHeader::DEFAULT_FEATURE_COMPAT,
            BlobMetadataHeader::DEFAULT_FEATURE_INCOMPAT,
            table_count,
            &self.bytes[BlobMetadataHeader::SIZE..],
        );
        write_bytes_at(&mut self.bytes, 0, &header.to_bytes());
        Ok((header, self.tables, self.bytes))
    }
}

/// The header every blob meta starts with, sealed with a crc32c over the
/// whole serialized metadata. It holds only what concerns the whole file,
/// each table's parameters living in that table's own header extension.
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

/// Writes and reads the header, and seals the file with its crc32.
impl BlobMetadataHeader {
    /// On-disk magic, 8 raw ASCII bytes ("NDBLMETA" = Nydus BLob META) written
    /// as-is so a hexdump of the file starts with the readable string. Same
    /// frozen `magic + feature_compat + feature_incompat + crc32` prefix as the
    /// blob footer (`NDFOOTER`), see [`crate::blob::flag`].
    pub const MAGIC: [u8; 8] = *b"NDBLMETA";

    /// The header's fixed on-disk size, 24 bytes at the start of the blob
    /// meta, which the first table follows.
    pub const SIZE: usize = 24;

    /// Byte range of the crc32 field within the header.
    const CRC32_FIELD: Range<usize> = 16..20;

    /// Every incompat bit this reader understands, none so far. A file
    /// setting a bit outside this mask was written by a newer nydus and is
    /// rejected by [`FeatureFlags::validate_incompat`].
    const INCOMPAT_SUPPORTED: u32 = 0;

    /// The `feature_compat` word a writer declares, no compat feature yet.
    pub const DEFAULT_FEATURE_COMPAT: u32 = 0;

    /// The `feature_incompat` word a writer declares, no incompat feature yet.
    pub const DEFAULT_FEATURE_INCOMPAT: u32 = 0;

    /// Creates the header sealing a blob meta whose `table_count` tables
    /// serialize to `tables`, padded to the block, behind it.
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

    /// Parse the header from the start of the file `bytes`. The raw bytes
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

    /// Validate the raw on-disk bytes before decoding them, the magic, a
    /// whole number of blocks, and the stored crc32 against
    /// [`Self::compute_crc32`] over the whole file.
    fn validate_bytes(bytes: &[u8]) -> Result<()> {
        if !Self::has_magic(bytes) {
            return Err(Error::InvalidImage("invalid blob meta magic".to_string()));
        }

        if bytes.len() % EROFS_BLOCK_SIZE as usize != 0 {
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

    /// Validate the intrinsic field invariants. Unknown incompat bits
    /// reject before anything behind the header is trusted, since they may
    /// change the table walk itself.
    fn validate_fields(&self) -> Result<()> {
        FeatureFlags::from_bits(self.feature_incompat).validate_incompat(Self::INCOMPAT_SUPPORTED)
    }

    /// Whether `bytes` starts with the blob meta magic.
    pub fn has_magic(bytes: &[u8]) -> bool {
        bytes.starts_with(&Self::MAGIC)
    }

    /// crc32c over the header bytes with the crc32 field treated as zero,
    /// continued over the `tables` behind it. The writer seals `to_bytes()`
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

/// A nydus blob's metadata, how the blob's logical address space maps onto
/// its compressed data, sealed with a crc32c in the header. Serialized it is
/// the `.blob.meta` sidecar file, and verbatim the blob meta region of a full
/// blob (see [`super::footer::BlobFooter`]).
///
/// The file is the [`BlobMetadataHeader`], then every table at the next
/// 8-byte boundary, zero padded to a 4 KiB multiple.
///
/// ```text
/// ┌────────┬─────────────────┬──────────────────┬──────────────────────┬──────────────────────────────────┬────────────────────────────────────┬─────┐
/// │ header │ ChunkGroupTable │ ChunkLengthTable │ ChunkGroupIndexTable │ ChunkGroupDigestTable (optional) │ ChunkGroupRedirectTable (optional) │ pad │
/// └────────┴─────────────────┴──────────────────┴──────────────────────┴──────────────────────────────────┴────────────────────────────────────┴─────┘
/// 0        24
///
/// table                    type  presence                        header extension                                  entries
/// ChunkGroupTable             1  required                        BlobMetadataChunkGroupTableHeaderExtension        (groups + 1) * 24 B,
///                                                                                                                  the last one only ends
/// ChunkLengthTable            2  required                        none                                              chunks * 4 B
/// ChunkGroupIndexTable        3  required                        BlobMetadataChunkGroupIndexTableHeaderExtension   ceil(blocks / stride) * 4 B
/// ChunkGroupDigestTable       4  optional, with a digester       BlobMetadataChunkGroupDigestTableHeaderExtension  groups * 32 B
/// ChunkGroupRedirectTable     5  optional, in redirect blobs     none                                              groups * 8 B
/// ```
///
/// The table headers are the compatibility contract. A reader skips an
/// unknown table without incompat bits, reads known tables through their
/// declared sizes, and keeps every byte so [`Self::write_to`] preserves what
/// it does not know. A redirect blob (an `optimize` output) copies chunk
/// groups of other blobs byte for byte and names their sources in
/// ChunkGroupRedirectTable.
#[derive(Debug)]
pub struct BlobMetadata {
    header: BlobMetadataHeader,
    compressor: BlobMetadataCompressor,
    tables: Vec<BlobMetadataTable>,
    chunk_groups: BlobMetadataEntries<BlobMetadataChunkGroup>,
    chunk_lengths: BlobMetadataEntries<BlobMetadataChunkLength>,
    chunk_group_indexes: BlobMetadataEntries<BlobMetadataChunkGroupIndex>,
    chunk_group_digests: Option<BlobMetadataEntries<BlobMetadataChunkGroupDigest>>,
    chunk_group_redirects: Option<BlobMetadataEntries<BlobMetadataChunkGroupRedirect>>,
    chunk_group_count: u32,
    max_blocks_per_chunk_group: u32,
    blocks_per_chunk_group_index: u32,
    chunk_count: u32,
    logical_block_count: u32,
    chunk_group_digest_algorithm: Option<u8>,
    bytes: Vec<u8>,
}

/// Builds a blob meta for a writer, parses one for a reader, and answers
/// every question about the blob it describes.
impl BlobMetadata {
    /// Default file chunk size, the largest chunk a file is cut into, 2 MiB.
    /// The builder controls chunk group sizes separately, so changing the file
    /// chunk size does not change the default chunk group minimum size.
    pub const DEFAULT_CHUNK_SIZE: u32 = 2 * 1024 * 1024;

    /// File-name suffix of a blob meta sidecar file (`<blob>.blob.meta`).
    pub const SUFFIX: &str = ".blob.meta";

    /// Largest `max_blocks_per_chunk_group`, 2 GiB, keeping byte sizes within a `u32`.
    const MAX_BLOCKS_PER_CHUNK_GROUP: u32 = 1 << 19;

    /// Creates validated metadata from a writer's tables, laid out behind the
    /// header and sealed. `max_blocks_per_chunk_group` bounds a group and
    /// `blocks_per_chunk_group_index` is the stride of one index entry, both
    /// stored as their log2. `chunk_groups` ends in its last entry, and
    /// `chunk_group_digests` and `chunk_group_redirects` hold one entry per
    /// group or none.
    pub fn new(
        max_blocks_per_chunk_group: u32,
        blocks_per_chunk_group_index: u32,
        compressor: BlobMetadataCompressor,
        chunk_groups: Vec<BlobMetadataChunkGroup>,
        chunk_lengths: Vec<BlobMetadataChunkLength>,
        chunk_group_digests: Vec<BlobMetadataChunkGroupDigest>,
        chunk_group_redirects: Vec<BlobMetadataChunkGroupRedirect>,
    ) -> Result<Self> {
        let mut writer = BlobMetadataWriter::new();

        // ChunkGroupTable takes the caller's rows, one per group plus the last
        // entry. Its header extension records the group bound and the
        // compressor.
        let chunk_group_header_extension = BlobMetadataChunkGroupTableHeaderExtension::new(
            max_blocks_per_chunk_group,
            compressor,
        )?
        .to_bytes();
        let chunk_group_table = writer.push_table(
            BlobMetadataTableType::CHUNK_GROUP,
            Some(&chunk_group_header_extension),
            &chunk_groups,
        )?;

        // ChunkLengthTable takes the caller's lengths, one per chunk in group
        // order. It has no header extension.
        let chunk_length_table =
            writer.push_table(BlobMetadataTableType::CHUNK_LENGTH, None, &chunk_lengths)?;

        // ChunkGroupIndexTable is built here from the rows, one entry per stride
        // of `blocks_per_chunk_group_index` blocks naming the group at the
        // stride's first block. Its header extension records the stride.
        let chunk_group_index_header_extension =
            BlobMetadataChunkGroupIndexTableHeaderExtension::new(blocks_per_chunk_group_index)?
                .to_bytes();
        let chunk_group_index_table = writer.push_table(
            BlobMetadataTableType::CHUNK_GROUP_INDEX,
            Some(&chunk_group_index_header_extension),
            &BlobMetadataChunkGroupIndex::from_chunk_groups(
                &chunk_groups,
                blocks_per_chunk_group_index,
            ),
        )?;

        // ChunkGroupDigestTable takes one digest per group and is written only
        // when the caller digested the groups. Its header extension records
        // the algorithm.
        let chunk_group_digest_header_extension = (!chunk_group_digests.is_empty())
            .then(BlobMetadataChunkGroupDigestTableHeaderExtension::new);
        let chunk_group_digest_table = match &chunk_group_digest_header_extension {
            None => None,
            Some(chunk_group_digest_header_extension) => Some(writer.push_table(
                BlobMetadataTableType::CHUNK_GROUP_DIGEST,
                Some(&chunk_group_digest_header_extension.to_bytes()),
                &chunk_group_digests,
            )?),
        };

        // ChunkGroupRedirectTable takes one source group per group and is
        // written only for a redirect blob. It has no header extension.
        let chunk_group_redirect_table = if chunk_group_redirects.is_empty() {
            None
        } else {
            Some(writer.push_table(
                BlobMetadataTableType::CHUNK_GROUP_REDIRECT,
                None,
                &chunk_group_redirects,
            )?)
        };
        let (header, tables, bytes) = writer.finish()?;

        let chunk_group_count = chunk_group_table.len().checked_sub(1).ok_or_else(|| {
            Error::InvalidParameter("blob meta ChunkGroupTable lacks its last entry".to_string())
        })?;
        let blob_metadata = Self {
            header,
            compressor,
            tables,
            chunk_groups: chunk_group_table,
            chunk_lengths: chunk_length_table,
            chunk_group_indexes: chunk_group_index_table,
            chunk_group_digests: chunk_group_digest_table,
            chunk_group_redirects: chunk_group_redirect_table,
            chunk_group_count: chunk_group_count as u32,
            max_blocks_per_chunk_group,
            blocks_per_chunk_group_index,
            chunk_count: chunk_group_table
                .get(&bytes, chunk_group_count)
                .first_chunk_index,
            logical_block_count: chunk_group_table
                .get(&bytes, chunk_group_count)
                .logical_block_offset,
            chunk_group_digest_algorithm: chunk_group_digest_header_extension.map(
                |chunk_group_digest_header_extension| chunk_group_digest_header_extension.algorithm,
            ),
            bytes,
        };

        blob_metadata.validate_fields()?;
        Ok(blob_metadata)
    }

    /// Parse a blob meta from its bytes, which it keeps. The header, the table
    /// walk, the supported tables and their header extensions, then
    /// `validate_fields`.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        let header = BlobMetadataHeader::from_bytes(&bytes)?;

        // The tables follow the header back to back. The first table of a type
        // is the one read, any further one is kept like an unknown table.
        let mut tables = Vec::with_capacity(usize::from(header.table_count));
        let mut end = BlobMetadataHeader::SIZE;
        for _ in 0..header.table_count {
            let table = BlobMetadataTable::from_bytes(&bytes, end)?;
            end = table.range().end;
            tables.push(table);
        }

        // ChunkGroupTable is required. It holds where every group starts in
        // the data region, the address space and ChunkLengthTable, one entry
        // per group plus the last entry that only marks the end. Its header
        // extension gives the group bound and the compressor.
        let chunk_groups = BlobMetadataTable::require(&tables, BlobMetadataTableType::CHUNK_GROUP)?
            .entries_of::<BlobMetadataChunkGroup>()?;
        let chunk_group_header_extension =
            BlobMetadataChunkGroupTableHeaderExtension::from_bytes(&bytes, &chunk_groups.table);
        let compressor = chunk_group_header_extension.compressor()?;
        let max_blocks_per_chunk_group = chunk_group_header_extension.max_blocks_per_chunk_group();
        let chunk_group_count = chunk_groups.len().checked_sub(1).ok_or_else(|| {
            Error::InvalidImage("blob meta ChunkGroupTable lacks its last entry".to_string())
        })?;

        // ChunkLengthTable is required. It holds the byte length of every
        // chunk of the blob in group order, one entry per chunk, so a group's
        // chunks are the run its ChunkGroupTable entry points at. It has no
        // header extension.
        let chunk_lengths =
            BlobMetadataTable::require(&tables, BlobMetadataTableType::CHUNK_LENGTH)?
                .entries_of::<BlobMetadataChunkLength>()?;

        // ChunkGroupIndexTable is required. It holds the group covering the
        // first block of every stride of the address space, one entry per
        // stride, so an address resolves with one read and at most one step
        // forward. Its header extension gives the stride.
        let chunk_group_indexes =
            BlobMetadataTable::require(&tables, BlobMetadataTableType::CHUNK_GROUP_INDEX)?
                .entries_of::<BlobMetadataChunkGroupIndex>()?;
        let chunk_group_index_header_extension =
            BlobMetadataChunkGroupIndexTableHeaderExtension::from_bytes(
                &bytes,
                &chunk_group_indexes.table,
            );
        let blocks_per_chunk_group_index =
            chunk_group_index_header_extension.blocks_per_chunk_group_index();

        // ChunkGroupDigestTable is optional. It holds the content digest of
        // every group, one entry per group in ChunkGroupTable order. Its
        // header extension gives the algorithm code, kept as stored, and the
        // entries are read only when this reader knows the algorithm, so an
        // unknown one leaves the blob undigested.
        let (chunk_group_digest_algorithm, chunk_group_digests) =
            match BlobMetadataTable::find(&tables, BlobMetadataTableType::CHUNK_GROUP_DIGEST) {
                None => (None, None),
                Some(table) => {
                    let chunk_group_digest_header_extension =
                        BlobMetadataChunkGroupDigestTableHeaderExtension::from_bytes(
                            &bytes, &table,
                        );

                    let chunk_group_digests = match chunk_group_digest_header_extension.digester() {
                        None => None,
                        Some(_) => Some(table.entries_of::<BlobMetadataChunkGroupDigest>()?),
                    };
                    (
                        Some(chunk_group_digest_header_extension.algorithm),
                        chunk_group_digests,
                    )
                }
            };

        // ChunkGroupRedirectTable is optional, present in a redirect blob only.
        // It holds the group of another blob that every group copies, one
        // entry per group in ChunkGroupTable order. It has no header
        // extension.
        let chunk_group_redirects =
            BlobMetadataTable::find(&tables, BlobMetadataTableType::CHUNK_GROUP_REDIRECT)
                .map(BlobMetadataTable::entries_of::<BlobMetadataChunkGroupRedirect>)
                .transpose()?;

        let blob_metadata = Self {
            header,
            compressor,
            tables,
            chunk_groups,
            chunk_lengths,
            chunk_group_indexes,
            chunk_group_digests,
            chunk_group_redirects,
            chunk_group_count: chunk_group_count as u32,
            max_blocks_per_chunk_group,
            blocks_per_chunk_group_index,
            chunk_count: chunk_groups
                .get(&bytes, chunk_group_count)
                .first_chunk_index,
            logical_block_count: chunk_groups
                .get(&bytes, chunk_group_count)
                .logical_block_offset,
            chunk_group_digest_algorithm,
            bytes,
        };

        blob_metadata.validate_fields()?;
        Ok(blob_metadata)
    }

    /// Validate the decoded fields, the geometry, the counts, every table's
    /// entry count, ChunkGroupTable's first and last entries and the groups
    /// ChunkGroupIndexTable names. The entries in between are trusted under
    /// the crc32.
    fn validate_fields(&self) -> Result<()> {
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

        if self.chunk_group_count == 0 && (self.chunk_count != 0 || self.logical_block_count != 0) {
            return Err(Error::InvalidImage(format!(
                "blob meta has no chunk groups but {} chunks and {} blocks",
                self.chunk_count, self.logical_block_count
            )));
        }

        if self.chunk_group_count > self.chunk_count {
            return Err(Error::InvalidImage(format!(
                "blob meta names {} chunk groups among {} chunks",
                self.chunk_group_count, self.chunk_count
            )));
        }

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

        let first_entry = self.chunk_groups.get(&self.bytes, 0);
        if first_entry.compressed_offset != 0
            || first_entry.logical_block_offset != 0
            || first_entry.first_chunk_index != 0
        {
            return Err(Error::InvalidImage(
                "blob meta chunk groups must start at offset zero, block zero and chunk zero"
                    .to_string(),
            ));
        }

        let last_entry = self.chunk_groups.get(&self.bytes, self.chunk_group_count());
        if last_entry.uncompressed_size != 0 || last_entry.uncompressed_crc32 != 0 {
            return Err(Error::InvalidImage(format!(
                "blob meta ChunkGroupTable last entry carries payload {} and crc {}",
                last_entry.uncompressed_size, last_entry.uncompressed_crc32
            )));
        }

        for index in 0..self.chunk_group_indexes.len() {
            let chunk_group = self.chunk_group_indexes.get(&self.bytes, index).get();
            if chunk_group >= self.chunk_group_count {
                return Err(Error::InvalidImage(format!(
                    "blob meta ChunkGroupIndexTable entry {index} names chunk group {chunk_group} of {}",
                    self.chunk_group_count
                )));
            }
        }

        Ok(())
    }

    /// Read a blob meta from a file, with the same checks as
    /// [`Self::from_bytes`].
    pub fn from_path(path: &Path) -> Result<Self> {
        let bytes = fs::read(path)?;
        Self::from_bytes(bytes)
    }

    /// Write the serialized metadata verbatim, including tables this reader
    /// does not know.
    pub fn write_to(&self, writer: &mut dyn Write) -> Result<()> {
        writer.write_all(&self.bytes)?;
        Ok(())
    }

    /// Write the serialized metadata to a new sidecar file at `path`.
    pub fn save(&self, path: &Path) -> Result<()> {
        fs::write(path, &self.bytes)?;
        Ok(())
    }

    /// The header, exactly as stored.
    pub fn header(&self) -> BlobMetadataHeader {
        self.header
    }

    /// The compressor every chunk group is stored with.
    pub fn compressor(&self) -> BlobMetadataCompressor {
        self.compressor
    }

    /// The digest algorithm, `None` without a ChunkGroupDigestTable this
    /// reader supports.
    pub fn digester(&self) -> BlobMetadataDigester {
        match self
            .chunk_group_digest_algorithm
            .and_then(BlobMetadataDigester::from_code)
        {
            Some(digester) => digester,
            None => BlobMetadataDigester::None,
        }
    }

    /// The tables, in file order.
    pub fn tables(&self) -> &[BlobMetadataTable] {
        &self.tables
    }

    /// The full serialized size, 4KiB aligned.
    pub fn size(&self) -> u64 {
        self.bytes.len() as u64
    }

    /// The most 4KiB blocks a chunk group covers.
    pub fn max_blocks_per_chunk_group(&self) -> u32 {
        self.max_blocks_per_chunk_group
    }

    /// The most bytes a chunk group covers, bounding a reader's decode buffer.
    pub fn max_bytes_per_chunk_group(&self) -> u32 {
        self.max_blocks_per_chunk_group * EROFS_BLOCK_SIZE
    }

    /// 4KiB blocks per ChunkGroupIndexTable entry.
    pub fn blocks_per_chunk_group_index(&self) -> u32 {
        self.blocks_per_chunk_group_index
    }

    /// Bytes of the address space one ChunkGroupIndexTable entry covers.
    pub fn bytes_per_chunk_group_index(&self) -> u32 {
        self.blocks_per_chunk_group_index * EROFS_BLOCK_SIZE
    }

    /// Number of chunk groups.
    pub fn chunk_group_count(&self) -> usize {
        self.chunk_group_count as usize
    }

    /// Number of chunks, lone chunks included.
    pub fn chunk_count(&self) -> usize {
        self.chunk_count as usize
    }

    /// Size of the logical address space in 4KiB blocks.
    pub fn logical_block_count(&self) -> u64 {
        u64::from(self.logical_block_count)
    }

    /// Size of the logical address space in bytes.
    pub fn logical_size(&self) -> u64 {
        self.logical_block_count() * EROFS_BLOCK_SIZE as u64
    }

    /// Size of the data region, where the last chunk group's compressed bytes end.
    pub fn compressed_size(&self) -> u64 {
        self.chunk_groups
            .get(&self.bytes, self.chunk_group_count())
            .compressed_offset
    }

    /// Bytes all chunk groups decode to, the chunks' bytes without padding,
    /// summed over every group.
    pub fn uncompressed_size(&self) -> u64 {
        (0..self.chunk_group_count())
            .map(|index| u64::from(self.chunk_groups.get(&self.bytes, index).uncompressed_size))
            .sum()
    }

    /// The chunk group at `index`, `None` past the table.
    pub fn chunk_group(&self, index: usize) -> Option<BlobMetadataChunkGroupExtent> {
        if index >= self.chunk_group_count() {
            return None;
        }

        Some(BlobMetadataChunkGroupExtent::new(
            index,
            self.chunk_groups.get(&self.bytes, index),
            self.chunk_groups.get(&self.bytes, index + 1),
            self.chunk_group_redirect(index),
        ))
    }

    /// The chunk groups in order.
    pub fn chunk_groups<'a>(&'a self) -> impl Iterator<Item = BlobMetadataChunkGroupExtent> + 'a {
        (0..self.chunk_group_count()).filter_map(move |index| self.chunk_group(index))
    }

    /// The chunk group covering the address `logical_offset`, `None` beyond the
    /// blob. One ChunkGroupIndexTable read and at most one forward correction.
    pub fn chunk_group_index(&self, logical_offset: u64) -> Option<usize> {
        let block = logical_offset / EROFS_BLOCK_SIZE as u64;
        if block >= u64::from(self.logical_block_count) {
            return None;
        }

        // The index entry covering the block names the group at the entry's
        // first block. A block at or past that group's end is in the next.
        let entry = (block / u64::from(self.blocks_per_chunk_group_index)) as usize;
        let chunk_group = self.chunk_group_indexes.get(&self.bytes, entry).get() as usize;
        let chunk_group_end = self
            .chunk_groups
            .get(&self.bytes, chunk_group + 1)
            .logical_block_offset;

        Some(if block < u64::from(chunk_group_end) {
            chunk_group
        } else {
            chunk_group + 1
        })
    }

    /// Byte length of chunk `index`, lone chunks included, `None` past
    /// ChunkLengthTable.
    pub fn chunk_length(&self, index: usize) -> Option<u32> {
        if index >= self.chunk_count() {
            return None;
        }

        Some(self.chunk_lengths.get(&self.bytes, index).get())
    }

    /// The digest of chunk group `index`, `None` past the table or without
    /// a supported digester.
    pub fn chunk_group_digest(&self, index: usize) -> Option<BlobMetadataChunkGroupDigest> {
        let entries = self.chunk_group_digests?;
        if index >= entries.len() {
            return None;
        }

        Some(entries.get(&self.bytes, index))
    }

    /// The digests in chunk group order, none without a supported digester.
    pub fn chunk_group_digests<'a>(
        &'a self,
    ) -> impl Iterator<Item = BlobMetadataChunkGroupDigest> + 'a {
        (0..self.chunk_group_count()).filter_map(|index| self.chunk_group_digest(index))
    }

    /// The ChunkGroupDigestTable algorithm code, exactly as stored, `None`
    /// without the table. One this reader does not know leaves
    /// [`Self::digester`] `None`.
    pub fn chunk_group_digest_algorithm(&self) -> Option<u8> {
        self.chunk_group_digest_algorithm
    }

    /// The redirect of chunk group `index`, `None` past the table or in a
    /// blob that is not a redirect blob.
    pub fn chunk_group_redirect(&self, index: usize) -> Option<BlobMetadataChunkGroupRedirect> {
        let entries = self.chunk_group_redirects?;
        if index >= entries.len() {
            return None;
        }

        Some(entries.get(&self.bytes, index))
    }

    /// Whether the blob is a redirect blob, its chunk groups copied from other
    /// blobs named in ChunkGroupRedirectTable.
    pub fn is_redirect(&self) -> bool {
        self.chunk_group_redirects.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn digest(bytes: &[u8]) -> [u8; BlobMetadataChunkGroupDigest::SIZE] {
        *blake3::hash(bytes).as_bytes()
    }

    /// A group as a writer knows it before laying it out, its lengths, the
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

    /// Lay `specs` out back to back into ChunkGroupTable, last entry
    /// included, and ChunkGroupRedirectTable, while `chunk_lengths` lists
    /// every chunk in group order.
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
            logical_block_offset += chunk_lengths.get(chunks).map_or(0, |chunk_lengths| {
                chunk_lengths
                    .iter()
                    .map(|length| length.div_ceil(EROFS_BLOCK_SIZE))
                    .sum()
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

    /// Lay `tables` out behind a sealed header, as a writer would.
    fn assemble(tables: &[Vec<u8>]) -> Vec<u8> {
        let mut bytes = vec![0u8; BlobMetadataHeader::SIZE];
        for table in tables {
            bytes.resize(
                bytes.len().next_multiple_of(BlobMetadataTable::ALIGNMENT),
                0,
            );
            bytes.extend_from_slice(table);
        }
        bytes.resize(bytes.len().next_multiple_of(EROFS_BLOCK_SIZE as usize), 0);
        let header = BlobMetadataHeader::new(
            BlobMetadataHeader::DEFAULT_FEATURE_COMPAT,
            BlobMetadataHeader::DEFAULT_FEATURE_INCOMPAT,
            tables.len() as u16,
            &bytes[BlobMetadataHeader::SIZE..],
        );
        write_bytes_at(&mut bytes, 0, &header.to_bytes());
        bytes
    }

    fn raw(meta: &BlobMetadata) -> Vec<u8> {
        let mut raw = Vec::new();
        meta.write_to(&mut raw).unwrap();
        raw
    }

    /// The serialized bytes of the table of `table_type`, header included.
    fn table_bytes(meta: &BlobMetadata, table_type: BlobMetadataTableType) -> Vec<u8> {
        raw(meta)[BlobMetadataTable::find(meta.tables(), table_type)
            .unwrap()
            .range()]
        .to_vec()
    }

    /// The encoded tables of `meta`, to reassemble a mutated file with.
    fn split(meta: &BlobMetadata) -> Vec<Vec<u8>> {
        meta.tables()
            .iter()
            .map(|table| table_bytes(meta, table.table_type()))
            .collect()
    }

    /// Byte offset of the header of table `table_type`.
    fn table_offset(meta: &BlobMetadata, table_type: BlobMetadataTableType) -> usize {
        BlobMetadataTable::find(meta.tables(), table_type)
            .unwrap()
            .range()
            .start
    }

    /// Byte offset of the first entry of table `table_type`.
    fn entries_offset(meta: &BlobMetadata, table_type: BlobMetadataTableType) -> usize {
        table_offset(meta, table_type) + read_u16_at(&table_bytes(meta, table_type), 2) as usize
    }

    fn entries(meta: &BlobMetadata) -> Vec<BlobMetadataChunkGroup> {
        (0..=meta.chunk_group_count())
            .map(|index| meta.chunk_groups.get(&meta.bytes, index))
            .collect()
    }

    fn chunk_group_indexes(meta: &BlobMetadata) -> Vec<usize> {
        (0..meta.chunk_group_indexes.len())
            .map(|index| meta.chunk_group_indexes.get(&meta.bytes, index).get() as usize)
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

    /// An uncompressed group with an explicit nonzero chunk count.
    fn uncompressed_chunk_group(payload: &[u8], chunk_count: usize) -> Spec {
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

    /// A fixture of 64 KiB (16 blocks) per chunk group at most and 4 KiB per
    /// chunk group index entry. Its groups are pack A [100, 5000] (3 blocks),
    /// pack B [40, 6000, 1] (4 blocks), lone C 20000 (5 blocks), lone D 65536
    /// (16 blocks) and pack E [1, 1] (2 blocks), 30 blocks and 30 index
    /// entries in all.
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
            uncompressed_chunk_group(&payloads[0], 2),
            uncompressed_chunk_group(&payloads[1], 3),
            uncompressed_chunk_group(&payloads[2], 1),
            uncompressed_chunk_group(&payloads[3], 1),
            uncompressed_chunk_group(&payloads[4], 2),
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
        // Tables back to back from 24, each at the next 8-byte boundary, as
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
        // The ChunkGroupTable header says 64 KiB per group, 16 blocks (bits 4),
        // and no compressor. The ChunkGroupIndexTable header says one block per
        // index (bits 0). The ChunkGroupDigestTable header says BLAKE3.
        assert_eq!(&raw[24 + 16..24 + 18], &[4, 0]);
        assert_eq!(raw[248 + 16], 0);
        assert_eq!(raw[392 + 16], 1);
        // The second group starts at block 3, and the last entry holds 30
        // blocks and 9 chunks.
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

        // Reserved fields and padding are ignored but sealed, namely the header
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
                0,
                BlobMetadataTableType(kind),
                None,
                BlobMetadataTable::DEFAULT_FEATURE_COMPAT,
                BlobMetadataTable::DEFAULT_FEATURE_INCOMPAT,
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
            BlobMetadata::from_bytes(assemble(&tables))
        };

        // An unknown table without incompat bits is skipped and kept
        // verbatim.
        let extension = unknown(0x100, 0);
        let loaded = with(extension.clone()).unwrap();
        assert_eq!(entries(&loaded), entries(&meta));
        assert_eq!(
            table_bytes(&loaded, BlobMetadataTableType(0x100)),
            extension
        );
        let bytes = raw(&loaded);
        let dir = tempdir().unwrap();
        let path = dir.path().join("x.blob.meta");
        loaded.save(&path).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        assert_eq!(
            table_bytes(
                &BlobMetadata::from_path(&path).unwrap(),
                BlobMetadataTableType(0x100)
            ),
            extension
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
        // A second table of a known type is skipped and kept like an
        // unknown one, the first is the one read.
        let doubled = with(unknown(2, 0)).unwrap();
        assert_eq!(doubled.tables().len(), meta.tables().len() + 1);
        assert_eq!(entries(&doubled), entries(&meta));
        // Type zero is unknown like any other unassigned type.
        assert!(with(unknown(0, 0)).is_ok());
        let mut without_chunks = tables.clone();
        without_chunks.remove(1);
        rejects(
            BlobMetadata::from_bytes(assemble(&without_chunks)),
            "lacks its ChunkLengthTable",
        );

        let raw = raw(&meta);
        let chunk_group_digest_table =
            table_offset(&meta, BlobMetadataTableType::CHUNK_GROUP_DIGEST);
        let mut past = raw.clone();
        write_u32_at(&mut past, chunk_group_digest_table + 12, 1000);
        rejects(BlobMetadata::from_bytes(reseal(past)), "runs past the file");
        // Padding beyond the last table is tolerated and kept.
        let mut grown = raw.clone();
        grown.resize(8192, 0);
        assert_eq!(
            BlobMetadata::from_bytes(reseal(grown)).unwrap().size(),
            8192
        );
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
        let loaded = BlobMetadata::from_bytes(assemble(&widened)).unwrap();
        assert_eq!(entries(&loaded), entries(&meta));
        assert_eq!(chunk_group_indexes(&loaded), chunk_group_indexes(&meta));
        assert!(loaded.chunk_group_digests().eq(meta.chunk_group_digests()));
        assert_eq!(loaded.max_blocks_per_chunk_group(), 16);
        assert_eq!(loaded.blocks_per_chunk_group_index(), 1);
        for index in 0..9 {
            assert_eq!(loaded.chunk_length(index), meta.chunk_length(index));
        }
        for offset in (0..meta.logical_size()).step_by(1000) {
            assert_eq!(
                loaded.chunk_group_index(offset),
                meta.chunk_group_index(offset)
            );
        }
        // A table narrower than this reader knows rejects. The last table
        // is narrowed so that no other table moves.
        let chunk_group_digest_table =
            table_offset(&meta, BlobMetadataTableType::CHUNK_GROUP_DIGEST);
        let mut narrow = raw(&meta);
        write_u32_at(&mut narrow, chunk_group_digest_table + 8, 16);
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
        let chunk_group_digest_table =
            table_offset(&meta, BlobMetadataTableType::CHUNK_GROUP_DIGEST);
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
        let err = mutate(chunk_group_digest_table + 2, 16).unwrap_err();
        assert!(
            err.to_string()
                .contains("ChunkGroupDigestTable header extension is shorter than its 8 bytes"),
            "{err}"
        );

        // An unknown digest algorithm leaves the blob undigested.
        let loaded = mutate(chunk_group_digest_table + 16, 9).unwrap();
        assert_eq!(loaded.digester(), BlobMetadataDigester::None);
        assert_eq!(loaded.chunk_group_digests().count(), 0);
        assert_eq!(loaded.chunk_group_digests().count(), 0);
        assert_eq!(loaded.chunk_group_digest_algorithm(), Some(9));
        assert_eq!(
            meta.chunk_group_digest_algorithm(),
            Some(BlobMetadataDigester::BLAKE3_CODE)
        );
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
        assert_eq!(meta.chunk_group_indexes.len(), 30);
        let raw = raw(&meta);
        assert_eq!(raw.len(), 4096);
        let loaded = BlobMetadata::from_bytes(raw.clone()).unwrap();
        assert_eq!(entries(&loaded), entries(&meta));
        assert!(loaded.chunk_group_digests().eq(meta.chunk_group_digests()));
        assert_eq!(chunk_group_indexes(&loaded), chunk_group_indexes(&meta));
        assert!(loaded
            .chunk_groups()
            .all(|chunk_group| chunk_group.redirect().is_none()));

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
        assert!(chunk_group.is_uncompressed(&loaded));
        assert_eq!(
            chunk_group.uncompressed_crc32(),
            crc32c(&chunks_data[2..5].concat())
        );
        assert!(chunk_group.redirect().is_none());
        assert!(loaded.chunk_group(5).is_none());
        assert!(loaded.chunk_group(usize::MAX).is_none());
        assert_eq!(
            loaded
                .chunk_group(1)
                .unwrap()
                .chunks(&loaded)
                .collect::<Vec<_>>(),
            vec![
                (3 * EROFS_BLOCK_SIZE as u64, 40),
                (4 * EROFS_BLOCK_SIZE as u64, 6000),
                (6 * EROFS_BLOCK_SIZE as u64, 1)
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
            loaded
                .chunk_group(2)
                .unwrap()
                .chunks(&loaded)
                .collect::<Vec<_>>(),
            vec![(7 * EROFS_BLOCK_SIZE as u64, 20000)]
        );
        assert_eq!(loaded.chunk_length(6), Some(65536));
        assert_eq!(loaded.chunk_length(9), None);

        let dir = tempdir().unwrap();
        let path = dir.path().join("m.blob.meta");
        meta.save(&path).unwrap();
        let saved = BlobMetadata::from_path(&path).unwrap();
        assert_eq!(entries(&saved), entries(&meta));
        assert!(saved.chunk_group(usize::MAX).is_none());
        assert_eq!(
            (0..9)
                .map(|i| saved.chunk_length(i).unwrap())
                .collect::<Vec<_>>(),
            vec![100, 5000, 40, 6000, 1, 20000, 65536, 1, 1]
        );
        assert_eq!(saved.chunk_group_digests().count(), 5);
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
            saved
                .chunk_group(4)
                .unwrap()
                .chunks(&saved)
                .collect::<Vec<_>>(),
            vec![
                (28 * EROFS_BLOCK_SIZE as u64, 1),
                (29 * EROFS_BLOCK_SIZE as u64, 1)
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
        // One index entry per block, with group boundaries at 0, 3, 7, 12, 28.
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
                meta.chunk_group_index(offset),
                Some(chunk_group),
                "block {block}"
            );
            assert_eq!(
                meta.chunk_group_index(offset + EROFS_BLOCK_SIZE as u64 - 1),
                Some(chunk_group),
                "block {block} tail"
            );
        }
        assert_eq!(meta.chunk_group_index(30 * EROFS_BLOCK_SIZE as u64), None);

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
        assert_eq!(plain.chunk_group_indexes.len(), 30);
        assert_eq!(plain.bytes_per_chunk_group_index(), 4096);
        for (block, chunk_group) in expect {
            assert_eq!(
                plain.chunk_group_index(block * EROFS_BLOCK_SIZE as u64),
                Some(chunk_group)
            );
        }
        assert_eq!(plain.chunk_group_index(30 * EROFS_BLOCK_SIZE as u64), None);
    }

    #[test]
    fn blocks_per_chunk_group_index_bound_every_chunk_group_but_the_last() {
        // At 8 KiB (2 blocks) per index a one-block group at the end is fine.
        let big = vec![7u8; 8192];
        let small = vec![8u8; 100];
        let ok = vec![
            uncompressed_chunk_group(&big, 1),
            uncompressed_chunk_group(&small, 1),
        ];
        let meta = layered(16384, Some(8192), ok, vec![8192, 100], vec![]).unwrap();
        assert_eq!(meta.chunk_group_indexes.len(), 2);
        assert_eq!(meta.chunk_group_index(2 * EROFS_BLOCK_SIZE as u64), Some(1));
        // The blocks per chunk group index is at least one block and at most the group bound.
        for bytes_per_chunk_group_index in [3000, 2048, 32768] {
            let chunk_groups = vec![uncompressed_chunk_group(&big, 1)];
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
        let chunk_groups = vec![uncompressed_chunk_group(&payload, 2)];
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
            loaded
                .chunk_group(0)
                .unwrap()
                .chunks(&loaded)
                .collect::<Vec<_>>(),
            vec![(0, 70000), (18 * EROFS_BLOCK_SIZE as u64, 100)]
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
        for (chunk_group, payload) in meta.chunk_groups().zip(&payloads) {
            for (offset, bytes) in chunk_group.decoded_chunks(&meta, payload).unwrap() {
                padded[offset as usize..offset as usize + bytes.len()].copy_from_slice(bytes);
            }
        }
        let mut chunk = 0;
        for chunk_group in meta.chunk_groups() {
            for (offset, len) in chunk_group.chunks(&meta) {
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
            .chunk_group(0)
            .unwrap()
            .decoded_chunks(&meta, &payloads[0][..10])
            .is_none());
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
        assert_eq!(loaded.chunk_group_indexes.len(), 0);
        assert_eq!(loaded.chunk_group_index(0), None);
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
        assert_eq!(meta.chunk_group_count(), 2);
        assert!(meta
            .chunk_groups()
            .all(|chunk_group| chunk_group.redirect().is_some()));
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
        assert!(BlobMetadata::from_path(&path)
            .unwrap()
            .chunk_groups()
            .map(|chunk_group| chunk_group.redirect())
            .eq(meta
                .chunk_groups()
                .map(|chunk_group| chunk_group.redirect())));

        // A zeroed source blob index is rejected on both sides, and the
        // reserved half of an entry is ignored.
        assert!(BlobMetadataChunkGroupRedirect::new(0, 1).is_err());
        let redirects = entries_offset(&meta, BlobMetadataTableType::CHUNK_GROUP_REDIRECT);
        assert_eq!(read_u16_at(&raw, redirects), 3);
        assert_eq!(read_u32_at(&raw, redirects + 4), 4);
        let mut reserved = raw.clone();
        write_u16_at(&mut reserved, redirects + 2, 0xffff);
        assert!(BlobMetadata::from_bytes(reseal(reserved)).is_ok());
        // ChunkGroupRedirectTable holds one entry per chunk group.
        let mut short = split(&meta);
        let table = &mut short[4];
        write_u32_at(table, 12, 1);
        table.truncate(table.len() - 8);
        let err = BlobMetadata::from_bytes(assemble(&short)).unwrap_err();
        assert!(err.to_string().contains("ChunkGroupRedirectTable"), "{err}");

        // ChunkGroupRedirectTable covers every group or none.
        let payload = chunks[5].clone();
        let mixed = vec![
            uncompressed_chunk_group(&payload, 1),
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
        assert!(!meta.chunk_group(0).unwrap().is_uncompressed(&meta));
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
            .map(|length| uncompressed_chunk_group(&vec![1; *length as usize], 1))
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
            assert_eq!(saved.chunk_group_index(offset), Some(expected));
        }
        assert_eq!(saved.chunk_group_index(u64::MAX), None);
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
        // An index entry naming a group past the table is rejected at load.
        let mut past = raw.clone();
        let chunk_group_index_offset =
            entries_offset(&meta, BlobMetadataTableType::CHUNK_GROUP_INDEX);
        write_u32_at(&mut past, chunk_group_index_offset, 5);
        assert!(BlobMetadata::from_bytes(reseal(past))
            .unwrap_err()
            .to_string()
            .contains("names chunk group 5 of 3"));
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
                uncompressed_chunk_group(&payloads[0], 2),
                uncompressed_chunk_group(&payloads[1], 3),
                uncompressed_chunk_group(&payloads[2], 1),
                uncompressed_chunk_group(&payloads[3], 1),
                uncompressed_chunk_group(&payloads[4], 2),
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

        // Tables whose counts disagree with the last entry.
        let raw = raw(&meta);
        let last_entry = entries_offset(&meta, BlobMetadataTableType::CHUNK_GROUP) + 5 * 24;
        for (offset, value) in [
            (last_entry + 8, 31u32),
            (last_entry + 12, 8),
            (last_entry + 16, 1),
        ] {
            let mut invalid = raw.clone();
            write_u32_at(&mut invalid, offset, value);
            assert!(BlobMetadata::from_bytes(reseal(invalid)).is_err());
        }
    }
}

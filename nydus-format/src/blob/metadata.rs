use crate::blob::algorithm::{BlobMetadataCompressor, BlobMetadataDigester};
use crate::blob::flag::FeatureFlags;
use crate::erofs::EROFS_BLOCK_SIZE;
use crate::error::{Context, Error, Result};
use crate::utils::align_up_u64;
use crate::utils::le::{
    read_u16_at, read_u32_at, read_u64_at, read_u8_at, write_u16_at, write_u32_at,
};
use crc32c::{crc32c, crc32c_append};
use memmap2::{Mmap, MmapOptions};
use std::fs::File;
use std::io::Write;
use std::ops::{Deref, Range};
use std::path::Path;

/// On-disk magic: 8 raw ASCII bytes ("NDBLMETA" = Nydus BLob META), written
/// as-is so a hexdump of the file starts with the readable string. Same
/// frozen `magic + feature_compat + feature_incompat + crc32` prefix as the
/// blob footer (`NDFOOTER`), see [`crate::blob::flag`].
pub const NYDUS_BLOB_METADATA_MAGIC: [u8; 8] = *b"NDBLMETA";

/// The global header's fixed on-disk size; the first table follows it.
pub const NYDUS_BLOB_METADATA_HEADER_SIZE: usize = 24;

/// On-disk size of the header fields every table starts with.
pub const NYDUS_BLOB_METADATA_TABLE_HEADER_SIZE: usize = 16;

/// Table type of GroupTable.
pub const NYDUS_BLOB_METADATA_TABLE_CHUNK_GROUP: u16 = 1;
/// Table type of ChunkTable.
pub const NYDUS_BLOB_METADATA_TABLE_CHUNK: u16 = 2;
/// Table type of GranuleIndexTable.
pub const NYDUS_BLOB_METADATA_TABLE_GRANULE_INDEX: u16 = 3;
/// Table type of DigestTable.
pub const NYDUS_BLOB_METADATA_TABLE_DIGEST: u16 = 4;
/// Table type of RedirectTable.
pub const NYDUS_BLOB_METADATA_TABLE_REDIRECT: u16 = 5;

/// On-disk size of one GroupTable entry (see [`BlobMetadataChunkGroup`]).
pub const NYDUS_BLOB_METADATA_CHUNK_GROUP_ENTRY_SIZE: usize = 24;

/// On-disk size of one ChunkTable entry, a chunk length.
pub const NYDUS_BLOB_METADATA_CHUNK_ENTRY_SIZE: usize = 4;

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

/// File-name suffix of a blob meta sidecar file (`<blob>.blob.meta`).
pub const NYDUS_BLOB_METADATA_SUFFIX: &str = ".blob.meta";

/// Header sizes of the tables that carry table-specific header fields.
const CHUNK_GROUP_TABLE_HEADER_SIZE: usize = 24;
const GRANULE_INDEX_TABLE_HEADER_SIZE: usize = 24;
const DIGEST_TABLE_HEADER_SIZE: usize = 24;

/// Largest `maximum_group_span_block_shift`: a 2 GiB span keeps byte sizes
/// within a `u32`.
const NYDUS_BLOB_METADATA_MAX_GROUP_SPAN_BLOCK_SHIFT: u8 = 19;

/// Byte range of the crc32 field within the header.
const NYDUS_BLOB_METADATA_HEADER_CRC32_FIELD: Range<usize> = 16..20;

/// No global incompatible feature is defined yet.
const NYDUS_BLOB_METADATA_SUPPORTED_INCOMPAT: u32 = 0;

/// No table-level incompatible feature is defined yet.
const NYDUS_BLOB_METADATA_SUPPORTED_TABLE_INCOMPAT: u16 = 0;

const BLOCK: u64 = EROFS_BLOCK_SIZE as u64;
/// log2 of the 4KiB block: byte exponents are block exponents plus this.
const EROFS_BLOCK_SIZE_BITS: u32 = EROFS_BLOCK_SIZE.trailing_zeros();

/// The global header, sealed with CRC32C over the complete metadata. It
/// holds only what concerns the whole file; every table-specific global
/// field lives in its own table header, see [`BlobMetadata`].
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
}

impl BlobMetadataHeader {
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < NYDUS_BLOB_METADATA_HEADER_SIZE {
            return Err(Error::InvalidImage(
                "blob meta header is truncated".to_string(),
            ));
        }
        if bytes[..8] != NYDUS_BLOB_METADATA_MAGIC {
            return Err(Error::InvalidImage("invalid blob meta magic".to_string()));
        }
        Ok(Self {
            feature_compat: read_u32_at(bytes, 8),
            feature_incompat: read_u32_at(bytes, 12),
            crc32: read_u32_at(bytes, 16),
            table_count: read_u16_at(bytes, 20),
        })
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

/// One table as described by the common header every table starts with.
/// Tables follow the global header back to back, each at the next 8-byte
/// boundary, so their layout needs no separate directory.
///
/// ```text
/// offset  size  field
///      0     2  type                    nonzero, unique; 0x8000 and above
///                                       are private
///      2     2  header_size             at least 16, a multiple of 8
///      4     2  feature_compat          unknown bits are ignored
///      6     2  feature_incompat        unknown bits reject the file; for
///                                       a table of unknown type every bit
///                                       is unknown, so a nonzero word
///                                       rejects and a zero one skips it
///      8     4  entry_size              bytes per entry
///     12     4  entry_count
/// ```
///
/// Table-specific header fields follow from offset 16, entries from
/// `header_size`; the table is `header_size + entry_size * entry_count`
/// bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlobMetadataTable {
    table_type: u16,
    feature_compat: u16,
    feature_incompat: u16,
    offset: usize,
    header_size: usize,
    entry_size: usize,
    entry_count: usize,
}

impl BlobMetadataTable {
    /// Parse the table header at `offset`, checking that the table fits in
    /// `bytes`.
    fn parse(bytes: &[u8], offset: usize) -> Result<Self> {
        if offset + NYDUS_BLOB_METADATA_TABLE_HEADER_SIZE > bytes.len() {
            return Err(Error::InvalidImage(format!(
                "blob meta table header at {offset:#x} is truncated"
            )));
        }
        let table = Self {
            table_type: read_u16_at(bytes, offset),
            header_size: read_u16_at(bytes, offset + 2) as usize,
            feature_compat: read_u16_at(bytes, offset + 4),
            feature_incompat: read_u16_at(bytes, offset + 6),
            entry_size: read_u32_at(bytes, offset + 8) as usize,
            entry_count: read_u32_at(bytes, offset + 12) as usize,
            offset,
        };
        let kind = table.table_type;
        if table.header_size < NYDUS_BLOB_METADATA_TABLE_HEADER_SIZE || table.header_size % 8 != 0 {
            return Err(Error::InvalidImage(format!(
                "blob meta table {kind:#x} header size {} is not a multiple of 8 of at least {NYDUS_BLOB_METADATA_TABLE_HEADER_SIZE}",
                table.header_size
            )));
        }
        // Both factors come from u32 fields, so the product fits in a u64.
        let size = table.header_size as u64 + table.entry_size as u64 * table.entry_count as u64;
        if offset as u64 + size > bytes.len() as u64 {
            return Err(Error::InvalidImage(format!(
                "blob meta table {kind:#x} extends past the {}-byte file",
                bytes.len()
            )));
        }
        Ok(table)
    }

    /// The table type.
    pub fn table_type(&self) -> u16 {
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
}

/// A known table resolved at load: where its header and entries start and
/// the declared entry stride, which may exceed the size this reader knows.
#[derive(Clone, Copy, Debug)]
struct TableView {
    header: usize,
    entries: usize,
    entry_size: usize,
    entry_count: usize,
}

impl TableView {
    /// Resolve a known table: its declared header and entry sizes must
    /// cover the ones this reader knows, and its incompat bits must be
    /// supported.
    fn of(
        table: &BlobMetadataTable,
        name: &str,
        header_size: usize,
        entry_size: usize,
    ) -> Result<Self> {
        if table.header_size < header_size {
            return Err(Error::InvalidImage(format!(
                "blob meta {name} header size {} is below {header_size}",
                table.header_size
            )));
        }
        let unknown = table.feature_incompat & !NYDUS_BLOB_METADATA_SUPPORTED_TABLE_INCOMPAT;
        if unknown != 0 {
            return Err(Error::Unsupported(format!(
                "unsupported blob meta {name} incompat flags {unknown:#x} (image is newer than this reader)"
            )));
        }
        if table.entry_size < entry_size {
            return Err(Error::InvalidImage(format!(
                "blob meta {name} entry size {} is below {entry_size}",
                table.entry_size
            )));
        }
        Ok(Self {
            header: table.offset,
            entries: table.offset + table.header_size,
            entry_size: table.entry_size,
            entry_count: table.entry_count,
        })
    }

    /// Byte offset of entry `index`; the caller keeps it below the count.
    fn at(&self, index: usize) -> usize {
        self.entries + index * self.entry_size
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
///      0     8  compressed_offset          bytes into the data region where
///                                          the group's encoded payload starts
///      8     4  uncompressed_block_offset  first 4KiB block of the group in
///                                          the address space
///     12     4  first_chunk_index          index of the group's first entry
///                                          in ChunkTable
///     16     4  payload_size               bytes the group decodes to (zero
///                                          in the terminator)
///     20     4  payload_crc32              CRC32C of the decoded payload
///                                          (zero in the terminator)
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ChunkGroupEntry {
    compressed_offset: u64,
    uncompressed_block_offset: u32,
    first_chunk_index: u32,
    payload_size: u32,
    payload_crc32: u32,
}

impl ChunkGroupEntry {
    fn read(bytes: &[u8], at: usize) -> Self {
        Self {
            compressed_offset: read_u64_at(bytes, at),
            uncompressed_block_offset: read_u32_at(bytes, at + 8),
            first_chunk_index: read_u32_at(bytes, at + 12),
            payload_size: read_u32_at(bytes, at + 16),
            payload_crc32: read_u32_at(bytes, at + 20),
        }
    }

    fn write(self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.compressed_offset.to_le_bytes());
        out.extend_from_slice(&self.uncompressed_block_offset.to_le_bytes());
        out.extend_from_slice(&self.first_chunk_index.to_le_bytes());
        out.extend_from_slice(&self.payload_size.to_le_bytes());
        out.extend_from_slice(&self.payload_crc32.to_le_bytes());
    }
}

/// One redirect table entry: the chunk group of another blob of the image
/// that the chunk group at the same index copies. Present only in a
/// redirect blob (an `optimize` output), one entry per chunk group.
///
/// ```text
/// offset  size  field
///      0     2  source_blob_index         nonzero source device index
///      2     2  reserved                  writers zero it, readers ignore it
///      4     4  source_chunk_group_index  the copied group within it
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlobMetadataRedirect {
    source_blob_index: u16,
    source_chunk_group_index: u32,
}

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
            source_chunk_group_index,
        })
    }

    fn read(bytes: &[u8], at: usize) -> Self {
        Self {
            source_blob_index: read_u16_at(bytes, at),
            source_chunk_group_index: read_u32_at(bytes, at + 4),
        }
    }

    fn write(self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.source_blob_index.to_le_bytes());
        out.extend_from_slice(&[0; 2]);
        out.extend_from_slice(&self.source_chunk_group_index.to_le_bytes());
    }

    fn validate(&self) -> Result<()> {
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
    uncompressed_block_offset: u32,
    blocks: u32,
    first_chunk_index: u32,
    chunk_count: u32,
    payload_size: u32,
    payload_crc32: u32,
    redirect: Option<BlobMetadataRedirect>,
}

impl BlobMetadataChunkGroup {
    /// Describes a group for a writer: `compressed_size` bytes of encoded
    /// payload decoding to `payload_size` bytes whose crc32c is `payload_crc32`,
    /// holding `chunk_count` nonempty chunks, including a single chunk.
    /// Every length is listed in ChunkTable. `redirect` names the source
    /// when the blob is an optimize output.
    /// Index, offsets and blocks are assigned by [`BlobMetadata::new`].
    pub fn new(
        compressed_size: u32,
        payload_size: u32,
        chunk_count: u32,
        payload_crc32: u32,
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
            uncompressed_block_offset: 0,
            blocks: 0,
            first_chunk_index: 0,
            chunk_count,
            payload_size,
            payload_crc32,
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
    pub fn payload_crc32(&self) -> u32 {
        self.payload_crc32
    }

    /// The source this group copies, in a redirect blob.
    pub fn redirect(&self) -> Option<BlobMetadataRedirect> {
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlobMetadataDigest {
    digest: [u8; 32],
}

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

    /// The digest, algorithm per the DigestTable header.
    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
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

impl Deref for BlobMetadataBytes {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        match self {
            Self::Owned(bytes) => bytes,
            Self::Mapped(mmap) => mmap,
        }
    }
}

/// A nydus blob's metadata: how the blob's uncompressed address space —
/// what the EROFS chunk indexes point into and the cache file mirrors —
/// maps onto its encoded payload, sealed with a crc32c in the header.
///
/// Serialized, it is the `.blob.meta` sidecar file — and, embedded verbatim,
/// the blob meta region of a full blob (see [`super::footer::BlobFooter`]):
///
/// ```text
/// Header (24 B, see BlobMetadataHeader)
/// table_count tables back to back, each at the next 8-byte boundary and
/// starting with the common 16 B header (see BlobMetadataTable):
///   GroupTable         type 1, 24 B header
///                        16  u8  maximum_group_span_block_shift, <= 19
///                        17  u8  compressor: 0 none, 1 zstd, 2 lz4
///                      (groups + 1) * 24 B, including the terminator
///   ChunkTable         type 2, 16 B header, chunks * 4 B lengths
///   GranuleIndexTable  type 3, 24 B header
///                        16  u8  lookup_granule_block_shift, <= the span's
///                      ceil(total blocks / granule blocks) * 4 B
///   DigestTable        type 4, optional, 24 B header
///                        16  u8  algorithm: 1 BLAKE3
///                      groups * 32 B
///   RedirectTable      type 5, only in redirect blobs, 16 B header,
///                      groups * 8 B
/// Zero padding to a 4 KiB multiple
/// ```
///
/// The table headers are the compatibility contract: a reader skips a table
/// of unknown type unless it has incompat bits, reads known tables
/// through their declared header and entry sizes so that fields a newer
/// writer appends are ignored, and rejects unknown incompat feature bits of
/// the file or of a known table. The bytes are kept verbatim, so
/// [`Self::write_to`] preserves tables this reader does not know. Unknown
/// DigestTable algorithms leave the blob undigested for this reader, see
/// [`Self::unsupported_digest_algorithm`].
///
/// The groups tile the address space back to back: group `i` spans the
/// blocks `[uncompressed_block_offset(i), uncompressed_block_offset(i + 1))`,
/// its chunks (whole files, or chunk-sized slices of larger files) sit back
/// to back inside it, each starting on its own 4KiB block. ChunkTable lists
/// every chunk length, including groups of one chunk. The encoded stream
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
/// A redirect blob (an `optimize` output) is laid out the same way, but
/// every group is a byte-exact copy of a chunk group of another blob of the
/// image, named by the redirect table; the runtime decodes it into that
/// source blob's cache instead of its own. It has its own GranuleIndexTable,
/// sized using the smallest non-final copied group's span.
#[derive(Debug)]
pub struct BlobMetadata {
    bytes: BlobMetadataBytes,
    header: BlobMetadataHeader,
    tables: Vec<BlobMetadataTable>,
    groups: TableView,
    chunks: TableView,
    granules: TableView,
    digests: Option<TableView>,
    redirects: Option<TableView>,
    compressor: BlobMetadataCompressor,
    unsupported_digest_algorithm: Option<u8>,
    maximum_group_span_block_shift: u8,
    lookup_granule_block_shift: u8,
    chunk_group_count: u32,
    chunk_count: u32,
    total_blocks: u32,
}

impl BlobMetadata {
    /// Creates validated metadata. `group_span` bounds the group span in
    /// bytes and `lookup_granule` is the lookup granule in bytes, both
    /// powers of two of at least one block, the granule at most the span.
    /// Every non-final group must
    /// span at least a granule. Payloads and padded spans tile their spaces
    /// from zero. `chunk_lengths` lists every chunk, including lone ones,
    /// in group order. `digests` is one entry per group with BLAKE3, else
    /// empty. Redirect sources must be present for all groups or none.
    /// Returns an error for invalid geometry, inconsistent tables or overflow.
    pub fn new(
        compressor: BlobMetadataCompressor,
        digester: BlobMetadataDigester,
        group_span: u32,
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
        let maximum_group_span_block_shift = size_to_block_shift(group_span)?;
        let lookup_granule_block_shift = size_to_block_shift(lookup_granule)?;

        // Lay the groups out back to back in the data region, the address
        // space and ChunkTable, and end with the terminator.
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
                uncompressed_block_offset: u32::try_from(uncompressed_block_offset).map_err(
                    |_| {
                        Error::Overflow(format!(
                            "blob meta chunk group {index} starts past the 32-bit block space"
                        ))
                    },
                )?,
                first_chunk_index,
                payload_size: group.payload_size,
                payload_crc32: group.payload_crc32,
            });
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
                "blob meta ChunkTable holds {} entries, the chunk groups name {first_chunk_index}",
                chunk_lengths.len()
            )));
        }
        let total_blocks = u32::try_from(uncompressed_block_offset).map_err(|_| {
            Error::Overflow("blob meta address space exceeds the 32-bit block space".to_string())
        })?;
        entries.push(ChunkGroupEntry {
            compressed_offset,
            uncompressed_block_offset: total_blocks,
            first_chunk_index,
            payload_size: 0,
            payload_crc32: 0,
        });
        let granule_indices =
            build_granule_index(&entries, total_blocks, lookup_granule_block_shift);

        let mut tables = vec![
            encode_table(
                NYDUS_BLOB_METADATA_TABLE_CHUNK_GROUP,
                CHUNK_GROUP_TABLE_HEADER_SIZE,
                &[maximum_group_span_block_shift, compressor.code()],
                NYDUS_BLOB_METADATA_CHUNK_GROUP_ENTRY_SIZE,
                entries.len(),
                |out| entries.iter().for_each(|entry| entry.write(out)),
            )?,
            encode_table(
                NYDUS_BLOB_METADATA_TABLE_CHUNK,
                NYDUS_BLOB_METADATA_TABLE_HEADER_SIZE,
                &[],
                NYDUS_BLOB_METADATA_CHUNK_ENTRY_SIZE,
                chunk_lengths.len(),
                |out| {
                    chunk_lengths
                        .iter()
                        .for_each(|len| out.extend_from_slice(&len.to_le_bytes()))
                },
            )?,
            encode_table(
                NYDUS_BLOB_METADATA_TABLE_GRANULE_INDEX,
                GRANULE_INDEX_TABLE_HEADER_SIZE,
                &[lookup_granule_block_shift],
                NYDUS_BLOB_METADATA_GRANULE_INDEX_ENTRY_SIZE,
                granule_indices.len(),
                |out| {
                    granule_indices
                        .iter()
                        .for_each(|group| out.extend_from_slice(&group.to_le_bytes()))
                },
            )?,
        ];
        if let Some(algorithm) = digester.code() {
            tables.push(encode_table(
                NYDUS_BLOB_METADATA_TABLE_DIGEST,
                DIGEST_TABLE_HEADER_SIZE,
                &[algorithm],
                NYDUS_BLOB_METADATA_DIGEST_ENTRY_SIZE,
                digests.len(),
                |out| {
                    digests
                        .iter()
                        .for_each(|digest| out.extend_from_slice(digest.digest()))
                },
            )?);
        }
        if is_redirect {
            tables.push(encode_table(
                NYDUS_BLOB_METADATA_TABLE_REDIRECT,
                NYDUS_BLOB_METADATA_TABLE_HEADER_SIZE,
                &[],
                NYDUS_BLOB_METADATA_REDIRECT_ENTRY_SIZE,
                redirects.len(),
                |out| redirects.iter().for_each(|redirect| redirect.write(out)),
            )?);
        }
        Self::parse(BlobMetadataBytes::Owned(assemble(&tables)?))
    }

    /// Read blob metadata from an in-memory byte slice, verifying the header
    /// crc32 over the full metadata.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Self::parse(BlobMetadataBytes::Owned(bytes.to_vec()))
    }

    /// Read blob metadata from a file (mmap-backed), verifying the header
    /// crc32 over the full metadata. The tables are validated in place; the
    /// mapping is kept and read zero-copy.
    pub fn from_path(path: &Path) -> Result<Self> {
        let file = File::open(path)
            .with_context(|| format!("failed to open blob meta: {}", path.display()))?;
        // SAFETY: the sidecar is written once and then only read; a
        // concurrent truncation would surface as SIGBUS, which is the
        // accepted trade-off for zero-copy tables (same as the other
        // mapped sidecars).
        let mmap = unsafe { MmapOptions::new().map(&file) }
            .with_context(|| format!("failed to mmap blob meta: {}", path.display()))?;
        Self::parse(BlobMetadataBytes::Mapped(mmap))
    }

    /// Anchor the bytes, walk the tables and resolve the known ones, then
    /// validate the tables against each other.
    fn parse(bytes: BlobMetadataBytes) -> Result<Self> {
        let raw: &[u8] = &bytes;
        let len = raw.len() as u64;
        if len < NYDUS_BLOB_METADATA_HEADER_SIZE as u64 || len % BLOCK != 0 {
            return Err(Error::InvalidImage(format!(
                "blob meta size {len} is not a whole number of 4 KiB blocks"
            )));
        }
        let header = BlobMetadataHeader::from_bytes(raw)?;
        let actual = compute_crc32(raw);
        if header.crc32 != actual {
            return Err(Error::InvalidImage(format!(
                "blob meta crc32 mismatch: expected {:#010x}, got {actual:#010x}",
                header.crc32
            )));
        }
        FeatureFlags::from_bits(header.feature_incompat)
            .validate_incompat(NYDUS_BLOB_METADATA_SUPPORTED_INCOMPAT)?;

        let mut tables: Vec<BlobMetadataTable> = Vec::with_capacity(header.table_count as usize);
        let mut end = NYDUS_BLOB_METADATA_HEADER_SIZE;
        for _ in 0..header.table_count {
            let table = BlobMetadataTable::parse(raw, end.next_multiple_of(8))?;
            let kind = table.table_type;
            if kind == 0 || tables.iter().any(|known| known.table_type == kind) {
                return Err(Error::InvalidImage(format!(
                    "blob meta table at {:#x} has a zero or duplicate type {kind:#x}",
                    table.offset
                )));
            }
            if !is_known_table(kind) && table.feature_incompat != 0 {
                return Err(Error::Unsupported(format!(
                    "unsupported incompat blob meta table {kind:#x} (image is newer than this reader)"
                )));
            }
            end = table.range().end;
            tables.push(table);
        }
        if align_up_u64(end as u64, BLOCK) != Some(len) {
            return Err(Error::InvalidImage(format!(
                "blob meta size mismatch: the tables end at {end}, the file holds {len} bytes"
            )));
        }

        let find = |kind: u16| tables.iter().find(|table| table.table_type == kind);
        let required = |kind: u16, name: &str| {
            find(kind).ok_or_else(|| Error::InvalidImage(format!("blob meta lacks its {name}")))
        };
        let groups = TableView::of(
            required(NYDUS_BLOB_METADATA_TABLE_CHUNK_GROUP, "GroupTable")?,
            "GroupTable",
            CHUNK_GROUP_TABLE_HEADER_SIZE,
            NYDUS_BLOB_METADATA_CHUNK_GROUP_ENTRY_SIZE,
        )?;
        let chunks = TableView::of(
            required(NYDUS_BLOB_METADATA_TABLE_CHUNK, "ChunkTable")?,
            "ChunkTable",
            NYDUS_BLOB_METADATA_TABLE_HEADER_SIZE,
            NYDUS_BLOB_METADATA_CHUNK_ENTRY_SIZE,
        )?;
        let granules = TableView::of(
            required(NYDUS_BLOB_METADATA_TABLE_GRANULE_INDEX, "GranuleIndexTable")?,
            "GranuleIndexTable",
            GRANULE_INDEX_TABLE_HEADER_SIZE,
            NYDUS_BLOB_METADATA_GRANULE_INDEX_ENTRY_SIZE,
        )?;
        let digests = find(NYDUS_BLOB_METADATA_TABLE_DIGEST)
            .map(|table| {
                TableView::of(
                    table,
                    "DigestTable",
                    DIGEST_TABLE_HEADER_SIZE,
                    NYDUS_BLOB_METADATA_DIGEST_ENTRY_SIZE,
                )
            })
            .transpose()?;
        let redirects = find(NYDUS_BLOB_METADATA_TABLE_REDIRECT)
            .map(|table| {
                TableView::of(
                    table,
                    "RedirectTable",
                    NYDUS_BLOB_METADATA_TABLE_HEADER_SIZE,
                    NYDUS_BLOB_METADATA_REDIRECT_ENTRY_SIZE,
                )
            })
            .transpose()?;

        let maximum_group_span_block_shift = read_u8_at(raw, groups.header + 16);
        if maximum_group_span_block_shift > NYDUS_BLOB_METADATA_MAX_GROUP_SPAN_BLOCK_SHIFT {
            return Err(Error::InvalidImage(format!(
                "blob meta maximum group span block shift {maximum_group_span_block_shift} exceeds {NYDUS_BLOB_METADATA_MAX_GROUP_SPAN_BLOCK_SHIFT}"
            )));
        }
        let compressor = BlobMetadataCompressor::from_code(read_u8_at(raw, groups.header + 17))?;
        let lookup_granule_block_shift = read_u8_at(raw, granules.header + 16);
        if lookup_granule_block_shift > maximum_group_span_block_shift {
            return Err(Error::InvalidImage(format!(
                "blob meta lookup granule block shift {lookup_granule_block_shift} exceeds the group span block shift {maximum_group_span_block_shift}"
            )));
        }
        let Some(chunk_group_count) = groups.entry_count.checked_sub(1) else {
            return Err(Error::InvalidImage(
                "blob meta chunk group table lacks its terminator".to_string(),
            ));
        };
        let terminator = groups.at(chunk_group_count);
        let total_blocks = read_u32_at(raw, terminator + 8);
        let chunk_count = read_u32_at(raw, terminator + 12);
        let chunk_group_count = chunk_group_count as u32;
        let empty = chunk_group_count == 0;
        if empty != (chunk_count == 0) || empty != (total_blocks == 0) {
            return Err(Error::InvalidImage(format!(
                "blob meta has {chunk_group_count} chunk groups, {chunk_count} chunks and {total_blocks} blocks"
            )));
        }
        if chunk_group_count > chunk_count {
            return Err(Error::InvalidImage(format!(
                "blob meta names {chunk_group_count} groups among {chunk_count} chunks"
            )));
        }
        if chunks.entry_count != chunk_count as usize {
            return Err(Error::InvalidImage(format!(
                "blob meta ChunkTable holds {} entries, the chunk groups name {chunk_count}",
                chunks.entry_count
            )));
        }
        let granule_count = u64::from(total_blocks).div_ceil(1 << lookup_granule_block_shift);
        if granules.entry_count as u64 != granule_count {
            return Err(Error::InvalidImage(format!(
                "blob meta GranuleIndexTable holds {} entries for {granule_count} granules",
                granules.entry_count
            )));
        }
        let (digests, unsupported_digest_algorithm) = match digests {
            None => (None, None),
            Some(view) => {
                let algorithm = read_u8_at(raw, view.header + 16);
                if BlobMetadataDigester::from_code(algorithm).is_some() {
                    (Some(view), None)
                } else {
                    (None, Some(algorithm))
                }
            }
        };
        for (name, view) in [("DigestTable", digests), ("RedirectTable", redirects)] {
            if view.is_some_and(|view| view.entry_count != chunk_group_count as usize) {
                return Err(Error::InvalidImage(format!(
                    "blob meta {name} does not hold one entry per chunk group"
                )));
            }
        }

        let blob_metadata = Self {
            bytes,
            header,
            tables,
            groups,
            chunks,
            granules,
            digests,
            redirects,
            compressor,
            unsupported_digest_algorithm,
            maximum_group_span_block_shift,
            lookup_granule_block_shift,
            chunk_group_count,
            chunk_count,
            total_blocks,
        };
        blob_metadata.validate_tables()?;
        blob_metadata.validate_index()?;
        Ok(blob_metadata)
    }

    fn entry(&self, index: usize) -> ChunkGroupEntry {
        ChunkGroupEntry::read(&self.bytes, self.groups.at(index))
    }

    /// First block of group `index`, the terminator's for `chunk_group_count`.
    fn block_offset_of(&self, index: usize) -> u32 {
        read_u32_at(&self.bytes, self.groups.at(index) + 8)
    }

    /// ChunkTable entry `index`; the caller keeps the index below chunk_count.
    fn chunk_length_of(&self, index: usize) -> u32 {
        read_u32_at(&self.bytes, self.chunks.at(index))
    }

    fn granule_group_of(&self, index: usize) -> usize {
        read_u32_at(&self.bytes, self.granules.at(index)) as usize
    }

    fn redirect_of(&self, index: usize) -> Option<BlobMetadataRedirect> {
        self.redirects
            .filter(|view| index < view.entry_count)
            .map(|view| BlobMetadataRedirect::read(&self.bytes, view.at(index)))
    }

    /// 4KiB blocks per GranuleIndexTable entry.
    fn granule_blocks(&self) -> u64 {
        1 << self.lookup_granule_block_shift
    }

    /// Validate contiguous data, block and chunk ranges, nonzero lengths,
    /// payload sums, span bounds, encoding sizes and redirect sources.
    fn validate_tables(&self) -> Result<()> {
        let span_blocks = u64::from(self.group_span_blocks());
        let granule_blocks = self.granule_blocks();
        let chunk_count = self.chunk_count;
        let terminator = self.entry(self.chunk_group_count as usize);
        if terminator.payload_size != 0 || terminator.payload_crc32 != 0 {
            return Err(Error::InvalidImage(format!(
                "blob meta chunk group terminator carries payload {} and crc {}",
                terminator.payload_size, terminator.payload_crc32
            )));
        }
        let first = self.entry(0);
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
            self.redirect_of(index)
                .expect("redirect index within the table")
                .validate()?;
        }
        let groups = self.chunk_group_count as usize;
        let mut total_chunk_count = 0u64;
        let mut start = first;
        for index in 0..groups {
            let end = self.entry(index + 1);
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
                    let len = self.chunk_length_of(member as usize);
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
        for index in 0..self.granules.entry_count {
            let block = index as u64 * self.granule_blocks();
            while group + 1 < groups && u64::from(self.block_offset_of(group + 1)) <= block {
                group += 1;
            }
            if self.granule_group_of(index) != group {
                return Err(Error::InvalidImage(
                    "blob meta GranuleIndexTable does not match GroupTable".to_string(),
                ));
            }
        }
        Ok(())
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

    /// The parsed global header, exactly as stored on disk.
    pub fn header(&self) -> &BlobMetadataHeader {
        &self.header
    }

    /// The tables, in file order.
    pub fn tables(&self) -> &[BlobMetadataTable] {
        &self.tables
    }

    /// The raw bytes of the table of type `table_type`, its header included,
    /// `None` when there is no such table.
    pub fn table_bytes(&self, table_type: u16) -> Option<&[u8]> {
        self.tables
            .iter()
            .find(|table| table.table_type == table_type)
            .map(|table| &self.bytes[table.range()])
    }

    /// The algorithm code of a DigestTable this reader does not know, which
    /// leaves the blob undigested for it; a reader that must verify digests
    /// fails on it instead of skipping the verification.
    pub fn unsupported_digest_algorithm(&self) -> Option<u8> {
        self.unsupported_digest_algorithm
    }

    /// Byte length of a stored chunk, including lone chunks; `None` past ChunkTable.
    pub fn chunk_len(&self, index: usize) -> Option<u32> {
        (index < self.chunk_count as usize).then(|| self.chunk_length_of(index))
    }

    /// The digest table, one entry per chunk group; empty without a
    /// supported digester.
    pub fn digests(&self) -> Vec<BlobMetadataDigest> {
        (0..self.digest_count())
            .filter_map(|index| self.digest(index))
            .collect()
    }

    /// The redirect table, one entry per chunk group of a redirect blob;
    /// empty otherwise.
    pub fn redirects(&self) -> Vec<BlobMetadataRedirect> {
        (0..self.redirect_count())
            .filter_map(|index| self.redirect_of(index))
            .collect()
    }

    /// The digest of chunk group `index`, `None` past the table or without
    /// a supported digester.
    pub fn digest(&self, index: usize) -> Option<BlobMetadataDigest> {
        let view = self.digests.filter(|view| index < view.entry_count)?;
        let at = view.at(index);
        let digest = self.bytes[at..at + NYDUS_BLOB_METADATA_DIGEST_ENTRY_SIZE]
            .try_into()
            .expect("digest entry is 32 bytes");
        Some(BlobMetadataDigest::new(digest))
    }

    /// The chunk group at `index`, `None` past the table.
    pub fn chunk_group(&self, index: usize) -> Option<BlobMetadataChunkGroup> {
        if index >= self.chunk_group_count() {
            return None;
        }
        let (start, end) = (self.entry(index), self.entry(index + 1));
        Some(BlobMetadataChunkGroup {
            index: index as u32,
            compressed_offset: start.compressed_offset,
            compressed_size: (end.compressed_offset - start.compressed_offset) as u32,
            uncompressed_block_offset: start.uncompressed_block_offset,
            blocks: end.uncompressed_block_offset - start.uncompressed_block_offset,
            first_chunk_index: start.first_chunk_index,
            chunk_count: end.first_chunk_index - start.first_chunk_index,
            payload_size: start.payload_size,
            payload_crc32: start.payload_crc32,
            redirect: self.redirect_of(index),
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

    /// Number of GranuleIndexTable entries.
    pub fn granule_index_count(&self) -> usize {
        self.granules.entry_count
    }

    /// Number of redirect entries: every chunk group of a redirect blob.
    pub fn redirect_count(&self) -> usize {
        self.redirects.map_or(0, |view| view.entry_count)
    }

    /// log2 of the most 4KiB blocks a chunk group spans, as stored in the
    /// GroupTable header.
    pub fn maximum_group_span_block_shift(&self) -> u8 {
        self.maximum_group_span_block_shift
    }

    /// log2 of the lookup granule in 4KiB blocks, as stored in the
    /// GranuleIndexTable header.
    pub fn lookup_granule_block_shift(&self) -> u8 {
        self.lookup_granule_block_shift
    }

    /// The most 4KiB blocks a chunk group spans.
    pub fn group_span_blocks(&self) -> u32 {
        1 << self.maximum_group_span_block_shift
    }

    /// The most bytes of the address space a chunk group spans: a lone
    /// chunk is at most a file chunk, a pack may span more. Bounds the
    /// decode scratch a reader needs for any group.
    pub fn group_span(&self) -> u32 {
        EROFS_BLOCK_SIZE << self.maximum_group_span_block_shift
    }

    /// The mandatory lookup granule in bytes; every non-final group spans
    /// at least this much.
    pub fn lookup_granule(&self) -> u32 {
        EROFS_BLOCK_SIZE << self.lookup_granule_block_shift
    }

    /// The chunk group payload compressor.
    pub fn compressor(&self) -> BlobMetadataCompressor {
        self.compressor
    }

    /// The digest algorithm, `None` without a DigestTable this reader
    /// supports.
    pub fn digester(&self) -> BlobMetadataDigester {
        if self.digests.is_some() {
            BlobMetadataDigester::Blake3
        } else {
            BlobMetadataDigester::None
        }
    }

    /// Whether the blob is an `optimize` output whose chunk groups copy
    /// other blobs' groups, named by its RedirectTable.
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
        self.uncompressed_block_count() * BLOCK
    }

    /// Bytes all chunk groups decode to: the chunks' bytes without padding.
    pub fn payload_total(&self) -> u64 {
        (0..self.chunk_group_count())
            .map(|index| u64::from(self.entry(index).payload_size))
            .sum()
    }

    /// End of the last chunk group's compressed range: the data region's
    /// size.
    pub fn compressed_end(&self) -> u64 {
        self.entry(self.chunk_group_count()).compressed_offset
    }

    /// The full serialized size, 4KiB aligned.
    pub fn padded_size(&self) -> u64 {
        self.bytes.len() as u64
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
        if block >= u64::from(self.total_blocks) {
            return None;
        }
        let mut group = self.granule_group_of((block >> self.lookup_granule_block_shift) as usize);
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
            let len = self.chunk_length_of(member);
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
}

/// Whether this reader interprets tables of type `table_type`.
fn is_known_table(table_type: u16) -> bool {
    (NYDUS_BLOB_METADATA_TABLE_CHUNK_GROUP..=NYDUS_BLOB_METADATA_TABLE_REDIRECT)
        .contains(&table_type)
}

/// crc32c over a serialized buffer with the header's crc32 field zeroed.
fn compute_crc32(bytes: &[u8]) -> u32 {
    let field = NYDUS_BLOB_METADATA_HEADER_CRC32_FIELD;
    let crc32 = crc32c_append(crc32c(&bytes[..field.start]), &[0; 4]);
    crc32c_append(crc32, &bytes[field.end..])
}

/// Encode one table: the common header, its table-specific header fields
/// from offset 16, then `entry_count` entries of `entry_size` bytes.
fn encode_table(
    table_type: u16,
    header_size: usize,
    header_fields: &[u8],
    entry_size: usize,
    entry_count: usize,
    write_entries: impl FnOnce(&mut Vec<u8>),
) -> Result<Vec<u8>> {
    let count = u32::try_from(entry_count)
        .map_err(|_| Error::Overflow("blob meta table entry count exceeds u32".to_string()))?;
    let mut table = vec![0u8; header_size];
    write_u16_at(&mut table, 0, table_type);
    write_u16_at(&mut table, 2, header_size as u16);
    write_u32_at(&mut table, 8, entry_size as u32);
    write_u32_at(&mut table, 12, count);
    table[NYDUS_BLOB_METADATA_TABLE_HEADER_SIZE..][..header_fields.len()]
        .copy_from_slice(header_fields);
    write_entries(&mut table);
    debug_assert_eq!(table.len(), header_size + entry_size * entry_count);
    Ok(table)
}

/// Lay out the header and the encoded `tables` in order, each at the next
/// 8-byte boundary, zero-pad to a 4 KiB multiple and seal the crc32.
fn assemble(tables: &[Vec<u8>]) -> Result<Vec<u8>> {
    let table_count = u16::try_from(tables.len())
        .map_err(|_| Error::Overflow("blob meta holds more than 65535 tables".to_string()))?;
    let mut out = vec![0u8; NYDUS_BLOB_METADATA_HEADER_SIZE];
    out[..8].copy_from_slice(&NYDUS_BLOB_METADATA_MAGIC);
    write_u16_at(&mut out, 20, table_count);
    for table in tables {
        out.resize(out.len().next_multiple_of(8), 0);
        out.extend_from_slice(table);
    }
    out.resize(out.len().next_multiple_of(BLOCK as usize), 0);
    let crc32 = compute_crc32(&out);
    write_u32_at(
        &mut out,
        NYDUS_BLOB_METADATA_HEADER_CRC32_FIELD.start,
        crc32,
    );
    Ok(out)
}

/// Build GranuleIndexTable: the group covering each granule's first block.
fn build_granule_index(
    entries: &[ChunkGroupEntry],
    total_blocks: u32,
    granule_block_shift: u8,
) -> Vec<u32> {
    let granule_blocks = 1u64 << granule_block_shift;
    let count = u64::from(total_blocks).div_ceil(granule_blocks);
    let groups = entries.len() - 1;
    let mut group = 0usize;
    (0..count)
        .map(|cell| {
            let cell_start = cell * granule_blocks;
            // The terminator's start is the address space's end, past every cell.
            while group + 1 < groups
                && u64::from(entries[group + 1].uncompressed_block_offset) <= cell_start
            {
                group += 1;
            }
            group as u32
        })
        .collect()
}

/// Encode a power-of-two byte size between one block and 2 GiB as the log2
/// of its 4KiB block count, the unit of the table header shift fields.
fn size_to_block_shift(size: u32) -> Result<u8> {
    if !size.is_power_of_two() || size < EROFS_BLOCK_SIZE {
        return Err(Error::InvalidParameter(format!(
            "blob meta size {size} must be a power of two of at least one block"
        )));
    }
    Ok((size.ilog2() - EROFS_BLOCK_SIZE_BITS) as u8)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn digest(bytes: &[u8]) -> [u8; 32] {
        *blake3::hash(bytes).as_bytes()
    }

    fn reseal(mut bytes: Vec<u8>) -> Vec<u8> {
        let crc32 = compute_crc32(&bytes);
        write_u32_at(
            &mut bytes,
            NYDUS_BLOB_METADATA_HEADER_CRC32_FIELD.start,
            crc32,
        );
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
    fn table_offset(meta: &BlobMetadata, table_type: u16) -> usize {
        meta.tables()
            .iter()
            .find(|table| table.table_type() == table_type)
            .unwrap()
            .range()
            .start
    }

    /// Byte offset of the first entry of table `table_type`.
    fn entries_offset(meta: &BlobMetadata, table_type: u16) -> usize {
        table_offset(meta, table_type)
            + read_u16_at(meta.table_bytes(table_type).unwrap(), 2) as usize
    }

    fn entries(meta: &BlobMetadata) -> Vec<ChunkGroupEntry> {
        (0..=meta.chunk_group_count())
            .map(|index| meta.entry(index))
            .collect()
    }

    fn granules(meta: &BlobMetadata) -> Vec<usize> {
        (0..meta.granule_index_count())
            .map(|index| meta.granule_group_of(index))
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
            span,
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
        // GroupTable header fields: 64 KiB span is 16 blocks (shift 4), no
        // compressor; GranuleIndexTable: a one-block granule (shift 0);
        // DigestTable: BLAKE3.
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
        assert_eq!(meta.maximum_group_span_block_shift(), 4);
        assert_eq!(meta.lookup_granule_block_shift(), 0);

        // Reserved fields and padding are ignored but sealed: the header
        // reserved field, the GroupTable header reserved bytes, table
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
        let group_table = table_offset(&meta, NYDUS_BLOB_METADATA_TABLE_CHUNK_GROUP);
        let mut compat = raw.clone();
        write_u16_at(&mut compat, group_table + 4, 1 << 15);
        assert!(BlobMetadata::from_bytes(&reseal(compat)).is_ok());
        let mut incompat = raw.clone();
        write_u16_at(&mut incompat, group_table + 6, 1);
        let err = BlobMetadata::from_bytes(&reseal(incompat)).unwrap_err();
        assert!(err.to_string().contains("GroupTable incompat"), "{err}");
    }

    #[test]
    fn unknown_tables_follow_their_incompat_bits() {
        let (meta, _) = fixture();
        let tables = split(&meta);
        let unknown = |kind: u16, incompat: u16| {
            let mut table =
                encode_table(kind, 16, &[], 4, 5, |out| out.extend([0x5a; 20])).unwrap();
            write_u16_at(&mut table, 6, incompat);
            table
        };
        let with = |extra: Vec<u8>| {
            let mut tables = tables.clone();
            tables.push(extra);
            assemble(&tables).unwrap()
        };

        // An unknown table without incompat bits is skipped and kept
        // verbatim.
        let extension = unknown(0x100, 0);
        let bytes = with(extension.clone());
        let loaded = BlobMetadata::from_bytes(&bytes).unwrap();
        assert_eq!(entries(&loaded), entries(&meta));
        assert_eq!(loaded.table_bytes(0x100), Some(&extension[..]));
        assert_eq!(raw(&loaded), bytes);
        let dir = tempdir().unwrap();
        let path = dir.path().join("x.blob.meta");
        loaded.save(&path).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        assert_eq!(
            BlobMetadata::from_path(&path).unwrap().table_bytes(0x100),
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
        rejects(assemble(&without_chunks).unwrap(), "lacks its ChunkTable");

        let raw = raw(&meta);
        let digest_table = table_offset(&meta, NYDUS_BLOB_METADATA_TABLE_DIGEST);
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
        let loaded = BlobMetadata::from_bytes(&assemble(&widened).unwrap()).unwrap();
        assert_eq!(entries(&loaded), entries(&meta));
        assert_eq!(granules(&loaded), granules(&meta));
        assert_eq!(loaded.digests(), meta.digests());
        assert_eq!(loaded.maximum_group_span_block_shift(), 4);
        assert_eq!(loaded.lookup_granule_block_shift(), 0);
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
        let digest_table = table_offset(&meta, NYDUS_BLOB_METADATA_TABLE_DIGEST);
        let mut narrow = raw(&meta);
        write_u32_at(&mut narrow, digest_table + 8, 16);
        let err = BlobMetadata::from_bytes(&reseal(narrow)).unwrap_err();
        assert!(
            err.to_string().contains("DigestTable entry size 16"),
            "{err}"
        );
    }

    #[test]
    fn table_header_fields_are_validated() {
        let (meta, _) = fixture();
        let raw = raw(&meta);
        let group_table = table_offset(&meta, NYDUS_BLOB_METADATA_TABLE_CHUNK_GROUP);
        let granule_table = table_offset(&meta, NYDUS_BLOB_METADATA_TABLE_GRANULE_INDEX);
        let digest_table = table_offset(&meta, NYDUS_BLOB_METADATA_TABLE_DIGEST);
        let mutate = |offset: usize, value: u8| {
            let mut bytes = raw.clone();
            bytes[offset] = value;
            BlobMetadata::from_bytes(&reseal(bytes))
        };
        let err = mutate(group_table + 16, 20).unwrap_err();
        assert!(err.to_string().contains("span block shift 20"), "{err}");
        let err = mutate(group_table + 17, 9).unwrap_err();
        assert!(err.to_string().contains("compressor 9"), "{err}");
        let err = mutate(granule_table + 16, 5).unwrap_err();
        assert!(err.to_string().contains("granule block shift 5"), "{err}");
        let err = mutate(group_table + 2, 20).unwrap_err();
        assert!(err.to_string().contains("header size 20"), "{err}");
        let err = mutate(digest_table + 2, 16).unwrap_err();
        assert!(
            err.to_string()
                .contains("DigestTable header size 16 is below 24"),
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
        assert_eq!(meta.uncompressed_size(), 30 * BLOCK);
        assert_eq!(meta.payload_total(), 5100 + 6041 + 20000 + 65536 + 2);
        assert_eq!(meta.compressed_end(), 5100 + 6041 + 20000 + 65536 + 2);
        assert_eq!(meta.lookup_granule(), 4096);
        assert_eq!(meta.group_span(), 64 * 1024);
        assert_eq!(meta.granule_index_count(), 30);
        let raw = raw(&meta);
        assert_eq!(raw.len(), 4096);
        let loaded = BlobMetadata::from_bytes(&raw).unwrap();
        assert_eq!(entries(&loaded), entries(&meta));
        assert_eq!(loaded.digests(), meta.digests());
        assert_eq!(granules(&loaded), granules(&meta));
        assert!(loaded.redirects().is_empty());

        let group = loaded.chunk_group(1).unwrap();
        assert_eq!(group.compressed_range(), 5100..11141);
        assert!(group.is_pack());
        assert_eq!(group.chunk_count(), 3);
        assert_eq!(group.chunk_range(), 2..5);
        assert_eq!(group.uncompressed_range(), 3 * BLOCK..7 * BLOCK);
        assert_eq!(loaded.payload_size(&group), 6041);
        assert!(loaded.is_plain(&group));
        assert_eq!(group.payload_crc32(), crc32c(&chunks_data[2..5].concat()));
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
            BlobMetadataDigest::of_group(&[
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
        let granule_indices = granules(&meta);
        assert_eq!(granule_indices.len(), 30);
        assert_eq!(granule_indices[0], 0);
        assert_eq!(granule_indices[3], 1);
        assert_eq!(granule_indices[28], 4);
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
        let mut tampered = raw(&meta);
        let granule_index_offset = entries_offset(&meta, NYDUS_BLOB_METADATA_TABLE_GRANULE_INDEX);
        write_u32_at(&mut tampered, granule_index_offset + 4, 1 << 3);
        assert!(BlobMetadata::from_bytes(&reseal(tampered))
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
        let meta = layered(16384, Some(8192), ok, vec![8192, 100], vec![]).unwrap();
        assert_eq!(meta.granule_index_count(), 2);
        assert_eq!(meta.chunk_group_index_of(2 * BLOCK), Some(1));
        let bad = vec![plain_group(&small, 1), plain_group(&big, 1)];
        assert!(layered(16384, Some(8192), bad, vec![100, 8192], vec![])
            .unwrap_err()
            .to_string()
            .contains("lookup granule"));
        // The granule is a power of two between one block and the span.
        for granule in [3000, 2048, 32768] {
            let groups = vec![plain_group(&big, 1)];
            assert!(layered(16384, Some(granule), groups, vec![8192], vec![]).is_err());
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
            vec![(0, 0, 70000), (1, 18 * BLOCK, 100)]
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
        let meta = layered(4096, Some(4096), Vec::new(), Vec::new(), Vec::new()).unwrap();
        let mut raw = Vec::new();
        meta.write_to(&mut raw).unwrap();
        assert_eq!(raw.len(), 4096);
        let loaded = BlobMetadata::from_bytes(&raw).unwrap();
        assert_eq!(loaded.uncompressed_size(), 0);
        assert_eq!(loaded.compressed_end(), 0);
        assert_eq!(loaded.granule_index_count(), 0);
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
                    Some(BlobMetadataRedirect::new(3, index as u32).unwrap()),
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
                .map(|table| (table.table_type(), table.feature_incompat()))
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
        assert_eq!(first.uncompressed_range(), 0..2 * BLOCK);
        assert_eq!(first.payload_crc32(), crc32c(&chunks[7..].concat()));
        let second = loaded.chunk_group(1).unwrap();
        assert_eq!(second.redirect().unwrap().source_chunk_group_index(), 0);
        assert_eq!(second.uncompressed_range(), 2 * BLOCK..5 * BLOCK);
        let dir = tempdir().unwrap();
        let path = dir.path().join("r.blob.meta");
        meta.save(&path).unwrap();
        assert_eq!(
            BlobMetadata::from_path(&path).unwrap().redirects(),
            meta.redirects()
        );

        // A zeroed source blob index is rejected on both sides; the
        // reserved half of an entry is ignored.
        assert!(BlobMetadataRedirect::new(0, 1).is_err());
        let redirects = entries_offset(&meta, NYDUS_BLOB_METADATA_TABLE_REDIRECT);
        assert_eq!(read_u16_at(&raw, redirects), 3);
        assert_eq!(read_u32_at(&raw, redirects + 4), 4);
        let mut zeroed = raw.clone();
        write_u16_at(&mut zeroed, redirects, 0);
        assert!(BlobMetadata::from_bytes(&reseal(zeroed)).is_err());
        let mut reserved = raw.clone();
        write_u16_at(&mut reserved, redirects + 2, 0xffff);
        assert!(BlobMetadata::from_bytes(&reseal(reserved)).is_ok());
        // RedirectTable holds one entry per chunk group.
        let mut short = split(&meta);
        let table = &mut short[4];
        write_u32_at(table, 12, 1);
        table.truncate(table.len() - 8);
        let err = BlobMetadata::from_bytes(&assemble(&short).unwrap()).unwrap_err();
        assert!(err.to_string().contains("RedirectTable"), "{err}");

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
    fn granule_index_corrects_once_and_rejects_corruption() {
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
        let granule_index_offset = entries_offset(&meta, NYDUS_BLOB_METADATA_TABLE_GRANULE_INDEX);
        for value in [1, u32::MAX] {
            let mut invalid = raw.clone();
            write_u32_at(&mut invalid, granule_index_offset, value);
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
            64 * 1024,
            Some(4096),
            groups(),
            chunk_lengths(),
            vec![BlobMetadataDigest::new([0; 32])]
        )
        .unwrap_err()
        .to_string()
        .contains("digest count"));

        // Tables whose counts disagree with the terminator.
        let raw = raw(&meta);
        let terminator = entries_offset(&meta, NYDUS_BLOB_METADATA_TABLE_CHUNK_GROUP) + 5 * 24;
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
        invalid[table_offset(&meta, NYDUS_BLOB_METADATA_TABLE_GRANULE_INDEX) + 16] = 1;
        assert!(BlobMetadata::from_bytes(&reseal(invalid)).is_err());
    }
}

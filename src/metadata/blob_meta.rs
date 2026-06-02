use super::{EROFS_BLOB_ID_SIZE, EROFS_BLOCK_SIZE};
use anyhow::{bail, Context, Result};
use bitflags::bitflags;
use crc32c::crc32c_append;
use memmap2::{Mmap, MmapOptions};
use std::fmt;
use std::fs::File;
use std::io::{Cursor, Read, Write};
use std::mem::{align_of, size_of};
use std::path::Path;

pub const BLOB_META_MAGIC: u32 = 0x4c50_424d;
pub const BLOB_META_HEADER_SIZE: u64 = 48;
pub const BLOB_META_DEFAULT_CHUNK_SIZE: u32 = 1024 * 1024;
pub const BLOB_META_DEFAULT_CHUNK_BLOCK_COUNT: u32 =
    BLOB_META_DEFAULT_CHUNK_SIZE / EROFS_BLOCK_SIZE;

const BLOB_META_HEADER_CRC32_OFFSET: usize = 8;
const BLOB_META_GROUP_RESERVED: u32 = 0;
const BLOB_META_CHUNK_RESERVED: u32 = 0;

bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct BlobMetaFeatures: u32 {
        const COMPRESSOR_ZSTD = 1 << 0;
        const DIGESTER_BLAKE3 = 1 << 16;
    }
}

const BLOB_META_COMPRESSOR_MASK: u32 = BlobMetaFeatures::COMPRESSOR_ZSTD.bits();
const BLOB_META_DIGESTER_MASK: u32 = BlobMetaFeatures::DIGESTER_BLAKE3.bits();

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlobMetaCompressor {
    None = 0,
    Zstd = 1,
}

impl BlobMetaCompressor {
    pub fn feature(self) -> BlobMetaFeatures {
        match self {
            Self::None => BlobMetaFeatures::empty(),
            Self::Zstd => BlobMetaFeatures::COMPRESSOR_ZSTD,
        }
    }
}

impl fmt::Display for BlobMetaCompressor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => f.write_str("none"),
            Self::Zstd => f.write_str("zstd"),
        }
    }
}

impl TryFrom<BlobMetaFeatures> for BlobMetaCompressor {
    type Error = anyhow::Error;

    fn try_from(value: BlobMetaFeatures) -> Result<Self> {
        match value.bits() & BLOB_META_COMPRESSOR_MASK {
            0 => Ok(Self::None),
            bits if bits == BlobMetaFeatures::COMPRESSOR_ZSTD.bits() => Ok(Self::Zstd),
            bits => bail!("unsupported blob meta compressor feature set: {:#x}", bits),
        }
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlobMetaDigester {
    Blake3 = 1,
}

impl BlobMetaDigester {
    pub fn feature(self) -> BlobMetaFeatures {
        match self {
            Self::Blake3 => BlobMetaFeatures::DIGESTER_BLAKE3,
        }
    }
}

impl fmt::Display for BlobMetaDigester {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Blake3 => f.write_str("blake3"),
        }
    }
}

impl TryFrom<BlobMetaFeatures> for BlobMetaDigester {
    type Error = anyhow::Error;

    fn try_from(value: BlobMetaFeatures) -> Result<Self> {
        match value.bits() & BLOB_META_DIGESTER_MASK {
            bits if bits == BlobMetaFeatures::DIGESTER_BLAKE3.bits() => Ok(Self::Blake3),
            0 => bail!("blob meta digester feature is missing"),
            bits => bail!("unsupported blob meta digester feature set: {:#x}", bits),
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlobMetaHeader {
    magic: u32,
    features: u32,
    crc32: u32,
    reserved0: u32,
    chunks_offset: u64,
    groups_offset: u64,
    chunk_count: u32,
    group_count: u32,
    chunk_block_count: u32,
    reserved1: u32,
}

const _: () = assert!(size_of::<BlobMetaHeader>() == BLOB_META_HEADER_SIZE as usize);

impl Default for BlobMetaHeader {
    fn default() -> Self {
        Self {
            magic: BLOB_META_MAGIC,
            features: BlobMetaDigester::Blake3.feature().bits(),
            crc32: 0,
            reserved0: 0,
            chunks_offset: BLOB_META_HEADER_SIZE,
            groups_offset: BLOB_META_HEADER_SIZE,
            chunk_count: 0,
            group_count: 0,
            chunk_block_count: BLOB_META_DEFAULT_CHUNK_BLOCK_COUNT,
            reserved1: 0,
        }
    }
}

impl BlobMetaHeader {
    pub fn chunk_count(&self) -> u32 {
        self.chunk_count
    }

    pub fn group_count(&self) -> u32 {
        self.group_count
    }

    pub fn chunk_block_count(&self) -> u32 {
        self.chunk_block_count
    }

    pub fn chunk_size(&self) -> u32 {
        self.chunk_block_count * EROFS_BLOCK_SIZE
    }

    pub fn features(&self) -> BlobMetaFeatures {
        self.validated_features()
            .expect("validated blob meta features")
    }

    pub fn crc32(&self) -> u32 {
        self.crc32
    }

    pub fn compressor(&self) -> BlobMetaCompressor {
        BlobMetaCompressor::try_from(self.features()).expect("validated blob meta compressor")
    }

    pub fn digester(&self) -> BlobMetaDigester {
        BlobMetaDigester::try_from(self.features()).expect("validated blob meta digester")
    }

    pub fn chunks_offset(&self) -> u64 {
        self.chunks_offset
    }

    pub fn groups_offset(&self) -> u64 {
        self.groups_offset
    }

    pub fn chunk_bytes(&self) -> u64 {
        self.chunk_count as u64 * size_of::<BlobMetaChunk>() as u64
    }

    pub fn group_bytes(&self) -> u64 {
        self.group_count as u64 * size_of::<BlobMetaGroup>() as u64
    }

    pub fn record_bytes(&self) -> u64 {
        self.groups_offset + self.group_bytes()
    }

    pub fn metadata_size(&self) -> u64 {
        align_to_block(self.record_bytes())
    }

    fn set_counts_and_offsets(&mut self, chunk_count: u32, group_count: u32) -> Result<()> {
        self.chunk_count = chunk_count;
        self.group_count = group_count;
        self.chunks_offset = BLOB_META_HEADER_SIZE;
        self.groups_offset = self
            .chunks_offset
            .checked_add(chunk_count as u64 * size_of::<BlobMetaChunk>() as u64)
            .context("blob meta group offset overflow")?;
        Ok(())
    }

    fn set_chunk_block_count(&mut self, blocks: u32) -> Result<()> {
        validate_chunk_block_count(blocks)?;
        self.chunk_block_count = blocks;
        Ok(())
    }

    fn set_compressor(&mut self, compressor: BlobMetaCompressor) {
        let mut features = self.features();
        features.remove(BlobMetaFeatures::COMPRESSOR_ZSTD);
        features.insert(compressor.feature());
        self.features = features.bits();
    }

    fn validate(&self) -> Result<()> {
        if self.magic != BLOB_META_MAGIC {
            bail!("invalid blob meta magic");
        }
        validate_chunk_block_count(self.chunk_block_count)?;
        self.validated_features()?;
        if self.reserved0 != 0 || self.reserved1 != 0 {
            bail!("blob meta reserved fields must be zero");
        }
        if self.chunks_offset != BLOB_META_HEADER_SIZE {
            bail!("invalid blob meta chunks offset: {}", self.chunks_offset);
        }
        let expected_groups_offset = self
            .chunks_offset
            .checked_add(self.chunk_bytes())
            .context("blob meta group offset overflow")?;
        if self.groups_offset != expected_groups_offset {
            bail!("invalid blob meta groups offset: {}", self.groups_offset);
        }
        if self.chunks_offset % align_of::<BlobMetaChunk>() as u64 != 0 {
            bail!("blob meta chunks offset is not aligned");
        }
        if self.groups_offset % align_of::<BlobMetaGroup>() as u64 != 0 {
            bail!("blob meta groups offset is not aligned");
        }
        Ok(())
    }

    fn validated_features(&self) -> Result<BlobMetaFeatures> {
        let features = BlobMetaFeatures::from_bits(self.features)
            .with_context(|| format!("unsupported blob meta features: {:#x}", self.features))?;
        BlobMetaCompressor::try_from(features)?;
        BlobMetaDigester::try_from(features)?;
        Ok(features)
    }

    fn write_to_with_crc32(&self, writer: &mut dyn Write, crc32: u32) -> Result<()> {
        writer.write_all(&self.as_bytes_with_crc32(crc32))?;
        Ok(())
    }

    fn as_bytes_with_crc32(&self, crc32: u32) -> [u8; BLOB_META_HEADER_SIZE as usize] {
        let mut data = [0u8; BLOB_META_HEADER_SIZE as usize];
        data[0..4].copy_from_slice(&self.magic.to_le_bytes());
        data[4..8].copy_from_slice(&self.features.to_le_bytes());
        data[BLOB_META_HEADER_CRC32_OFFSET..BLOB_META_HEADER_CRC32_OFFSET + 4]
            .copy_from_slice(&crc32.to_le_bytes());
        data[12..16].copy_from_slice(&self.reserved0.to_le_bytes());
        data[16..24].copy_from_slice(&self.chunks_offset.to_le_bytes());
        data[24..32].copy_from_slice(&self.groups_offset.to_le_bytes());
        data[32..36].copy_from_slice(&self.chunk_count.to_le_bytes());
        data[36..40].copy_from_slice(&self.group_count.to_le_bytes());
        data[40..44].copy_from_slice(&self.chunk_block_count.to_le_bytes());
        data[44..48].copy_from_slice(&self.reserved1.to_le_bytes());
        data
    }

    fn read_from(reader: &mut dyn Read) -> Result<Self> {
        let header = Self {
            magic: read_u32(reader)?,
            features: read_u32(reader)?,
            crc32: read_u32(reader)?,
            reserved0: read_u32(reader)?,
            chunks_offset: read_u64(reader)?,
            groups_offset: read_u64(reader)?,
            chunk_count: read_u32(reader)?,
            group_count: read_u32(reader)?,
            chunk_block_count: read_u32(reader)?,
            reserved1: read_u32(reader)?,
        };
        header.validate()?;
        Ok(header)
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BlobMetaGroup {
    uncompressed_block_offset: u64,
    compressed_block_offset: u64,
    uncompressed_block_count: u32,
    compressed_size: u32,
    crc32: u32,
    reserved: u32,
}

const _: () = assert!(size_of::<BlobMetaGroup>() == 32);

impl BlobMetaGroup {
    pub fn new(
        uncompressed_block_offset: u64,
        uncompressed_block_count: u32,
        compressed_block_offset: u64,
        compressed_size: u32,
        crc32: u32,
    ) -> Result<Self> {
        let group = Self {
            uncompressed_block_offset,
            compressed_block_offset,
            uncompressed_block_count,
            compressed_size,
            crc32,
            reserved: BLOB_META_GROUP_RESERVED,
        };
        group.validate()?;
        Ok(group)
    }

    pub fn uncompressed_block_offset(&self) -> u64 {
        self.uncompressed_block_offset
    }

    pub fn compressed_block_offset(&self) -> u64 {
        self.compressed_block_offset
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

    pub fn compressed_byte_offset(&self) -> u64 {
        self.compressed_block_offset
            .checked_mul(EROFS_BLOCK_SIZE as u64)
            .expect("validated blob meta group compressed byte offset")
    }

    pub fn compressed_byte_end(&self) -> u64 {
        self.compressed_byte_offset() + self.compressed_size as u64
    }

    pub fn compressed_padded_byte_end(&self) -> u64 {
        align_to_block(self.compressed_byte_end())
    }

    pub fn with_compressed_block_offset_bias(&self, block_bias: u64) -> Result<Self> {
        Self::new(
            self.uncompressed_block_offset(),
            self.uncompressed_block_count(),
            self.compressed_block_offset()
                .checked_add(block_bias)
                .context("blob meta compressed block offset overflow")?,
            self.compressed_size(),
            self.crc32(),
        )
    }

    pub fn write_to(&self, writer: &mut dyn Write) -> Result<()> {
        self.validate()?;
        writer.write_all(&self.to_bytes())?;
        Ok(())
    }

    fn to_bytes(self) -> [u8; 32] {
        let mut data = [0u8; 32];
        data[0..8].copy_from_slice(&self.uncompressed_block_offset.to_le_bytes());
        data[8..16].copy_from_slice(&self.compressed_block_offset.to_le_bytes());
        data[16..20].copy_from_slice(&self.uncompressed_block_count.to_le_bytes());
        data[20..24].copy_from_slice(&self.compressed_size.to_le_bytes());
        data[24..28].copy_from_slice(&self.crc32.to_le_bytes());
        data[28..32].copy_from_slice(&self.reserved.to_le_bytes());
        data
    }

    pub fn read_from(reader: &mut dyn Read) -> Result<Self> {
        let group = Self {
            uncompressed_block_offset: read_u64(reader)?,
            compressed_block_offset: read_u64(reader)?,
            uncompressed_block_count: read_u32(reader)?,
            compressed_size: read_u32(reader)?,
            crc32: read_u32(reader)?,
            reserved: read_u32(reader)?,
        };
        group.validate()?;
        Ok(group)
    }

    fn validate(&self) -> Result<()> {
        if self.uncompressed_block_count == 0 {
            bail!("blob meta group uncompressed block count must be non-zero");
        }
        if self.compressed_size == 0 {
            bail!("blob meta group compressed size must be non-zero");
        }
        self.uncompressed_block_offset
            .checked_mul(EROFS_BLOCK_SIZE as u64)
            .context("blob meta group uncompressed byte offset overflow")?;
        self.compressed_block_offset
            .checked_mul(EROFS_BLOCK_SIZE as u64)
            .context("blob meta group compressed byte offset overflow")?;
        self.uncompressed_byte_offset()
            .checked_add(self.uncompressed_byte_size())
            .context("blob meta group uncompressed byte range overflow")?;
        self.compressed_byte_offset()
            .checked_add(self.compressed_size as u64)
            .context("blob meta group compressed byte range overflow")?;
        if self.reserved != BLOB_META_GROUP_RESERVED {
            bail!("blob meta group reserved field must be zero");
        }
        Ok(())
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BlobMetaChunk {
    digest: [u8; 32],
    group_index: u32,
    group_uncompressed_block_offset: u32,
    uncompressed_block_count: u32,
    reserved: u32,
}

const _: () = assert!(size_of::<BlobMetaChunk>() == 48);

impl BlobMetaChunk {
    pub fn new(
        digest: [u8; 32],
        group_index: u32,
        group_uncompressed_block_offset: u32,
        uncompressed_block_count: u32,
    ) -> Result<Self> {
        let chunk = Self {
            digest,
            group_index,
            group_uncompressed_block_offset,
            uncompressed_block_count,
            reserved: BLOB_META_CHUNK_RESERVED,
        };
        chunk.validate()?;
        Ok(chunk)
    }

    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    pub fn group_index(&self) -> u32 {
        self.group_index
    }

    pub fn group_uncompressed_block_offset(&self) -> u32 {
        self.group_uncompressed_block_offset
    }

    pub fn uncompressed_block_count(&self) -> u32 {
        self.uncompressed_block_count
    }

    pub fn group_uncompressed_byte_offset(&self) -> u64 {
        self.group_uncompressed_block_offset as u64 * EROFS_BLOCK_SIZE as u64
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
        data[32..36].copy_from_slice(&self.group_index.to_le_bytes());
        data[36..40].copy_from_slice(&self.group_uncompressed_block_offset.to_le_bytes());
        data[40..44].copy_from_slice(&self.uncompressed_block_count.to_le_bytes());
        data[44..48].copy_from_slice(&self.reserved.to_le_bytes());
        data
    }

    pub fn read_from(reader: &mut dyn Read) -> Result<Self> {
        let chunk = Self {
            digest: read_digest(reader)?,
            group_index: read_u32(reader)?,
            group_uncompressed_block_offset: read_u32(reader)?,
            uncompressed_block_count: read_u32(reader)?,
            reserved: read_u32(reader)?,
        };
        chunk.validate()?;
        Ok(chunk)
    }

    fn validate(&self) -> Result<()> {
        if self.uncompressed_block_count == 0 {
            bail!("blob meta chunk uncompressed block count must be non-zero");
        }
        self.group_uncompressed_byte_offset()
            .checked_add(self.uncompressed_byte_size())
            .context("blob meta chunk group byte range overflow")?;
        if self.reserved != BLOB_META_CHUNK_RESERVED {
            bail!("blob meta chunk reserved field must be zero");
        }
        Ok(())
    }
}

enum BlobMetaStorage {
    Owned {
        chunks: Vec<BlobMetaChunk>,
        groups: Vec<BlobMetaGroup>,
    },
    Mapped(Mmap),
}

pub struct BlobMeta {
    header: BlobMetaHeader,
    blob_id: [u8; EROFS_BLOB_ID_SIZE],
    storage: BlobMetaStorage,
}

impl BlobMeta {
    pub fn from_parts(
        blob_id: [u8; EROFS_BLOB_ID_SIZE],
        chunk_block_count: u32,
        groups: Vec<BlobMetaGroup>,
        chunks: Vec<BlobMetaChunk>,
    ) -> Result<Self> {
        Self::from_parts_with_options(
            blob_id,
            chunk_block_count,
            BlobMetaCompressor::None,
            groups,
            chunks,
        )
    }

    pub fn from_parts_with_options(
        blob_id: [u8; EROFS_BLOB_ID_SIZE],
        chunk_block_count: u32,
        compressor: BlobMetaCompressor,
        groups: Vec<BlobMetaGroup>,
        chunks: Vec<BlobMetaChunk>,
    ) -> Result<Self> {
        let mut header = BlobMetaHeader::default();
        header.set_chunk_block_count(chunk_block_count)?;
        header.set_compressor(compressor);
        header.set_counts_and_offsets(chunks.len() as u32, groups.len() as u32)?;
        validate_tables(&groups, &chunks)?;
        let mut blob_meta = Self {
            header,
            blob_id,
            storage: BlobMetaStorage::Owned { chunks, groups },
        };
        blob_meta.header.crc32 = blob_meta.compute_crc32();
        Ok(blob_meta)
    }

    pub fn with_compressed_offset_bias(&self, bias: u64) -> Result<Self> {
        if bias % EROFS_BLOCK_SIZE as u64 != 0 {
            bail!("blob meta compressed offset bias must be block aligned");
        }
        let block_bias = bias / EROFS_BLOCK_SIZE as u64;
        let mut groups = Vec::with_capacity(self.group_count());
        for group in self.groups() {
            groups.push(group.with_compressed_block_offset_bias(block_bias)?);
        }
        Self::from_parts_with_options(
            self.blob_id,
            self.chunk_block_count(),
            self.compressor(),
            groups,
            self.chunks().to_vec(),
        )
    }

    pub fn header(&self) -> &BlobMetaHeader {
        &self.header
    }

    pub fn blob_id(&self) -> &[u8; EROFS_BLOB_ID_SIZE] {
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

    pub fn compressor(&self) -> BlobMetaCompressor {
        self.header.compressor()
    }

    pub fn digester(&self) -> BlobMetaDigester {
        self.header.digester()
    }

    pub fn chunks(&self) -> &[BlobMetaChunk] {
        match &self.storage {
            BlobMetaStorage::Owned { chunks, .. } => chunks,
            BlobMetaStorage::Mapped(mmap) => mapped_chunks(mmap, &self.header),
        }
    }

    pub fn groups(&self) -> &[BlobMetaGroup] {
        match &self.storage {
            BlobMetaStorage::Owned { groups, .. } => groups,
            BlobMetaStorage::Mapped(mmap) => mapped_groups(mmap, &self.header),
        }
    }

    pub fn chunk_at(&self, index: usize) -> Option<&BlobMetaChunk> {
        self.chunks().get(index)
    }

    pub fn group_at(&self, index: usize) -> Option<&BlobMetaGroup> {
        self.groups().get(index)
    }

    pub fn chunk_logical_byte_offset(&self, index: usize) -> u64 {
        index as u64 * self.chunk_size() as u64
    }

    pub fn chunk_for_uncompressed_byte_offset(
        &self,
        offset: u64,
    ) -> Option<(usize, &BlobMetaChunk)> {
        let chunk_size = self.chunk_size() as u64;
        let index = usize::try_from(offset / chunk_size).ok()?;
        let chunk = self.chunk_at(index)?;
        let chunk_offset = offset - self.chunk_logical_byte_offset(index);
        if chunk_offset < chunk.uncompressed_byte_size() {
            Some((index, chunk))
        } else {
            None
        }
    }

    pub fn chunks_for_uncompressed_byte_range(
        &self,
        offset: u64,
        len: usize,
    ) -> Result<Vec<(usize, BlobMetaChunk)>> {
        if len == 0 {
            return Ok(Vec::new());
        }
        let end = offset
            .checked_add(len as u64)
            .context("blob meta range overflow")?;
        let (mut index, _) = self
            .chunk_for_uncompressed_byte_offset(offset)
            .with_context(|| format!("blob meta chunk not found for offset {}", offset))?;
        let mut current = offset;
        let mut chunks = Vec::new();
        while current < end {
            let chunk = *self
                .chunk_at(index)
                .with_context(|| format!("blob meta chunk not found for offset {}", current))?;
            let chunk_start = self.chunk_logical_byte_offset(index);
            let chunk_end = chunk_start
                .checked_add(chunk.uncompressed_byte_size())
                .context("blob meta chunk byte range overflow")?;
            if current < chunk_start || current >= chunk_end {
                bail!("blob meta chunks do not cover requested range");
            }
            current = chunk_end.min(end);
            chunks.push((index, chunk));
            index += 1;
        }
        Ok(chunks)
    }

    pub fn cache_size(&self) -> u64 {
        self.total_uncompressed_size()
    }

    pub fn total_uncompressed_size(&self) -> u64 {
        groups_total_uncompressed_size(self.groups())
    }

    pub fn total_compressed_size(&self) -> u64 {
        groups_total_compressed_size(self.groups())
    }

    pub fn metadata_size(&self) -> u64 {
        self.header.metadata_size()
    }

    fn compute_crc32(&self) -> u32 {
        let mut crc32 = crc32c_append(0, &self.header.as_bytes_with_crc32(0));
        for chunk in self.chunks() {
            crc32 = crc32c_append(crc32, &chunk.to_bytes());
        }
        for group in self.groups() {
            crc32 = crc32c_append(crc32, &group.to_bytes());
        }
        crc32c_append(crc32, &vec![0u8; self.padding_size()])
    }

    fn padding_size(&self) -> usize {
        (self.metadata_size() - self.header.record_bytes()) as usize
    }

    pub fn write_to(&self, writer: &mut dyn Write) -> Result<()> {
        self.header
            .write_to_with_crc32(writer, self.compute_crc32())?;
        for chunk in self.chunks() {
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

    pub fn from_bytes_with_blob_id(data: &[u8], blob_id: [u8; EROFS_BLOB_ID_SIZE]) -> Result<Self> {
        Self::from_bytes_with_blob_id_inner(data, blob_id, false)
    }

    pub fn from_bytes_with_blob_id_checked_crc32(
        data: &[u8],
        blob_id: [u8; EROFS_BLOB_ID_SIZE],
    ) -> Result<Self> {
        Self::from_bytes_with_blob_id_inner(data, blob_id, true)
    }

    fn from_bytes_with_blob_id_inner(
        data: &[u8],
        blob_id: [u8; EROFS_BLOB_ID_SIZE],
        check_crc32: bool,
    ) -> Result<Self> {
        if data.len() < BLOB_META_HEADER_SIZE as usize {
            bail!("blob meta data too small");
        }

        let mut cursor = Cursor::new(data);
        let header = BlobMetaHeader::read_from(&mut cursor)?;
        if data.len() as u64 != header.metadata_size() {
            bail!(
                "blob meta data size mismatch: expected {}, got {}",
                header.metadata_size(),
                data.len()
            );
        }
        validate_padding(data, &header)?;
        if check_crc32 {
            validate_blob_meta_crc32(data, &header)?;
        }

        let mut chunks = Vec::with_capacity(header.chunk_count() as usize);
        cursor.set_position(header.chunks_offset());
        for index in 0..header.chunk_count() as usize {
            chunks.push(
                BlobMetaChunk::read_from(&mut cursor)
                    .with_context(|| format!("failed to read blob meta chunk {index}"))?,
            );
        }

        let mut groups = Vec::with_capacity(header.group_count() as usize);
        cursor.set_position(header.groups_offset());
        for index in 0..header.group_count() as usize {
            groups.push(
                BlobMetaGroup::read_from(&mut cursor)
                    .with_context(|| format!("failed to read blob meta group {index}"))?,
            );
        }
        validate_tables(&groups, &chunks)?;
        Ok(Self {
            header,
            blob_id,
            storage: BlobMetaStorage::Owned { chunks, groups },
        })
    }

    pub fn load(path: &Path) -> Result<Self> {
        Self::load_inner(path, false)
    }

    pub fn load_checked_crc32(path: &Path) -> Result<Self> {
        Self::load_inner(path, true)
    }

    fn load_inner(path: &Path, check_crc32: bool) -> Result<Self> {
        let file = File::open(path)
            .with_context(|| format!("failed to open blob meta: {}", path.display()))?;
        let file_len = file.metadata()?.len();
        if file_len < BLOB_META_HEADER_SIZE {
            bail!("blob meta file too small");
        }
        let mmap = unsafe { MmapOptions::new().map(&file) }
            .with_context(|| format!("failed to mmap blob meta: {}", path.display()))?;
        let mut cursor = Cursor::new(&mmap[..BLOB_META_HEADER_SIZE as usize]);
        let header = BlobMetaHeader::read_from(&mut cursor)?;
        if file_len != header.metadata_size() {
            bail!(
                "blob meta file size mismatch: expected {}, got {}",
                header.metadata_size(),
                file_len
            );
        }
        validate_padding(&mmap, &header)?;
        if check_crc32 {
            validate_blob_meta_crc32(&mmap, &header)?;
        }
        validate_tables(mapped_groups(&mmap, &header), mapped_chunks(&mmap, &header))?;
        Ok(Self {
            header,
            blob_id: [0u8; EROFS_BLOB_ID_SIZE],
            storage: BlobMetaStorage::Mapped(mmap),
        })
    }

    pub fn load_with_blob_id(path: &Path, blob_id: [u8; EROFS_BLOB_ID_SIZE]) -> Result<Self> {
        let mut blob_meta = Self::load(path)?;
        blob_meta.blob_id = blob_id;
        Ok(blob_meta)
    }

    pub fn load_checked_crc32_with_blob_id(
        path: &Path,
        blob_id: [u8; EROFS_BLOB_ID_SIZE],
    ) -> Result<Self> {
        let mut blob_meta = Self::load_checked_crc32(path)?;
        blob_meta.blob_id = blob_id;
        Ok(blob_meta)
    }
}

fn validate_chunk_block_count(blocks: u32) -> Result<()> {
    if blocks == 0 {
        bail!("blob meta chunk block count must be non-zero");
    }
    if !blocks.is_power_of_two() {
        bail!("blob meta chunk block count must be a power of two");
    }
    Ok(())
}

pub fn align_to_block(value: u64) -> u64 {
    let block_size = EROFS_BLOCK_SIZE as u64;
    value.div_ceil(block_size) * block_size
}

fn validate_padding(data: &[u8], header: &BlobMetaHeader) -> Result<()> {
    let padding_start = header.record_bytes() as usize;
    if data[padding_start..].iter().any(|byte| *byte != 0) {
        bail!("blob meta padding must be zero");
    }
    Ok(())
}

fn validate_blob_meta_crc32(data: &[u8], header: &BlobMetaHeader) -> Result<()> {
    let computed = compute_blob_meta_crc32(data);
    if computed != header.crc32() {
        bail!(
            "blob meta header crc32 mismatch: stored {:#010x}, computed {:#010x}",
            header.crc32(),
            computed
        );
    }
    Ok(())
}

fn compute_blob_meta_crc32(data: &[u8]) -> u32 {
    let crc32 = crc32c_append(0, &data[..BLOB_META_HEADER_CRC32_OFFSET]);
    let crc32 = crc32c_append(crc32, &[0u8; 4]);
    crc32c_append(crc32, &data[BLOB_META_HEADER_CRC32_OFFSET + 4..])
}

fn validate_tables(groups: &[BlobMetaGroup], chunks: &[BlobMetaChunk]) -> Result<()> {
    validate_groups(groups)?;
    validate_chunks(groups, chunks)
}

fn validate_groups(groups: &[BlobMetaGroup]) -> Result<()> {
    let mut previous_uncompressed_block_end = 0u64;
    let mut previous_compressed_padded_end = 0u64;
    for (index, group) in groups.iter().enumerate() {
        group
            .validate()
            .with_context(|| format!("invalid blob meta group {}", index))?;
        if group.uncompressed_block_offset() != previous_uncompressed_block_end {
            bail!("blob meta groups must be dense at index {}", index);
        }
        if index > 0 && group.compressed_byte_offset() < previous_compressed_padded_end {
            bail!(
                "blob meta groups overlap compressed ranges at index {}",
                index
            );
        }
        previous_uncompressed_block_end = group
            .uncompressed_block_offset()
            .checked_add(group.uncompressed_block_count() as u64)
            .context("blob meta group uncompressed block range overflow")?;
        previous_compressed_padded_end = group.compressed_padded_byte_end();
    }
    Ok(())
}

fn validate_chunks(groups: &[BlobMetaGroup], chunks: &[BlobMetaChunk]) -> Result<()> {
    for (index, chunk) in chunks.iter().enumerate() {
        chunk
            .validate()
            .with_context(|| format!("invalid blob meta chunk {}", index))?;
        let group = groups
            .get(chunk.group_index() as usize)
            .with_context(|| format!("blob meta chunk {} references missing group", index))?;
        let chunk_end = chunk
            .group_uncompressed_block_offset()
            .checked_add(chunk.uncompressed_block_count())
            .context("blob meta chunk group block range overflow")?;
        if chunk_end > group.uncompressed_block_count() {
            bail!("blob meta chunk {} exceeds its group", index);
        }
    }
    Ok(())
}

fn groups_total_uncompressed_size(groups: &[BlobMetaGroup]) -> u64 {
    groups
        .last()
        .map(BlobMetaGroup::uncompressed_byte_end)
        .unwrap_or(0)
}

fn groups_total_compressed_size(groups: &[BlobMetaGroup]) -> u64 {
    groups
        .last()
        .map(BlobMetaGroup::compressed_padded_byte_end)
        .unwrap_or(0)
}

fn mapped_chunks<'a>(data: &'a [u8], header: &BlobMetaHeader) -> &'a [BlobMetaChunk] {
    let offset = header.chunks_offset() as usize;
    let byte_len = header.chunk_count() as usize * size_of::<BlobMetaChunk>();
    let bytes = &data[offset..offset + byte_len];
    let ptr = bytes.as_ptr().cast::<BlobMetaChunk>();
    unsafe { std::slice::from_raw_parts(ptr, header.chunk_count() as usize) }
}

fn mapped_groups<'a>(data: &'a [u8], header: &BlobMetaHeader) -> &'a [BlobMetaGroup] {
    let offset = header.groups_offset() as usize;
    let byte_len = header.group_count() as usize * size_of::<BlobMetaGroup>();
    let bytes = &data[offset..offset + byte_len];
    let ptr = bytes.as_ptr().cast::<BlobMetaGroup>();
    unsafe { std::slice::from_raw_parts(ptr, header.group_count() as usize) }
}

fn read_u32(reader: &mut dyn Read) -> Result<u32> {
    let mut buf = [0u8; 4];
    reader.read_exact(&mut buf)?;
    Ok(u32::from_le_bytes(buf))
}

fn read_u64(reader: &mut dyn Read) -> Result<u64> {
    let mut buf = [0u8; 8];
    reader.read_exact(&mut buf)?;
    Ok(u64::from_le_bytes(buf))
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
        compressed_block_offset: u64,
        compressed_size: u32,
        payload: &[u8],
    ) -> BlobMetaGroup {
        BlobMetaGroup::new(
            uncompressed_block_offset,
            uncompressed_block_count,
            compressed_block_offset,
            compressed_size,
            crc32c::crc32c(payload),
        )
        .unwrap()
    }

    fn chunk(
        payload: &[u8],
        group_index: u32,
        group_uncompressed_block_offset: u32,
        uncompressed_block_count: u32,
    ) -> BlobMetaChunk {
        BlobMetaChunk::new(
            digest(payload),
            group_index,
            group_uncompressed_block_offset,
            uncompressed_block_count,
        )
        .unwrap()
    }

    #[test]
    fn blob_meta_round_trips_through_mmap() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("blob.meta");
        let blob_id = [0x5au8; EROFS_BLOB_ID_SIZE];
        let payload_a = vec![0x11; EROFS_BLOCK_SIZE as usize];
        let payload_b = vec![0x22; EROFS_BLOCK_SIZE as usize];
        let group_payload = [payload_a.as_slice(), payload_b.as_slice()].concat();
        let blob_meta = BlobMeta::from_parts(
            blob_id,
            1,
            vec![group(0, 2, 2, 8192, &group_payload)],
            vec![chunk(&payload_a, 0, 0, 1), chunk(&payload_b, 0, 1, 1)],
        )
        .unwrap();

        blob_meta.save(&path).unwrap();
        let loaded = BlobMeta::load(&path).unwrap();

        assert_eq!(loaded.header().chunk_count(), 2);
        assert_eq!(loaded.header().group_count(), 1);
        assert_eq!(loaded.header().chunk_bytes(), 96);
        assert_eq!(loaded.header().group_bytes(), 32);
        assert_eq!(loaded.header().record_bytes(), 176);
        assert_eq!(loaded.header().metadata_size(), 4096);
        assert_eq!(loaded.header().chunk_size(), EROFS_BLOCK_SIZE);
        assert_eq!(loaded.header().compressor(), BlobMetaCompressor::None);
        assert_eq!(loaded.header().digester(), BlobMetaDigester::Blake3);
        assert_ne!(loaded.header().crc32(), 0);
        assert_eq!(loaded.groups()[0].compressed_byte_offset(), 8192);
        assert_eq!(loaded.chunks()[1].digest(), &digest(&payload_b));
        assert_eq!(
            loaded.chunk_for_uncompressed_byte_offset(4096).unwrap().0,
            1
        );
        assert_eq!(loaded.cache_size(), 8192);
    }

    #[test]
    fn blob_meta_header_crc32_covers_full_metadata() {
        let payload = vec![0x33; EROFS_BLOCK_SIZE as usize];
        let blob_meta = BlobMeta::from_parts(
            [0x7bu8; EROFS_BLOB_ID_SIZE],
            1,
            vec![group(0, 1, 0, 4096, &payload)],
            vec![chunk(&payload, 0, 0, 1)],
        )
        .unwrap();
        let mut raw = Vec::new();
        blob_meta.write_to(&mut raw).unwrap();

        let stored_crc32 = u32::from_le_bytes(
            raw[BLOB_META_HEADER_CRC32_OFFSET..BLOB_META_HEADER_CRC32_OFFSET + 4]
                .try_into()
                .unwrap(),
        );
        raw[BLOB_META_HEADER_CRC32_OFFSET..BLOB_META_HEADER_CRC32_OFFSET + 4].fill(0);

        assert_eq!(stored_crc32, crc32c::crc32c(&raw));
    }

    #[test]
    fn blob_meta_read_keeps_but_checked_read_rejects_bad_header_crc32() {
        let payload = vec![0x55; EROFS_BLOCK_SIZE as usize];
        let blob_meta = BlobMeta::from_parts(
            [0x8cu8; EROFS_BLOB_ID_SIZE],
            1,
            vec![group(0, 1, 0, 4096, &payload)],
            vec![chunk(&payload, 0, 0, 1)],
        )
        .unwrap();
        let mut raw = Vec::new();
        blob_meta.write_to(&mut raw).unwrap();
        raw[BLOB_META_HEADER_CRC32_OFFSET] ^= 0xff;
        let corrupted_crc32 = u32::from_le_bytes(
            raw[BLOB_META_HEADER_CRC32_OFFSET..BLOB_META_HEADER_CRC32_OFFSET + 4]
                .try_into()
                .unwrap(),
        );

        let loaded = BlobMeta::from_bytes_with_blob_id(&raw, [0u8; EROFS_BLOB_ID_SIZE]).unwrap();

        assert_eq!(loaded.header().crc32(), corrupted_crc32);
        let err = match BlobMeta::from_bytes_with_blob_id_checked_crc32(
            &raw,
            [0u8; EROFS_BLOB_ID_SIZE],
        ) {
            Ok(_) => panic!("corrupted blob meta crc32 should be rejected"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("crc32"));
    }

    #[test]
    fn blob_meta_rejects_old_tail_header_magic() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("old.blob.meta");
        let mut raw = vec![0u8; BLOB_META_HEADER_SIZE as usize];
        raw[..4].copy_from_slice(&0xb10b_b10bu32.to_le_bytes());
        std::fs::write(&path, raw).unwrap();

        assert!(BlobMeta::load(&path).is_err());
    }

    #[test]
    fn blob_meta_finds_chunks_for_cross_group_range() {
        let payload = vec![0x44; EROFS_BLOCK_SIZE as usize];
        let group_payload = [payload.as_slice(), payload.as_slice()].concat();
        let blob_meta = BlobMeta::from_parts(
            [0u8; EROFS_BLOB_ID_SIZE],
            1,
            vec![group(0, 2, 0, 8192, &group_payload)],
            vec![chunk(&payload, 0, 0, 1), chunk(&payload, 0, 1, 1)],
        )
        .unwrap();

        let chunks = blob_meta
            .chunks_for_uncompressed_byte_range(2048, 4096)
            .unwrap();

        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].0, 0);
        assert_eq!(chunks[1].0, 1);
    }
}

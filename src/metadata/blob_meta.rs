use super::{EROFS_BLOB_ID_SIZE, EROFS_BLOCK_SIZE};
use anyhow::{bail, Context, Result};
use bitflags::bitflags;
use memmap2::{Mmap, MmapOptions};
use std::fmt;
use std::fs::File;
use std::io::{Cursor, Read, Write};
use std::mem::size_of;
use std::path::Path;

pub const BLOB_META_MAGIC: u32 = 0x4c50_424d;
pub const BLOB_META_HEADER_SIZE: u64 = 0x1000;
pub const BLOB_META_DEFAULT_CHUNK_SIZE: u32 = 1024 * 1024;

const BLOB_META_HEADER_RESERVED_SIZE: usize = (BLOB_META_HEADER_SIZE as usize) - 24;
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
    chunk_entry_size: u32,
    chunk_count: u32,
    chunk_size: u32,
    reserved0: u32,
    reserved: [u8; BLOB_META_HEADER_RESERVED_SIZE],
}

const _: () = assert!(size_of::<BlobMetaHeader>() == BLOB_META_HEADER_SIZE as usize);

impl Default for BlobMetaHeader {
    fn default() -> Self {
        Self {
            magic: BLOB_META_MAGIC,
            features: BlobMetaDigester::Blake3.feature().bits(),
            chunk_entry_size: size_of::<BlobMetaChunk>() as u32,
            chunk_count: 0,
            chunk_size: BLOB_META_DEFAULT_CHUNK_SIZE,
            reserved0: 0,
            reserved: [0u8; BLOB_META_HEADER_RESERVED_SIZE],
        }
    }
}

impl BlobMetaHeader {
    pub fn chunk_count(&self) -> u32 {
        self.chunk_count
    }

    pub fn chunk_size(&self) -> u32 {
        self.chunk_size
    }

    pub fn features(&self) -> BlobMetaFeatures {
        self.validated_features()
            .expect("validated blob meta features")
    }

    pub fn compressor(&self) -> BlobMetaCompressor {
        BlobMetaCompressor::try_from(self.features()).expect("validated blob meta compressor")
    }

    pub fn digester(&self) -> BlobMetaDigester {
        BlobMetaDigester::try_from(self.features()).expect("validated blob meta digester")
    }

    pub fn chunk_bytes(&self) -> u64 {
        self.chunk_count as u64 * self.chunk_entry_size as u64
    }

    pub fn metadata_size(&self) -> u64 {
        BLOB_META_HEADER_SIZE + self.chunk_bytes()
    }

    fn set_chunk_count(&mut self, entries: u32) {
        self.chunk_count = entries;
    }

    fn set_chunk_size(&mut self, size: u32) -> Result<()> {
        validate_chunk_size(size)?;
        self.chunk_size = size;
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
        if self.chunk_entry_size != size_of::<BlobMetaChunk>() as u32 {
            bail!(
                "invalid blob meta chunk entry size: {}",
                self.chunk_entry_size
            );
        }
        validate_chunk_size(self.chunk_size)?;
        self.validated_features()?;
        if self.reserved0 != 0 || self.reserved.iter().any(|byte| *byte != 0) {
            bail!("blob meta reserved fields must be zero");
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

    fn write_to(&self, writer: &mut dyn Write) -> Result<()> {
        writer.write_all(&self.magic.to_le_bytes())?;
        writer.write_all(&self.features.to_le_bytes())?;
        writer.write_all(&self.chunk_entry_size.to_le_bytes())?;
        writer.write_all(&self.chunk_count.to_le_bytes())?;
        writer.write_all(&self.chunk_size.to_le_bytes())?;
        writer.write_all(&self.reserved0.to_le_bytes())?;
        writer.write_all(&self.reserved)?;
        Ok(())
    }

    fn read_from(reader: &mut dyn Read) -> Result<Self> {
        let magic = read_u32(reader)?;
        let features = read_u32(reader)?;
        let chunk_entry_size = read_u32(reader)?;
        let chunk_count = read_u32(reader)?;
        let chunk_size = read_u32(reader)?;
        let reserved0 = read_u32(reader)?;
        let mut reserved = [0u8; BLOB_META_HEADER_RESERVED_SIZE];
        reader.read_exact(&mut reserved)?;

        let header = Self {
            magic,
            features,
            chunk_entry_size,
            chunk_count,
            chunk_size,
            reserved0,
            reserved,
        };
        header.validate()?;
        Ok(header)
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BlobMetaChunk {
    uncompressed_offset: u64,
    compressed_offset: u64,
    uncompressed_size: u32,
    compressed_size: u32,
    crc32: u32,
    reserved: u32,
    digest: [u8; 32],
}

const _: () = assert!(size_of::<BlobMetaChunk>() == 64);

impl BlobMetaChunk {
    pub fn new(
        uncompressed_offset: u64,
        uncompressed_size: u32,
        compressed_offset: u64,
        compressed_size: u32,
        digest: [u8; 32],
        crc32: u32,
    ) -> Result<Self> {
        let chunk = Self {
            uncompressed_offset,
            compressed_offset,
            uncompressed_size,
            compressed_size,
            crc32,
            reserved: BLOB_META_CHUNK_RESERVED,
            digest,
        };
        chunk.validate()?;
        Ok(chunk)
    }

    pub fn uncompressed_offset(&self) -> u64 {
        self.uncompressed_offset
    }

    pub fn uncompressed_size(&self) -> u32 {
        self.uncompressed_size
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

    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    pub fn uncompressed_end(&self) -> u64 {
        self.uncompressed_offset() + self.uncompressed_size() as u64
    }

    pub fn compressed_end(&self) -> u64 {
        self.compressed_offset() + self.compressed_size() as u64
    }

    pub fn with_compressed_offset_bias(&self, bias: u64) -> Result<Self> {
        Self::new(
            self.uncompressed_offset(),
            self.uncompressed_size(),
            self.compressed_offset()
                .checked_add(bias)
                .context("blob meta compressed offset overflow")?,
            self.compressed_size(),
            self.digest,
            self.crc32(),
        )
    }

    pub fn contains_uncompressed_offset(&self, offset: u64) -> bool {
        offset >= self.uncompressed_offset() && offset < self.uncompressed_end()
    }

    pub fn write_to(&self, writer: &mut dyn Write) -> Result<()> {
        self.validate()?;
        writer.write_all(&self.uncompressed_offset.to_le_bytes())?;
        writer.write_all(&self.compressed_offset.to_le_bytes())?;
        writer.write_all(&self.uncompressed_size.to_le_bytes())?;
        writer.write_all(&self.compressed_size.to_le_bytes())?;
        writer.write_all(&self.crc32.to_le_bytes())?;
        writer.write_all(&self.reserved.to_le_bytes())?;
        writer.write_all(&self.digest)?;
        Ok(())
    }

    pub fn read_from(reader: &mut dyn Read) -> Result<Self> {
        let chunk = Self {
            uncompressed_offset: read_u64(reader)?,
            compressed_offset: read_u64(reader)?,
            uncompressed_size: read_u32(reader)?,
            compressed_size: read_u32(reader)?,
            crc32: read_u32(reader)?,
            reserved: read_u32(reader)?,
            digest: read_digest(reader)?,
        };
        chunk.validate()?;
        Ok(chunk)
    }

    fn validate(&self) -> Result<()> {
        if self.uncompressed_size == 0 {
            bail!("blob meta chunk uncompressed size must be non-zero");
        }
        if self.compressed_size == 0 {
            bail!("blob meta chunk compressed size must be non-zero");
        }
        if self.uncompressed_offset % EROFS_BLOCK_SIZE as u64 != 0 {
            bail!("blob meta chunk uncompressed offset must be block aligned");
        }
        if self.uncompressed_size % EROFS_BLOCK_SIZE != 0 {
            bail!("blob meta chunk uncompressed size must be block aligned");
        }
        if self.reserved != BLOB_META_CHUNK_RESERVED {
            bail!("blob meta chunk reserved field must be zero");
        }
        Ok(())
    }
}

enum BlobMetaStorage {
    Owned(Vec<BlobMetaChunk>),
    Mapped(Mmap),
}

pub struct BlobMeta {
    header: BlobMetaHeader,
    blob_id: [u8; EROFS_BLOB_ID_SIZE],
    storage: BlobMetaStorage,
}

impl BlobMeta {
    pub fn from_chunks(blob_id: [u8; EROFS_BLOB_ID_SIZE], chunks: Vec<BlobMetaChunk>) -> Self {
        Self::from_chunks_with_options(
            blob_id,
            BLOB_META_DEFAULT_CHUNK_SIZE,
            BlobMetaCompressor::None,
            chunks,
        )
        .expect("default blob meta options are valid")
    }

    pub fn from_chunks_with_options(
        blob_id: [u8; EROFS_BLOB_ID_SIZE],
        chunk_size: u32,
        compressor: BlobMetaCompressor,
        chunks: Vec<BlobMetaChunk>,
    ) -> Result<Self> {
        let mut header = BlobMetaHeader::default();
        header.set_chunk_size(chunk_size)?;
        header.set_compressor(compressor);
        header.set_chunk_count(chunks.len() as u32);
        validate_chunks(&chunks)?;
        Ok(Self {
            header,
            blob_id,
            storage: BlobMetaStorage::Owned(chunks),
        })
    }

    pub fn with_compressed_offset_bias(&self, bias: u64) -> Result<Self> {
        let mut chunks = Vec::with_capacity(self.chunk_count());
        for chunk in self.chunks() {
            chunks.push(chunk.with_compressed_offset_bias(bias)?);
        }
        Self::from_chunks_with_options(self.blob_id, self.chunk_size(), self.compressor(), chunks)
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
            BlobMetaStorage::Owned(chunks) => chunks,
            BlobMetaStorage::Mapped(mmap) => mapped_chunks(mmap, self.chunk_count()),
        }
    }

    pub fn chunk_at(&self, index: usize) -> Option<&BlobMetaChunk> {
        self.chunks().get(index)
    }

    pub fn chunk_for_uncompressed_offset(&self, offset: u64) -> Option<(usize, &BlobMetaChunk)> {
        let chunks = self.chunks();
        let mut low = 0usize;
        let mut high = chunks.len();
        while low < high {
            let mid = low + (high - low) / 2;
            let chunk = &chunks[mid];
            if offset < chunk.uncompressed_offset() {
                high = mid;
            } else if offset >= chunk.uncompressed_end() {
                low = mid + 1;
            } else {
                return Some((mid, chunk));
            }
        }
        None
    }

    pub fn chunks_for_uncompressed_range(
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
            .chunk_for_uncompressed_offset(offset)
            .with_context(|| format!("blob meta chunk not found for offset {}", offset))?;
        let mut current = offset;
        let mut chunks = Vec::new();
        while current < end {
            let chunk = *self
                .chunk_at(index)
                .with_context(|| format!("blob meta chunk not found for offset {}", current))?;
            if current < chunk.uncompressed_offset() || current >= chunk.uncompressed_end() {
                bail!("blob meta chunks do not cover requested range");
            }
            current = chunk.uncompressed_end().min(end);
            chunks.push((index, chunk));
            index += 1;
        }
        Ok(chunks)
    }

    pub fn cache_size(&self) -> u64 {
        self.total_uncompressed_size()
    }

    pub fn total_uncompressed_size(&self) -> u64 {
        chunks_total_uncompressed_size(self.chunks())
    }

    pub fn total_compressed_size(&self) -> u64 {
        chunks_total_compressed_size(self.chunks())
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let mut file = File::create(path)
            .with_context(|| format!("failed to create blob meta: {}", path.display()))?;
        self.header.write_to(&mut file)?;
        for chunk in self.chunks() {
            chunk.write_to(&mut file)?;
        }
        file.flush()
            .with_context(|| format!("failed to flush blob meta: {}", path.display()))?;
        Ok(())
    }

    pub fn load(path: &Path) -> Result<Self> {
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
        validate_chunks(mapped_chunks(&mmap, header.chunk_count() as usize))?;
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
}

fn validate_chunk_size(size: u32) -> Result<()> {
    if size < BLOB_META_DEFAULT_CHUNK_SIZE {
        bail!("blob meta chunk size must be at least 1MiB");
    }
    if !size.is_power_of_two() {
        bail!("blob meta chunk size must be a power of two");
    }
    if size % EROFS_BLOCK_SIZE != 0 {
        bail!("blob meta chunk size must be block aligned");
    }
    Ok(())
}

fn validate_chunks(chunks: &[BlobMetaChunk]) -> Result<()> {
    let mut previous_uncompressed_end = 0u64;
    let mut total_compressed_size = 0u64;
    for (index, chunk) in chunks.iter().enumerate() {
        chunk
            .validate()
            .with_context(|| format!("invalid blob meta chunk {}", index))?;
        if chunk.uncompressed_offset() < previous_uncompressed_end {
            bail!("blob meta chunks overlap at index {}", index);
        }
        if index > 0 && chunk.uncompressed_offset() != previous_uncompressed_end {
            bail!("blob meta chunks must be dense at index {}", index);
        }
        previous_uncompressed_end = chunk.uncompressed_end();
        total_compressed_size = total_compressed_size
            .checked_add(chunk.compressed_size() as u64)
            .context("blob meta compressed size overflow")?;
    }
    Ok(())
}

fn chunks_total_uncompressed_size(chunks: &[BlobMetaChunk]) -> u64 {
    chunks
        .last()
        .map(BlobMetaChunk::uncompressed_end)
        .unwrap_or(0)
}

fn chunks_total_compressed_size(chunks: &[BlobMetaChunk]) -> u64 {
    chunks
        .iter()
        .map(|chunk| chunk.compressed_size() as u64)
        .sum()
}

fn mapped_chunks(mmap: &Mmap, chunk_count: usize) -> &[BlobMetaChunk] {
    let offset = BLOB_META_HEADER_SIZE as usize;
    let byte_len = chunk_count * size_of::<BlobMetaChunk>();
    let bytes = &mmap[offset..offset + byte_len];
    let ptr = bytes.as_ptr().cast::<BlobMetaChunk>();
    unsafe { std::slice::from_raw_parts(ptr, chunk_count) }
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

    #[test]
    fn blob_meta_round_trips_through_mmap() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("blob.meta");
        let blob_id = [0x5au8; EROFS_BLOB_ID_SIZE];
        let payload_a = vec![0x11; EROFS_BLOCK_SIZE as usize];
        let payload_b = vec![0x22; EROFS_BLOCK_SIZE as usize];
        let blob_meta = BlobMeta::from_chunks(
            blob_id,
            vec![
                BlobMetaChunk::new(0, 4096, 8192, 4096, digest(&payload_a), 0x1234).unwrap(),
                BlobMetaChunk::new(4096, 4096, 12288, 4096, digest(&payload_b), 0x5678).unwrap(),
            ],
        );

        blob_meta.save(&path).unwrap();
        let loaded = BlobMeta::load(&path).unwrap();

        assert_eq!(loaded.header().chunk_count(), 2);
        assert_eq!(loaded.header().chunk_bytes(), 128);
        assert_eq!(loaded.header().metadata_size(), 4224);
        assert_eq!(loaded.header().chunk_size(), BLOB_META_DEFAULT_CHUNK_SIZE);
        assert_eq!(loaded.header().compressor(), BlobMetaCompressor::None);
        assert_eq!(loaded.header().digester(), BlobMetaDigester::Blake3);
        assert_eq!(loaded.chunks()[0].compressed_offset(), 8192);
        assert_eq!(loaded.chunks()[1].digest(), &digest(&payload_b));
        assert_eq!(loaded.chunk_for_uncompressed_offset(4096).unwrap().0, 1);
        assert_eq!(loaded.cache_size(), 8192);
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
        let blob_meta = BlobMeta::from_chunks(
            [0u8; EROFS_BLOB_ID_SIZE],
            vec![
                BlobMetaChunk::new(0, 4096, 0, 4096, digest(&payload), 1).unwrap(),
                BlobMetaChunk::new(4096, 4096, 4096, 4096, digest(&payload), 2).unwrap(),
            ],
        );

        let chunks = blob_meta.chunks_for_uncompressed_range(2048, 4096).unwrap();

        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].0, 0);
        assert_eq!(chunks[1].0, 1);
    }
}

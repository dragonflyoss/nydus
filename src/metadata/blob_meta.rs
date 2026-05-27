use super::{EROFS_BLOB_ID_SIZE, EROFS_BLOCK_SIZE};
use anyhow::{bail, Context, Result};
use bitflags::bitflags;
use crc32c::crc32c_append;
use memmap2::{Mmap, MmapOptions};
use std::fmt;
use std::fs::File;
use std::io::{Cursor, Read, Write};
use std::mem::size_of;
use std::path::Path;

pub const BLOB_META_MAGIC: u32 = 0x4c50_424d;
pub const BLOB_META_HEADER_SIZE: u64 = 0x1000;
pub const BLOB_META_DEFAULT_CHUNK_SIZE: u32 = 1024 * 1024;

const BLOB_META_HEADER_FIXED_SIZE: usize = 28;
const BLOB_META_HEADER_CRC32_OFFSET: usize = 8;
const BLOB_META_HEADER_RESERVED_SIZE: usize =
    (BLOB_META_HEADER_SIZE as usize) - BLOB_META_HEADER_FIXED_SIZE;
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
            crc32: 0,
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

    pub fn crc32(&self) -> u32 {
        self.crc32
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

    pub fn record_bytes(&self) -> u64 {
        BLOB_META_HEADER_SIZE + self.chunk_bytes()
    }

    pub fn metadata_size(&self) -> u64 {
        align_to_block(self.record_bytes())
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
        data[12..16].copy_from_slice(&self.chunk_entry_size.to_le_bytes());
        data[16..20].copy_from_slice(&self.chunk_count.to_le_bytes());
        data[20..24].copy_from_slice(&self.chunk_size.to_le_bytes());
        data[24..28].copy_from_slice(&self.reserved0.to_le_bytes());
        data[BLOB_META_HEADER_FIXED_SIZE..].copy_from_slice(&self.reserved);
        data
    }

    fn read_from(reader: &mut dyn Read) -> Result<Self> {
        let magic = read_u32(reader)?;
        let features = read_u32(reader)?;
        let crc32 = read_u32(reader)?;
        let chunk_entry_size = read_u32(reader)?;
        let chunk_count = read_u32(reader)?;
        let chunk_size = read_u32(reader)?;
        let reserved0 = read_u32(reader)?;
        let mut reserved = [0u8; BLOB_META_HEADER_RESERVED_SIZE];
        reader.read_exact(&mut reserved)?;

        let header = Self {
            magic,
            features,
            crc32,
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
    uncompressed_block_offset: u64,
    compressed_offset: u64,
    uncompressed_block_count: u32,
    compressed_size: u32,
    crc32: u32,
    reserved: u32,
    digest: [u8; 32],
}

const _: () = assert!(size_of::<BlobMetaChunk>() == 64);

impl BlobMetaChunk {
    pub fn new(
        uncompressed_block_offset: u64,
        uncompressed_block_count: u32,
        compressed_offset: u64,
        compressed_size: u32,
        digest: [u8; 32],
        crc32: u32,
    ) -> Result<Self> {
        let chunk = Self {
            uncompressed_block_offset,
            compressed_offset,
            uncompressed_block_count,
            compressed_size,
            crc32,
            reserved: BLOB_META_CHUNK_RESERVED,
            digest,
        };
        chunk.validate()?;
        Ok(chunk)
    }

    pub fn uncompressed_block_offset(&self) -> u64 {
        self.uncompressed_block_offset
    }

    pub fn uncompressed_block_count(&self) -> u32 {
        self.uncompressed_block_count
    }

    pub fn uncompressed_byte_offset(&self) -> u64 {
        self.uncompressed_block_offset
            .checked_mul(EROFS_BLOCK_SIZE as u64)
            .expect("validated blob meta chunk byte offset")
    }

    pub fn uncompressed_byte_size(&self) -> u64 {
        self.uncompressed_block_count as u64 * EROFS_BLOCK_SIZE as u64
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

    pub fn uncompressed_byte_end(&self) -> u64 {
        self.uncompressed_byte_offset() + self.uncompressed_byte_size()
    }

    pub fn compressed_end(&self) -> u64 {
        self.compressed_offset() + self.compressed_size() as u64
    }

    pub fn with_compressed_offset_bias(&self, bias: u64) -> Result<Self> {
        Self::new(
            self.uncompressed_block_offset(),
            self.uncompressed_block_count(),
            self.compressed_offset()
                .checked_add(bias)
                .context("blob meta compressed offset overflow")?,
            self.compressed_size(),
            self.digest,
            self.crc32(),
        )
    }

    pub fn contains_uncompressed_byte_offset(&self, offset: u64) -> bool {
        offset >= self.uncompressed_byte_offset() && offset < self.uncompressed_byte_end()
    }

    pub fn write_to(&self, writer: &mut dyn Write) -> Result<()> {
        self.validate()?;
        writer.write_all(&self.to_bytes())?;
        Ok(())
    }

    fn to_bytes(self) -> [u8; 64] {
        let mut data = [0u8; 64];
        data[0..8].copy_from_slice(&self.uncompressed_block_offset.to_le_bytes());
        data[8..16].copy_from_slice(&self.compressed_offset.to_le_bytes());
        data[16..20].copy_from_slice(&self.uncompressed_block_count.to_le_bytes());
        data[20..24].copy_from_slice(&self.compressed_size.to_le_bytes());
        data[24..28].copy_from_slice(&self.crc32.to_le_bytes());
        data[28..32].copy_from_slice(&self.reserved.to_le_bytes());
        data[32..64].copy_from_slice(&self.digest);
        data
    }

    pub fn read_from(reader: &mut dyn Read) -> Result<Self> {
        let chunk = Self {
            uncompressed_block_offset: read_u64(reader)?,
            compressed_offset: read_u64(reader)?,
            uncompressed_block_count: read_u32(reader)?,
            compressed_size: read_u32(reader)?,
            crc32: read_u32(reader)?,
            reserved: read_u32(reader)?,
            digest: read_digest(reader)?,
        };
        chunk.validate()?;
        Ok(chunk)
    }

    fn validate(&self) -> Result<()> {
        if self.uncompressed_block_count == 0 {
            bail!("blob meta chunk uncompressed block count must be non-zero");
        }
        if self.compressed_size == 0 {
            bail!("blob meta chunk compressed size must be non-zero");
        }
        let byte_offset = self
            .uncompressed_block_offset
            .checked_mul(EROFS_BLOCK_SIZE as u64)
            .context("blob meta chunk uncompressed byte offset overflow")?;
        byte_offset
            .checked_add(self.uncompressed_byte_size())
            .context("blob meta chunk uncompressed byte range overflow")?;
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
        let mut blob_meta = Self {
            header,
            blob_id,
            storage: BlobMetaStorage::Owned(chunks),
        };
        blob_meta.header.crc32 = blob_meta.compute_crc32();
        Ok(blob_meta)
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

    pub fn chunk_for_uncompressed_byte_offset(
        &self,
        offset: u64,
    ) -> Option<(usize, &BlobMetaChunk)> {
        let chunks = self.chunks();
        let mut low = 0usize;
        let mut high = chunks.len();
        while low < high {
            let mid = low + (high - low) / 2;
            let chunk = &chunks[mid];
            if offset < chunk.uncompressed_byte_offset() {
                high = mid;
            } else if offset >= chunk.uncompressed_byte_end() {
                low = mid + 1;
            } else {
                return Some((mid, chunk));
            }
        }
        None
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
            if current < chunk.uncompressed_byte_offset()
                || current >= chunk.uncompressed_byte_end()
            {
                bail!("blob meta chunks do not cover requested range");
            }
            current = chunk.uncompressed_byte_end().min(end);
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

    pub fn metadata_size(&self) -> u64 {
        self.header.metadata_size()
    }

    fn compute_crc32(&self) -> u32 {
        let mut crc32 = crc32c_append(0, &self.header.as_bytes_with_crc32(0));
        for chunk in self.chunks() {
            crc32 = crc32c_append(crc32, &chunk.to_bytes());
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
        for index in 0..header.chunk_count() as usize {
            chunks.push(
                BlobMetaChunk::read_from(&mut cursor)
                    .with_context(|| format!("failed to read blob meta chunk {index}"))?,
            );
        }
        validate_chunks(&chunks)?;
        Ok(Self {
            header,
            blob_id,
            storage: BlobMetaStorage::Owned(chunks),
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

    pub fn load_checked_crc32_with_blob_id(
        path: &Path,
        blob_id: [u8; EROFS_BLOB_ID_SIZE],
    ) -> Result<Self> {
        let mut blob_meta = Self::load_checked_crc32(path)?;
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

fn align_to_block(value: u64) -> u64 {
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

fn validate_chunks(chunks: &[BlobMetaChunk]) -> Result<()> {
    let mut previous_uncompressed_block_end = 0u64;
    let mut total_compressed_size = 0u64;
    for (index, chunk) in chunks.iter().enumerate() {
        chunk
            .validate()
            .with_context(|| format!("invalid blob meta chunk {}", index))?;
        if chunk.uncompressed_block_offset() < previous_uncompressed_block_end {
            bail!("blob meta chunks overlap at index {}", index);
        }
        if index > 0 && chunk.uncompressed_block_offset() != previous_uncompressed_block_end {
            bail!("blob meta chunks must be dense at index {}", index);
        }
        previous_uncompressed_block_end = chunk
            .uncompressed_block_offset()
            .checked_add(chunk.uncompressed_block_count() as u64)
            .context("blob meta uncompressed block range overflow")?;
        total_compressed_size = total_compressed_size
            .checked_add(chunk.compressed_size() as u64)
            .context("blob meta compressed size overflow")?;
    }
    Ok(())
}

fn chunks_total_uncompressed_size(chunks: &[BlobMetaChunk]) -> u64 {
    chunks
        .last()
        .map(BlobMetaChunk::uncompressed_byte_end)
        .unwrap_or(0)
}

fn chunks_total_compressed_size(chunks: &[BlobMetaChunk]) -> u64 {
    chunks
        .iter()
        .map(|chunk| chunk.compressed_size() as u64)
        .sum()
}

fn mapped_chunks(data: &[u8], chunk_count: usize) -> &[BlobMetaChunk] {
    let offset = BLOB_META_HEADER_SIZE as usize;
    let byte_len = chunk_count * size_of::<BlobMetaChunk>();
    let bytes = &data[offset..offset + byte_len];
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
                BlobMetaChunk::new(0, 1, 8192, 4096, digest(&payload_a), 0x1234).unwrap(),
                BlobMetaChunk::new(1, 1, 12288, 4096, digest(&payload_b), 0x5678).unwrap(),
            ],
        );

        blob_meta.save(&path).unwrap();
        let loaded = BlobMeta::load(&path).unwrap();

        assert_eq!(loaded.header().chunk_count(), 2);
        assert_eq!(loaded.header().chunk_bytes(), 128);
        assert_eq!(loaded.header().record_bytes(), 4224);
        assert_eq!(loaded.header().metadata_size(), 8192);
        assert_eq!(loaded.header().chunk_size(), BLOB_META_DEFAULT_CHUNK_SIZE);
        assert_eq!(loaded.header().compressor(), BlobMetaCompressor::None);
        assert_eq!(loaded.header().digester(), BlobMetaDigester::Blake3);
        assert_ne!(loaded.header().crc32(), 0);
        assert_eq!(loaded.chunks()[0].compressed_offset(), 8192);
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
        let blob_meta = BlobMeta::from_chunks(
            [0x7bu8; EROFS_BLOB_ID_SIZE],
            vec![BlobMetaChunk::new(0, 1, 0, 4096, digest(&payload), 0x1234).unwrap()],
        );
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
        let blob_meta = BlobMeta::from_chunks(
            [0x8cu8; EROFS_BLOB_ID_SIZE],
            vec![BlobMetaChunk::new(0, 1, 0, 4096, digest(&payload), 0x5678).unwrap()],
        );
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
        let blob_meta = BlobMeta::from_chunks(
            [0u8; EROFS_BLOB_ID_SIZE],
            vec![
                BlobMetaChunk::new(0, 1, 0, 4096, digest(&payload), 1).unwrap(),
                BlobMetaChunk::new(1, 1, 4096, 4096, digest(&payload), 2).unwrap(),
            ],
        );

        let chunks = blob_meta
            .chunks_for_uncompressed_byte_range(2048, 4096)
            .unwrap();

        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].0, 0);
        assert_eq!(chunks[1].0, 1);
    }
}

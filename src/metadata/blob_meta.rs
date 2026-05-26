use super::{round_up_u64, EROFS_BLOB_ID_SIZE};
use anyhow::{bail, Context, Result};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::mem::size_of;
use std::path::Path;

pub const BLOB_META_MAGIC: u32 = 0xb10bb10b;
pub const BLOB_META_HEADER_SIZE: u64 = 0x1000;
const BLOB_META_HEADER_RESERVED_SIZE: usize = (BLOB_META_HEADER_SIZE as usize) - 12;

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlobMetaHeader {
    magic: u32,
    features: u32,
    chunk_count: u32,
    reserved: [u8; BLOB_META_HEADER_RESERVED_SIZE],
}

const _: () = assert!(size_of::<BlobMetaHeader>() == BLOB_META_HEADER_SIZE as usize);

impl Default for BlobMetaHeader {
    fn default() -> Self {
        Self {
            magic: BLOB_META_MAGIC,
            features: 0,
            chunk_count: 0,
            reserved: [0u8; BLOB_META_HEADER_RESERVED_SIZE],
        }
    }
}

impl BlobMetaHeader {
    pub fn features(&self) -> u32 {
        self.features
    }

    pub fn chunk_count(&self) -> u32 {
        self.chunk_count
    }

    pub fn chunk_bytes(&self) -> u64 {
        self.chunk_count as u64 * size_of::<BlobMetaChunk>() as u64
    }

    pub fn aligned_chunk_bytes(&self) -> u64 {
        round_up_u64(self.chunk_bytes(), BLOB_META_HEADER_SIZE)
    }

    fn set_chunk_count(&mut self, entries: u32) {
        self.chunk_count = entries;
    }

    fn validate(&self) -> Result<()> {
        if self.magic != BLOB_META_MAGIC {
            bail!("invalid blob meta magic");
        }

        Ok(())
    }

    fn write_to(&self, writer: &mut dyn Write) -> Result<()> {
        writer.write_all(&self.magic.to_le_bytes())?;
        writer.write_all(&self.features.to_le_bytes())?;
        writer.write_all(&self.chunk_count.to_le_bytes())?;
        writer.write_all(&self.reserved)?;
        Ok(())
    }

    fn read_from(reader: &mut dyn Read) -> Result<Self> {
        let magic = read_u32(reader)?;
        let features = read_u32(reader)?;
        let chunk_count = read_u32(reader)?;
        let mut reserved = [0u8; BLOB_META_HEADER_RESERVED_SIZE];
        reader.read_exact(&mut reserved)?;
        let header = Self {
            magic,
            features,
            chunk_count,
            reserved,
        };
        header.validate()?;
        Ok(header)
    }
}

#[repr(C, packed)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BlobMetaChunk {
    offset: u64,
    size: u32,
    compressed_offset: u64,
    compressed_size: u32,
}

const _: () = assert!(size_of::<BlobMetaChunk>() == 24);

impl BlobMetaChunk {
    pub fn new(
        offset: u64,
        size: u32,
        compressed_offset: u64,
        compressed_size: u32,
    ) -> Result<Self> {
        let mut chunk = Self::default();
        chunk.set_offset(offset)?;
        chunk.set_size(size)?;
        chunk.set_compressed_offset(compressed_offset)?;
        chunk.set_compressed_size(compressed_size)?;
        Ok(chunk)
    }

    pub fn offset(&self) -> u64 {
        self.offset
    }

    pub fn size(&self) -> u32 {
        self.size
    }

    pub fn compressed_offset(&self) -> u64 {
        self.compressed_offset
    }

    pub fn compressed_size(&self) -> u32 {
        self.compressed_size
    }

    pub fn with_compressed_offset_bias(&self, bias: u64) -> Result<Self> {
        Self::new(
            self.offset(),
            self.size(),
            self.compressed_offset()
                .checked_add(bias)
                .context("blob meta compressed offset overflow")?,
            self.compressed_size(),
        )
    }

    pub fn uncompressed_end(&self) -> u64 {
        self.offset() + self.size() as u64
    }

    pub fn write_to(&self, writer: &mut dyn Write) -> Result<()> {
        writer.write_all(&self.offset.to_le_bytes())?;
        writer.write_all(&self.size.to_le_bytes())?;
        writer.write_all(&self.compressed_offset.to_le_bytes())?;
        writer.write_all(&self.compressed_size.to_le_bytes())?;
        Ok(())
    }

    pub fn read_from(reader: &mut dyn Read) -> Result<Self> {
        Ok(Self {
            offset: read_u64(reader)?,
            size: read_u32(reader)?,
            compressed_offset: read_u64(reader)?,
            compressed_size: read_u32(reader)?,
        })
    }

    fn set_offset(&mut self, offset: u64) -> Result<()> {
        self.offset = offset;
        Ok(())
    }

    fn set_size(&mut self, size: u32) -> Result<()> {
        if size == 0 {
            bail!("uncompressed size must be non-zero");
        }
        self.size = size;
        Ok(())
    }

    fn set_compressed_offset(&mut self, offset: u64) -> Result<()> {
        self.compressed_offset = offset;
        Ok(())
    }

    fn set_compressed_size(&mut self, size: u32) -> Result<()> {
        self.compressed_size = size;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlobMeta {
    header: BlobMetaHeader,
    chunks: Vec<BlobMetaChunk>,
    blob_id: [u8; EROFS_BLOB_ID_SIZE],
}

impl BlobMeta {
    pub fn from_chunks(blob_id: [u8; EROFS_BLOB_ID_SIZE], chunks: Vec<BlobMetaChunk>) -> Self {
        let mut header = BlobMetaHeader::default();
        header.set_chunk_count(chunks.len() as u32);
        Self {
            header,
            chunks,
            blob_id,
        }
    }

    pub fn with_compressed_offset_bias(&self, bias: u64) -> Result<Self> {
        let mut chunks = Vec::with_capacity(self.chunks.len());
        for chunk in &self.chunks {
            chunks.push(chunk.with_compressed_offset_bias(bias)?);
        }
        Ok(Self::from_chunks(self.blob_id, chunks))
    }

    pub fn header(&self) -> &BlobMetaHeader {
        &self.header
    }

    pub fn blob_id(&self) -> &[u8; EROFS_BLOB_ID_SIZE] {
        &self.blob_id
    }

    pub fn chunks(&self) -> &[BlobMetaChunk] {
        &self.chunks
    }

    pub fn chunk_for_source_offset(&self, offset: u64) -> Option<(usize, &BlobMetaChunk)> {
        self.chunks
            .iter()
            .enumerate()
            .find(|(_, chunk)| chunk.compressed_offset() == offset)
    }

    pub fn cache_size(&self) -> u64 {
        self.chunks
            .iter()
            .map(BlobMetaChunk::uncompressed_end)
            .max()
            .unwrap_or(0)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let mut file = File::create(path)
            .with_context(|| format!("failed to create blob meta: {}", path.display()))?;
        for chunk in &self.chunks {
            chunk.write_to(&mut file)?;
        }
        let aligned_chunk_bytes = self.header.aligned_chunk_bytes();
        let chunk_bytes = self.header.chunk_bytes();
        if aligned_chunk_bytes > chunk_bytes {
            let padding = vec![0u8; (aligned_chunk_bytes - chunk_bytes) as usize];
            file.write_all(&padding)?;
        }
        self.header.write_to(&mut file)?;
        file.flush()
            .with_context(|| format!("failed to flush blob meta: {}", path.display()))?;
        Ok(())
    }

    pub fn load(path: &Path) -> Result<Self> {
        let mut file = File::open(path)
            .with_context(|| format!("failed to open blob meta: {}", path.display()))?;
        let file_len = file.metadata()?.len();
        if file_len < BLOB_META_HEADER_SIZE {
            bail!("blob meta file too small");
        }
        file.seek(SeekFrom::Start(file_len - BLOB_META_HEADER_SIZE))?;
        let header = BlobMetaHeader::read_from(&mut file)?;
        let expected_total = header.aligned_chunk_bytes() + BLOB_META_HEADER_SIZE;
        if file_len != expected_total {
            bail!(
                "blob meta file size mismatch: expected {}, got {}",
                expected_total,
                file_len
            );
        }
        file.seek(SeekFrom::Start(0))?;
        let mut chunks = Vec::with_capacity(header.chunk_count() as usize);
        for _ in 0..header.chunk_count() {
            chunks.push(BlobMetaChunk::read_from(&mut file)?);
        }
        Ok(Self {
            header,
            chunks,
            blob_id: [0u8; EROFS_BLOB_ID_SIZE],
        })
    }

    pub fn load_with_blob_id(path: &Path, blob_id: [u8; EROFS_BLOB_ID_SIZE]) -> Result<Self> {
        let mut blob_meta = Self::load(path)?;
        blob_meta.blob_id = blob_id;
        Ok(blob_meta)
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn blob_meta_round_trips_through_disk() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("blob.meta");
        let blob_id = [0x5au8; EROFS_BLOB_ID_SIZE];
        let blob_meta = BlobMeta::from_chunks(
            blob_id,
            vec![
                BlobMetaChunk::new(0, 4096, 8192, 4096).unwrap(),
                BlobMetaChunk::new(4096, 4096, 12288, 4096).unwrap(),
            ],
        );

        blob_meta.save(&path).unwrap();
        let loaded = BlobMeta::load(&path).unwrap();

        assert_eq!(loaded.header().chunk_count(), 2);
        assert_eq!(loaded.header().chunk_bytes(), 48);
        assert_eq!(loaded.header().aligned_chunk_bytes(), 4096);
        assert_eq!(loaded.chunks()[0].compressed_offset(), 8192);
        assert_eq!(loaded.chunk_for_source_offset(12288).unwrap().0, 1);
        assert_eq!(loaded.cache_size(), 8192);
    }
}

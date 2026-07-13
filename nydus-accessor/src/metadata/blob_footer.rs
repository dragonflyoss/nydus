use anyhow::{bail, Context, Result};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use super::EROFS_BLOCK_SIZE;

pub const NYDUS_BLOB_FOOTER_MAGIC: u32 = 0x4c46_5452;
pub const NYDUS_BLOB_FOOTER_SIZE: usize = 4096;
pub const NYDUS_BLOB_FOOTER_ALIGNMENT: u64 = EROFS_BLOCK_SIZE as u64;

const NYDUS_BLOB_FOOTER_SUPPORTED_FEATURES: u32 = 0;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlobFooter {
    magic: u32,
    features: u32,
    crc32: u32,
    reserved0: u32,
    compressed_data_offset: u64,
    bootstrap_offset: u64,
    blob_meta_offset: u64,
    compressed_data_size: u64,
    bootstrap_blocks: u32,
    blob_meta_blocks: u32,
    reserved1: u64,
}

impl BlobFooter {
    pub fn new(
        compressed_data_offset: u64,
        compressed_data_size: u64,
        bootstrap_offset: u64,
        bootstrap_blocks: u32,
        blob_meta_offset: u64,
        blob_meta_blocks: u32,
    ) -> Result<Self> {
        let mut footer = Self {
            magic: NYDUS_BLOB_FOOTER_MAGIC,
            features: 0,
            crc32: 0,
            reserved0: 0,
            compressed_data_offset,
            bootstrap_offset,
            blob_meta_offset,
            compressed_data_size,
            bootstrap_blocks,
            blob_meta_blocks,
            reserved1: 0,
        };
        footer.validate_layout(
            blob_meta_offset
                .checked_add(blocks_to_bytes(blob_meta_blocks))
                .context("blob footer offset overflow")?,
        )?;
        footer.crc32 = footer.compute_crc32();
        Ok(footer)
    }

    pub fn parse_from_tail(data: &[u8]) -> Result<Self> {
        if data.len() < NYDUS_BLOB_FOOTER_SIZE {
            bail!("blob too small for nydus footer");
        }
        let footer_offset = data.len() - NYDUS_BLOB_FOOTER_SIZE;
        let footer = Self::from_bytes(&data[footer_offset..])?;
        footer.validate(data.len() as u64)?;
        Ok(footer)
    }

    /// Parse a footer from exactly its `NYDUS_BLOB_FOOTER_SIZE` trailing bytes,
    /// validating the region layout against the known total blob size. Use this
    /// when the footer has been fetched in isolation (e.g. a registry range
    /// read) rather than reading the whole blob.
    pub fn parse(footer_bytes: &[u8], blob_size: u64) -> Result<Self> {
        if footer_bytes.len() != NYDUS_BLOB_FOOTER_SIZE {
            bail!(
                "invalid nydus footer size: {} (expected {})",
                footer_bytes.len(),
                NYDUS_BLOB_FOOTER_SIZE
            );
        }
        let footer = Self::from_bytes(footer_bytes)?;
        footer.validate(blob_size)?;
        Ok(footer)
    }

    pub fn read_from_path(path: &Path) -> Result<Self> {
        let mut file = File::open(path)
            .with_context(|| format!("failed to open blob footer: {}", path.display()))?;
        let file_size = file
            .metadata()
            .with_context(|| format!("failed to stat blob footer: {}", path.display()))?
            .len();
        if file_size < NYDUS_BLOB_FOOTER_SIZE as u64 {
            bail!("blob too small for nydus footer: {}", path.display());
        }
        file.seek(SeekFrom::Start(file_size - NYDUS_BLOB_FOOTER_SIZE as u64))
            .with_context(|| format!("failed to seek blob footer: {}", path.display()))?;
        let mut data = [0u8; NYDUS_BLOB_FOOTER_SIZE];
        file.read_exact(&mut data)
            .with_context(|| format!("failed to read blob footer: {}", path.display()))?;
        let footer = Self::from_bytes(&data)?;
        footer.validate(file_size)?;
        Ok(footer)
    }

    pub fn has_magic(data: &[u8]) -> bool {
        data.len() >= 4
            && u32::from_le_bytes(data[..4].try_into().expect("slice length checked"))
                == NYDUS_BLOB_FOOTER_MAGIC
    }

    pub fn write_to(&self, writer: &mut dyn Write) -> Result<()> {
        writer.write_all(&self.to_bytes())?;
        Ok(())
    }

    pub fn compressed_data_offset(&self) -> u64 {
        self.compressed_data_offset
    }

    pub fn bootstrap_offset(&self) -> u64 {
        self.bootstrap_offset
    }

    pub fn blob_meta_offset(&self) -> u64 {
        self.blob_meta_offset
    }

    pub fn compressed_data_size(&self) -> u64 {
        self.compressed_data_size
    }

    pub fn bootstrap_blocks(&self) -> u32 {
        self.bootstrap_blocks
    }

    pub fn blob_meta_blocks(&self) -> u32 {
        self.blob_meta_blocks
    }

    pub fn bootstrap_size(&self) -> u64 {
        blocks_to_bytes(self.bootstrap_blocks)
    }

    pub fn blob_meta_size(&self) -> u64 {
        blocks_to_bytes(self.blob_meta_blocks)
    }

    pub fn footer_offset(file_size: u64) -> Result<u64> {
        file_size
            .checked_sub(NYDUS_BLOB_FOOTER_SIZE as u64)
            .context("blob too small for nydus footer")
    }

    fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() != NYDUS_BLOB_FOOTER_SIZE {
            bail!("invalid nydus footer size: {}", data.len());
        }
        if data[64..].iter().any(|byte| *byte != 0) {
            bail!("nydus footer reserved extension area must be zero");
        }
        let footer = Self {
            magic: read_u32(data, 0),
            features: read_u32(data, 4),
            crc32: read_u32(data, 8),
            reserved0: read_u32(data, 12),
            compressed_data_offset: read_u64(data, 16),
            bootstrap_offset: read_u64(data, 24),
            blob_meta_offset: read_u64(data, 32),
            compressed_data_size: read_u64(data, 40),
            bootstrap_blocks: read_u32(data, 48),
            blob_meta_blocks: read_u32(data, 52),
            reserved1: read_u64(data, 56),
        };
        footer.validate_common()?;
        let actual = footer.compute_crc32();
        if footer.crc32 != actual {
            bail!("nydus footer crc32 mismatch");
        }
        Ok(footer)
    }

    fn to_bytes(self) -> [u8; NYDUS_BLOB_FOOTER_SIZE] {
        let mut data = [0u8; NYDUS_BLOB_FOOTER_SIZE];
        write_u32(&mut data, 0, self.magic);
        write_u32(&mut data, 4, self.features);
        write_u32(&mut data, 8, self.crc32);
        write_u32(&mut data, 12, self.reserved0);
        write_u64(&mut data, 16, self.compressed_data_offset);
        write_u64(&mut data, 24, self.bootstrap_offset);
        write_u64(&mut data, 32, self.blob_meta_offset);
        write_u64(&mut data, 40, self.compressed_data_size);
        write_u32(&mut data, 48, self.bootstrap_blocks);
        write_u32(&mut data, 52, self.blob_meta_blocks);
        write_u64(&mut data, 56, self.reserved1);
        data
    }

    fn validate(&self, file_size: u64) -> Result<()> {
        let footer_offset = Self::footer_offset(file_size)?;
        self.validate_layout(footer_offset)
    }

    fn validate_common(&self) -> Result<()> {
        if self.magic != NYDUS_BLOB_FOOTER_MAGIC {
            bail!("invalid nydus footer magic");
        }
        if self.features & !NYDUS_BLOB_FOOTER_SUPPORTED_FEATURES != 0 {
            bail!("unsupported nydus footer features: {:#x}", self.features);
        }
        if self.reserved0 != 0 || self.reserved1 != 0 {
            bail!("nydus footer reserved fields must be zero");
        }
        // `bootstrap_blocks` may be zero: an "ondemand" redirect blob carries
        // only group data plus blob meta and embeds no bootstrap image.
        if self.blob_meta_blocks == 0 {
            bail!("nydus footer blob meta block count must be non-zero");
        }
        Ok(())
    }

    fn validate_layout(&self, footer_offset: u64) -> Result<()> {
        self.validate_common()?;
        for (name, value) in [
            ("compressed_data_offset", self.compressed_data_offset),
            ("bootstrap_offset", self.bootstrap_offset),
            ("blob_meta_offset", self.blob_meta_offset),
            ("footer_offset", footer_offset),
        ] {
            if value % NYDUS_BLOB_FOOTER_ALIGNMENT != 0 {
                bail!("nydus footer {name} is not 4KiB aligned");
            }
        }

        let compressed_data_end = self
            .compressed_data_offset
            .checked_add(self.compressed_data_size)
            .context("nydus footer compressed data region overflow")?;
        let bootstrap_end = self
            .bootstrap_offset
            .checked_add(self.bootstrap_size())
            .context("nydus footer bootstrap region overflow")?;
        let blob_meta_end = self
            .blob_meta_offset
            .checked_add(self.blob_meta_size())
            .context("nydus footer blob meta region overflow")?;

        if !(compressed_data_end <= self.bootstrap_offset
            && bootstrap_end <= self.blob_meta_offset
            && blob_meta_end == footer_offset)
        {
            bail!("invalid nydus footer region layout");
        }
        Ok(())
    }

    fn compute_crc32(&self) -> u32 {
        let mut data = self.to_bytes();
        data[8..12].fill(0);
        crc32c::crc32c(&data)
    }
}

fn blocks_to_bytes(blocks: u32) -> u64 {
    blocks as u64 * EROFS_BLOCK_SIZE as u64
}

fn read_u32(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(data[offset..offset + 4].try_into().expect("slice checked"))
}

fn read_u64(data: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(data[offset..offset + 8].try_into().expect("slice checked"))
}

fn write_u32(data: &mut [u8], offset: usize, value: u32) {
    data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u64(data: &mut [u8], offset: usize, value: u64) {
    data[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn footer_round_trips_and_validates_crc32() {
        let footer = BlobFooter::new(0, 17, 4096, 1, 8192, 1).unwrap();
        let parsed = BlobFooter::from_bytes(&footer.to_bytes()).unwrap();

        assert_eq!(parsed, footer);
        assert_eq!(NYDUS_BLOB_FOOTER_SIZE, 4096);
    }

    #[test]
    fn footer_rejects_unaligned_offsets() {
        let err = BlobFooter::new(0, 17, 17, 1, 8192, 1).unwrap_err();

        assert!(err.to_string().contains("aligned"));
    }
}

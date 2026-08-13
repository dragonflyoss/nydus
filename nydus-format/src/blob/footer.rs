use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use crate::blob::validate::{crc32_with_zeroed_field, validate_incompat_flags};
use crate::erofs::{blocks_to_bytes, EROFS_BLOCK_SIZE};
use crate::error::{Context, Error, Result};
use crate::utils::le::{read_u32_at, read_u64_at, write_u32_at, write_u64_at};

/// On-disk magic: 8 raw ASCII bytes, written as-is so a hexdump of the
/// footer starts with the readable string. Same style and `magic + version +
/// flags` header prefix as the blob meta (`LPBLMETA`) and group_map
/// (`LPGRPMAP`) sidecars.
pub const NYDUS_BLOB_FOOTER_MAGIC: [u8; 8] = *b"LPFOOTER";
/// On-disk format generation, informational only: readers do not gate on it.
/// Compatibility is governed EROFS-style by the magic and the incompat half
/// of `flags` (unknown incompat bits reject the footer).
pub const NYDUS_BLOB_FOOTER_VERSION: u32 = 1;
pub const NYDUS_BLOB_FOOTER_SIZE: usize = 4096;
pub const NYDUS_BLOB_FOOTER_ALIGNMENT: u64 = EROFS_BLOCK_SIZE as u64;

/// `flags` is split EROFS-style (see [`crate::blob::validate`]): the low 16
/// bits are incompatible features (unknown bits reject), the high 16 bits
/// are compatible features (unknown bits are ignored). No bits are defined
/// yet.
const NYDUS_BLOB_FOOTER_SUPPORTED_INCOMPAT: u32 = 0;
/// Byte offset of the crc32 field within the footer.
const NYDUS_BLOB_FOOTER_CRC32_OFFSET: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlobFooter {
    magic: [u8; 8],
    version: u32,
    flags: u32,
    crc32: u32,
    reserved0: u32,
    compressed_data_offset: u64,
    bootstrap_offset: u64,
    blob_metadata_offset: u64,
    compressed_data_size: u64,
    bootstrap_blocks: u32,
    blob_metadata_blocks: u32,
}

impl BlobFooter {
    pub fn new(
        compressed_data_offset: u64,
        compressed_data_size: u64,
        bootstrap_offset: u64,
        bootstrap_blocks: u32,
        blob_metadata_offset: u64,
        blob_metadata_blocks: u32,
    ) -> Result<Self> {
        let mut footer = Self {
            magic: NYDUS_BLOB_FOOTER_MAGIC,
            version: NYDUS_BLOB_FOOTER_VERSION,
            flags: 0,
            crc32: 0,
            reserved0: 0,
            compressed_data_offset,
            bootstrap_offset,
            blob_metadata_offset,
            compressed_data_size,
            bootstrap_blocks,
            blob_metadata_blocks,
        };
        footer.validate_layout(
            blob_metadata_offset
                .checked_add(blocks_to_bytes(blob_metadata_blocks))
                .ok_or_else(|| Error::Overflow("blob footer offset overflow".to_string()))?,
        )?;
        footer.crc32 = footer.compute_crc32();
        Ok(footer)
    }

    pub fn parse_from_tail(data: &[u8]) -> Result<Self> {
        if data.len() < NYDUS_BLOB_FOOTER_SIZE {
            return Err(Error::InvalidImage(
                "blob too small for nydus footer".to_string(),
            ));
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
            return Err(Error::InvalidImage(format!(
                "invalid nydus footer size: {} (expected {})",
                footer_bytes.len(),
                NYDUS_BLOB_FOOTER_SIZE
            )));
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
            return Err(Error::InvalidImage(format!(
                "blob too small for nydus footer: {}",
                path.display()
            )));
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
        data.len() >= NYDUS_BLOB_FOOTER_MAGIC.len()
            && data[..NYDUS_BLOB_FOOTER_MAGIC.len()] == NYDUS_BLOB_FOOTER_MAGIC
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

    pub fn blob_metadata_offset(&self) -> u64 {
        self.blob_metadata_offset
    }

    pub fn compressed_data_size(&self) -> u64 {
        self.compressed_data_size
    }

    pub fn bootstrap_blocks(&self) -> u32 {
        self.bootstrap_blocks
    }

    pub fn blob_metadata_blocks(&self) -> u32 {
        self.blob_metadata_blocks
    }

    pub fn bootstrap_size(&self) -> u64 {
        blocks_to_bytes(self.bootstrap_blocks)
    }

    pub fn blob_metadata_size(&self) -> u64 {
        blocks_to_bytes(self.blob_metadata_blocks)
    }

    pub fn footer_offset(file_size: u64) -> Result<u64> {
        file_size
            .checked_sub(NYDUS_BLOB_FOOTER_SIZE as u64)
            .ok_or_else(|| Error::InvalidImage("blob too small for nydus footer".to_string()))
    }

    fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() != NYDUS_BLOB_FOOTER_SIZE {
            return Err(Error::InvalidImage(format!(
                "invalid nydus footer size: {}",
                data.len()
            )));
        }
        // Bytes past the fixed fields are reserved for future compat fields.
        // Writers zero them, but readers deliberately do not enforce that
        // (EROFS-style): a newer writer may have placed compat fields there
        // that this reader ignores. Corruption is caught by the footer crc32c.
        let footer = Self {
            magic: data[0..8].try_into().expect("slice checked"),
            version: read_u32_at(data, 8),
            flags: read_u32_at(data, 12),
            crc32: read_u32_at(data, 16),
            reserved0: read_u32_at(data, 20),
            compressed_data_offset: read_u64_at(data, 24),
            bootstrap_offset: read_u64_at(data, 32),
            blob_metadata_offset: read_u64_at(data, 40),
            compressed_data_size: read_u64_at(data, 48),
            bootstrap_blocks: read_u32_at(data, 56),
            blob_metadata_blocks: read_u32_at(data, 60),
        };
        footer.validate_common()?;
        // Verify the crc32 over the raw incoming bytes (with the crc32 field
        // zeroed), not over a re-serialization of the parsed struct: the
        // reserved tail may carry nonzero compat fields from a newer writer,
        // which `to_bytes` would drop and thereby corrupt the checksum.
        if footer.crc32 != crc32_with_zeroed_field(data, Self::crc32_field()) {
            return Err(Error::InvalidImage(
                "nydus footer crc32 mismatch".to_string(),
            ));
        }
        Ok(footer)
    }

    fn to_bytes(self) -> [u8; NYDUS_BLOB_FOOTER_SIZE] {
        let mut data = [0u8; NYDUS_BLOB_FOOTER_SIZE];
        data[0..8].copy_from_slice(&self.magic);
        write_u32_at(&mut data, 8, self.version);
        write_u32_at(&mut data, 12, self.flags);
        write_u32_at(&mut data, 16, self.crc32);
        write_u32_at(&mut data, 20, self.reserved0);
        write_u64_at(&mut data, 24, self.compressed_data_offset);
        write_u64_at(&mut data, 32, self.bootstrap_offset);
        write_u64_at(&mut data, 40, self.blob_metadata_offset);
        write_u64_at(&mut data, 48, self.compressed_data_size);
        write_u32_at(&mut data, 56, self.bootstrap_blocks);
        write_u32_at(&mut data, 60, self.blob_metadata_blocks);
        data
    }

    fn validate(&self, file_size: u64) -> Result<()> {
        let footer_offset = Self::footer_offset(file_size)?;
        self.validate_layout(footer_offset)
    }

    fn validate_common(&self) -> Result<()> {
        if self.magic != NYDUS_BLOB_FOOTER_MAGIC {
            return Err(Error::InvalidImage(
                "invalid nydus footer magic".to_string(),
            ));
        }
        // `version` is informational and deliberately not gated on:
        // compatibility is carried by the magic and the incompat flag bits.
        validate_incompat_flags(
            self.flags,
            NYDUS_BLOB_FOOTER_SUPPORTED_INCOMPAT,
            "nydus footer",
        )?;
        // `reserved0` is a future compat-field slot and deliberately not
        // enforced to zero; corruption is caught by the footer crc32c.
        // `bootstrap_blocks` may be zero: an "ondemand" redirect blob carries
        // only group data plus blob meta and embeds no bootstrap image.
        if self.blob_metadata_blocks == 0 {
            return Err(Error::InvalidImage(
                "nydus footer blob meta block count must be non-zero".to_string(),
            ));
        }
        Ok(())
    }

    fn validate_layout(&self, footer_offset: u64) -> Result<()> {
        self.validate_common()?;
        for (name, value) in [
            ("compressed_data_offset", self.compressed_data_offset),
            ("bootstrap_offset", self.bootstrap_offset),
            ("blob_metadata_offset", self.blob_metadata_offset),
            ("footer_offset", footer_offset),
        ] {
            if value % NYDUS_BLOB_FOOTER_ALIGNMENT != 0 {
                return Err(Error::InvalidImage(format!(
                    "nydus footer {name} is not 4KiB aligned"
                )));
            }
        }

        let compressed_data_end = self
            .compressed_data_offset
            .checked_add(self.compressed_data_size)
            .ok_or_else(|| {
                Error::Overflow("nydus footer compressed data region overflow".to_string())
            })?;
        let bootstrap_end = self
            .bootstrap_offset
            .checked_add(self.bootstrap_size())
            .ok_or_else(|| Error::Overflow("nydus footer bootstrap region overflow".to_string()))?;
        let blob_metadata_end = self
            .blob_metadata_offset
            .checked_add(self.blob_metadata_size())
            .ok_or_else(|| Error::Overflow("nydus footer blob meta region overflow".to_string()))?;

        if !(compressed_data_end <= self.bootstrap_offset
            && bootstrap_end <= self.blob_metadata_offset
            && blob_metadata_end == footer_offset)
        {
            return Err(Error::InvalidImage(
                "invalid nydus footer region layout".to_string(),
            ));
        }
        Ok(())
    }

    fn crc32_field() -> std::ops::Range<usize> {
        NYDUS_BLOB_FOOTER_CRC32_OFFSET..NYDUS_BLOB_FOOTER_CRC32_OFFSET + 4
    }

    fn compute_crc32(&self) -> u32 {
        crc32_with_zeroed_field(&self.to_bytes(), Self::crc32_field())
    }
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
    fn footer_version_is_informational_and_incompat_flags_reject() {
        let footer = BlobFooter::new(0, 17, 4096, 1, 8192, 1).unwrap();

        // Re-seal the footer bytes after poking a field: crc32 covers
        // everything but itself.
        let reseal = |mut data: [u8; NYDUS_BLOB_FOOTER_SIZE]| {
            let crc32 = crc32_with_zeroed_field(&data, BlobFooter::crc32_field());
            data[BlobFooter::crc32_field()].copy_from_slice(&crc32.to_le_bytes());
            data
        };

        // A future format generation is readable: version is informational.
        let mut future = footer.to_bytes();
        future[8..12].copy_from_slice(&(NYDUS_BLOB_FOOTER_VERSION + 1).to_le_bytes());
        BlobFooter::from_bytes(&reseal(future)).expect("future version must be readable");

        // An unknown compat (high-half) flag bit is ignored.
        let mut compat = footer.to_bytes();
        compat[12..16].copy_from_slice(&(1u32 << 31).to_le_bytes());
        BlobFooter::from_bytes(&reseal(compat)).expect("unknown compat flag must be ignored");

        // An unknown incompat (low-half) flag bit rejects the footer.
        let mut incompat = footer.to_bytes();
        incompat[12..16].copy_from_slice(&(1u32 << 3).to_le_bytes());
        let err = BlobFooter::from_bytes(&reseal(incompat)).unwrap_err();
        assert!(err.to_string().contains("incompat"), "{err}");

        // A resealed nonzero reserved tail (a future compat field) is readable.
        let mut tail = footer.to_bytes();
        tail[NYDUS_BLOB_FOOTER_SIZE - 1] = 0xff;
        BlobFooter::from_bytes(&reseal(tail)).expect("reserved tail must be ignored");
    }

    #[test]
    fn footer_rejects_unaligned_offsets() {
        let err = BlobFooter::new(0, 17, 17, 1, 8192, 1).unwrap_err();

        assert!(err.to_string().contains("aligned"));
    }
}

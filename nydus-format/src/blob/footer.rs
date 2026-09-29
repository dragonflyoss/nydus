use crate::blob::flag::FeatureFlags;
use crate::erofs::EROFS_BLOCK_SIZE;
use crate::error::{Error, Result};
use crate::utils::le::{read_u32_at, read_u64_at, write_u32_at, write_u64_at};
use crc32c::crc32c;
use std::fs::File;
use std::io::Write;
use std::ops::Range;
use std::os::unix::fs::FileExt;
use std::path::Path;

/// The trailing footer of a nydus full blob, the blob's self-describing map
/// of where each region lives, sealed with a crc32c. The whole-blob layout
/// is drawn at [`finish_full_blob`](crate::blob::finish_full_blob).
///
/// The footer's own 4096 bytes, integers little-endian.
///
/// ```text
/// offset  size  field
///      0     8  magic                   b"NDFOOTER"
///      8     4  feature_compat          unknown bits are ignored
///     12     4  feature_incompat        unknown bits reject the footer
///     16     4  crc32                   crc32c of these 4096 bytes with
///                                       this field treated as zero
///     20     4  bootstrap_crc32         crc32c of the bootstrap region,
///                                       padding included, zero when empty
///     24     8  compressed_data_offset  bytes
///     32     8  compressed_data_size    bytes
///     40     8  bootstrap_offset        bytes, 4KiB aligned
///     48     8  bootstrap_size          bytes, 4KiB multiple, zero for an
///                                       ondemand redirect blob
///     56     8  bootstrap_compressed_size  exact zstd frame bytes with
///                                       BOOTSTRAP_ZSTD, else zero
///     64     8  blob_metadata_offset    bytes, 4KiB aligned
///     72     8  blob_metadata_size      bytes, 4KiB multiple, zero exactly
///                                       with RAW_DEVICE
///     80  4016  reserved                writers zero it, readers ignore it
/// ```
///
/// A new field goes into the reserved bytes together with a feature bit
/// announcing it, compat when older readers may ignore it, else incompat.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlobFooter {
    feature_compat: u32,
    feature_incompat: FeatureFlags,
    crc32: u32,
    bootstrap_crc32: u32,
    compressed_data_offset: u64,
    compressed_data_size: u64,
    bootstrap_offset: u64,
    bootstrap_size: u64,
    bootstrap_compressed_size: u64,
    blob_metadata_offset: u64,
    blob_metadata_size: u64,
}

/// Writes and reads the footer, and answers where each region of the blob
/// lies.
impl BlobFooter {
    /// On-disk magic, 8 raw ASCII bytes written as-is so a hexdump of the
    /// footer starts with the readable string. Same frozen prefix as the
    /// blob meta (`NDBLMETA`), see [`crate::blob::flag`].
    pub const MAGIC: [u8; 8] = *b"NDFOOTER";

    /// The footer's fixed on-disk size, one EROFS block at the blob's tail.
    /// Every region offset and size in the blob is block aligned too, except
    /// the compressed data size.
    pub const SIZE: usize = EROFS_BLOCK_SIZE as usize;

    /// The embedded bootstrap region holds one zstd frame instead of raw
    /// EROFS bytes, its exact length in `bootstrap_compressed_size`. Only
    /// merge, `check` and single-blob mounts decode this region.
    pub const INCOMPAT_BOOTSTRAP_ZSTD: u32 = 1 << 0;

    /// The data region is a raw EROFS device the kernel reads at offset 0
    /// (native `erofs-*` layers) and there is no blob meta region. Such blobs
    /// are never served on demand, they are mounted through the kernel or
    /// read whole from a local store.
    pub const INCOMPAT_RAW_DEVICE: u32 = 1 << 1;

    /// Every incompat bit this reader understands. A footer setting a bit
    /// outside this mask was written by a newer nydus and is rejected by
    /// [`FeatureFlags::validate_incompat`].
    const INCOMPAT_SUPPORTED: u32 = Self::INCOMPAT_BOOTSTRAP_ZSTD | Self::INCOMPAT_RAW_DEVICE;

    /// Byte range of the crc32 field within the footer.
    const CRC32_FIELD: Range<usize> = 16..20;

    /// Creates a validated, sealed footer for the given region layout. The
    /// fields and the layout are checked first, then the crc32 is computed
    /// over the final bytes.
    ///
    /// `Some(n)` declares the bootstrap region stores one zstd frame of
    /// exactly `n` bytes and sets BOOTSTRAP_ZSTD, `None` keeps the region
    /// raw. `blob_metadata_size == 0` declares a raw device blob and sets
    /// RAW_DEVICE. `bootstrap_crc32` covers the whole bootstrap region.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        compressed_data_offset: u64,
        compressed_data_size: u64,
        bootstrap_offset: u64,
        bootstrap_size: u64,
        bootstrap_crc32: u32,
        blob_metadata_offset: u64,
        blob_metadata_size: u64,
        bootstrap_compressed_size: Option<u64>,
    ) -> Result<Self> {
        let mut footer = Self {
            feature_compat: 0,
            feature_incompat: Self::feature_incompat(
                bootstrap_compressed_size.is_some(),
                blob_metadata_size == 0,
            ),
            crc32: 0,
            bootstrap_crc32,
            compressed_data_offset,
            compressed_data_size,
            bootstrap_offset,
            bootstrap_size,
            bootstrap_compressed_size: bootstrap_compressed_size.unwrap_or(0),
            blob_metadata_offset,
            blob_metadata_size,
        };

        footer.validate_fields()?;
        footer.validate_layout(footer.offset()?)?;
        footer.crc32 = Self::compute_crc32(&footer.to_bytes());
        Ok(footer)
    }

    /// Parse a footer from exactly its [`Self::SIZE`] bytes. The raw bytes
    /// are checked first (`validate_bytes`), then the decoded fields against
    /// each other (`validate_fields`).
    ///
    /// The declared region offsets are not anchored against the blob's
    /// actual size here. [`Self::from_blob_bytes`] and
    /// [`Self::from_blob_path`] do that, a caller parsing an isolated footer
    /// does it with [`Self::validate_layout`] before trusting any offset.
    pub fn from_bytes(bytes: &[u8; Self::SIZE]) -> Result<Self> {
        Self::validate_bytes(bytes)?;
        let footer = Self {
            feature_compat: read_u32_at(bytes, 8),
            feature_incompat: FeatureFlags::from_bits(read_u32_at(bytes, 12)),
            crc32: read_u32_at(bytes, Self::CRC32_FIELD.start),
            bootstrap_crc32: read_u32_at(bytes, 20),
            compressed_data_offset: read_u64_at(bytes, 24),
            compressed_data_size: read_u64_at(bytes, 32),
            bootstrap_offset: read_u64_at(bytes, 40),
            bootstrap_size: read_u64_at(bytes, 48),
            bootstrap_compressed_size: read_u64_at(bytes, 56),
            blob_metadata_offset: read_u64_at(bytes, 64),
            blob_metadata_size: read_u64_at(bytes, 72),
        };

        footer.validate_fields()?;
        Ok(footer)
    }

    /// Serialize the footer into its on-disk bytes. The reserved tail is
    /// zeroed, so this is only the writer's view. Raw bytes read from disk
    /// may carry newer fields there that this type does not model.
    fn to_bytes(self) -> [u8; Self::SIZE] {
        let mut data = [0u8; Self::SIZE];
        data[0..8].copy_from_slice(&Self::MAGIC);
        write_u32_at(&mut data, 8, self.feature_compat);
        write_u32_at(&mut data, 12, self.feature_incompat.bits());
        write_u32_at(&mut data, Self::CRC32_FIELD.start, self.crc32);
        write_u32_at(&mut data, 20, self.bootstrap_crc32);
        write_u64_at(&mut data, 24, self.compressed_data_offset);
        write_u64_at(&mut data, 32, self.compressed_data_size);
        write_u64_at(&mut data, 40, self.bootstrap_offset);
        write_u64_at(&mut data, 48, self.bootstrap_size);
        write_u64_at(&mut data, 56, self.bootstrap_compressed_size);
        write_u64_at(&mut data, 64, self.blob_metadata_offset);
        write_u64_at(&mut data, 72, self.blob_metadata_size);
        data
    }

    /// Parse the trailing footer of a whole blob's bytes and anchor its
    /// declared layout against the blob's size. Errors when the bytes are
    /// too short for a footer, the tail carries no footer magic (the input
    /// is not a full blob, e.g. a bare bootstrap), or the footer is
    /// malformed. The bootstrap region is not read here, its consumer
    /// checks it against [`Self::bootstrap_crc32`].
    pub fn from_blob_bytes(blob: &[u8]) -> Result<Self> {
        let footer_offset = Self::calculate_offset_by_blob_size(blob.len() as u64)?;
        let footer_bytes = blob
            .last_chunk::<{ Self::SIZE }>()
            .ok_or_else(|| Error::InvalidImage("blob too small for nydus footer".to_string()))?;

        let footer = Self::from_bytes(footer_bytes)?;
        footer.validate_layout(footer_offset)?;
        Ok(footer)
    }

    /// Read and fully validate the footer of the blob file at `path`,
    /// without reading the rest of the blob.
    pub fn from_blob_path(path: &Path) -> Result<Self> {
        let file = File::open(path)?;
        let file_size = file.metadata()?.len();
        let footer_offset = Self::calculate_offset_by_blob_size(file_size)?;

        let mut bytes = [0u8; Self::SIZE];
        file.read_exact_at(&mut bytes, footer_offset)?;

        let footer = Self::from_bytes(&bytes)?;
        footer.validate_layout(footer_offset)?;
        Ok(footer)
    }

    /// The `feature_incompat` word a new footer declares, BOOTSTRAP_ZSTD
    /// when the bootstrap region holds a zstd frame and RAW_DEVICE when
    /// there is no blob meta region.
    fn feature_incompat(bootstrap_zstd: bool, raw_device: bool) -> FeatureFlags {
        let mut flags = FeatureFlags::empty();
        flags.set(Self::INCOMPAT_BOOTSTRAP_ZSTD, bootstrap_zstd);
        flags.set(Self::INCOMPAT_RAW_DEVICE, raw_device);
        flags
    }

    /// Validate the raw on-disk bytes before decoding them, the magic and
    /// the stored crc32 against [`Self::compute_crc32`]. Runs over the
    /// incoming bytes, never over `to_bytes()`, which would zero a newer
    /// writer's fields in the reserved tail and reject a valid image.
    fn validate_bytes(bytes: &[u8; Self::SIZE]) -> Result<()> {
        if !Self::has_magic(bytes) {
            return Err(Error::InvalidImage(
                "invalid nydus footer magic".to_string(),
            ));
        }

        if read_u32_at(bytes, Self::CRC32_FIELD.start) != Self::compute_crc32(bytes) {
            return Err(Error::InvalidImage(
                "nydus footer crc32 mismatch".to_string(),
            ));
        }

        Ok(())
    }

    /// Validate the intrinsic field invariants, needing nothing beyond the
    /// fields themselves. Run by [`Self::from_bytes`] on the read side and
    /// by [`Self::new`] on the write side.
    ///
    /// The reserved tail is deliberately not checked, since a newer writer
    /// may use it, and `bootstrap_size` may be zero, since an ondemand
    /// redirect blob embeds no bootstrap image.
    fn validate_fields(&self) -> Result<()> {
        self.feature_incompat
            .validate_incompat(Self::INCOMPAT_SUPPORTED)?;

        // RAW_DEVICE has no blob meta region and a mandatory bootstrap.
        // Every other blob carries blob meta.
        let raw_device = self.feature_incompat.contains(Self::INCOMPAT_RAW_DEVICE);
        if raw_device {
            if self.blob_metadata_size != 0 {
                return Err(Error::InvalidImage(
                    "nydus footer raw device blob must not carry a blob meta region".to_string(),
                ));
            }
            if self.bootstrap_size == 0 {
                return Err(Error::InvalidImage(
                    "nydus footer raw device blob must embed a bootstrap".to_string(),
                ));
            }
        } else if self.blob_metadata_size == 0 {
            return Err(Error::InvalidImage(
                "nydus footer blob without blob meta must set the RAW_DEVICE feature".to_string(),
            ));
        }

        // BOOTSTRAP_ZSTD declares a frame length within the bootstrap
        // region. A raw bootstrap declares none.
        let bootstrap_zstd = self
            .feature_incompat
            .contains(Self::INCOMPAT_BOOTSTRAP_ZSTD);
        if bootstrap_zstd {
            if self.bootstrap_compressed_size == 0 {
                return Err(Error::InvalidImage(
                    "nydus footer BOOTSTRAP_ZSTD blob must declare its compressed bootstrap size"
                        .to_string(),
                ));
            }
            if self.bootstrap_compressed_size > self.bootstrap_size {
                return Err(Error::InvalidImage(format!(
                    "nydus footer compressed bootstrap size {} exceeds its region of {} bytes",
                    self.bootstrap_compressed_size, self.bootstrap_size
                )));
            }
        } else if self.bootstrap_compressed_size != 0 {
            return Err(Error::InvalidImage(
                "nydus footer compressed bootstrap size requires the BOOTSTRAP_ZSTD feature"
                    .to_string(),
            ));
        }

        if self.compressed_data_offset % EROFS_BLOCK_SIZE as u64 != 0 {
            return Err(Error::InvalidImage(format!(
                "nydus footer compressed data region offset {:#x} is not 4KiB aligned",
                self.compressed_data_offset
            )));
        }

        if self.blob_metadata_offset % EROFS_BLOCK_SIZE as u64 != 0 {
            return Err(Error::InvalidImage(format!(
                "nydus footer blob meta region offset {:#x} is not 4KiB aligned",
                self.blob_metadata_offset
            )));
        }

        if self.blob_metadata_size % EROFS_BLOCK_SIZE as u64 != 0 {
            return Err(Error::InvalidImage(format!(
                "nydus footer blob meta region size {:#x} is not a 4KiB multiple",
                self.blob_metadata_size
            )));
        }

        if self.bootstrap_offset % EROFS_BLOCK_SIZE as u64 != 0 {
            return Err(Error::InvalidImage(format!(
                "nydus footer bootstrap region offset {:#x} is not 4KiB aligned",
                self.bootstrap_offset
            )));
        }

        if self.bootstrap_size % EROFS_BLOCK_SIZE as u64 != 0 {
            return Err(Error::InvalidImage(format!(
                "nydus footer bootstrap region size {:#x} is not a 4KiB multiple",
                self.bootstrap_size
            )));
        }

        if self.bootstrap_size == 0 && self.bootstrap_crc32 != 0 {
            return Err(Error::InvalidImage(
                "nydus footer bootstrap crc32 must be zero without a bootstrap".to_string(),
            ));
        }

        Ok(())
    }

    /// Validate the declared region layout against `offset`, the footer's
    /// actual position, an external fact the footer cannot fake. The regions
    /// must tile the blob in order (alignment gaps allowed) and end exactly
    /// where the footer sits.
    pub fn validate_layout(&self, offset: u64) -> Result<()> {
        if offset % EROFS_BLOCK_SIZE as u64 != 0 {
            return Err(Error::InvalidImage(format!(
                "nydus footer offset {offset:#x} is not 4KiB aligned"
            )));
        }

        let compressed_data_end = self
            .compressed_data_offset
            .checked_add(self.compressed_data_size)
            .ok_or_else(|| {
                Error::Overflow("nydus footer compressed data region overflow".to_string())
            })?;
        if self.bootstrap_offset < compressed_data_end {
            return Err(Error::InvalidImage(format!(
                "nydus footer bootstrap region starts at {:#x}, overlapping the compressed data region ending at {compressed_data_end:#x}",
                self.bootstrap_offset
            )));
        }

        let bootstrap_end = self
            .bootstrap_offset
            .checked_add(self.bootstrap_size)
            .ok_or_else(|| Error::Overflow("nydus footer bootstrap region overflow".to_string()))?;
        if self.blob_metadata_offset < bootstrap_end {
            return Err(Error::InvalidImage(format!(
                "nydus footer blob meta region starts at {:#x}, overlapping the bootstrap region ending at {bootstrap_end:#x}",
                self.blob_metadata_offset
            )));
        }

        let blob_metadata_end = self.offset()?;
        if blob_metadata_end != offset {
            return Err(Error::InvalidImage(format!(
                "nydus footer declared layout ends at {blob_metadata_end:#x}, not at the footer offset {offset:#x}"
            )));
        }

        Ok(())
    }

    /// Whether `data` starts with the footer magic.
    pub fn has_magic(bytes: &[u8]) -> bool {
        bytes.starts_with(&Self::MAGIC)
    }

    /// Write the footer's on-disk bytes to `writer`.
    pub fn write_to(&self, writer: &mut dyn Write) -> Result<()> {
        writer.write_all(&self.to_bytes())?;
        Ok(())
    }

    /// The footer's actual offset in a blob of `blob_size` total bytes, the
    /// footer being the blob's fixed-size tail.
    pub fn calculate_offset_by_blob_size(blob_size: u64) -> Result<u64> {
        blob_size
            .checked_sub(Self::SIZE as u64)
            .ok_or_else(|| Error::InvalidImage("blob too small for nydus footer".to_string()))
    }

    /// The footer offset the declared layout implies, the end of the blob
    /// meta region, since a full blob lays the footer right after it.
    pub fn offset(&self) -> Result<u64> {
        self.blob_metadata_offset
            .checked_add(self.blob_metadata_size())
            .ok_or_else(|| Error::Overflow("nydus footer blob meta region overflow".to_string()))
    }

    /// Byte offset of the embedded EROFS bootstrap region.
    pub fn bootstrap_offset(&self) -> u64 {
        self.bootstrap_offset
    }

    /// Size of the bootstrap region in bytes.
    pub fn bootstrap_size(&self) -> u64 {
        self.bootstrap_size
    }

    /// Exact byte length of the zstd frame in the bootstrap region, or
    /// `None` when the bootstrap is stored raw.
    pub fn bootstrap_compressed_size(&self) -> Option<u64> {
        self.feature_incompat
            .contains(Self::INCOMPAT_BOOTSTRAP_ZSTD)
            .then_some(self.bootstrap_compressed_size)
    }

    /// Size of the bootstrap region in 4KiB blocks, zero for an ondemand
    /// redirect blob.
    pub fn bootstrap_block_count(&self) -> u64 {
        self.bootstrap_size / EROFS_BLOCK_SIZE as u64
    }

    /// crc32c of the whole bootstrap region, alignment padding included.
    pub fn bootstrap_crc32(&self) -> u32 {
        self.bootstrap_crc32
    }

    /// Byte offset of the compressed data region.
    pub fn compressed_data_offset(&self) -> u64 {
        self.compressed_data_offset
    }

    /// Size of the compressed data region in bytes.
    pub fn compressed_data_size(&self) -> u64 {
        self.compressed_data_size
    }

    /// Byte offset of the blob meta region.
    pub fn blob_metadata_offset(&self) -> u64 {
        self.blob_metadata_offset
    }

    /// Size of the blob meta region in bytes.
    pub fn blob_metadata_size(&self) -> u64 {
        self.blob_metadata_size
    }

    /// Size of the blob meta region in 4KiB blocks, zero for a raw device
    /// blob (see [`Self::is_raw_device`]).
    pub fn blob_metadata_block_count(&self) -> u64 {
        self.blob_metadata_size / EROFS_BLOCK_SIZE as u64
    }

    /// Whether the data region is a raw EROFS device without blob meta
    /// (native `erofs-*` layers, RAW_DEVICE feature).
    pub fn is_raw_device(&self) -> bool {
        self.feature_incompat.contains(Self::INCOMPAT_RAW_DEVICE)
    }

    /// crc32c over the footer bytes with the crc32 field treated as zero.
    /// The writer seals `to_bytes()` with it, the reader verifies the raw
    /// incoming bytes against it.
    fn compute_crc32(bytes: &[u8; Self::SIZE]) -> u32 {
        let mut zeroed = *bytes;
        zeroed[Self::CRC32_FIELD].fill(0);
        crc32c(&zeroed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn to_bytes_encodes_every_field() {
        let footer =
            BlobFooter::new(0, 17, 4096, 4096, crc32c(&[0u8; 4096]), 8192, 4096, None).unwrap();
        let bytes = footer.to_bytes();
        assert_eq!(&bytes[..8], b"NDFOOTER");
        assert_eq!(read_u32_at(&bytes, 8), 0);
        assert_eq!(read_u32_at(&bytes, 12), 0);
        assert_eq!(read_u32_at(&bytes, 16), BlobFooter::compute_crc32(&bytes));
        assert_eq!(read_u32_at(&bytes, 20), crc32c(&[0u8; 4096]));
        assert!(bytes[80..].iter().all(|byte| *byte == 0));

        let test_cases = vec![
            (24, 0),
            (32, 17),
            (40, 4096),
            (48, 4096),
            (56, 0),
            (64, 8192),
            (72, 4096),
        ];

        for (offset, expected) in test_cases {
            assert_eq!(read_u64_at(&bytes, offset), expected);
        }
    }

    #[test]
    fn getters_return_the_layout() {
        let footer =
            BlobFooter::new(0, 17, 4096, 4096, crc32c(&[0u8; 4096]), 8192, 4096, None).unwrap();
        assert_eq!(footer.compressed_data_offset(), 0);
        assert_eq!(footer.compressed_data_size(), 17);
        assert_eq!(footer.bootstrap_offset(), 4096);
        assert_eq!(footer.bootstrap_size(), 4096);
        assert_eq!(footer.bootstrap_block_count(), 1);
        assert_eq!(footer.bootstrap_crc32(), crc32c(&[0u8; 4096]));
        assert_eq!(footer.bootstrap_compressed_size(), None);
        assert_eq!(footer.blob_metadata_offset(), 8192);
        assert_eq!(footer.blob_metadata_size(), 4096);
        assert_eq!(footer.blob_metadata_block_count(), 1);
        assert_eq!(footer.offset().unwrap(), 12288);
        assert!(!footer.is_raw_device());
    }

    #[test]
    fn new_accepts_raw_device_and_compressed_bootstrap_layouts() {
        let test_cases = vec![
            ((0, 17, 4096, 0, 0, 4096, 4096, None), false, None, 8192),
            ((0, 17, 4096, 4096, 0, 8192, 0, None), true, None, 8192),
            (
                (0, 17, 4096, 4096, 0, 8192, 4096, Some(100)),
                false,
                Some(100),
                12288,
            ),
        ];

        for (layout, raw_device, bootstrap_compressed_size, offset) in test_cases {
            let footer = BlobFooter::new(
                layout.0, layout.1, layout.2, layout.3, layout.4, layout.5, layout.6, layout.7,
            )
            .unwrap();
            assert_eq!(footer.is_raw_device(), raw_device);
            assert_eq!(
                footer.bootstrap_compressed_size(),
                bootstrap_compressed_size
            );
            assert_eq!(footer.offset().unwrap(), offset);
            assert_eq!(BlobFooter::from_bytes(&footer.to_bytes()).unwrap(), footer);
        }
    }

    #[test]
    fn new_rejects_inconsistent_layouts() {
        let test_cases = vec![
            (
                (0, 17, 4096, 0, 1, 4096, 4096, None),
                "nydus footer bootstrap crc32 must be zero without a bootstrap",
            ),
            (
                (0, 17, 4096, 0, 0, 4096, 0, None),
                "nydus footer raw device blob must embed a bootstrap",
            ),
            (
                (0, 17, 4096, 4096, 0, 8192, 4096, Some(5000)),
                "nydus footer compressed bootstrap size 5000 exceeds its region of 4096 bytes",
            ),
            (
                (0, 17, 4096, 4097, 0, 12288, 4096, None),
                "nydus footer bootstrap region size 0x1001 is not a 4KiB multiple",
            ),
            (
                (0, 17, 17, 4096, 0, 8192, 4096, None),
                "nydus footer bootstrap region offset 0x11 is not 4KiB aligned",
            ),
            (
                (0, 8192, 4096, 4096, 0, 8192, 4096, None),
                "nydus footer bootstrap region starts at 0x1000, overlapping the compressed data region ending at 0x2000",
            ),
            (
                (4096, u64::MAX, 4096, 4096, 0, 8192, 4096, None),
                "nydus footer compressed data region overflow",
            ),
        ];

        for (layout, expected) in test_cases {
            let err = BlobFooter::new(
                layout.0, layout.1, layout.2, layout.3, layout.4, layout.5, layout.6, layout.7,
            )
            .unwrap_err();
            assert_eq!(err.to_string(), expected);
        }
    }

    #[test]
    fn from_bytes_reads_what_write_to_wrote() {
        let footer =
            BlobFooter::new(0, 17, 4096, 4096, crc32c(&[0u8; 4096]), 8192, 4096, None).unwrap();
        let mut written = Vec::new();
        footer.write_to(&mut written).unwrap();

        let bytes: [u8; BlobFooter::SIZE] = written.try_into().unwrap();
        assert!(BlobFooter::has_magic(&bytes));
        assert_eq!(BlobFooter::from_bytes(&bytes).unwrap(), footer);
    }

    #[test]
    fn from_bytes_rejects_corrupted_bytes() {
        let footer =
            BlobFooter::new(0, 17, 4096, 4096, crc32c(&[0u8; 4096]), 8192, 4096, None).unwrap();

        let test_cases = vec![
            (0, "invalid nydus footer magic"),
            (24, "nydus footer crc32 mismatch"),
        ];

        for (offset, expected) in test_cases {
            let mut bytes = footer.to_bytes();
            bytes[offset] ^= 0xff;
            assert_eq!(
                BlobFooter::from_bytes(&bytes).unwrap_err().to_string(),
                expected
            );
        }
    }

    #[test]
    fn from_bytes_ignores_reserved_bytes_and_rejects_unknown_incompat_flags() {
        let footer =
            BlobFooter::new(0, 17, 4096, 4096, crc32c(&[0u8; 4096]), 8192, 4096, None).unwrap();

        let test_cases = vec![
            (8, 1u32 << 31, Ok(())),
            (
                12,
                1 << 3,
                Err("unsupported incompat flags 0x8 (image is newer than this reader)"),
            ),
            (
                12,
                1 << 31,
                Err("unsupported incompat flags 0x80000000 (image is newer than this reader)"),
            ),
            (
                12,
                BlobFooter::INCOMPAT_RAW_DEVICE,
                Err("nydus footer raw device blob must not carry a blob meta region"),
            ),
            (
                12,
                BlobFooter::INCOMPAT_BOOTSTRAP_ZSTD,
                Err("nydus footer BOOTSTRAP_ZSTD blob must declare its compressed bootstrap size"),
            ),
            (80, 0xffff_ffff, Ok(())),
            (BlobFooter::SIZE - 4, 0xff00_0000, Ok(())),
        ];

        for (offset, value, expected) in test_cases {
            let mut bytes = footer.to_bytes();
            write_u32_at(&mut bytes, offset, value);
            let crc32 = BlobFooter::compute_crc32(&bytes);
            write_u32_at(&mut bytes, 16, crc32);
            assert_eq!(
                BlobFooter::from_bytes(&bytes)
                    .map(drop)
                    .map_err(|err| err.to_string()),
                expected.map_err(String::from),
                "{offset}"
            );
        }
    }

    #[test]
    fn from_blob_bytes_reads_the_tail_footer_or_rejects_a_bad_blob() {
        let footer =
            BlobFooter::new(0, 17, 4096, 4096, crc32c(&[0u8; 4096]), 8192, 4096, None).unwrap();
        assert_eq!(
            BlobFooter::from_blob_bytes(&[0u8; 100])
                .unwrap_err()
                .to_string(),
            "blob too small for nydus footer"
        );
        assert_eq!(
            BlobFooter::from_blob_bytes(&[0u8; 16384])
                .unwrap_err()
                .to_string(),
            "invalid nydus footer magic"
        );

        let test_cases = vec![
            (16384, 0, Ok(footer)),
            (16384, 0xff, Err("nydus footer crc32 mismatch")),
            (
                16385,
                0,
                Err("nydus footer offset 0x3001 is not 4KiB aligned"),
            ),
            (
                20480,
                0,
                Err("nydus footer declared layout ends at 0x3000, not at the footer offset 0x4000"),
            ),
        ];

        for (blob_size, corruption, expected) in test_cases {
            let footer_offset = blob_size - BlobFooter::SIZE;
            let mut blob = vec![0u8; blob_size];
            blob[footer_offset..].copy_from_slice(&footer.to_bytes());
            blob[footer_offset + 24] ^= corruption;
            assert_eq!(
                BlobFooter::from_blob_bytes(&blob).map_err(|err| err.to_string()),
                expected.map_err(String::from)
            );
        }
    }

    #[test]
    fn from_blob_path_reads_the_tail_footer() {
        let footer =
            BlobFooter::new(0, 17, 4096, 4096, crc32c(&[0u8; 4096]), 8192, 4096, None).unwrap();
        let mut blob = vec![0u8; 16384];
        blob[12288..].copy_from_slice(&footer.to_bytes());
        let temp_dir = tempdir().unwrap();
        let path = temp_dir.path().join("layer.blob");
        std::fs::write(&path, blob).unwrap();

        assert_eq!(BlobFooter::from_blob_path(&path).unwrap(), footer);
    }

    #[test]
    fn calculate_offset_by_blob_size_subtracts_the_footer_size() {
        let test_cases = vec![
            (16384, Ok(12288)),
            (4096, Ok(0)),
            (100, Err("blob too small for nydus footer")),
        ];

        for (blob_size, expected) in test_cases {
            assert_eq!(
                BlobFooter::calculate_offset_by_blob_size(blob_size).map_err(|err| err.to_string()),
                expected.map_err(String::from)
            );
        }
    }
}

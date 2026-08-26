use crate::blob::flag::validate_incompat_flags;
use crate::erofs::{blocks_to_bytes, EROFS_BLOCK_SIZE};
use crate::error::{Context, Error, Result};
use crate::utils::le::{read_u32_at, read_u64_at, write_u32_at, write_u64_at};
use crc32c::crc32c;
use std::fs::File;
use std::io::Write;
use std::ops::Range;
use std::os::unix::fs::FileExt;
use std::path::Path;

/// On-disk magic: 8 raw ASCII bytes, written as-is so a hexdump of the
/// footer starts with the readable string. Same style and `magic + version +
/// flags` header prefix as the blob meta (`LPBLMETA`) and block_group_map
/// (`LPGRPMAP`) sidecars.
pub const NYDUS_BLOB_FOOTER_MAGIC: [u8; 8] = *b"LPFOOTER";

/// On-disk format generation, informational only: readers do not gate on it.
/// Compatibility is governed EROFS-style by the magic and the incompat half
/// of `flags` (unknown incompat bits reject the footer).
pub const NYDUS_BLOB_FOOTER_VERSION: u32 = 1;

/// The footer's fixed on-disk size: one EROFS block at the blob's tail.
pub const NYDUS_BLOB_FOOTER_SIZE: usize = 4096;

/// Every region offset in the blob, and the footer itself, is aligned to
/// this boundary (the EROFS block size).
pub const NYDUS_BLOB_FOOTER_ALIGNMENT: u64 = EROFS_BLOCK_SIZE as u64;

/// `flags` is split EROFS-style (see [`crate::blob::flag`]): the low 16
/// bits are incompatible features (unknown bits reject), the high 16 bits
/// are compatible features (unknown bits are ignored). No bits are defined
/// yet.
const NYDUS_BLOB_FOOTER_SUPPORTED_INCOMPAT: u32 = 0;

/// Byte range of the crc32 field within the footer.
const NYDUS_BLOB_FOOTER_CRC32_FIELD: Range<usize> = 16..20;

/// The trailing footer of a nydus full blob: the blob's self-describing map,
/// recording where each region lives, sealed with a crc32c.
///
/// A full blob lays its regions out back to back (alignment gaps allowed),
/// every offset 4KiB aligned, with the footer as the fixed-size tail:
///
/// ```text
/// ┌─────────────────┬───────────────────┬───────────┬────────┐
/// │ compressed data │ bootstrap (EROFS) │ blob meta │ footer │
/// └─────────────────┴───────────────────┴───────────┴────────┘
/// 0                                                 ▲        EOF
///                                 blob meta ends exactly at the
///                                 footer offset (EOF - 4096)
/// ```
///
/// The footer's own 4096 bytes (integers little-endian):
///
/// ```text
/// offset  size  field
///      0     8  magic                   b"LPFOOTER"
///      8     4  version                 informational, never gated on
///     12     4  flags                   low 16 incompat / high 16 compat
///     16     4  crc32                   crc32c of these 4096 bytes with
///                                       this field treated as zero
///     20     4  reserved0               future compat field slot
///     24     8  compressed_data_offset
///     32     8  bootstrap_offset
///     40     8  blob_metadata_offset
///     48     8  compressed_data_size    bytes
///     56     4  bootstrap_blocks        4KiB blocks, zero for an ondemand
///                                       redirect blob without a bootstrap
///     60     4  blob_metadata_blocks    4KiB blocks, never zero
///     64  4032  reserved                writers zero it, readers ignore it
/// ```
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
    /// Creates a validated, sealed footer for the given region layout: the
    /// fields and the layout are checked first, so a constructed footer is
    /// valid by definition, then the crc32 is computed over the final bytes.
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

        footer.validate()?;
        footer.validate_layout(footer.offset()?)?;
        footer.crc32 = Self::compute_crc32(&footer.to_bytes());
        Ok(footer)
    }

    /// Parse a footer from exactly its `NYDUS_BLOB_FOOTER_SIZE` bytes,
    /// verifying the intrinsic fields and the crc32 over the raw bytes.
    ///
    /// The declared region offsets are not anchored against the blob's actual
    /// size here. The whole-blob entry points ([`Self::from_blob_bytes`],
    /// [`Self::from_blob_path`]) do that anchoring themselves. Callers
    /// parsing an isolated footer (e.g. a registry range read) must treat the
    /// offsets as untrusted hints whose reads are bounds-checked downstream.
    pub fn from_bytes(bytes: &[u8; NYDUS_BLOB_FOOTER_SIZE]) -> Result<Self> {
        let footer = Self {
            magic: bytes[0..8].try_into().unwrap(),
            version: read_u32_at(bytes, 8),
            flags: read_u32_at(bytes, 12),
            crc32: read_u32_at(bytes, 16),
            reserved0: read_u32_at(bytes, 20),
            compressed_data_offset: read_u64_at(bytes, 24),
            bootstrap_offset: read_u64_at(bytes, 32),
            blob_metadata_offset: read_u64_at(bytes, 40),
            compressed_data_size: read_u64_at(bytes, 48),
            bootstrap_blocks: read_u32_at(bytes, 56),
            blob_metadata_blocks: read_u32_at(bytes, 60),
        };
        footer.validate()?;

        // Verify over the raw incoming bytes, never over `to_bytes()`: a
        // re-serialization emits only the fields this reader knows, zeroing a
        // newer writer's compat fields in the reserved tail and thereby
        // rejecting a valid image.
        if footer.crc32 != Self::compute_crc32(bytes) {
            return Err(Error::InvalidImage(
                "nydus footer crc32 mismatch".to_string(),
            ));
        }

        Ok(footer)
    }

    /// Serialize the footer into its on-disk bytes. The reserved tail is
    /// zeroed, so this is only the writer's view: raw bytes read from disk
    /// may carry newer compat fields there that this type does not model.
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

    /// Probe a whole blob's bytes for a trailing footer and parse it.
    ///
    /// Returns `Ok(None)` when the bytes are too short for a footer or the
    /// tail carries no footer magic (the input is not a full blob, e.g. a
    /// bare bootstrap), the parsed and fully validated footer when it is,
    /// and an error when the magic is present but the footer is malformed
    /// or its declared layout does not match the blob's size.
    pub fn from_blob_bytes(blob: &[u8]) -> Result<Option<Self>> {
        let Some(footer_bytes) = blob.last_chunk::<NYDUS_BLOB_FOOTER_SIZE>() else {
            return Ok(None);
        };

        if !Self::has_magic(footer_bytes) {
            return Ok(None);
        }

        let footer = Self::from_bytes(footer_bytes)?;
        footer.validate_layout(Self::offset_from_size(blob.len() as u64)?)?;
        Ok(Some(footer))
    }

    /// Read and fully validate the footer of the blob file at `path`,
    /// without reading the rest of the blob.
    pub fn from_blob_path(path: &Path) -> Result<Self> {
        let file = File::open(path)
            .with_context(|| format!("failed to open blob footer: {}", path.display()))?;

        let file_size = file
            .metadata()
            .with_context(|| format!("failed to stat blob footer: {}", path.display()))?
            .len();

        let footer_offset = Self::offset_from_size(file_size)
            .with_context(|| format!("failed to locate blob footer: {}", path.display()))?;

        let mut bytes = [0u8; NYDUS_BLOB_FOOTER_SIZE];
        file.read_exact_at(&mut bytes, footer_offset)
            .with_context(|| format!("failed to read blob footer: {}", path.display()))?;

        let footer = Self::from_bytes(&bytes)
            .with_context(|| format!("failed to parse blob footer: {}", path.display()))?;

        footer.validate_layout(footer_offset).with_context(|| {
            format!("failed to validate blob footer layout: {}", path.display())
        })?;

        Ok(footer)
    }

    /// Validate the intrinsic field invariants, needing nothing beyond the
    /// fields themselves. Run once per entry point: by [`Self::from_bytes`]
    /// on the read side and by [`Self::new`] on the write side.
    ///
    /// Deliberately not checked: `version` is informational (compatibility
    /// is governed by the magic and the incompat flag bits), `reserved0` and
    /// the reserved tail may carry a newer writer's compat fields (corruption
    /// is caught by the crc32), and `bootstrap_blocks` may be zero (an
    /// ondemand redirect blob embeds no bootstrap image).
    fn validate(&self) -> Result<()> {
        if self.magic != NYDUS_BLOB_FOOTER_MAGIC {
            return Err(Error::InvalidImage(
                "invalid nydus footer magic".to_string(),
            ));
        }

        if self.blob_metadata_blocks == 0 {
            return Err(Error::InvalidImage(
                "nydus footer blob meta block count must be non-zero".to_string(),
            ));
        }

        validate_incompat_flags(self.flags, NYDUS_BLOB_FOOTER_SUPPORTED_INCOMPAT)?;
        Ok(())
    }

    /// Validate the declared region layout against `offset`, the footer's
    /// actual position (an external fact the footer cannot fake): the
    /// regions must tile the blob back to back (alignment gaps allowed) and
    /// end exactly where the footer sits.
    fn validate_layout(&self, offset: u64) -> Result<()> {
        let regions = [
            (
                "compressed data",
                self.compressed_data_offset,
                self.compressed_data_size,
            ),
            ("bootstrap", self.bootstrap_offset, self.bootstrap_size()),
            (
                "blob meta",
                self.blob_metadata_offset,
                self.blob_metadata_size(),
            ),
        ];

        let mut cursor = 0;
        for (name, start, size) in regions {
            if start % NYDUS_BLOB_FOOTER_ALIGNMENT != 0 {
                return Err(Error::InvalidImage(format!(
                    "nydus footer {name} region offset {start:#x} is not 4KiB aligned"
                )));
            }

            if start < cursor {
                return Err(Error::InvalidImage(format!(
                    "nydus footer {name} region starts at {start:#x}, overlapping the previous region ending at {cursor:#x}"
                )));
            }

            cursor = start
                .checked_add(size)
                .ok_or_else(|| Error::Overflow(format!("nydus footer {name} region overflow")))?;
        }

        if offset % NYDUS_BLOB_FOOTER_ALIGNMENT != 0 {
            return Err(Error::InvalidImage(format!(
                "nydus footer offset {offset:#x} is not 4KiB aligned"
            )));
        }

        if cursor != offset {
            return Err(Error::InvalidImage(format!(
                "nydus footer declared layout ends at {cursor:#x}, not at the footer offset {offset:#x}"
            )));
        }

        Ok(())
    }

    /// Whether `data` starts with the footer magic.
    pub fn has_magic(data: &[u8]) -> bool {
        data.starts_with(&NYDUS_BLOB_FOOTER_MAGIC)
    }

    /// Write the footer's on-disk bytes to `writer`.
    pub fn write_to(&self, writer: &mut dyn Write) -> Result<()> {
        writer.write_all(&self.to_bytes())?;
        Ok(())
    }

    /// The footer offset the declared layout implies: a full blob lays the
    /// footer immediately after the blob meta region, so this is the
    /// exclusive end of that region.
    pub fn offset(&self) -> Result<u64> {
        self.blob_metadata_offset
            .checked_add(self.blob_metadata_size())
            .ok_or_else(|| Error::Overflow("nydus footer blob meta region overflow".to_string()))
    }

    /// The footer's actual offset in a blob of `blob_size` total bytes: the
    /// footer is the blob's fixed-size tail.
    pub fn offset_from_size(blob_size: u64) -> Result<u64> {
        blob_size
            .checked_sub(NYDUS_BLOB_FOOTER_SIZE as u64)
            .ok_or_else(|| Error::InvalidImage("blob too small for nydus footer".to_string()))
    }

    /// Byte offset of the compressed data region.
    pub fn compressed_data_offset(&self) -> u64 {
        self.compressed_data_offset
    }

    /// Byte offset of the embedded EROFS bootstrap region.
    pub fn bootstrap_offset(&self) -> u64 {
        self.bootstrap_offset
    }

    /// Byte offset of the blob meta region.
    pub fn blob_metadata_offset(&self) -> u64 {
        self.blob_metadata_offset
    }

    /// Size of the compressed data region in bytes.
    pub fn compressed_data_size(&self) -> u64 {
        self.compressed_data_size
    }

    /// Size of the bootstrap region in 4KiB blocks, zero for an ondemand
    /// redirect blob.
    pub fn bootstrap_blocks(&self) -> u32 {
        self.bootstrap_blocks
    }

    /// Size of the blob meta region in 4KiB blocks, never zero.
    pub fn blob_metadata_blocks(&self) -> u32 {
        self.blob_metadata_blocks
    }

    /// Size of the bootstrap region in bytes.
    pub fn bootstrap_size(&self) -> u64 {
        blocks_to_bytes(self.bootstrap_blocks)
    }

    /// Size of the blob meta region in bytes.
    pub fn blob_metadata_size(&self) -> u64 {
        blocks_to_bytes(self.blob_metadata_blocks)
    }

    /// crc32c over the footer bytes with the crc32 field treated as zero:
    /// the writer seals `to_bytes()` with it, the reader verifies the raw
    /// incoming bytes against it.
    fn compute_crc32(bytes: &[u8; NYDUS_BLOB_FOOTER_SIZE]) -> u32 {
        let mut zeroed = *bytes;
        zeroed[NYDUS_BLOB_FOOTER_CRC32_FIELD].fill(0);
        crc32c(&zeroed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn footer() -> BlobFooter {
        BlobFooter::new(0, 17, 4096, 1, 8192, 1).unwrap()
    }

    fn reseal(mut bytes: [u8; NYDUS_BLOB_FOOTER_SIZE]) -> [u8; NYDUS_BLOB_FOOTER_SIZE] {
        let crc32 = BlobFooter::compute_crc32(&bytes);
        bytes[NYDUS_BLOB_FOOTER_CRC32_FIELD].copy_from_slice(&crc32.to_le_bytes());
        bytes
    }

    fn sealed_blob() -> Vec<u8> {
        let mut blob = vec![0u8; 16384];
        blob[12288..].copy_from_slice(&footer().to_bytes());
        blob
    }

    #[test]
    fn accessors_expose_the_sealed_layout() {
        let footer = footer();
        assert_eq!(footer.compressed_data_offset(), 0);
        assert_eq!(footer.compressed_data_size(), 17);
        assert_eq!(footer.bootstrap_offset(), 4096);
        assert_eq!(footer.bootstrap_blocks(), 1);
        assert_eq!(footer.bootstrap_size(), 4096);
        assert_eq!(footer.blob_metadata_offset(), 8192);
        assert_eq!(footer.blob_metadata_blocks(), 1);
        assert_eq!(footer.blob_metadata_size(), 4096);
        assert_eq!(footer.offset().unwrap(), 12288);
    }

    #[test]
    fn offset_from_size_locates_the_fixed_tail() {
        assert_eq!(BlobFooter::offset_from_size(16384).unwrap(), 12288);
    }

    #[test]
    fn write_to_emits_parseable_bytes() {
        let footer = footer();
        let mut written = Vec::new();
        footer.write_to(&mut written).unwrap();

        let bytes: [u8; NYDUS_BLOB_FOOTER_SIZE] = written.as_slice().try_into().unwrap();
        assert!(BlobFooter::has_magic(&bytes));
        assert_eq!(BlobFooter::from_bytes(&bytes).unwrap(), footer);
    }

    #[test]
    fn round_trips_through_bytes() {
        let footer = footer();

        assert_eq!(BlobFooter::from_bytes(&footer.to_bytes()).unwrap(), footer);
    }

    #[test]
    fn resealed_header_mutations_follow_the_compat_rules() {
        let cases: [(&str, usize, [u8; 4], Option<&str>); 4] = [
            (
                "future version is readable",
                8,
                (NYDUS_BLOB_FOOTER_VERSION + 1).to_le_bytes(),
                None,
            ),
            (
                "unknown compat flag is ignored",
                12,
                (1u32 << 31).to_le_bytes(),
                None,
            ),
            (
                "unknown incompat flag rejects",
                12,
                (1u32 << 3).to_le_bytes(),
                Some("incompat"),
            ),
            (
                "nonzero reserved tail is readable",
                NYDUS_BLOB_FOOTER_SIZE - 4,
                [0, 0, 0, 0xff],
                None,
            ),
        ];

        for (case, offset, value, expected_err) in cases {
            let mut bytes = footer().to_bytes();
            bytes[offset..offset + 4].copy_from_slice(&value);

            let result = BlobFooter::from_bytes(&reseal(bytes));
            match expected_err {
                None => {
                    result.unwrap_or_else(|err| panic!("{case}: {err}"));
                }
                Some(expected) => {
                    let err = result.unwrap_err();
                    assert!(err.to_string().contains(expected), "{case}: {err}");
                }
            }
        }
    }

    #[test]
    fn corrupted_bytes_fail_the_crc32_check() {
        let mut bytes = footer().to_bytes();
        bytes[24] ^= 0xff;

        let err = BlobFooter::from_bytes(&bytes).unwrap_err();
        assert!(err.to_string().contains("crc32 mismatch"), "{err}");
    }

    #[test]
    fn from_blob_bytes_returns_none_for_a_short_input() {
        assert!(BlobFooter::from_blob_bytes(&[0u8; 100]).unwrap().is_none());
    }

    #[test]
    fn from_blob_bytes_returns_none_without_the_magic() {
        assert!(BlobFooter::from_blob_bytes(&[0u8; 16384])
            .unwrap()
            .is_none());
    }

    #[test]
    fn from_blob_bytes_parses_a_sealed_blob() {
        let parsed = BlobFooter::from_blob_bytes(&sealed_blob())
            .unwrap()
            .unwrap();

        assert_eq!(parsed, footer());
    }

    #[test]
    fn from_blob_bytes_errors_on_corruption_behind_the_magic() {
        let mut blob = sealed_blob();
        blob[12288 + 24] ^= 0xff;

        let err = BlobFooter::from_blob_bytes(&blob).unwrap_err();
        assert!(err.to_string().contains("crc32 mismatch"), "{err}");
    }

    #[test]
    fn zero_bootstrap_blocks_are_valid() {
        BlobFooter::new(0, 17, 4096, 0, 4096, 1).unwrap();
    }

    #[test]
    fn invalid_layouts_reject() {
        let cases = [
            (
                "zero blob meta blocks",
                (0, 17, 4096, 1, 8192, 0),
                "must be non-zero",
            ),
            ("unaligned offset", (0, 17, 17, 1, 8192, 1), "aligned"),
            (
                "overlapping regions",
                (0, 8192, 4096, 1, 8192, 1),
                "overlapping",
            ),
            (
                "region overflow",
                (4096, u64::MAX, 4096, 1, 8192, 1),
                "overflow",
            ),
        ];

        for (case, (data_off, data_size, boot_off, boot_blocks, meta_off, meta_blocks), expected) in
            cases
        {
            let err = BlobFooter::new(
                data_off,
                data_size,
                boot_off,
                boot_blocks,
                meta_off,
                meta_blocks,
            )
            .unwrap_err();
            assert!(err.to_string().contains(expected), "{case}: {err}");
        }
    }

    #[test]
    fn a_layout_not_ending_at_the_footer_rejects() {
        let err = footer()
            .validate_layout(BlobFooter::offset_from_size(16384 + 4096).unwrap())
            .unwrap_err();

        assert!(
            err.to_string().contains("not at the footer offset"),
            "{err}"
        );
    }

    #[test]
    fn from_blob_path_reads_back_the_sealed_footer() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("layer.blob");
        std::fs::write(&path, sealed_blob()).unwrap();

        assert_eq!(BlobFooter::from_blob_path(&path).unwrap(), footer());
    }

    #[test]
    fn bad_magic_rejects() {
        let mut bytes = footer().to_bytes();
        bytes[0] ^= 0xff;

        let err = BlobFooter::from_bytes(&bytes).unwrap_err();
        assert!(err.to_string().contains("magic"), "{err}");
    }

    #[test]
    fn an_unaligned_blob_length_rejects() {
        let mut blob = vec![0u8; 16385];
        let tail = blob.len() - NYDUS_BLOB_FOOTER_SIZE;
        blob[tail..].copy_from_slice(&footer().to_bytes());

        let err = BlobFooter::from_blob_bytes(&blob).unwrap_err();
        assert!(err.to_string().contains("aligned"), "{err}");
    }

    #[test]
    fn an_undersized_blob_rejects() {
        let err = BlobFooter::offset_from_size(100).unwrap_err();

        assert!(err.to_string().contains("too small"), "{err}");
    }
}

use super::*;
use crate::utils::le::{read_u16, read_u32, read_u64, write_u16, write_u32, write_u64};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::mem;
use std::path::Path;

/// EROFS superblock — 128 bytes, `#[repr(C, packed)]`.
#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct ErofsSuperblock {
    pub magic: [u8; 4],
    pub checksum: [u8; 4],
    pub feature_compat: [u8; 4],
    pub blkszbits: u8,
    pub sb_extslots: u8,
    pub rootnid_2b: [u8; 2],
    pub inos: [u8; 8],
    pub epoch: [u8; 8],
    pub fixed_nsec: [u8; 4],
    pub blocks_lo: [u8; 4],
    pub meta_blkaddr: [u8; 4],
    pub xattr_blkaddr: [u8; 4],
    pub uuid: [u8; 16],
    pub volume_name: [u8; 16],
    pub feature_incompat: [u8; 4],
    pub compr_or_distance: [u8; 2],
    pub extra_devices: [u8; 2],
    pub devt_slotoff: [u8; 2],
    pub dirblkbits: u8,
    pub xattr_prefix_count: u8,
    pub xattr_prefix_start: [u8; 4],
    pub packed_nid: [u8; 8],
    pub xattr_filter_reserved: u8,
    pub _reserved2: [u8; 3],
    pub build_time: [u8; 8],
    pub rootnid_8b: [u8; 8],
    pub _reserved3: [u8; 4],
}

const _: () = assert!(mem::size_of::<ErofsSuperblock>() == EROFS_SB_BASE_SIZE);

impl ErofsSuperblock {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        feature_compat: u32,
        feature_incompat: u32,
        root_nid: u16,
        inos: u64,
        epoch: u64,
        blocks: u64,
        meta_blkaddr: u32,
        extra_devices: u16,
        devt_slotoff: u16,
        uuid: &[u8; 16],
    ) -> Self {
        let mut sb: Self = unsafe { mem::zeroed() };
        write_u32(&mut sb.magic, EROFS_SUPER_MAGIC_V1);
        write_u32(&mut sb.feature_compat, feature_compat);
        sb.blkszbits = EROFS_BLKSZBITS;
        write_u16(&mut sb.rootnid_2b, root_nid);
        write_u64(&mut sb.inos, inos);
        write_u64(&mut sb.epoch, epoch);
        write_u32(&mut sb.blocks_lo, blocks as u32);
        write_u32(&mut sb.meta_blkaddr, meta_blkaddr);
        sb.uuid = *uuid;
        write_u32(&mut sb.feature_incompat, feature_incompat);
        write_u16(&mut sb.extra_devices, extra_devices);
        write_u16(&mut sb.devt_slotoff, devt_slotoff);
        sb
    }

    pub fn as_bytes(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self as *const _ as *const u8, EROFS_SB_BASE_SIZE) }
    }

    pub fn magic(&self) -> u32 {
        read_u32(&self.magic)
    }

    pub fn feature_compat(&self) -> u32 {
        read_u32(&self.feature_compat)
    }

    pub fn feature_incompat(&self) -> u32 {
        read_u32(&self.feature_incompat)
    }

    pub fn root_nid(&self) -> u64 {
        read_u16(&self.rootnid_2b) as u64
    }

    pub fn inos(&self) -> u64 {
        read_u64(&self.inos)
    }

    pub fn epoch(&self) -> u64 {
        read_u64(&self.epoch)
    }

    pub fn fixed_nsec(&self) -> u32 {
        read_u32(&self.fixed_nsec)
    }

    pub fn blocks(&self) -> u64 {
        read_u32(&self.blocks_lo) as u64
    }

    pub fn meta_blkaddr(&self) -> u32 {
        read_u32(&self.meta_blkaddr)
    }

    pub fn extra_devices(&self) -> u16 {
        read_u16(&self.extra_devices)
    }

    pub fn devt_slotoff(&self) -> u16 {
        read_u16(&self.devt_slotoff)
    }
}

/// Check whether `path` is a rafs v7 (pure EROFS) bootstrap.
///
/// Reads the EROFS superblock at [`EROFS_SUPER_OFFSET`] and requires:
/// - the EROFS magic,
/// - only incompat features this crate implements (standard EROFS contract),
/// - the [`EROFS_FEATURE_COMPAT_RAFS_V6`] marker bit to be absent.
///
/// Returns `Ok(false)` for RAFS v6 bootstraps (which always carry the marker
/// bit) and an error for files that are not readable EROFS images at all, so
/// callers can route `nydus://` paths to the right backend by content instead
/// of by URI scheme.
pub fn is_rafs_v7_bootstrap(path: &Path) -> io::Result<bool> {
    let mut file = File::open(path)?;
    file.seek(SeekFrom::Start(EROFS_SUPER_OFFSET))?;
    let mut buf = [0u8; EROFS_SB_BASE_SIZE];
    file.read_exact(&mut buf)?;
    // Safety: ErofsSuperblock is #[repr(C, packed)], exactly
    // EROFS_SB_BASE_SIZE bytes, and valid for any bit pattern.
    let sb: &ErofsSuperblock = unsafe { &*(buf.as_ptr() as *const ErofsSuperblock) };

    validate_superblock(sb)?;
    Ok(sb.feature_compat() & EROFS_FEATURE_COMPAT_RAFS_V6 == 0)
}

/// Validate the superblock magic and reject images declaring incompat
/// features this reader does not implement (the standard EROFS incompat
/// contract: unknown bits mean the image cannot be read correctly).
///
/// The single source of truth for the supported-incompat feature set —
/// extend the list here when a new feature bit is implemented.
pub fn validate_superblock(sb: &ErofsSuperblock) -> io::Result<()> {
    if sb.magic() != EROFS_SUPER_MAGIC_V1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("bad EROFS magic: 0x{:08X}", sb.magic()),
        ));
    }
    // This reader hardcodes 4 KiB blocks (`EROFS_BLOCK_SIZE`); an untrusted
    // `blkszbits` would otherwise feed unchecked `1 << blkszbits` shifts in
    // the block-geometry math.
    if sb.blkszbits != EROFS_BLKSZBITS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported EROFS block size bits: {}", sb.blkszbits),
        ));
    }
    const SUPPORTED_INCOMPAT: u32 = EROFS_FEATURE_INCOMPAT_CHUNKED_FILE
        | EROFS_FEATURE_INCOMPAT_DEVICE_TABLE
        | EROFS_FEATURE_INCOMPAT_48BIT;
    let unknown = sb.feature_incompat() & !SUPPORTED_INCOMPAT;
    if unknown != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported EROFS incompat features: {unknown:#x}"),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_bootstrap(
        feature_compat: u32,
        feature_incompat: u32,
        magic: Option<u32>,
    ) -> tempfile::NamedTempFile {
        let mut sb = ErofsSuperblock::new(
            feature_compat,
            feature_incompat,
            0,
            0,
            0,
            1,
            1,
            0,
            0,
            &[0u8; 16],
        );
        if let Some(m) = magic {
            write_u32(&mut sb.magic, m);
        }
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(&[0u8; EROFS_SUPER_OFFSET as usize]).unwrap();
        file.write_all(sb.as_bytes()).unwrap();
        file.flush().unwrap();
        file
    }

    #[test]
    fn detects_rafs_v7_and_rejects_v6_and_corrupt_bootstraps() {
        // Pure EROFS with standard bits only: rafs v7.
        let v7 = write_bootstrap(
            EROFS_FEATURE_COMPAT_SB_CHKSUM,
            EROFS_FEATURE_INCOMPAT_CHUNKED_FILE | EROFS_FEATURE_INCOMPAT_DEVICE_TABLE,
            None,
        );
        assert!(is_rafs_v7_bootstrap(v7.path()).unwrap());

        // RAFS v6 marker bit present: not v7.
        let v6 = write_bootstrap(
            EROFS_FEATURE_COMPAT_RAFS_V6,
            EROFS_FEATURE_INCOMPAT_CHUNKED_FILE | EROFS_FEATURE_INCOMPAT_DEVICE_TABLE,
            None,
        );
        assert!(!is_rafs_v7_bootstrap(v6.path()).unwrap());

        // Bad magic: error.
        let bad = write_bootstrap(0, 0, Some(0xDEAD_BEEF));
        assert!(is_rafs_v7_bootstrap(bad.path()).is_err());

        // Unknown incompat bit: error.
        let unknown = write_bootstrap(0, 0x8000_0000, None);
        assert!(is_rafs_v7_bootstrap(unknown.path()).is_err());

        // Truncated file (no superblock): error.
        let empty = tempfile::NamedTempFile::new().unwrap();
        assert!(is_rafs_v7_bootstrap(empty.path()).is_err());
    }
}

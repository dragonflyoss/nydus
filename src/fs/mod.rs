mod data;
pub mod fuse;
mod meta;

pub use self::fuse::ErofsFs;

use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::Path;

use memmap2::Mmap;

use crate::metadata::*;
use crate::utils::{hex_string, sha256_bytes};

/// Parsed directory entry (name must be owned since it is sliced from mmap).
pub struct DirEntry {
    pub nid: u64,
    pub file_type: u8,
    pub name: String,
}

pub(crate) struct CachedDirEntry {
    pub nid: u64,
    pub file_type: u8,
    pub name: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceInfo {
    pub device_id: u16,
    pub blob_id: [u8; EROFS_BLOB_ID_SIZE],
    pub blocks: u64,
}

struct BlobDevice {
    mmap: Mmap,
    data_offset: usize,
}

/// EROFS image reader — lock-free, zero-copy.
///
/// Both the image and blob device are memory-mapped for zero-copy access.
/// On-disk structs are cast directly from the mapped memory.
pub struct ErofsReader {
    pub(crate) mmap: Mmap,
    blob_devices: HashMap<u16, BlobDevice>,
    pub(crate) sb_offset: usize,
}

impl ErofsReader {
    /// Open an EROFS blob directly, or a bootstrap with an external blob directory.
    pub fn open(
        blob_path: Option<&Path>,
        bootstrap_path: Option<&Path>,
        blob_dir: Option<&Path>,
    ) -> io::Result<Self> {
        match (blob_path, bootstrap_path, blob_dir) {
            (Some(blob), None, None) => Self::open_blob(blob),
            (None, Some(bootstrap), Some(blob_dir)) => Self::open_bootstrap(bootstrap, blob_dir),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "expected either --blob <path> or --bootstrap <path> --blob-dir <dir>",
            )),
        }
    }

    /// Open a lepton blob / bootstrap file for metadata-only inspection.
    pub fn open_layer(path: &Path) -> io::Result<Self> {
        let mmap = Self::map_file(path)?;
        let sb_offset = EROFS_SUPER_OFFSET as usize;
        let sb = Self::superblock_from(&mmap, sb_offset)?;
        if sb.magic() != EROFS_SUPER_MAGIC_V1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("bad EROFS magic: 0x{:08X}", sb.magic()),
            ));
        }

        Ok(Self {
            mmap,
            blob_devices: HashMap::new(),
            sb_offset,
        })
    }

    fn open_blob(blob_path: &Path) -> io::Result<Self> {
        let mmap = Self::map_file(blob_path)?;
        let sb_offset = EROFS_SUPER_OFFSET as usize;
        let sb = Self::superblock_from(&mmap, sb_offset)?;
        if sb.magic() != EROFS_SUPER_MAGIC_V1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("bad EROFS magic: 0x{:08X}", sb.magic()),
            ));
        }

        let mut blob_devices = HashMap::new();
        if sb.extra_devices() > 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "direct blob mounting currently supports at most one external device",
            ));
        }
        if sb.extra_devices() == 1 {
            blob_devices.insert(
                1,
                BlobDevice {
                    mmap: Self::map_file(blob_path)?,
                    data_offset: 0,
                },
            );
        }

        Ok(Self {
            mmap,
            blob_devices,
            sb_offset,
        })
    }

    fn open_bootstrap(bootstrap_path: &Path, blob_dir: &Path) -> io::Result<Self> {
        let mmap = Self::map_file(bootstrap_path)?;
        let sb_offset = EROFS_SUPER_OFFSET as usize;
        let sb = Self::superblock_from(&mmap, sb_offset)?;
        if sb.magic() != EROFS_SUPER_MAGIC_V1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("bad EROFS magic: 0x{:08X}", sb.magic()),
            ));
        }

        let blob_devices = Self::device_infos_from(&mmap, sb_offset)?
            .into_iter()
            .map(|info| {
                let (mmap, data_offset) = Self::find_blob_in_dir(blob_dir, &info.blob_id)?;
                Ok((info.device_id, BlobDevice { mmap, data_offset }))
            })
            .collect::<io::Result<HashMap<_, _>>>()?;

        Ok(Self {
            mmap,
            blob_devices,
            sb_offset,
        })
    }

    fn map_file(path: &Path) -> io::Result<Mmap> {
        let file = fs::File::open(path)?;
        // SAFETY: file opened read-only, never modified while mapped.
        unsafe { Mmap::map(&file) }
    }

    fn superblock_from(mmap: &[u8], sb_offset: usize) -> io::Result<&ErofsSuperblock> {
        let end = sb_offset + EROFS_SB_BASE_SIZE;
        if mmap.len() < end {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "image too small for superblock",
            ));
        }
        Ok(cast_ref::<ErofsSuperblock>(&mmap[sb_offset..]))
    }

    fn device_infos_from(mmap: &[u8], sb_offset: usize) -> io::Result<Vec<DeviceInfo>> {
        let sb = Self::superblock_from(mmap, sb_offset)?;
        let mut infos = Vec::with_capacity(sb.extra_devices() as usize);
        for index in 0..sb.extra_devices() as usize {
            let slot = Self::device_slot_from(mmap, sb_offset, index)?;
            infos.push(DeviceInfo {
                device_id: index as u16 + 1,
                blob_id: slot.blob_id(),
                blocks: slot.blocks(),
            });
        }
        Ok(infos)
    }

    fn device_slot_from(
        mmap: &[u8],
        sb_offset: usize,
        index: usize,
    ) -> io::Result<&ErofsDeviceSlot> {
        let sb = Self::superblock_from(mmap, sb_offset)?;
        if sb.extra_devices() == 0 || index >= sb.extra_devices() as usize {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "blob device slot not found in bootstrap",
            ));
        }

        let slot_offset =
            sb.devt_slotoff() as usize * EROFS_DEVICESLOT_SIZE + index * EROFS_DEVICESLOT_SIZE;
        let slot_end = slot_offset + EROFS_DEVICESLOT_SIZE;
        if slot_end > mmap.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "device slot out of bounds",
            ));
        }

        Ok(cast_ref::<ErofsDeviceSlot>(&mmap[slot_offset..]))
    }

    fn primary_image_size(sb: &ErofsSuperblock) -> io::Result<usize> {
        let bytes = sb
            .blocks()
            .checked_mul(EROFS_BLOCK_SIZE as u64)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bootstrap size overflow"))?;
        usize::try_from(bytes).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "bootstrap size does not fit usize",
            )
        })
    }

    fn find_blob_in_dir(
        blob_dir: &Path,
        expected_blob_id: &[u8; EROFS_BLOB_ID_SIZE],
    ) -> io::Result<(Mmap, usize)> {
        if let Some(candidate) = Self::find_blob_by_exact_filename(blob_dir, expected_blob_id)? {
            return Ok(candidate);
        }

        for entry in fs::read_dir(blob_dir)? {
            let entry = entry?;
            let path = entry.path();
            if !path.is_file() {
                continue;
            }

            let mapped = match Self::map_file(&path) {
                Ok(mapped) => mapped,
                Err(_) => continue,
            };
            let blob_data_offset = match Self::data_offset_for_blob_candidate(&mapped) {
                Ok(offset) => offset,
                Err(_) => continue,
            };
            if blob_data_offset > mapped.len() {
                continue;
            }

            let digest = sha256_bytes(&mapped[blob_data_offset..]);
            if &digest == expected_blob_id {
                return Ok((mapped, 0));
            }
        }

        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "failed to locate blob matching bootstrap blob id",
        ))
    }

    fn find_blob_by_exact_filename(
        blob_dir: &Path,
        expected_blob_id: &[u8; EROFS_BLOB_ID_SIZE],
    ) -> io::Result<Option<(Mmap, usize)>> {
        let path = blob_dir.join(hex_string(expected_blob_id));
        if !path.is_file() {
            return Ok(None);
        }

        let mapped = Self::map_file(&path)?;
        if &sha256_bytes(&mapped) != expected_blob_id {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "blob file {} exists but its SHA256 does not match bootstrap device slot",
                    path.display()
                ),
            ));
        }
        let blob_data_offset = Self::data_offset_for_blob_candidate(&mapped)?;
        if blob_data_offset > mapped.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("blob file {} has invalid data offset", path.display()),
            ));
        }
        Ok(Some((mapped, 0)))
    }

    fn data_offset_for_blob_candidate(mmap: &[u8]) -> io::Result<usize> {
        let sb = Self::superblock_from(mmap, EROFS_SUPER_OFFSET as usize)?;
        if sb.magic() != EROFS_SUPER_MAGIC_V1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "candidate is not an EROFS blob",
            ));
        }
        Self::primary_image_size(sb)
    }

    /// Get a zero-copy reference to the on-disk superblock.
    pub fn sb(&self) -> &ErofsSuperblock {
        cast_ref::<ErofsSuperblock>(&self.mmap[self.sb_offset..])
    }

    pub fn device_infos(&self) -> io::Result<Vec<DeviceInfo>> {
        Self::device_infos_from(&self.mmap, self.sb_offset)
    }

    pub(crate) fn mmap_slice(&self, offset: usize, len: usize) -> io::Result<&[u8]> {
        let end = offset
            .checked_add(len)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "offset + len overflow"))?;
        if end > self.mmap.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!(
                    "mmap read out of bounds: offset={}, len={}, mmap_len={}",
                    offset,
                    len,
                    self.mmap.len()
                ),
            ));
        }
        Ok(&self.mmap[offset..end])
    }

    pub(crate) fn blob_mmap_slice(
        &self,
        device_id: u16,
        offset: usize,
        len: usize,
    ) -> io::Result<&[u8]> {
        let blob = self.blob_devices.get(&device_id).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("blob device {device_id} not available"),
            )
        })?;
        let start = blob.data_offset.checked_add(offset).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "blob data offset + offset overflow",
            )
        })?;
        let end = start.checked_add(len).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "blob offset + len overflow")
        })?;
        if end > blob.mmap.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!(
                    "blob mmap read out of bounds: device_id={}, offset={}, len={}, blob_len={}",
                    device_id,
                    start,
                    len,
                    blob.mmap.len()
                ),
            ));
        }
        Ok(&blob.mmap[start..end])
    }

    pub(crate) fn nid_to_offset(&self, nid: u64) -> usize {
        (self.sb().meta_blkaddr() as u64 * EROFS_BLOCK_SIZE as u64 + nid * EROFS_SLOTSIZE as u64)
            as usize
    }
}

mod data;
pub mod fuse;
mod meta;

pub use self::fuse::ErofsFs;

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{self, Write};
use std::path::Path;
use std::sync::Arc;

use memmap2::Mmap;
use tempfile::TempDir;

use crate::metadata::*;
use crate::storage::backend::{BlobBackend, LocalBackend};
use crate::storage::cache::{BlobCache, LocalBlobCache};

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
    cache: Box<dyn BlobCache>,
}

/// Parse a `trusted.lepton.prefetch.blobs` xattr value such as `"2,5,1"` into an
/// ordered list of blob device ids, skipping empty, zero, or non-numeric tokens.
fn parse_prefetch_blobs_value(value: &[u8]) -> Vec<u16> {
    let text = match std::str::from_utf8(value) {
        Ok(text) => text,
        Err(_) => return Vec::new(),
    };
    text.split(',')
        .filter_map(|token| {
            let token = token.trim();
            if token.is_empty() {
                None
            } else {
                token.parse::<u16>().ok().filter(|id| *id != 0)
            }
        })
        .collect()
}

/// EROFS image reader — lock-free, zero-copy.
///
/// Both the image and blob device are memory-mapped for zero-copy access.
/// On-disk structs are cast directly from the mapped memory.
pub struct ErofsReader {
    pub(crate) mmap: Mmap,
    blob_devices: HashMap<u16, BlobDevice>,
    image_offset: usize,
    pub(crate) sb_offset: usize,
    _temporary_cache_dir: Option<TempDir>,
}

impl ErofsReader {
    /// Open an EROFS blob directly, or a bootstrap with an external blob directory.
    pub fn open(
        blob_path: Option<&Path>,
        bootstrap_path: Option<&Path>,
        blob_dir: Option<&Path>,
        cache_dir: Option<&Path>,
    ) -> io::Result<Self> {
        match (blob_path, bootstrap_path, blob_dir, cache_dir) {
            (Some(blob), None, None, None) => Self::open_blob(blob),
            (None, Some(bootstrap), Some(blob_dir), cache_dir) => {
                Self::open_bootstrap(bootstrap, blob_dir, cache_dir)
            }
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "expected either --blob <path> or --bootstrap <path> --blob-dir <dir> [--cache-dir <dir>]",
            )),
        }
    }

    /// Open a lepton blob / bootstrap file for metadata-only inspection.
    pub fn open_layer(path: &Path) -> io::Result<Self> {
        let mmap = Self::map_file(path)?;
        let image_offset = Self::image_offset_from_footer(&mmap)?.unwrap_or(0);
        let sb_offset = image_offset
            .checked_add(EROFS_SUPER_OFFSET as usize)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "superblock offset overflow")
            })?;
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
            image_offset,
            sb_offset,
            _temporary_cache_dir: None,
        })
    }

    fn open_blob(blob_path: &Path) -> io::Result<Self> {
        let mmap = Self::map_file(blob_path)?;
        let image_offset = Self::image_offset_from_footer(&mmap)?.ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "lepton blob footer not found")
        })?;
        let sb_offset = image_offset
            .checked_add(EROFS_SUPER_OFFSET as usize)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "superblock offset overflow")
            })?;
        let sb = Self::superblock_from(&mmap, sb_offset)?;
        if sb.magic() != EROFS_SUPER_MAGIC_V1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("bad EROFS magic: 0x{:08X}", sb.magic()),
            ));
        }

        let device_infos = Self::device_infos_from(&mmap, sb_offset)?;
        let blob_dir = blob_path.parent().unwrap_or_else(|| Path::new("."));
        let (blob_devices, temporary_cache_dir) =
            Self::open_blob_devices(device_infos, blob_dir, None)?;

        Ok(Self {
            mmap,
            blob_devices,
            image_offset,
            sb_offset,
            _temporary_cache_dir: temporary_cache_dir,
        })
    }

    fn open_bootstrap(
        bootstrap_path: &Path,
        blob_dir: &Path,
        cache_dir: Option<&Path>,
    ) -> io::Result<Self> {
        let mmap = Self::map_file(bootstrap_path)?;
        let sb_offset = EROFS_SUPER_OFFSET as usize;
        let sb = Self::superblock_from(&mmap, sb_offset)?;
        if sb.magic() != EROFS_SUPER_MAGIC_V1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("bad EROFS magic: 0x{:08X}", sb.magic()),
            ));
        }

        let device_infos = Self::device_infos_from(&mmap, sb_offset)?;

        let (blob_devices, temporary_cache_dir) =
            Self::open_blob_devices(device_infos, blob_dir, cache_dir)?;

        Ok(Self {
            mmap,
            blob_devices,
            image_offset: 0,
            sb_offset,
            _temporary_cache_dir: temporary_cache_dir,
        })
    }

    fn map_file(path: &Path) -> io::Result<Mmap> {
        let file = fs::File::open(path)?;
        // SAFETY: file opened read-only, never modified while mapped.
        unsafe { Mmap::map(&file) }
    }

    fn image_offset_from_footer(mmap: &[u8]) -> io::Result<Option<usize>> {
        if mmap.len() < LEPTON_BLOB_FOOTER_SIZE {
            return Ok(None);
        }
        let footer_bytes = &mmap[mmap.len() - LEPTON_BLOB_FOOTER_SIZE..];
        if !BlobFooter::has_magic(footer_bytes) {
            return Ok(None);
        }
        let footer = BlobFooter::parse_from_tail(mmap).map_err(io::Error::other)?;
        usize::try_from(footer.bootstrap_offset())
            .map(Some)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bootstrap offset too large"))
    }

    fn open_blob_devices(
        device_infos: Vec<DeviceInfo>,
        blob_dir: &Path,
        cache_dir: Option<&Path>,
    ) -> io::Result<(HashMap<u16, BlobDevice>, Option<TempDir>)> {
        let backend: Arc<dyn BlobBackend> = Arc::new(LocalBackend::new(blob_dir.to_path_buf()));
        let temporary_cache_dir = if cache_dir.is_none() {
            Some(tempfile::Builder::new().prefix("lepton-cache-").tempdir()?)
        } else {
            None
        };
        let cache_dir = cache_dir
            .or_else(|| temporary_cache_dir.as_ref().map(|dir| dir.path()))
            .ok_or_else(|| io::Error::other("failed to create cache directory"))?;
        let blob_devices = device_infos
            .into_iter()
            .map(|info| {
                let cache: Box<dyn BlobCache> = Box::new(LocalBlobCache::open(
                    info.blob_id,
                    cache_dir,
                    backend.clone(),
                )?);
                Ok((info.device_id, BlobDevice { cache }))
            })
            .collect::<io::Result<HashMap<_, _>>>()?;
        Ok((blob_devices, temporary_cache_dir))
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

        let image_offset = sb_offset - EROFS_SUPER_OFFSET as usize;
        let slot_offset = image_offset
            + sb.devt_slotoff() as usize * EROFS_DEVICESLOT_SIZE
            + index * EROFS_DEVICESLOT_SIZE;
        let slot_end = slot_offset + EROFS_DEVICESLOT_SIZE;
        if slot_end > mmap.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "device slot out of bounds",
            ));
        }

        Ok(cast_ref::<ErofsDeviceSlot>(&mmap[slot_offset..]))
    }

    /// Get a zero-copy reference to the on-disk superblock.
    pub fn sb(&self) -> &ErofsSuperblock {
        cast_ref::<ErofsSuperblock>(&self.mmap[self.sb_offset..])
    }

    pub fn device_infos(&self) -> io::Result<Vec<DeviceInfo>> {
        Self::device_infos_from(&self.mmap, self.sb_offset)
    }

    /// Prefetch every group of the blob device identified by `device_id`.
    pub fn prefetch_blob(&self, device_id: u16) -> io::Result<()> {
        let device = self.blob_devices.get(&device_id).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("blob device {} not found", device_id),
            )
        })?;
        device.cache.prefetch_all()
    }

    /// Build the blob prefetch plan: blobs listed in the root prefetch xattr (in
    /// order, deduplicated, filtered to existing devices), followed by the
    /// remaining blob device ids in ascending order.
    pub fn prefetch_plan(&self) -> (Vec<u16>, Vec<u16>) {
        let mut ordered = Vec::new();
        let mut seen = HashSet::new();
        for device_id in self.read_prefetch_order() {
            if self.blob_devices.contains_key(&device_id) && seen.insert(device_id) {
                ordered.push(device_id);
            }
        }
        let mut rest: Vec<u16> = self
            .blob_devices
            .keys()
            .copied()
            .filter(|id| !seen.contains(id))
            .collect();
        rest.sort_unstable();
        (ordered, rest)
    }

    fn read_prefetch_order(&self) -> Vec<u16> {
        let root_nid = self.sb().root_nid();
        let inode = match self.inode(root_nid) {
            Ok(inode) => inode,
            Err(_) => return Vec::new(),
        };
        let xattrs = match self.read_xattrs(root_nid, &inode) {
            Ok(xattrs) => xattrs,
            Err(_) => return Vec::new(),
        };
        for (name, value) in xattrs {
            if name == LEPTON_PREFETCH_BLOBS_XATTR_NAME {
                return parse_prefetch_blobs_value(&value);
            }
        }
        Vec::new()
    }

    pub(crate) fn mmap_slice(&self, offset: usize, len: usize) -> io::Result<&[u8]> {
        let mapped_offset = self
            .image_offset
            .checked_add(offset)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "image offset overflow"))?;
        let end = mapped_offset
            .checked_add(len)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "offset + len overflow"))?;
        if end > self.mmap.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!(
                    "mmap read out of bounds: offset={}, len={}, mmap_len={}",
                    mapped_offset,
                    len,
                    self.mmap.len()
                ),
            ));
        }
        Ok(&self.mmap[mapped_offset..end])
    }

    pub(crate) fn read_blob_into(
        &self,
        device_id: u16,
        source_offset: u64,
        chunk_off: u64,
        dst: &mut [u8],
    ) -> io::Result<()> {
        let blob = self.blob_devices.get(&device_id).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("blob device {device_id} not available"),
            )
        })?;
        let absolute_offset = source_offset.checked_add(chunk_off).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "blob read offset overflow")
        })?;
        blob.cache.read_at(absolute_offset, dst)
    }

    pub(crate) fn write_blob_to(
        &self,
        device_id: u16,
        source_offset: u64,
        chunk_off: u64,
        len: usize,
        writer: &mut dyn Write,
    ) -> io::Result<()> {
        let blob = self.blob_devices.get(&device_id).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("blob device {device_id} not available"),
            )
        })?;
        let absolute_offset = source_offset.checked_add(chunk_off).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "blob write offset overflow")
        })?;
        let mut buf = vec![0u8; len];
        blob.cache.read_at(absolute_offset, &mut buf)?;
        writer.write_all(&buf)
    }

    pub(crate) fn nid_to_offset(&self, nid: u64) -> usize {
        (self.sb().meta_blkaddr() as u64 * EROFS_BLOCK_SIZE as u64 + nid * EROFS_SLOTSIZE as u64)
            as usize
    }
}

#[cfg(test)]
mod tests {
    use super::parse_prefetch_blobs_value;

    #[test]
    fn parse_prefetch_blobs_value_keeps_order_and_skips_invalid_tokens() {
        assert_eq!(parse_prefetch_blobs_value(b"2,5,1"), vec![2, 5, 1]);
        assert_eq!(
            parse_prefetch_blobs_value(b" 3 , ,4, 0 ,x,7"),
            vec![3, 4, 7]
        );
        assert_eq!(parse_prefetch_blobs_value(b""), Vec::<u16>::new());
        assert_eq!(parse_prefetch_blobs_value(b"0,0"), Vec::<u16>::new());
    }
}

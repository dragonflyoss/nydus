mod data;
pub mod fuse;
mod meta;

pub use self::fuse::ErofsFs;

use std::io;

use memmap2::Mmap;
use tokio::fs::File as TokioFile;

use crate::metadata::*;

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

/// EROFS image reader — lock-free, zero-copy.
///
/// Both the image and blob device are memory-mapped for zero-copy access.
/// On-disk structs are cast directly from the mapped memory.
pub struct ErofsReader {
    pub(crate) mmap: Mmap,
    pub(crate) blob_mmap: Option<Mmap>,
    pub(crate) sb_offset: usize,
}

impl ErofsReader {
    /// Open an EROFS image file and optional blob device.
    pub async fn open(image_path: &str, blob_path: Option<&str>) -> io::Result<Self> {
        let image_tokio = TokioFile::open(image_path).await?;
        let image_std = image_tokio.into_std().await;
        // SAFETY: file opened read-only, never modified.
        let mmap = unsafe { Mmap::map(&image_std) }?;

        let sb_offset = EROFS_SUPER_OFFSET as usize;
        // Validate superblock
        {
            let sb = Self::superblock_from(&mmap, sb_offset)?;
            if sb.magic() != EROFS_SUPER_MAGIC_V1 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("bad EROFS magic: 0x{:08X}", sb.magic()),
                ));
            }
        }

        let blob_mmap = match blob_path {
            Some(p) => {
                let blob_tokio = TokioFile::open(p).await?;
                let blob_std = blob_tokio.into_std().await;
                // SAFETY: file opened read-only, never modified.
                let bm = unsafe { Mmap::map(&blob_std) }?;
                Some(bm)
            }
            None => None,
        };

        Ok(Self {
            mmap,
            blob_mmap,
            sb_offset,
        })
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

    /// Get a zero-copy reference to the on-disk superblock.
    pub fn sb(&self) -> &ErofsSuperblock {
        cast_ref::<ErofsSuperblock>(&self.mmap[self.sb_offset..])
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

    pub(crate) fn blob_mmap_slice(&self, offset: usize, len: usize) -> io::Result<&[u8]> {
        let blob = self
            .blob_mmap
            .as_ref()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "blob device not available"))?;
        let end = offset.checked_add(len).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "blob offset + len overflow")
        })?;
        if end > blob.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!(
                    "blob mmap read out of bounds: offset={}, len={}, blob_len={}",
                    offset,
                    len,
                    blob.len()
                ),
            ));
        }
        Ok(&blob[offset..end])
    }

    pub(crate) fn nid_to_offset(&self, nid: u64) -> usize {
        (self.sb().meta_blkaddr() as u64 * EROFS_BLOCK_SIZE as u64 + nid * EROFS_SLOTSIZE as u64)
            as usize
    }
}

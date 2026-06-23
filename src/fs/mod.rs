mod data;
#[cfg(feature = "fuse")]
pub mod fuse;
mod meta;

#[cfg(feature = "fuse")]
pub use self::fuse::ErofsFs;

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use memmap2::Mmap;
use tempfile::TempDir;
use tracing::warn;

use crate::metadata::*;
use crate::metrics::trace::TraceRecorder;
use crate::storage::backend::{BlobBackend, LocalBackend};
use crate::storage::cache::{BlobCache, LocalBlobCache};

/// Parsed directory entry (name must be owned since it is sliced from mmap).
pub struct DirEntry {
    pub nid: u64,
    pub file_type: u8,
    pub name: String,
}

#[cfg(feature = "fuse")]
pub(crate) struct CachedDirEntry {
    pub nid: u64,
    pub file_type: u8,
    pub name: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobInfo {
    /// 1-based index of the blob in the bootstrap device table.
    pub blob_index: u16,
    pub blob_id: [u8; EROFS_BLOB_ID_SIZE],
    pub blocks: u64,
    pub mapped_blkaddr: u64,
}

/// A blob referenced by the bootstrap device table. The blob cache is opened
/// lazily on first read or prefetch so mounting does not pay a blob.meta
/// download per blob up front.
struct Blob {
    blob_id: [u8; EROFS_BLOB_ID_SIZE],
    blob_index: u16,
    cache_dir: PathBuf,
    backend: Arc<dyn BlobBackend>,
    trace_recorder: Option<Arc<TraceRecorder>>,
    cache: Mutex<Option<Arc<dyn BlobCache>>>,
}

impl Blob {
    fn cache(&self) -> io::Result<Arc<dyn BlobCache>> {
        let mut guard = self.cache.lock().unwrap();
        if let Some(cache) = guard.as_ref() {
            return Ok(cache.clone());
        }
        let cache: Arc<dyn BlobCache> = Arc::new(LocalBlobCache::open_with_trace(
            self.blob_id,
            self.blob_index as u32,
            &self.cache_dir,
            self.backend.clone(),
            self.trace_recorder.clone(),
        )?);
        *guard = Some(cache.clone());
        Ok(cache)
    }
}

/// Parse a `trusted.lepton.prefetch.blobs` xattr value such as `"2,5,1"` into an
/// ordered list of blob indexes, skipping empty, zero, or non-numeric tokens.
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
    blobs: HashMap<u16, Blob>,
    image_offset: usize,
    pub(crate) sb_offset: usize,
    _temporary_cache_dir: Option<TempDir>,
}

impl ErofsReader {
    /// Open an EROFS blob directly, or a bootstrap served by a blob backend.
    pub fn open(
        blob_path: Option<&Path>,
        bootstrap_path: Option<&Path>,
        backend: Option<Arc<dyn BlobBackend>>,
        cache_dir: Option<&Path>,
    ) -> io::Result<Self> {
        Self::open_with_trace(blob_path, bootstrap_path, backend, cache_dir, None)
    }

    pub(crate) fn open_with_trace(
        blob_path: Option<&Path>,
        bootstrap_path: Option<&Path>,
        backend: Option<Arc<dyn BlobBackend>>,
        cache_dir: Option<&Path>,
        trace_recorder: Option<Arc<TraceRecorder>>,
    ) -> io::Result<Self> {
        match (blob_path, bootstrap_path, backend, cache_dir) {
            (Some(blob), None, None, None) => Self::open_blob(blob),
            (None, Some(bootstrap), Some(backend), cache_dir) => {
                Self::open_bootstrap(bootstrap, backend, cache_dir, trace_recorder)
            }
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "expected either --blob <path> or --bootstrap <path> with a configured backend",
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
            blobs: HashMap::new(),
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

        let blob_infos = Self::blob_infos_from(&mmap, sb_offset)?;
        let blob_dir = blob_path.parent().unwrap_or_else(|| Path::new("."));
        let backend: Arc<dyn BlobBackend> = match blob_infos.as_slice() {
            [info] => Arc::new(LocalBackend::with_full_blob_source(
                blob_dir.to_path_buf(),
                info.blob_id,
                blob_path,
            )?),
            _ => Arc::new(LocalBackend::new(blob_dir.to_path_buf())),
        };
        let (blobs, temporary_cache_dir) = Self::open_blobs(blob_infos, backend, None, None)?;

        Ok(Self {
            mmap,
            blobs,
            image_offset,
            sb_offset,
            _temporary_cache_dir: temporary_cache_dir,
        })
    }

    fn open_bootstrap(
        bootstrap_path: &Path,
        backend: Arc<dyn BlobBackend>,
        cache_dir: Option<&Path>,
        trace_recorder: Option<Arc<TraceRecorder>>,
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

        let blob_infos = Self::blob_infos_from(&mmap, sb_offset)?;

        let (blobs, temporary_cache_dir) =
            Self::open_blobs(blob_infos, backend, cache_dir, trace_recorder)?;

        Ok(Self {
            mmap,
            blobs,
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

    fn open_blobs(
        blob_infos: Vec<BlobInfo>,
        backend: Arc<dyn BlobBackend>,
        cache_dir: Option<&Path>,
        trace_recorder: Option<Arc<TraceRecorder>>,
    ) -> io::Result<(HashMap<u16, Blob>, Option<TempDir>)> {
        let temporary_cache_dir = if cache_dir.is_none() {
            Some(tempfile::Builder::new().prefix("lepton-cache-").tempdir()?)
        } else {
            None
        };
        let cache_dir = cache_dir
            .or_else(|| temporary_cache_dir.as_ref().map(|dir| dir.path()))
            .ok_or_else(|| io::Error::other("failed to create cache directory"))?;
        let blobs = blob_infos
            .into_iter()
            .map(|info| {
                (
                    info.blob_index,
                    Blob {
                        blob_id: info.blob_id,
                        blob_index: info.blob_index,
                        cache_dir: cache_dir.to_path_buf(),
                        backend: backend.clone(),
                        trace_recorder: trace_recorder.clone(),
                        cache: Mutex::new(None),
                    },
                )
            })
            .collect();
        Ok((blobs, temporary_cache_dir))
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

    fn blob_infos_from(mmap: &[u8], sb_offset: usize) -> io::Result<Vec<BlobInfo>> {
        let sb = Self::superblock_from(mmap, sb_offset)?;
        let mut infos = Vec::with_capacity(sb.extra_devices() as usize);
        for index in 0..sb.extra_devices() as usize {
            let slot = Self::device_slot_from(mmap, sb_offset, index)?;
            infos.push(BlobInfo {
                blob_index: index as u16 + 1,
                blob_id: slot.blob_id(),
                blocks: slot.blocks(),
                mapped_blkaddr: slot.mapped_blkaddr(),
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

    pub fn blob_infos(&self) -> io::Result<Vec<BlobInfo>> {
        Self::blob_infos_from(&self.mmap, self.sb_offset)
    }

    /// The (lazily opened) blob cache for the blob identified by `blob_index`,
    /// shared with the read and prefetch paths.
    pub(crate) fn blob_cache(
        &self,
        blob_index: u16,
    ) -> io::Result<std::sync::Arc<dyn crate::storage::cache::BlobCache>> {
        let blob = self.blobs.get(&blob_index).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("blob {blob_index} not found"),
            )
        })?;
        blob.cache()
    }

    /// Prefetch every group of the blob identified by `blob_index`. An
    /// "ondemand" redirect blob is dispatched group by group into the source
    /// blobs' caches instead of building its own cache file.
    pub fn prefetch_blob(&self, blob_index: u16) -> io::Result<()> {
        let blob = self.blobs.get(&blob_index).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("blob {blob_index} not found"),
            )
        })?;
        let cache = blob.cache()?;
        if cache.is_redirect_blob() {
            self.prefetch_redirect_blob(blob_index, blob, cache.as_ref())
        } else {
            cache.prefetch_all()
        }
    }

    /// Phase-0 prefetch for a redirect blob: stream its groups in optimized
    /// order and fill the decoded bytes into the source blobs' caches so early
    /// on-demand reads hit cache. Per-group failures are logged and skipped so
    /// a bad group can never poison the source caches or abort the warmup.
    fn prefetch_redirect_blob(
        &self,
        blob_index: u16,
        blob: &Blob,
        cache: &dyn BlobCache,
    ) -> io::Result<()> {
        cache.redirect_stream(&mut |group, decoded| {
            if !group.is_redirect() {
                crate::metrics::inc_cache_redirect_skip_group();
                warn!("ondemand blob {blob_index} contains a non-redirect group; skipping");
                return Ok(());
            }
            let source_blob_index = group.source_blob_index();
            let source_index = group.source_group_index() as usize;
            let source = match self.blobs.get(&source_blob_index) {
                Some(source) => source,
                None => {
                    crate::metrics::inc_cache_redirect_skip_group();
                    warn!("ondemand blob {blob_index} redirects to unknown blob {source_blob_index}; skipping group");
                    return Ok(());
                }
            };
            let source_cache = match source.cache() {
                Ok(cache) => cache,
                Err(err) => {
                    crate::metrics::inc_cache_redirect_skip_group();
                    warn!("failed to open source blob {source_blob_index} for redirect: {err}");
                    return Ok(());
                }
            };
            if let Err(err) = source_cache.fill_group_from_redirect(source_index, decoded) {
                if crate::storage::cache::is_group_crc_mismatch(&err) {
                    crate::metrics::record_backend_crc_error(blob.backend.backend_target());
                }
                crate::metrics::inc_cache_redirect_skip_group();
                warn!(
                    "failed to fill blob {source_blob_index} group {source_index} from ondemand blob {blob_index}: {err}"
                );
            }
            Ok(())
        })
    }

    /// Build the blob prefetch plan: blobs listed in the root prefetch xattr (in
    /// order, deduplicated, filtered to existing blobs), followed by the
    /// remaining blob indexes in ascending order.
    pub fn prefetch_plan(&self) -> (Vec<u16>, Vec<u16>) {
        let mut ordered = Vec::new();
        let mut seen = HashSet::new();
        for blob_index in self.read_prefetch_order() {
            if self.blobs.contains_key(&blob_index) && seen.insert(blob_index) {
                ordered.push(blob_index);
            }
        }
        let mut rest: Vec<u16> = self
            .blobs
            .keys()
            .copied()
            .filter(|id| !seen.contains(id))
            .collect();
        rest.sort_unstable();
        (ordered, rest)
    }

    /// Ordered blob indexes from the root `trusted.lepton.prefetch.blobs` xattr,
    /// unfiltered. Empty when the xattr is missing or unreadable.
    pub fn read_prefetch_order(&self) -> Vec<u16> {
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
            if is_lepton_prefetch_blobs_xattr(&name) {
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
        blob_index: u16,
        source_offset: u64,
        chunk_off: u64,
        dst: &mut [u8],
    ) -> io::Result<()> {
        let blob = self.blobs.get(&blob_index).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("blob {blob_index} not available"),
            )
        })?;
        let absolute_offset = source_offset.checked_add(chunk_off).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "blob read offset overflow")
        })?;
        blob.cache()?.read_at(absolute_offset, dst)
    }

    pub(crate) fn write_blob_to(
        &self,
        blob_index: u16,
        source_offset: u64,
        chunk_off: u64,
        len: usize,
        writer: &mut dyn Write,
    ) -> io::Result<()> {
        let blob = self.blobs.get(&blob_index).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("blob {blob_index} not available"),
            )
        })?;
        let absolute_offset = source_offset.checked_add(chunk_off).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "blob write offset overflow")
        })?;
        let mut buf = vec![0u8; len];
        blob.cache()?.read_at(absolute_offset, &mut buf)?;
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

pub(crate) mod data;
mod metadata;

use std::collections::HashSet;
use std::fs;
use std::io::{self, Write};
use std::path::Path;
use std::sync::{Arc, OnceLock};

use memmap2::Mmap;

use nydus_backend::{BlobBackend, Local};
use nydus_format::blob::BlobFooter;
use nydus_format::erofs::{
    cast_ref, is_nydus_prefetch_blobs_xattr, ErofsDeviceSlot, ErofsSuperblock, EROFS_BLOB_ID_SIZE,
    EROFS_BLOCK_SIZE, EROFS_DEVICESLOT_SIZE, EROFS_SB_BASE_SIZE, EROFS_SLOTSIZE,
    EROFS_SUPER_OFFSET,
};
use nydus_storage::access_trace::TraceRecorder;
use nydus_storage::cache::BlobCaches;
use nydus_storage::prefetch::PrefetchPlan;

/// Parsed directory entry (name must be owned since it is sliced from mmap).
pub struct RawDirEntry {
    pub nid: u64,
    pub file_type: u8,
    pub name: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawBlobInfo {
    /// 1-based index of the blob in the bootstrap device table.
    pub blob_index: u16,
    pub blob_id: [u8; EROFS_BLOB_ID_SIZE],
    pub blocks: u64,
    pub mapped_blkaddr: u64,
}

/// Parse a `trusted.nydus.prefetch.blobs` xattr value such as `"2,5,1"` into an
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
    blobs: Arc<BlobCaches>,
    /// Memoised device table. Pre-populated by the open paths that already
    /// parse it; metadata-only readers fill it on first use.
    blob_infos: OnceLock<Vec<RawBlobInfo>>,
    image_offset: usize,
    pub(crate) sb_offset: usize,
}

impl ErofsReader {
    /// Open a nydus blob / bootstrap file for metadata-only inspection.
    pub fn open_metadata_only(path: &Path) -> io::Result<Self> {
        let mmap = Self::mmap_file(path, false)?;
        let (mmap, image_offset) = match Self::unpack_embedded_image(mmap)? {
            (mmap, Some(image_offset)) => (mmap, image_offset),
            (mmap, None) => (mmap, 0),
        };
        let sb_offset = image_offset
            .checked_add(EROFS_SUPER_OFFSET as usize)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "superblock offset overflow")
            })?;
        let sb = Self::superblock_from(&mmap, sb_offset)?;
        Self::validate_superblock(sb)?;

        Ok(Self {
            mmap,
            blobs: Arc::new(BlobCaches::empty()),
            blob_infos: OnceLock::new(),
            image_offset,
            sb_offset,
        })
    }

    /// Open a self-contained full blob (`payload + bootstrap + blob meta +
    /// footer`): everything is served from the file itself, no remote
    /// backend is involved. `cache_dir`, when given, caches the decoded
    /// block groups so repeat reads skip re-decoding from the blob.
    pub fn open_blob(blob_path: &Path, cache_dir: Option<&Path>) -> io::Result<Self> {
        let mmap = Self::mmap_file(blob_path, false)?;
        let (mmap, image_offset) = match Self::unpack_embedded_image(mmap)? {
            (mmap, Some(image_offset)) => (mmap, image_offset),
            (_, None) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "nydus blob footer not found",
                ))
            }
        };
        let sb_offset = image_offset
            .checked_add(EROFS_SUPER_OFFSET as usize)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "superblock offset overflow")
            })?;
        let sb = Self::superblock_from(&mmap, sb_offset)?;
        Self::validate_superblock(sb)?;

        let blob_infos = Self::blob_infos_from(&mmap, sb_offset)?;
        let blob_dir = blob_path.parent().unwrap_or_else(|| Path::new("."));
        let backend: Arc<dyn BlobBackend> = match blob_infos.as_slice() {
            [info] => Arc::new(Local::with_full_blob_source(
                blob_dir.to_path_buf(),
                info.blob_id,
                blob_path,
            )?),
            _ => Arc::new(Local::new(blob_dir.to_path_buf())),
        };
        let blobs = BlobCaches::new(
            blob_infos
                .iter()
                .map(|info| (info.blob_index, info.blob_id)),
            nydus_backend::metered(backend),
            cache_dir,
            None,
        )?;

        Ok(Self {
            mmap,
            blobs: Arc::new(blobs),
            blob_infos: OnceLock::from(blob_infos),
            image_offset,
            sb_offset,
        })
    }

    /// Open a standalone bootstrap whose blob data is served by `backend`
    /// through per-blob caches under `cache_dir` (a temporary directory when
    /// `None`). `trace_recorder`, when given, records on-demand block group
    /// accesses for `nydus optimize`.
    pub fn open_bootstrap(
        bootstrap_path: &Path,
        backend: Arc<dyn BlobBackend>,
        cache_dir: Option<&Path>,
        trace_recorder: Option<Arc<TraceRecorder>>,
    ) -> io::Result<Self> {
        let mmap = Self::mmap_file(bootstrap_path, true)?;
        let sb_offset = EROFS_SUPER_OFFSET as usize;
        let sb = Self::superblock_from(&mmap, sb_offset)?;
        Self::validate_superblock(sb)?;

        let blob_infos = Self::blob_infos_from(&mmap, sb_offset)?;

        let blobs = BlobCaches::new(
            blob_infos
                .iter()
                .map(|info| (info.blob_index, info.blob_id)),
            backend,
            cache_dir,
            trace_recorder,
        )?;

        Ok(Self {
            mmap,
            blobs: Arc::new(blobs),
            blob_infos: OnceLock::from(blob_infos),
            image_offset: 0,
            sb_offset,
        })
    }

    fn mmap_file(path: &Path, populate: bool) -> io::Result<Mmap> {
        let file = fs::File::open(path)?;
        // Populate is only for standalone bootstraps: a few MiB that every
        // metadata operation resolves against, so paying the read up front
        // (milliseconds) removes a page fault per cold folio. Full blobs must
        // NOT be populated — they carry the entire data region, and faulting
        // in a multi-GiB blob just to read its metadata tail multiplies RSS
        // by the blob size (as `nydus merge` over large layers showed).
        let mut options = memmap2::MmapOptions::new();
        if populate {
            options.populate();
        }
        unsafe { options.map(&file) }
    }

    /// Resolve the EROFS image inside `mmap`: `(mmap, None)` for a bare
    /// bootstrap without a footer, `(mmap, Some(offset))` for a full blob
    /// with a raw embedded bootstrap, and a fresh anonymous mapping holding
    /// the decompressed bytes (offset 0) when the footer declares the
    /// bootstrap region zstd-compressed.
    fn unpack_embedded_image(mmap: Mmap) -> io::Result<(Mmap, Option<usize>)> {
        let Some(footer) = BlobFooter::from_blob_bytes(&mmap).map_err(io::Error::other)? else {
            return Ok((mmap, None));
        };

        let bootstrap_offset = usize::try_from(footer.bootstrap_offset()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "bootstrap offset too large")
        })?;

        let Some(compressed_size) = footer.bootstrap_compressed_size() else {
            return Ok((mmap, Some(bootstrap_offset)));
        };
        let compressed_size = usize::try_from(compressed_size)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bootstrap frame too large"))?;
        let end = bootstrap_offset
            .checked_add(compressed_size)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "bootstrap region overflow")
            })?;
        if end > mmap.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "compressed bootstrap region beyond blob end",
            ));
        }

        let decoded = zstd::stream::decode_all(&mmap[bootstrap_offset..end])
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        // An anonymous mapping keeps the field type (and every downstream
        // zero-copy cast) unchanged; the file mapping is dropped here.
        let mut anon = memmap2::MmapOptions::new().len(decoded.len()).map_anon()?;
        anon.copy_from_slice(&decoded);
        Ok((anon.make_read_only()?, Some(0)))
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

    /// Validate the superblock; see [`nydus_format::erofs::validate_superblock`]
    /// for the supported-incompat contract (single source of truth).
    fn validate_superblock(sb: &ErofsSuperblock) -> io::Result<()> {
        nydus_format::erofs::validate_superblock(sb)
    }

    fn blob_infos_from(mmap: &[u8], sb_offset: usize) -> io::Result<Vec<RawBlobInfo>> {
        let sb = Self::superblock_from(mmap, sb_offset)?;
        let mut infos = Vec::with_capacity(sb.extra_devices() as usize);
        for index in 0..sb.extra_devices() as usize {
            let slot = Self::device_slot_from(mmap, sb_offset, index)?;
            infos.push(RawBlobInfo {
                blob_index: index as u16 + 1,
                blob_id: slot.blob_id().map_err(io::Error::other)?,
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
    pub fn superblock(&self) -> &ErofsSuperblock {
        cast_ref::<ErofsSuperblock>(&self.mmap[self.sb_offset..])
    }

    pub fn blob_infos(&self) -> io::Result<&[RawBlobInfo]> {
        if let Some(infos) = self.blob_infos.get() {
            return Ok(infos);
        }
        let infos = Self::blob_infos_from(&self.mmap, self.sb_offset)?;
        Ok(self.blob_infos.get_or_init(|| infos))
    }

    /// The storage-side cache set shared with the read and prefetch paths,
    /// e.g. to construct a [`nydus_storage::prefetch::BlobPrefetcher`].
    pub fn blob_caches(&self) -> Arc<BlobCaches> {
        self.blobs.clone()
    }

    /// The (lazily opened) blob cache for the blob identified by `blob_index`,
    /// shared with the read and prefetch paths.
    pub(crate) fn blob_cache(
        &self,
        blob_index: u16,
    ) -> io::Result<std::sync::Arc<dyn nydus_storage::cache::BlobCache>> {
        self.blobs.cache(blob_index)
    }

    /// Return whether the blob identified by `blob_index` is an "ondemand"
    /// redirect blob (produced by `nydus optimize`). Opens the blob cache,
    /// which reads the local blob meta but performs no data prefetch.
    pub fn is_redirect(&self, blob_index: u16) -> io::Result<bool> {
        self.blobs.is_redirect(blob_index)
    }

    /// Prefetch every block group of the blob identified by `blob_index`. An
    /// "ondemand" redirect blob is dispatched block group by block group into the source
    /// blobs' caches instead of building its own cache file, fetching its
    /// segments concurrently with up to `threads` workers. A non-zero
    /// `timeout` bounds the whole blob's prefetch.
    pub fn prefetch_blob(
        &self,
        blob_index: u16,
        threads: usize,
        timeout: std::time::Duration,
    ) -> io::Result<()> {
        self.blobs.prefetch_blob(blob_index, threads, timeout)
    }

    /// Build the blob prefetch plan: blobs listed in the root prefetch xattr (in
    /// order, deduplicated, filtered to existing blobs), followed by the
    /// remaining blob indexes in ascending order.
    pub fn prefetch_plan(&self) -> PrefetchPlan {
        let mut ordered = Vec::new();
        let mut seen = HashSet::new();
        for blob_index in self.read_prefetch_order() {
            if self.blobs.contains(blob_index) && seen.insert(blob_index) {
                ordered.push(blob_index);
            }
        }
        let mut rest: Vec<u16> = self
            .blobs
            .indexes()
            .filter(|id| !seen.contains(id))
            .collect();
        rest.sort_unstable();
        PrefetchPlan {
            priority: ordered,
            rest,
        }
    }

    /// Ordered blob indexes from the root `trusted.nydus.prefetch.blobs` xattr,
    /// unfiltered. Empty when the xattr is missing or unreadable.
    pub fn read_prefetch_order(&self) -> Vec<u16> {
        let root_nid = self.superblock().root_nid();
        let inode = match self.inode(root_nid) {
            Ok(inode) => inode,
            Err(_) => return Vec::new(),
        };

        let xattrs = match self.read_xattrs(root_nid, &inode) {
            Ok(xattrs) => xattrs,
            Err(_) => return Vec::new(),
        };

        for (name, value) in xattrs {
            if is_nydus_prefetch_blobs_xattr(&name) {
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
        blob_offset: u64,
        chunk_off: u64,
        dst: &mut [u8],
    ) -> io::Result<()> {
        let cache = self.blobs.try_cache(blob_index).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("blob {blob_index} not available"),
            )
        })??;
        let absolute_offset = blob_offset.checked_add(chunk_off).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "blob read offset overflow")
        })?;
        cache.read_at(absolute_offset, dst)
    }

    pub(crate) fn write_blob_to(
        &self,
        blob_index: u16,
        blob_offset: u64,
        chunk_off: u64,
        len: usize,
        writer: &mut dyn Write,
    ) -> io::Result<()> {
        let cache = self.blobs.try_cache(blob_index).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("blob {blob_index} not available"),
            )
        })??;
        let absolute_offset = blob_offset.checked_add(chunk_off).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "blob write offset overflow")
        })?;
        cache.write_data_to(absolute_offset, len, writer)
    }

    pub(crate) fn nid_to_offset(&self, nid: u64) -> usize {
        (self.superblock().meta_blkaddr() as u64 * EROFS_BLOCK_SIZE as u64
            + nid * EROFS_SLOTSIZE as u64) as usize
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

//! Host-side accessor for nydus images backing guest virtio-pmem devices.
//!
//! A guest kernel mounts the nydus bootstrap as an EROFS image whose external
//! devices are virtio-pmem devices backed by the host-side cache data files
//! (`{cache_dir}/{hex}.blob.data`). Each cache file mirrors the blob's dense
//! decoded block address space, so a guest read of block `N` lands at byte
//! `N * 4096` of the backing file. [`NydusAccessor`] exposes the device
//! table needed to wire up those pmem devices and a [`blob.fetch`] entry point
//! that guarantees a block-aligned range is decoded and resident before the
//! guest touches it.
//!
//! [`blob.fetch`]: BlobAccessor::fetch

use std::collections::HashMap;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::os::fd::{AsRawFd, RawFd};
use std::path::{Component, Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;

use anyhow::{bail, Context, Result};

use crate::config::Config;
use crate::fs::{BlobInfo as ReaderBlobInfo, ErofsReader};
use crate::metadata::{
    ErofsInode, EROFS_BLOB_ID_SIZE, EROFS_BLOCK_SIZE, EROFS_FT_BLKDEV, EROFS_FT_CHRDEV,
    EROFS_FT_DIR, EROFS_FT_FIFO, EROFS_FT_REG_FILE, EROFS_FT_SOCK, EROFS_FT_SYMLINK,
    EROFS_INODE_CHUNK_BASED, EROFS_INODE_FLAT_INLINE, EROFS_INODE_FLAT_PLAIN, EROFS_NULL_ADDR,
};
use crate::metrics::trace::{TraceDocument, TraceRecorder};
use crate::storage::backend::build_backend;
use crate::storage::prefetch::BlobPrefetcher;
use crate::utils::{hex_string, parse_sha256_hex};

/// Blob digest used by public accessor APIs.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct BlobID([u8; EROFS_BLOB_ID_SIZE]);

impl BlobID {
    pub fn new(bytes: [u8; EROFS_BLOB_ID_SIZE]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; EROFS_BLOB_ID_SIZE] {
        &self.0
    }

    pub fn into_bytes(self) -> [u8; EROFS_BLOB_ID_SIZE] {
        self.0
    }

    pub fn to_hex(self) -> String {
        hex_string(&self.0)
    }
}

impl From<[u8; EROFS_BLOB_ID_SIZE]> for BlobID {
    fn from(value: [u8; EROFS_BLOB_ID_SIZE]) -> Self {
        Self::new(value)
    }
}

impl From<BlobID> for [u8; EROFS_BLOB_ID_SIZE] {
    fn from(value: BlobID) -> Self {
        value.into_bytes()
    }
}

impl FromStr for BlobID {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Ok(Self(parse_sha256_hex(value)?))
    }
}

impl fmt::Display for BlobID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex_string(&self.0))
    }
}

/// One blob entry from the bootstrap device table.
#[derive(Clone, Debug)]
pub struct BlobInfo {
    /// 1-based blob index, matching the EROFS device table order.
    pub index: u16,
    /// Blob digest recorded in the device slot.
    pub id: BlobID,
    /// Start block of this blob in the flattened single-device layout.
    pub mapped_blkaddr: u64,
    /// Start byte offset of this blob in the flattened single-device layout.
    pub mapped_offset: u64,
    /// Dense uncompressed size in 4 KiB blocks (the pmem device size).
    pub blocks: u64,
    /// Size in bytes of the cache data file (`blocks * 4096`).
    pub cache_size: u64,
    /// Host path of the sparse cache data file backing the pmem device.
    pub cache_path: PathBuf,
    /// True when this is an "ondemand" redirect blob produced by
    /// `nydus optimize`. Its data file is never read by the guest (no chunk
    /// index points at it); it only feeds the phase-0 prefetch that warms the
    /// source blobs' caches.
    pub is_redirect: bool,
}

/// Resolved mmap-ready byte range.
///
/// `fd` is always a real file descriptor. Zero-filled ranges use the
/// accessor-owned `/dev/zero` fd with `offset == 0`; callers can compare
/// against [`NydusAccessor::zero_fd`] to recognize those ranges for optimized
/// copy-mode handling.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FdRange {
    /// Raw fd backing this range. The fd is owned by the accessor/cache and
    /// must not be closed by the caller.
    pub fd: RawFd,
    /// Byte offset within `fd`. For zero-filled ranges this is always `0`.
    pub offset: u64,
    /// Length in bytes.
    pub len: u64,
    /// Offset in the source view: flattened-device offset for
    /// [`NydusAccessor`] ranges, file-relative offset for [`FsEntry`] ranges.
    pub source_offset: u64,
}

impl FdRange {
    fn new(fd: RawFd, offset: u64, len: u64, source_offset: u64) -> Self {
        Self {
            fd,
            offset,
            len,
            source_offset,
        }
    }
}

/// File type exposed by the static accessor API, independent of FUSE types.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileType {
    RegularFile,
    Directory,
    Symlink,
    BlockDevice,
    CharDevice,
    Fifo,
    Socket,
}

impl FileType {
    fn from_erofs_file_type(file_type: u8) -> Result<Self> {
        match file_type {
            EROFS_FT_REG_FILE => Ok(Self::RegularFile),
            EROFS_FT_DIR => Ok(Self::Directory),
            EROFS_FT_SYMLINK => Ok(Self::Symlink),
            EROFS_FT_BLKDEV => Ok(Self::BlockDevice),
            EROFS_FT_CHRDEV => Ok(Self::CharDevice),
            EROFS_FT_FIFO => Ok(Self::Fifo),
            EROFS_FT_SOCK => Ok(Self::Socket),
            other => bail!("unsupported EROFS file type: {other}"),
        }
    }

    fn from_mode(mode: u16) -> Result<Self> {
        match mode & libc::S_IFMT as u16 {
            x if x == libc::S_IFREG as u16 => Ok(Self::RegularFile),
            x if x == libc::S_IFDIR as u16 => Ok(Self::Directory),
            x if x == libc::S_IFLNK as u16 => Ok(Self::Symlink),
            x if x == libc::S_IFBLK as u16 => Ok(Self::BlockDevice),
            x if x == libc::S_IFCHR as u16 => Ok(Self::CharDevice),
            x if x == libc::S_IFIFO as u16 => Ok(Self::Fifo),
            x if x == libc::S_IFSOCK as u16 => Ok(Self::Socket),
            other => bail!("unsupported inode mode file type: {other:#o}"),
        }
    }
}

/// Owned metadata for a static filesystem entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Metadata {
    pub ino: u64,
    pub file_type: FileType,
    pub mode: u16,
    pub size: u64,
    pub uid: u32,
    pub gid: u32,
    pub nlink: u32,
    pub mtime: u64,
    pub mtime_nsec: u32,
    pub rdev: u32,
}

/// Owned directory entry for the static filesystem API.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirEntry {
    pub name: String,
    pub ino: u64,
    pub file_type: FileType,
}

/// Resolved static filesystem entry. Reuse this handle for repeated operations
/// on the same path to avoid resolving the path for every `read_at` call.
#[derive(Clone)]
pub struct FsEntry {
    reader: Arc<ErofsReader>,
    zero_file: Arc<File>,
    ino: u64,
}

/// Read-side handle over a nydus image, split into blob data access and
/// static filesystem metadata/data access.
pub struct NydusAccessor {
    /// Size in bytes of the standalone bootstrap image passed to [`new`].
    ///
    /// [`new`]: Self::new
    pub bootstrap_size: u64,
    /// Blob table and decoded-cache preparation/fetch APIs.
    pub blob: BlobAccessor,
    /// Static path-based filesystem APIs.
    pub fs: FsAccessor,
    bootstrap: Arc<File>,
    zero_file: Arc<File>,
    flat_size: u64,
    trace_recorder: Arc<TraceRecorder>,
}

/// Blob table and decoded-cache preparation/fetch APIs.
pub struct BlobAccessor {
    reader: Arc<ErofsReader>,
    blob_infos: Vec<ReaderBlobInfo>,
    index_by_blob_id: HashMap<BlobID, u16>,
}

/// Static path-based filesystem APIs.
pub struct FsAccessor {
    reader: Arc<ErofsReader>,
    zero_file: Arc<File>,
}

impl NydusAccessor {
    /// Parse the bootstrap and config and build the blob table,
    /// deferring all per-blob work: no blob meta is downloaded and no cache
    /// file is created until [`blobs`], [`fetch`], or [`prefetch`] first
    /// touches a blob.
    ///
    /// `config` uses the same structure as `nydus fuse --config` and must
    /// provide both the backend serving the blobs and a persistent local cache
    /// directory.
    ///
    /// When `config.prefetch.enable` is set, a background prefetch worker is
    /// spawned before returning: for an optimized image it streams the
    /// "ondemand" redirect blob first (priority) to warm the source blobs'
    /// caches in recorded access order, then prefetches the remaining blobs.
    /// The worker borrows the shared reader, so callers that want network
    /// access (e.g. the virtio-pmem backend) must construct the accessor while
    /// the desired network namespace is active so the spawned thread inherits
    /// it.
    ///
    /// [`blobs`]: Self::blobs
    /// [`fetch`]: Self::fetch
    pub fn new(bootstrap: &Path, config: Config) -> Result<Self> {
        let bootstrap_file = Arc::new(
            OpenOptions::new()
                .read(true)
                .open(bootstrap)
                .with_context(|| format!("failed to open bootstrap: {}", bootstrap.display()))?,
        );
        let zero_file = Arc::new(
            OpenOptions::new()
                .read(true)
                .open("/dev/zero")
                .context("failed to open /dev/zero")?,
        );
        let bootstrap_size = bootstrap_file
            .metadata()
            .with_context(|| format!("failed to stat bootstrap: {}", bootstrap.display()))?
            .len();
        let prefetch_enable = config.prefetch.enable;
        let prefetch_threads = config.prefetch.threads;
        let prefetch_full = config.prefetch.full;
        let backend = build_backend(&config.backend).context("failed to build blob backend")?;
        let cache_dir = config
            .cache_dir()
            .context("failed to resolve cache directory from config")?;
        std::fs::create_dir_all(&cache_dir).with_context(|| {
            format!("failed to create cache directory: {}", cache_dir.display())
        })?;

        let trace_recorder = Arc::new(TraceRecorder::default());
        let reader = ErofsReader::open_with_trace(
            None,
            Some(bootstrap),
            Some(backend),
            Some(&cache_dir),
            Some(trace_recorder.clone()),
        )
        .context("failed to open nydus bootstrap")?;
        let blob_infos = reader.blob_infos().context("failed to read blob table")?;
        if blob_infos.is_empty() {
            bail!("bootstrap contains no blobs");
        }
        let flat_size = blob_infos.iter().try_fold(bootstrap_size, |size, info| {
            let offset = info
                .mapped_blkaddr
                .checked_mul(EROFS_BLOCK_SIZE as u64)
                .context("mapped blob offset overflow")?;
            let len = info
                .blocks
                .checked_mul(EROFS_BLOCK_SIZE as u64)
                .context("blob size overflow")?;
            Ok::<u64, anyhow::Error>(
                size.max(
                    offset
                        .checked_add(len)
                        .context("flat blob range overflow")?,
                ),
            )
        })?;
        let index_by_blob_id = blob_infos
            .iter()
            .map(|info| (BlobID::from(info.blob_id), info.blob_index))
            .collect();
        let reader = Arc::new(reader);

        // Kick off background prefetch as soon as the accessor is built when the
        // config opts in. The worker holds its own `Arc` clone of the reader,
        // so it keeps running (and keeps the reader alive) independently of the
        // returned accessor. The handle is detached: prefetch is best-effort
        // warmup and must never block accessor construction or teardown.
        if prefetch_enable {
            match BlobPrefetcher::new(reader.clone(), prefetch_threads, prefetch_full).spawn() {
                Ok(_handle) => {
                    tracing::info!(
                        "nydus accessor: background prefetch started (full={prefetch_full})"
                    );
                }
                Err(err) => {
                    tracing::warn!("nydus accessor: failed to start prefetch worker: {err}");
                }
            }
        }

        Ok(Self {
            bootstrap_size,
            blob: BlobAccessor {
                reader: reader.clone(),
                blob_infos,
                index_by_blob_id,
            },
            fs: FsAccessor {
                reader,
                zero_file: zero_file.clone(),
            },
            bootstrap: bootstrap_file,
            zero_file,
            flat_size,
            trace_recorder,
        })
    }

    /// Return the bootstrap file backing this accessor.
    pub fn bootstrap(&self) -> &File {
        &self.bootstrap
    }

    /// Return the size of the flattened device view.
    pub fn flat_size(&self) -> u64 {
        self.flat_size
    }

    /// Return the accessor-owned `/dev/zero` fd used for zero-filled ranges.
    pub fn zero_fd(&self) -> RawFd {
        self.zero_file.as_raw_fd()
    }

    /// Fetch `[offset, offset + len)` in the flattened device view and return
    /// mmap-ready ranges. The bootstrap is exposed at the beginning of the
    /// view, and gaps between blob files are returned as `/dev/zero` ranges.
    pub fn fetch_flat_ranges(&self, offset: u64, len: u64) -> Result<Vec<FdRange>> {
        self.resolve_flat_ranges(offset, len, ResolveMode::Fetch)
    }

    /// Probe `[offset, offset + len)` in the flattened device view without
    /// downloading missing blob data. Bootstrap and gaps are returned when
    /// ready; cold blob cache ranges are omitted, so the result may be
    /// discontinuous.
    pub fn probe_flat_ranges(&self, offset: u64, len: u64) -> Result<Vec<FdRange>> {
        self.resolve_flat_ranges(offset, len, ResolveMode::Probe)
    }

    /// Return a stable snapshot of this accessor's on-demand group trace.
    pub fn trace_snapshot(&self) -> TraceDocument {
        self.trace_recorder.snapshot()
    }

    /// Serialize this accessor's on-demand group trace as optimize-compatible JSON.
    pub fn trace_json(&self) -> String {
        self.trace_recorder.encode_json()
    }

    /// Clear this accessor's on-demand group trace.
    pub fn clear_trace(&self) {
        self.trace_recorder.clear();
    }

    /// Return a snapshot of the process-wide nydus metrics (counters and
    /// gauges). The metrics are global, so this reflects all blob activity in
    /// the process, not just this accessor; callers typically inspect
    /// `backend_ondemand_read_count` to tell whether any group was fetched
    /// over the network rather than served from a warmed cache.
    pub fn metrics_snapshot(&self) -> crate::metrics::MetricsSnapshot {
        crate::metrics::snapshot()
    }

    fn resolve_flat_ranges(
        &self,
        offset: u64,
        len: u64,
        mode: ResolveMode,
    ) -> Result<Vec<FdRange>> {
        let end = match checked_range_end(offset, len)? {
            Some(end) => end.min(self.flat_size),
            None => return Ok(Vec::new()),
        };
        if offset >= end {
            return Ok(Vec::new());
        }

        let mut ranges = Vec::new();
        let mut pos = offset;
        let bootstrap_end = end.min(self.bootstrap_size);
        if pos < bootstrap_end {
            push_fd_range(
                &mut ranges,
                FdRange::new(self.bootstrap.as_raw_fd(), pos, bootstrap_end - pos, pos),
                self.zero_file.as_raw_fd(),
            );
            pos = bootstrap_end;
        }
        if pos >= end {
            return Ok(ranges);
        }

        let mut blobs = self
            .blob
            .entries()
            .context("failed to describe blob device layout")?;
        blobs.retain(|blob| !blob.is_redirect);
        blobs.sort_by_key(|blob| blob.mapped_offset);

        while pos < end {
            let blob_index = blobs.iter().position(|blob| {
                mapped_range_offset(blob.mapped_offset, blob.cache_size, pos).is_some()
            });

            if let Some(blob_index) = blob_index {
                let blob = &blobs[blob_index];
                let blob_end = blob
                    .mapped_offset
                    .checked_add(blob.cache_size)
                    .context("blob device range overflow")?;
                let seg_end = end.min(blob_end);
                let blob_offset = pos - blob.mapped_offset;
                push_blob_fd_ranges(
                    &self.blob.reader,
                    self.zero_file.as_raw_fd(),
                    &mut ranges,
                    BlobRangeSpec {
                        index: blob.index,
                        offset: blob_offset,
                        len: seg_end - pos,
                        source_offset: pos,
                    },
                    mode,
                )?;
                pos = seg_end;
            } else {
                let next_blob = blobs
                    .iter()
                    .filter(|blob| blob.mapped_offset > pos)
                    .map(|blob| blob.mapped_offset)
                    .min()
                    .unwrap_or(end);
                let hole_end = end.min(next_blob);
                if hole_end <= pos {
                    break;
                }
                push_fd_range(
                    &mut ranges,
                    FdRange::new(self.zero_file.as_raw_fd(), 0, hole_end - pos, pos),
                    self.zero_file.as_raw_fd(),
                );
                pos = hole_end;
            }
        }

        Ok(ranges)
    }
}

impl BlobAccessor {
    /// Describe every blob in device-table order, preparing each on first
    /// use: the blob meta is downloaded and validated, and the sparse cache
    /// data file is created and sized to the dense uncompressed address
    /// space. Idempotent.
    pub fn entries(&self) -> Result<Vec<BlobInfo>> {
        let block_size = EROFS_BLOCK_SIZE as u64;
        self.blob_infos
            .iter()
            .map(|info| {
                let mapped_offset = info
                    .mapped_blkaddr
                    .checked_mul(block_size)
                    .context("mapped blob offset overflow")?;
                let cache = self
                    .reader
                    .blob_cache(info.blob_index)
                    .with_context(|| format!("failed to open blob {}", info.blob_index))?;
                let cache_path = cache.prepare().with_context(|| {
                    format!("failed to prepare cache file for blob {}", info.blob_index)
                })?;
                let cache_size = info
                    .blocks
                    .checked_mul(block_size)
                    .context("blob cache size overflow")?;
                Ok(BlobInfo {
                    index: info.blob_index,
                    id: BlobID::from(info.blob_id),
                    mapped_blkaddr: info.mapped_blkaddr,
                    mapped_offset,
                    blocks: info.blocks,
                    cache_size,
                    cache_path,
                    is_redirect: cache.is_redirect_blob(),
                })
            })
            .collect()
    }

    /// Ensure `[offset, offset + len)` of the blob's dense uncompressed
    /// address space is decoded, CRC-validated, and written to its cache data
    /// file, fetching missing groups through the backend. Both `offset` and
    /// `len` must be 4 KiB block aligned; the fetch rounds outward to whole
    /// blob meta groups. Idempotent and safe to call concurrently.
    pub fn fetch(&self, id: &BlobID, offset: u64, len: u64) -> Result<()> {
        let block_size = EROFS_BLOCK_SIZE as u64;
        if offset % block_size != 0 || len % block_size != 0 {
            bail!("fetch range must be 4 KiB block aligned: offset={offset} len={len}");
        }
        if len == 0 {
            return Ok(());
        }

        let blob_index = *self
            .index_by_blob_id
            .get(id)
            .ok_or_else(|| anyhow::anyhow!("blob is not referenced by the bootstrap"))?;
        let cache = self
            .reader
            .blob_cache(blob_index)
            .with_context(|| format!("failed to open blob {blob_index}"))?;
        cache
            .ensure_range(offset, len)
            .with_context(|| format!("failed to fetch blob {blob_index} range [{offset}, +{len})"))
    }

    /// Return cache-ready byte intervals overlapping `[offset, offset + len)`
    /// without triggering a backend fetch. The groupmap remains authoritative.
    pub fn ready_ranges(
        &self,
        id: &BlobID,
        offset: u64,
        len: u64,
    ) -> Result<Vec<std::ops::Range<u64>>> {
        if len == 0 {
            return Ok(Vec::new());
        }
        let blob_index = *self
            .index_by_blob_id
            .get(id)
            .ok_or_else(|| anyhow::anyhow!("blob is not referenced by the bootstrap"))?;
        let cache = self
            .reader
            .blob_cache(blob_index)
            .with_context(|| format!("failed to open blob {blob_index}"))?;
        cache.ready_ranges(offset, len).with_context(|| {
            format!("failed to inspect blob {blob_index} ready range [{offset}, +{len})")
        })
    }
}

impl FsAccessor {
    /// Resolve `path` once and return a reusable entry handle.
    pub fn open(&self, path: impl AsRef<Path>) -> Result<FsEntry> {
        let ino = self.resolve_path(path.as_ref())?;
        Ok(FsEntry {
            reader: self.reader.clone(),
            zero_file: self.zero_file.clone(),
            ino,
        })
    }

    fn inode(&self, ino: u64) -> Result<ErofsInode<'_>> {
        self.reader
            .inode(ino)
            .with_context(|| format!("failed to read inode {ino}"))
    }

    fn resolve_path(&self, path: &Path) -> Result<u64> {
        let mut ino = self.reader.sb().root_nid();
        for component in path.components() {
            match component {
                Component::RootDir | Component::CurDir => continue,
                Component::Normal(name) => {
                    let wanted = name
                        .to_str()
                        .ok_or_else(|| anyhow::anyhow!("path component is not valid UTF-8"))?;
                    let inode = self.inode(ino)?;
                    if FileType::from_mode(inode.mode())? != FileType::Directory {
                        bail!("path component is not a directory: {wanted}");
                    }
                    let entries = self.reader.read_dir(ino, &inode)?;
                    let entry = entries
                        .into_iter()
                        .find(|entry| entry.name == wanted)
                        .ok_or_else(|| anyhow::anyhow!("path not found: {}", path.display()))?;
                    ino = entry.nid;
                }
                Component::ParentDir | Component::Prefix(_) => {
                    bail!("unsupported path component in {}", path.display())
                }
            }
        }
        Ok(ino)
    }
}

impl FsEntry {
    /// Inode number of this resolved entry.
    pub fn ino(&self) -> u64 {
        self.ino
    }

    /// Return owned metadata for this entry.
    pub fn metadata(&self) -> Result<Metadata> {
        let inode = self.inode()?;
        metadata_from_inode(&self.reader, self.ino, &inode)
    }

    /// List this directory's entries.
    pub fn read_dir(&self) -> Result<Vec<DirEntry>> {
        let inode = self.inode()?;
        if FileType::from_mode(inode.mode())? != FileType::Directory {
            bail!("not a directory");
        }
        self.reader
            .read_dir(self.ino, &inode)
            .with_context(|| format!("failed to read directory inode {}", self.ino))?
            .into_iter()
            .map(|entry| {
                Ok(DirEntry {
                    name: entry.name,
                    ino: entry.nid,
                    file_type: FileType::from_erofs_file_type(entry.file_type)?,
                })
            })
            .collect()
    }

    /// Read the whole file.
    pub fn read(&self) -> Result<Vec<u8>> {
        let inode = self.inode()?;
        self.read_inode(&inode, 0, u32::MAX)
    }

    /// Read file data at `offset` into `buf`, returning bytes read.
    pub fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let inode = self.inode()?;
        let data = self.read_inode(&inode, offset, buf.len() as u32)?;
        let n = data.len();
        buf[..n].copy_from_slice(&data);
        Ok(n)
    }

    /// Ensure this regular file's `[offset, offset + len)` byte range is
    /// decoded into the underlying blob cache files without returning data.
    pub fn fetch(&self, offset: u64, len: u64) -> Result<()> {
        if len == 0 {
            return Ok(());
        }
        let inode = self.inode()?;
        if FileType::from_mode(inode.mode())? != FileType::RegularFile {
            bail!("not a regular file");
        }
        if offset >= inode.size() {
            return Ok(());
        }

        let actual_end = offset.saturating_add(len).min(inode.size());
        match inode.data_layout() {
            EROFS_INODE_FLAT_PLAIN | EROFS_INODE_FLAT_INLINE => Ok(()),
            EROFS_INODE_CHUNK_BASED => self.fetch_chunk_data(&inode, offset, actual_end - offset),
            other => bail!("unsupported data layout: {other}"),
        }
    }

    /// Fetch this regular file's byte range and return mmap-ready ranges.
    ///
    /// Offsets in returned ranges are relative to this file in
    /// [`FdRange::source_offset`]. Sparse file holes are returned as
    /// `/dev/zero` ranges.
    pub fn fetch_ranges(&self, offset: u64, len: u64) -> Result<Vec<FdRange>> {
        self.resolve_file_ranges(offset, len, ResolveMode::Fetch)
    }

    /// Probe this regular file's byte range without downloading missing blob
    /// data. Sparse holes are returned as ready `/dev/zero` ranges; cold blob
    /// ranges are omitted.
    pub fn probe_ranges(&self, offset: u64, len: u64) -> Result<Vec<FdRange>> {
        self.resolve_file_ranges(offset, len, ResolveMode::Probe)
    }

    /// Read this symlink target as raw bytes.
    pub fn read_link(&self) -> Result<Vec<u8>> {
        let inode = self.inode()?;
        if FileType::from_mode(inode.mode())? != FileType::Symlink {
            bail!("not a symlink");
        }
        self.reader
            .read_symlink(self.ino, &inode)
            .with_context(|| format!("failed to read symlink inode {}", self.ino))
    }

    /// Read inline xattrs as `(full_name, value)` byte vectors.
    pub fn xattrs(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let inode = self.inode()?;
        self.reader
            .read_xattrs(self.ino, &inode)
            .with_context(|| format!("failed to read xattrs for inode {}", self.ino))
    }

    fn inode(&self) -> Result<ErofsInode<'_>> {
        self.reader
            .inode(self.ino)
            .with_context(|| format!("failed to read inode {}", self.ino))
    }

    fn read_inode(&self, inode: &ErofsInode<'_>, offset: u64, size: u32) -> Result<Vec<u8>> {
        if FileType::from_mode(inode.mode())? != FileType::RegularFile {
            bail!("not a regular file");
        }
        self.reader
            .read_file_data_sync(self.ino, inode, offset, size)
            .with_context(|| format!("failed to read file inode {}", self.ino))
    }

    fn fetch_chunk_data(&self, inode: &ErofsInode<'_>, offset: u64, len: u64) -> Result<()> {
        let chunkbits = self.reader.sb().blkszbits as u32 + (inode.chunk_format() as u32 & 0x1F);
        let chunksize = 1u64 << chunkbits;
        let chunk_indexes = self
            .reader
            .read_chunk_indexes(self.ino, inode)
            .with_context(|| format!("failed to read chunk indexes for inode {}", self.ino))?;

        let mut remaining = len;
        let mut file_pos = offset;
        while remaining > 0 {
            let file_chunk_index = (file_pos / chunksize) as usize;
            let chunk_off = file_pos % chunksize;
            let to_fetch = remaining.min(chunksize - chunk_off);
            let Some(chunk_index) = chunk_indexes.get(file_chunk_index) else {
                break;
            };

            if chunk_index.blkaddr != u64::MAX {
                let chunk_addr = chunk_index
                    .blkaddr
                    .checked_mul(EROFS_BLOCK_SIZE as u64)
                    .ok_or_else(|| anyhow::anyhow!("blob fetch offset overflow"))?;
                // Resolve the chunk to a blob: the legacy layout names the blob
                // by a non-zero device_id with a blob-relative address; the
                // flattened layout uses device_id 0 with an absolute address.
                let resolved = if chunk_index.device_id > 0 {
                    Some((chunk_index.device_id, chunk_addr))
                } else {
                    self.reader.flat_blob_at(chunk_addr)?
                };
                if let Some((blob_index, blob_rel)) = resolved {
                    let blob_offset = blob_rel
                        .checked_add(chunk_off)
                        .ok_or_else(|| anyhow::anyhow!("blob fetch offset overflow"))?;
                    self.reader
                        .blob_cache(blob_index)
                        .with_context(|| format!("failed to open blob {blob_index}"))?
                        .ensure_range(blob_offset, to_fetch)
                        .with_context(|| {
                            format!(
                                "failed to fetch inode {} blob {} range [{}, +{})",
                                self.ino, blob_index, blob_offset, to_fetch
                            )
                        })?;
                }
                // Otherwise the chunk is bootstrap-local; nothing to fetch.
            }

            file_pos += to_fetch;
            remaining -= to_fetch;
        }
        Ok(())
    }

    fn resolve_file_ranges(
        &self,
        offset: u64,
        len: u64,
        mode: ResolveMode,
    ) -> Result<Vec<FdRange>> {
        let inode = self.inode()?;
        if FileType::from_mode(inode.mode())? != FileType::RegularFile {
            bail!("not a regular file");
        }
        let end = match checked_range_end(offset, len)? {
            Some(end) => end.min(inode.size()),
            None => return Ok(Vec::new()),
        };
        if offset >= end {
            return Ok(Vec::new());
        }

        match inode.data_layout() {
            EROFS_INODE_FLAT_PLAIN | EROFS_INODE_FLAT_INLINE => {
                bail!("flat file data is not supported by FsEntry range API")
            }
            EROFS_INODE_CHUNK_BASED => {
                self.resolve_chunk_file_ranges(&inode, offset, end - offset, mode)
            }
            other => bail!("unsupported data layout: {other}"),
        }
    }

    fn resolve_chunk_file_ranges(
        &self,
        inode: &ErofsInode<'_>,
        offset: u64,
        len: u64,
        mode: ResolveMode,
    ) -> Result<Vec<FdRange>> {
        let chunkbits = self.reader.sb().blkszbits as u32 + (inode.chunk_format() as u32 & 0x1F);
        let chunksize = 1u64 << chunkbits;
        let chunk_indexes = self
            .reader
            .read_chunk_indexes(self.ino, inode)
            .with_context(|| format!("failed to read chunk indexes for inode {}", self.ino))?;
        let blob_layout = self.reader.blob_infos()?;

        let mut ranges = Vec::new();
        let mut remaining = len;
        let mut file_pos = offset;
        while remaining > 0 {
            let file_chunk_index = (file_pos / chunksize) as usize;
            let chunk_off = file_pos % chunksize;
            let to_resolve = remaining.min(chunksize - chunk_off);
            let Some(chunk_index) = chunk_indexes.get(file_chunk_index) else {
                break;
            };

            if chunk_index.blkaddr == EROFS_NULL_ADDR {
                push_fd_range(
                    &mut ranges,
                    FdRange::new(self.zero_file.as_raw_fd(), 0, to_resolve, file_pos),
                    self.zero_file.as_raw_fd(),
                );
            } else {
                let chunk_addr = chunk_index
                    .blkaddr
                    .checked_mul(EROFS_BLOCK_SIZE as u64)
                    .ok_or_else(|| anyhow::anyhow!("blob fetch offset overflow"))?;
                let resolved = if chunk_index.device_id > 0 {
                    // Legacy layout: device_id directly names the blob.
                    Some((chunk_index.device_id, chunk_addr))
                } else {
                    // Flattened layout: device_id 0 stores a flat device address.
                    blob_layout.iter().find_map(|blob| {
                        let start = blob.mapped_blkaddr.checked_mul(EROFS_BLOCK_SIZE as u64)?;
                        let size = blob.blocks.checked_mul(EROFS_BLOCK_SIZE as u64)?;
                        mapped_range_offset(start, size, chunk_addr)
                            .map(|offset| (blob.blob_index, offset))
                    })
                };
                if let Some((blob_index, blob_rel)) = resolved {
                    let blob_offset = blob_rel
                        .checked_add(chunk_off)
                        .ok_or_else(|| anyhow::anyhow!("blob fetch offset overflow"))?;
                    push_blob_fd_ranges(
                        &self.reader,
                        self.zero_file.as_raw_fd(),
                        &mut ranges,
                        BlobRangeSpec {
                            index: blob_index,
                            offset: blob_offset,
                            len: to_resolve,
                            source_offset: file_pos,
                        },
                        mode,
                    )?;
                } else {
                    bail!("bootstrap-local file data is not supported by FsEntry range API");
                }
            }

            file_pos += to_resolve;
            remaining -= to_resolve;
        }

        Ok(ranges)
    }
}

fn metadata_from_inode(reader: &ErofsReader, ino: u64, inode: &ErofsInode<'_>) -> Result<Metadata> {
    Ok(Metadata {
        ino,
        file_type: FileType::from_mode(inode.mode())?,
        mode: inode.mode(),
        size: inode.size(),
        uid: inode.uid(),
        gid: inode.gid(),
        nlink: inode.nlink(),
        mtime: inode.mtime(reader.sb().epoch()),
        mtime_nsec: inode.effective_mtime_nsec(reader.sb().fixed_nsec()),
        rdev: inode.rdev(),
    })
}

#[derive(Clone, Copy)]
enum ResolveMode {
    Fetch,
    Probe,
}

#[derive(Clone, Copy)]
struct BlobRangeSpec {
    index: u16,
    offset: u64,
    len: u64,
    source_offset: u64,
}

fn checked_range_end(offset: u64, len: u64) -> Result<Option<u64>> {
    if len == 0 {
        return Ok(None);
    }
    Ok(Some(offset.checked_add(len).ok_or_else(|| {
        anyhow::anyhow!("range offset + length overflow")
    })?))
}

fn mapped_range_offset(mapped_offset: u64, size: u64, offset: u64) -> Option<u64> {
    let end = mapped_offset.checked_add(size)?;
    if offset >= mapped_offset && offset < end {
        Some(offset - mapped_offset)
    } else {
        None
    }
}

fn push_blob_fd_ranges(
    reader: &ErofsReader,
    zero_fd: RawFd,
    ranges: &mut Vec<FdRange>,
    spec: BlobRangeSpec,
    mode: ResolveMode,
) -> Result<()> {
    let cache = reader
        .blob_cache(spec.index)
        .with_context(|| format!("failed to open blob {}", spec.index))?;
    let fd = cache
        .cache_fd()
        .with_context(|| format!("failed to get cache fd for blob {}", spec.index))?;

    match mode {
        ResolveMode::Fetch => {
            cache.ensure_range(spec.offset, spec.len).with_context(|| {
                format!(
                    "failed to fetch blob {} range [{}, +{})",
                    spec.index, spec.offset, spec.len
                )
            })?;
            push_fd_range(
                ranges,
                FdRange::new(fd, spec.offset, spec.len, spec.source_offset),
                zero_fd,
            );
        }
        ResolveMode::Probe => {
            for ready in cache.ready_ranges(spec.offset, spec.len)? {
                push_fd_range(
                    ranges,
                    FdRange::new(
                        fd,
                        ready.start,
                        ready.end - ready.start,
                        spec.source_offset + (ready.start - spec.offset),
                    ),
                    zero_fd,
                );
            }
        }
    }

    Ok(())
}

fn push_fd_range(ranges: &mut Vec<FdRange>, range: FdRange, zero_fd: RawFd) {
    if range.len == 0 {
        return;
    }
    if let Some(last) = ranges.last_mut() {
        let source_contiguous = last.source_offset + last.len == range.source_offset;
        let file_contiguous = last.offset + last.len == range.offset;
        let both_zero =
            last.fd == zero_fd && range.fd == zero_fd && last.offset == 0 && range.offset == 0;
        if last.fd == range.fd && source_contiguous && (file_contiguous || both_zero) {
            last.len += range.len;
            return;
        }
    }
    ranges.push(range);
}

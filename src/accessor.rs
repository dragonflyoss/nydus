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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::build::blob_chunk::BlobWriter;
    use crate::build::bootstrap::{
        render_bootstrap, render_flattened_bootstrap, FLATTENED_BLOB_ALIGNMENT,
    };
    use crate::build::inode::{build_tree, set_root_prefetch_blobs_xattr};
    use crate::config::Config;
    use crate::metadata::{
        BlobFooter, BlobMetaCompressor, ErofsDeviceSlot, NYDUS_BLOB_FOOTER_ALIGNMENT,
    };
    use crate::utils::{hex_string, sha256_file};
    use crc32c::crc32c_append;
    use std::collections::HashSet;
    use std::fs;
    use std::io::Write;
    use std::os::unix::fs::symlink;
    use tempfile::tempdir;

    /// Build a minimal single-blob nydus image (blob dir + bootstrap +
    /// config) and return (bootstrap, config, data blob id, expected file bytes).
    fn build_test_image(
        root: &Path,
    ) -> (
        PathBuf,
        Config,
        [u8; EROFS_BLOB_ID_SIZE],
        HashMap<String, Vec<u8>>,
    ) {
        build_test_image_with_layout(root, false)
    }

    fn build_flattened_test_image(
        root: &Path,
    ) -> (
        PathBuf,
        Config,
        [u8; EROFS_BLOB_ID_SIZE],
        HashMap<String, Vec<u8>>,
    ) {
        build_test_image_with_layout(root, true)
    }

    fn build_test_image_with_layout(
        root: &Path,
        flattened: bool,
    ) -> (
        PathBuf,
        Config,
        [u8; EROFS_BLOB_ID_SIZE],
        HashMap<String, Vec<u8>>,
    ) {
        let corpus_dir = root.join("corpus");
        fs::create_dir_all(&corpus_dir).unwrap();
        // Two ~1.1 MiB incompressible-ish files so the blob spans multiple
        // 1 MiB groups.
        let mut corpus = HashMap::new();
        for seed in 1u64..=2 {
            let mut state = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15);
            let mut data = vec![0u8; (1 << 20) + 64 * 1024];
            for byte in data.iter_mut() {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                *byte = state as u8;
            }
            fs::write(corpus_dir.join(format!("file{seed}")), &data).unwrap();
            corpus.insert(format!("file{seed}"), data);
        }
        fs::create_dir_all(corpus_dir.join("dir")).unwrap();
        fs::write(corpus_dir.join("dir/small.txt"), b"small file").unwrap();
        corpus.insert("dir/small.txt".to_string(), b"small file".to_vec());
        fs::write(corpus_dir.join("tiny.txt"), b"hello").unwrap();
        corpus.insert("tiny.txt".to_string(), b"hello".to_vec());
        fs::write(corpus_dir.join("empty.txt"), b"").unwrap();
        corpus.insert("empty.txt".to_string(), Vec::new());
        symlink("file1", corpus_dir.join("link_to_file1")).unwrap();

        let blob_dir = root.join("blobs");
        fs::create_dir_all(&blob_dir).unwrap();
        let staging = blob_dir.join("staging");
        let mut writer = BlobWriter::new_with_compressor(
            &staging,
            crate::metadata::BLOB_META_DEFAULT_CHUNK_SIZE,
            BlobMetaCompressor::Zstd,
        )
        .unwrap();
        let mut inodes = build_tree(
            &corpus_dir,
            &mut writer,
            crate::metadata::BLOB_META_DEFAULT_CHUNK_SIZE,
            &HashSet::new(),
        )
        .unwrap();
        writer.finish().unwrap();

        let data_blob_id = writer.data_digest();
        let blob_meta = writer.blob_meta(data_blob_id, 0).unwrap();
        let blocks = writer.total_blocks();
        set_root_prefetch_blobs_xattr(&mut inodes[0], &[1]).unwrap();
        let embedded_device_slots = [ErofsDeviceSlot::with_blob_id(blocks, &data_blob_id)];
        let embedded_bootstrap_bytes = render_bootstrap(
            &mut inodes,
            0,
            crate::metadata::BLOB_META_DEFAULT_CHUNK_SIZE.trailing_zeros(),
            &embedded_device_slots,
            &[0u8; 16],
        )
        .unwrap();
        assert_eq!(
            embedded_bootstrap_bytes.len() % EROFS_BLOCK_SIZE as usize,
            0
        );

        let full_blob_id =
            write_full_blob(&staging, &blob_dir, &embedded_bootstrap_bytes, &blob_meta);

        let device_slots = [ErofsDeviceSlot::with_blob_id(blocks, &full_blob_id)];
        let bootstrap_bytes = if flattened {
            render_flattened_bootstrap(
                &mut inodes,
                0,
                crate::metadata::BLOB_META_DEFAULT_CHUNK_SIZE.trailing_zeros(),
                &device_slots,
                &[0u8; 16],
            )
            .unwrap()
        } else {
            render_bootstrap(
                &mut inodes,
                0,
                crate::metadata::BLOB_META_DEFAULT_CHUNK_SIZE.trailing_zeros(),
                &device_slots,
                &[0u8; 16],
            )
            .unwrap()
        };
        let bootstrap = root.join("bootstrap");
        fs::write(&bootstrap, &bootstrap_bytes).unwrap();

        let config = Config::from_yaml(&format!(
            "backend:\n  type: local\n  config:\n    dir: {}\ncache:\n  type: local\n  config:\n    dir: {}\nprefetch:\n  enable: false\n",
            blob_dir.display(),
            root.join("cache").display(),
        ))
        .unwrap();

        (bootstrap, config, full_blob_id, corpus)
    }

    fn write_full_blob(
        data_path: &Path,
        blob_dir: &Path,
        bootstrap_bytes: &[u8],
        blob_meta: &crate::metadata::BlobMeta,
    ) -> [u8; EROFS_BLOB_ID_SIZE] {
        let data = fs::read(data_path).unwrap();
        let data_size = data.len() as u64;
        let bootstrap_offset = align_u64(data_size, NYDUS_BLOB_FOOTER_ALIGNMENT);
        let bootstrap_blocks = bytes_to_blocks(bootstrap_bytes.len() as u64);
        let blob_meta_offset = align_u64(
            bootstrap_offset + bootstrap_bytes.len() as u64,
            NYDUS_BLOB_FOOTER_ALIGNMENT,
        );
        let blob_meta_blocks = bytes_to_blocks(blob_meta.metadata_size());
        let footer = BlobFooter::new(
            0,
            data_size,
            bootstrap_offset,
            bootstrap_blocks,
            blob_meta_offset,
            blob_meta_blocks,
        )
        .unwrap();

        let full_blob_path = blob_dir.join("full.blob");
        let mut full_blob = fs::File::create(&full_blob_path).unwrap();
        full_blob.write_all(&data).unwrap();
        write_zero_padding(&mut full_blob, data_size, bootstrap_offset).unwrap();
        full_blob.write_all(bootstrap_bytes).unwrap();
        write_zero_padding(
            &mut full_blob,
            bootstrap_offset + bootstrap_bytes.len() as u64,
            blob_meta_offset,
        )
        .unwrap();
        blob_meta.write_to(&mut full_blob).unwrap();
        footer.write_to(&mut full_blob).unwrap();
        drop(full_blob);

        let full_blob_id = sha256_file(&full_blob_path).unwrap();
        let final_blob_path = blob_dir.join(hex_string(&full_blob_id));
        fs::rename(&full_blob_path, &final_blob_path).unwrap();
        blob_meta
            .save(&blob_dir.join(format!("{}.blob.meta", hex_string(&full_blob_id))))
            .unwrap();
        fs::remove_file(data_path).unwrap();
        full_blob_id
    }

    fn align_u64(value: u64, align: u64) -> u64 {
        debug_assert!(align.is_power_of_two());
        (value + align - 1) & !(align - 1)
    }

    fn bytes_to_blocks(size: u64) -> u32 {
        assert_eq!(size % EROFS_BLOCK_SIZE as u64, 0);
        (size / EROFS_BLOCK_SIZE as u64) as u32
    }

    fn write_zero_padding(
        writer: &mut dyn Write,
        current: u64,
        aligned: u64,
    ) -> std::io::Result<()> {
        let padding = aligned - current;
        if padding > 0 {
            writer.write_all(&vec![0u8; padding as usize])?;
        }
        Ok(())
    }

    #[test]
    fn accessor_describes_devices_and_fetches_aligned_ranges() {
        let dir = tempdir().unwrap();
        let (bootstrap, config, blob_id, _corpus) = build_flattened_test_image(dir.path());
        let blob_id = BlobID::from(blob_id);

        let accessor = NydusAccessor::new(&bootstrap, config).unwrap();
        assert_eq!(
            accessor.bootstrap_size,
            fs::metadata(&bootstrap).unwrap().len()
        );
        assert_eq!(accessor.bootstrap_size % EROFS_BLOCK_SIZE as u64, 0);
        let blobs = accessor.blob.entries().unwrap();
        assert_eq!(blobs.len(), 1);
        let descriptor = &blobs[0];
        assert_eq!(descriptor.index, 1);
        assert_eq!(descriptor.id, blob_id);
        assert!(!descriptor.is_redirect);
        assert_eq!(
            descriptor.cache_size,
            descriptor.blocks * EROFS_BLOCK_SIZE as u64
        );
        assert!(descriptor.mapped_offset >= accessor.bootstrap_size);
        assert_eq!(
            descriptor.mapped_offset,
            descriptor.mapped_blkaddr * EROFS_BLOCK_SIZE as u64
        );
        let meta = fs::metadata(&descriptor.cache_path).unwrap();
        assert_eq!(meta.len(), descriptor.cache_size);
        assert_eq!(
            accessor.flat_size(),
            descriptor.mapped_offset + descriptor.cache_size
        );
        assert_eq!(
            accessor.bootstrap().metadata().unwrap().len(),
            accessor.bootstrap_size
        );
        assert!(accessor.zero_fd() >= 0);
        let bootstrap_ranges = accessor
            .fetch_flat_ranges(0, EROFS_BLOCK_SIZE as u64)
            .unwrap();
        assert_eq!(bootstrap_ranges.len(), 1);
        assert_eq!(bootstrap_ranges[0].fd, accessor.bootstrap().as_raw_fd());
        assert_eq!(bootstrap_ranges[0].offset, 0);
        assert_eq!(bootstrap_ranges[0].source_offset, 0);
        assert_eq!(bootstrap_ranges[0].len, EROFS_BLOCK_SIZE as u64);

        // Fetch a block-aligned range in the middle; the cache file should be
        // populated for that range and a second fetch is idempotent. The dense
        // blob address space is independent of path order, so exact file
        // content is covered by the static read API test below.
        let block = EROFS_BLOCK_SIZE as u64;
        let (blob_offset, len) = (256 * block, 16 * block);
        let offset = descriptor.mapped_offset + blob_offset;
        assert!(accessor.probe_flat_ranges(offset, len).unwrap().is_empty());
        let fd_ranges = accessor.fetch_flat_ranges(offset, len).unwrap();
        assert_eq!(fd_ranges.len(), 1);
        assert_eq!(fd_ranges[0].offset, blob_offset);
        assert_eq!(fd_ranges[0].len, len);
        assert_eq!(fd_ranges[0].source_offset, offset);
        assert_ne!(fd_ranges[0].fd, accessor.zero_fd());
        accessor.blob.fetch(&blob_id, blob_offset, len).unwrap();
        let cached = fs::read(&descriptor.cache_path).unwrap();
        assert!(cached[blob_offset as usize..(blob_offset + len) as usize]
            .iter()
            .any(|byte| *byte != 0));
        assert_eq!(accessor.probe_flat_ranges(offset, len).unwrap(), fd_ranges);

        // Idempotent re-fetch and zero-length fetch are fine.
        accessor.blob.fetch(&blob_id, offset, len).unwrap();
        accessor.blob.fetch(&blob_id, 0, 0).unwrap();

        let trace = accessor.trace_snapshot();
        assert_eq!(trace.patterns.len(), 1);
        assert_eq!(trace.patterns[0].blob_index, 1);
        assert_eq!(trace.patterns[0].group_index, 1);
        assert_eq!(
            accessor.trace_json(),
            "{\"patterns\":[{\"blob_index\":1,\"group_index\":1}]}"
        );

        // Unaligned ranges and unknown blobs are rejected.
        assert!(accessor.blob.fetch(&blob_id, 1, block).is_err());
        assert!(accessor.blob.fetch(&blob_id, 0, block + 1).is_err());
        assert!(accessor
            .blob
            .fetch(&BlobID::from([0u8; 32]), 0, block)
            .is_err());

        // Out-of-range fetch fails rather than fabricating data.
        assert!(accessor
            .blob
            .fetch(&blob_id, descriptor.cache_size, block)
            .is_err());
    }

    #[test]
    fn flattened_bootstrap_records_mapped_device_slots() {
        let dir = tempdir().unwrap();
        let (bootstrap, _config, blob_id, _corpus) = build_test_image(dir.path());
        let reader = ErofsReader::open_layer(&bootstrap).unwrap();
        let blob_infos = reader.blob_infos().unwrap();
        assert_eq!(blob_infos.len(), 1);
        assert_eq!(blob_infos[0].blob_id, blob_id);
        assert_eq!(blob_infos[0].mapped_blkaddr, 0);

        let corpus_dir = dir.path().join("corpus");
        let blob_dir = dir.path().join("second-blobs");
        fs::create_dir_all(&blob_dir).unwrap();
        let staging = blob_dir.join("staging");
        let mut writer = BlobWriter::new_with_compressor(
            &staging,
            crate::metadata::BLOB_META_DEFAULT_CHUNK_SIZE,
            BlobMetaCompressor::Zstd,
        )
        .unwrap();
        let mut inodes = build_tree(
            &corpus_dir,
            &mut writer,
            crate::metadata::BLOB_META_DEFAULT_CHUNK_SIZE,
            &HashSet::new(),
        )
        .unwrap();
        writer.finish().unwrap();

        let second_blob_id = writer.data_digest();
        let device_slots = [
            ErofsDeviceSlot::with_blob_id(blob_infos[0].blocks, &blob_id),
            ErofsDeviceSlot::with_blob_id(writer.total_blocks(), &second_blob_id),
        ];
        set_root_prefetch_blobs_xattr(&mut inodes[0], &[1, 2]).unwrap();
        let flattened = render_flattened_bootstrap(
            &mut inodes,
            0,
            crate::metadata::BLOB_META_DEFAULT_CHUNK_SIZE.trailing_zeros(),
            &device_slots,
            &[0u8; 16],
        )
        .unwrap();
        assert_eq!(flattened.len() % EROFS_BLOCK_SIZE as usize, 0);

        let sb_offset = crate::metadata::EROFS_SUPER_OFFSET as usize;
        let checksum =
            u32::from_le_bytes(flattened[sb_offset + 4..sb_offset + 8].try_into().unwrap());
        let mut block0 = flattened[sb_offset..EROFS_BLOCK_SIZE as usize].to_vec();
        block0[4..8].fill(0);
        assert_eq!(checksum, !crc32c_append(0u32, &block0));

        let flattened_path = dir.path().join("flattened.bootstrap");
        fs::write(&flattened_path, flattened).unwrap();
        let flattened_reader = ErofsReader::open_layer(&flattened_path).unwrap();
        let infos = flattened_reader.blob_infos().unwrap();
        assert_eq!(infos.len(), 2);

        let first_offset =
            (fs::metadata(&flattened_path).unwrap().len() + FLATTENED_BLOB_ALIGNMENT - 1)
                & !(FLATTENED_BLOB_ALIGNMENT - 1);
        let second_offset =
            (first_offset + infos[0].blocks * EROFS_BLOCK_SIZE as u64 + FLATTENED_BLOB_ALIGNMENT
                - 1)
                & !(FLATTENED_BLOB_ALIGNMENT - 1);
        assert_eq!(
            infos[0].mapped_blkaddr,
            first_offset / EROFS_BLOCK_SIZE as u64
        );
        assert_eq!(
            infos[1].mapped_blkaddr,
            second_offset / EROFS_BLOCK_SIZE as u64
        );
        assert!(infos[1].mapped_blkaddr > infos[0].mapped_blkaddr);
    }

    #[test]
    fn accessor_static_filesystem_api_reads_metadata_and_data() {
        let dir = tempdir().unwrap();
        let (bootstrap, config, blob_id, corpus) = build_test_image(dir.path());
        let blob_id = BlobID::from(blob_id);

        let accessor = NydusAccessor::new(&bootstrap, config).unwrap();

        let root_entry = accessor.fs.open("/").unwrap();
        let root = root_entry.metadata().unwrap();
        assert_eq!(root.file_type, FileType::Directory);

        let entries = root_entry.read_dir().unwrap();
        let names = entries
            .iter()
            .map(|entry| entry.name.as_str())
            .collect::<Vec<_>>();
        assert!(names.contains(&"file1"));
        assert!(names.contains(&"dir"));
        assert!(names.contains(&"link_to_file1"));

        let file1_entry = accessor.fs.open("file1").unwrap();
        let file1 = file1_entry.metadata().unwrap();
        assert_eq!(file1.file_type, FileType::RegularFile);
        assert!(file1.size >= corpus["file1"].len() as u64);

        let all = file1_entry.read().unwrap();
        assert_eq!(&all[..corpus["file1"].len()], corpus["file1"].as_slice());
        assert!(all[corpus["file1"].len()..].iter().all(|byte| *byte == 0));

        let mut buf = vec![0u8; 4097];
        let read = file1_entry.read_at(12345, &mut buf).unwrap();
        assert_eq!(read, buf.len());
        assert_eq!(&buf, &corpus["file1"][12345..12345 + read]);
        let mut second = vec![0u8; 32];
        let read = file1_entry.read_at(777, &mut second).unwrap();
        assert_eq!(read, second.len());
        assert_eq!(&second, &corpus["file1"][777..777 + read]);

        let tiny = accessor.fs.open("tiny.txt").unwrap().read().unwrap();
        assert_eq!(
            &tiny[..corpus["tiny.txt"].len()],
            corpus["tiny.txt"].as_slice()
        );
        assert!(tiny[corpus["tiny.txt"].len()..]
            .iter()
            .all(|byte| *byte == 0));
        assert!(accessor
            .fs
            .open("empty.txt")
            .unwrap()
            .read()
            .unwrap()
            .is_empty());
        let small = accessor.fs.open("dir/small.txt").unwrap().read().unwrap();
        assert_eq!(
            &small[..corpus["dir/small.txt"].len()],
            corpus["dir/small.txt"].as_slice()
        );
        assert!(small[corpus["dir/small.txt"].len()..]
            .iter()
            .all(|byte| *byte == 0));

        let link_entry = accessor.fs.open("link_to_file1").unwrap();
        let link = link_entry.read_link().unwrap();
        assert_eq!(link, b"file1");
        assert_eq!(link_entry.read_link().unwrap(), b"file1");
        let link_meta = link_entry.metadata().unwrap();
        assert_eq!(link_meta.file_type, FileType::Symlink);

        let xattrs = root_entry.xattrs().unwrap();
        assert!(xattrs.iter().any(|(name, value)| {
            name.as_slice() == b"trusted.nydus.prefetch.blobs" && value.as_slice() == b"1"
        }));

        let blobs = accessor.blob.entries().unwrap();
        let cached = fs::read(&blobs[0].cache_path).unwrap();
        assert!(cached.iter().any(|byte| *byte != 0));
        assert_eq!(blobs[0].id, blob_id);
    }

    #[test]
    fn fs_entry_fetch_populates_blob_cache_without_reading_data() {
        let dir = tempdir().unwrap();
        let (bootstrap, config, _blob_id, _corpus) = build_test_image(dir.path());

        let accessor = NydusAccessor::new(&bootstrap, config).unwrap();
        let blobs = accessor.blob.entries().unwrap();
        let before = fs::read(&blobs[0].cache_path).unwrap();
        assert!(before.iter().all(|byte| *byte == 0));

        let file1_entry = accessor.fs.open("file1").unwrap();
        assert!(file1_entry.probe_ranges(12345, 4097).unwrap().is_empty());
        let ranges = file1_entry.fetch_ranges(12345, 4097).unwrap();
        assert!(!ranges.is_empty());
        assert_eq!(ranges[0].source_offset, 12345);
        assert_ne!(ranges[0].fd, accessor.zero_fd());
        file1_entry.fetch(12345, 4097).unwrap();
        assert_eq!(file1_entry.probe_ranges(12345, 4097).unwrap(), ranges);

        let after = fs::read(&blobs[0].cache_path).unwrap();
        assert!(after.iter().any(|byte| *byte != 0));
        file1_entry.fetch(0, 0).unwrap();
        accessor.fs.open("/").unwrap().fetch(0, 4096).unwrap_err();
    }
}

//! Path-based, owned-type filesystem API over [`ErofsReader`]: resolve a
//! path once into a [`Node`] handle, then read metadata, directory
//! entries, file data and xattrs without FUSE or mmap lifetimes.

use std::fs::File;
use std::os::fd::AsRawFd;
use std::path::{Component, Path};
use std::sync::Arc;

use crate::extent::{clamped_range_end, BlobRangeSpec, Extent, ExtentResolver, ResolveMode};
use crate::reader::data::{for_each_chunk_span, locate_chunk, ChunkLocation};
use crate::reader::ErofsReader;
use nydus_error::{Context, Error, Result};
use nydus_format::erofs::{
    ErofsInode, EROFS_FT_BLKDEV, EROFS_FT_CHRDEV, EROFS_FT_DIR, EROFS_FT_FIFO, EROFS_FT_REG_FILE,
    EROFS_FT_SOCK, EROFS_FT_SYMLINK, EROFS_INODE_CHUNK_BASED, EROFS_INODE_FLAT_INLINE,
    EROFS_INODE_FLAT_PLAIN,
};

/// File type exposed by the static core API, independent of FUSE types.
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
            other => Err(Error::Unsupported(format!(
                "unsupported EROFS file type: {other}"
            ))),
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
            other => Err(Error::Unsupported(format!(
                "unsupported inode mode file type: {other:#o}"
            ))),
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

/// Static path-based filesystem APIs.
pub struct ImageFs {
    reader: Arc<ErofsReader>,
    zero_file: Arc<File>,
}

/// Resolved static filesystem entry. Reuse this handle for repeated operations
/// on the same path to avoid resolving the path for every `read_at` call.
#[derive(Clone)]
pub struct Node {
    reader: Arc<ErofsReader>,
    zero_file: Arc<File>,
    ino: u64,
}

impl ImageFs {
    pub(crate) fn new(reader: Arc<ErofsReader>, zero_file: Arc<File>) -> Self {
        Self { reader, zero_file }
    }

    /// Resolve `path` once and return a reusable entry handle.
    pub fn open(&self, path: impl AsRef<Path>) -> Result<Node> {
        let ino = self.resolve_path(path.as_ref())?;
        Ok(Node {
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
        let mut ino = self.reader.superblock().root_nid();
        for component in path.components() {
            match component {
                Component::RootDir | Component::CurDir => continue,
                Component::Normal(name) => {
                    let wanted = name.to_str().ok_or_else(|| {
                        Error::InvalidParameter("path component is not valid UTF-8".to_string())
                    })?;
                    let inode = self.inode(ino)?;
                    if FileType::from_mode(inode.mode())? != FileType::Directory {
                        return Err(Error::InvalidParameter(format!(
                            "path component is not a directory: {wanted}"
                        )));
                    }
                    let entries = self.reader.read_dir(ino, &inode)?;
                    let entry = entries
                        .into_iter()
                        .find(|entry| entry.name == wanted.as_bytes())
                        .ok_or_else(|| {
                            Error::NotFound(format!("path not found: {}", path.display()))
                        })?;
                    ino = entry.nid;
                }
                Component::ParentDir | Component::Prefix(_) => {
                    return Err(Error::Unsupported(format!(
                        "unsupported path component in {}",
                        path.display()
                    )))
                }
            }
        }
        Ok(ino)
    }
}

impl Node {
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
            return Err(Error::InvalidParameter("not a directory".to_string()));
        }
        self.reader
            .read_dir(self.ino, &inode)
            .with_context(|| format!("failed to read directory inode {}", self.ino))?
            .into_iter()
            .map(|entry| {
                Ok(DirEntry {
                    name: String::from_utf8_lossy(&entry.name).into_owned(),
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
            return Err(Error::InvalidParameter("not a regular file".to_string()));
        }
        if offset >= inode.size() {
            return Ok(());
        }

        let actual_end = offset.saturating_add(len).min(inode.size());
        match inode.data_layout() {
            EROFS_INODE_FLAT_PLAIN | EROFS_INODE_FLAT_INLINE => Ok(()),
            EROFS_INODE_CHUNK_BASED => self.fetch_chunk_data(&inode, offset, actual_end - offset),
            other => Err(Error::Unsupported(format!(
                "unsupported data layout: {other}"
            ))),
        }
    }

    /// Fetch this regular file's byte range and return mmap-ready ranges.
    ///
    /// Offsets in returned ranges are relative to this file in
    /// [`Extent::source_offset`]. Sparse file holes are returned as
    /// `/dev/zero` ranges.
    pub fn fetch_ranges(&self, offset: u64, len: u64) -> Result<Vec<Extent>> {
        self.resolve_file_ranges(offset, len, ResolveMode::Fetch)
    }

    /// Probe this regular file's byte range without downloading missing blob
    /// data. Sparse holes are returned as ready `/dev/zero` ranges; cold blob
    /// ranges are omitted.
    pub fn probe_ranges(&self, offset: u64, len: u64) -> Result<Vec<Extent>> {
        self.resolve_file_ranges(offset, len, ResolveMode::Probe)
    }

    /// Read this symlink target as raw bytes.
    pub fn read_link(&self) -> Result<Vec<u8>> {
        let inode = self.inode()?;
        if FileType::from_mode(inode.mode())? != FileType::Symlink {
            return Err(Error::InvalidParameter("not a symlink".to_string()));
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
            return Err(Error::InvalidParameter("not a regular file".to_string()));
        }
        self.reader
            .read_file_data(self.ino, inode, offset, size)
            .with_context(|| format!("failed to read file inode {}", self.ino))
    }

    fn fetch_chunk_data(&self, inode: &ErofsInode<'_>, offset: u64, len: u64) -> Result<()> {
        let chunk_size = self.reader.chunk_size(inode);
        let chunk_index_entries = self
            .reader
            .read_chunk_index_entries(self.ino, inode)
            .with_context(|| format!("failed to read chunk indexes for inode {}", self.ino))?;
        let blob_layout = self.reader.blob_infos()?;

        for_each_chunk_span(
            offset,
            len,
            chunk_size,
            chunk_index_entries.len(),
            |span| -> Result<()> {
                let entry = &chunk_index_entries[span.index];
                match locate_chunk(blob_layout, entry.blkaddr, entry.device_id)? {
                    ChunkLocation::Hole => {}
                    ChunkLocation::Blob { index, offset } => {
                        let blob_offset = offset.checked_add(span.chunk_off).ok_or_else(|| {
                            Error::Overflow("blob fetch offset overflow".to_string())
                        })?;
                        self.reader
                            .blob_cache(index)
                            .with_context(|| format!("failed to open blob {index}"))?
                            .ensure_range(blob_offset, span.len)
                            .with_context(|| {
                                format!(
                                    "failed to fetch inode {} blob {} range [{}, +{})",
                                    self.ino, index, blob_offset, span.len
                                )
                            })?;
                    }
                    // The chunk is bootstrap-local; nothing to fetch.
                    ChunkLocation::Local { .. } => {}
                }
                Ok(())
            },
        )?;
        Ok(())
    }

    fn resolve_file_ranges(&self, offset: u64, len: u64, mode: ResolveMode) -> Result<Vec<Extent>> {
        let inode = self.inode()?;
        if FileType::from_mode(inode.mode())? != FileType::RegularFile {
            return Err(Error::InvalidParameter("not a regular file".to_string()));
        }
        let Some(end) = clamped_range_end(offset, len, inode.size())? else {
            return Ok(Vec::new());
        };

        match inode.data_layout() {
            EROFS_INODE_FLAT_PLAIN | EROFS_INODE_FLAT_INLINE => Err(Error::Unsupported(
                "flat file data is not supported by Node range API".to_string(),
            )),
            EROFS_INODE_CHUNK_BASED => {
                self.resolve_chunk_file_ranges(&inode, offset, end - offset, mode)
            }
            other => Err(Error::Unsupported(format!(
                "unsupported data layout: {other}"
            ))),
        }
    }

    fn resolve_chunk_file_ranges(
        &self,
        inode: &ErofsInode<'_>,
        offset: u64,
        len: u64,
        mode: ResolveMode,
    ) -> Result<Vec<Extent>> {
        let chunk_size = self.reader.chunk_size(inode);
        let chunk_index_entries = self
            .reader
            .read_chunk_index_entries(self.ino, inode)
            .with_context(|| format!("failed to read chunk indexes for inode {}", self.ino))?;
        let blob_layout = self.reader.blob_infos()?;

        let mut resolver = ExtentResolver::new(&self.reader, self.zero_file.as_raw_fd());
        for_each_chunk_span(offset, len, chunk_size, chunk_index_entries.len(), |span| {
            let entry = &chunk_index_entries[span.index];
            match locate_chunk(blob_layout, entry.blkaddr, entry.device_id)? {
                ChunkLocation::Hole => {
                    resolver.push(Extent::new(
                        self.zero_file.as_raw_fd(),
                        0,
                        span.len,
                        span.file_pos,
                    ));
                }
                ChunkLocation::Blob { index, offset } => {
                    let blob_offset = offset
                        .checked_add(span.chunk_off)
                        .ok_or_else(|| Error::Overflow("blob fetch offset overflow".to_string()))?;
                    resolver.push_blob(
                        BlobRangeSpec {
                            index,
                            offset: blob_offset,
                            len: span.len,
                            source_offset: span.file_pos,
                        },
                        mode,
                    )?;
                }
                ChunkLocation::Local { .. } => {
                    return Err(Error::Unsupported(
                        "bootstrap-local file data is not supported by Node range API".to_string(),
                    ));
                }
            }
            Ok(())
        })?;

        Ok(resolver.finish())
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
        mtime: inode.mtime(reader.superblock().epoch()),
        mtime_nsec: inode.effective_mtime_nsec(reader.superblock().fixed_nsec()),
        rdev: inode.rdev(),
    })
}

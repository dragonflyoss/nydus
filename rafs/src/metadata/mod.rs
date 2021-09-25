// Copyright 2020 Ant Group. All rights reserved.
// Copyright (C) 2020 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Structs and Traits for RAFS file system meta data management.

use std::collections::HashSet;
use std::ffi::{OsStr, OsString};
use std::fmt::{Debug, Display, Formatter, Result as FmtResult};
use std::io::{Error, Result};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use fuse_backend_rs::abi::linux_abi::Attr;
use fuse_backend_rs::api::filesystem::{Entry, ROOT_ID};
use nydus_utils::digest::{self, RafsDigest};
use serde::Serialize;
use serde_with::{serde_as, DisplayFromStr};
use storage::compress;
use storage::device::v5::BlobV5ChunkInfo;
use storage::device::{BlobChunkInfo, BlobInfo, BlobIoVec};

use self::layout::v5::{RafsV5PrefetchTable, RafsV5SuperBlock, RafsV5SuperFlags};
use self::layout::{XattrName, XattrValue, RAFS_SUPER_VERSION_V4, RAFS_SUPER_VERSION_V5};
use self::noop::NoopSuperBlock;
use crate::fs::{RafsConfig, RAFS_DEFAULT_ATTR_TIMEOUT, RAFS_DEFAULT_ENTRY_TIMEOUT};
use crate::{RafsError, RafsIoReader, RafsIoWriter, RafsResult};

pub mod cached_v5;
pub mod direct_v5;
pub mod layout;
mod md_v5;
mod noop;

pub use crate::storage::{RAFS_DEFAULT_BLOCK_SIZE, RAFS_MAX_BLOCK_SIZE};

/// Maximum size of blob id string.
pub const RAFS_BLOB_ID_MAX_LENGTH: usize = 64;
/// Block size reported to fuse by get_attr()
pub const RAFS_INODE_BLOCKSIZE: u32 = 4096;
/// Maximum size of file name supported by rafs.
pub const RAFS_MAX_NAME: usize = 255;
/// Maximum size of the rafs metadata blob.
pub const RAFS_MAX_METADATA_SIZE: usize = 0x8000_0000;
/// File name for Unix current directory.
pub const DOT: &str = ".";
/// File name for Unix parent directory.
pub const DOTDOT: &str = "..";

/// Type of RAFS inode number.
pub type Inode = u64;

/// Trait to get information about inodes supported by the filesystem instance.
pub trait RafsSuperInodes {
    /// Get the maximum inode number supported by the filesystem instance.
    fn get_max_ino(&self) -> Inode;

    /// Get a `RafsInode` trait object for an inode, validating the inode content if requested.
    fn get_inode(&self, ino: Inode, digest_validate: bool) -> Result<Arc<dyn RafsInode>>;

    /// Validate the content of inode itself, optionally recursively validate into children.
    fn validate_digest(
        &self,
        inode: Arc<dyn RafsInode>,
        recursive: bool,
        digester: digest::Algorithm,
    ) -> Result<bool>;
}

/// Trait to get information about a Rafs filesystem instance.
pub trait RafsSuperBlobs {
    /// Get blob information for all blobs referenced by the filesystem instance.
    fn get_blobs(&self) -> Vec<Arc<BlobInfo>>;
}

/// Trait to access Rafs filesystem superblock and inodes.
pub trait RafsSuperBlock: RafsSuperBlobs + RafsSuperInodes + Send + Sync {
    /// Load the super block from a reader.
    fn load(&mut self, r: &mut RafsIoReader) -> Result<()>;

    /// Update Rafs filesystem metadata and storage backend.
    fn update(&self, r: &mut RafsIoReader) -> RafsResult<()>;

    /// Destroy a Rafs filesystem super block.
    fn destroy(&mut self);

    /// Get all blob information objects used by the filesystem.
    fn get_blob_infos(&self) -> Vec<Arc<BlobInfo>>;
}

/// Trait to access metadata and data for an inode.
///
/// The RAFS filesystem is a readonly filesystem, so does its inodes. The `RafsInode` trait acts
/// as field accessors for those readonly inodes, to hide implementation details.
pub trait RafsInode {
    /// Validate the node for data integrity.
    ///
    /// The inode object may be transmuted from a raw buffer, read from an external file, so the
    /// caller must validate it before accessing any fields.
    fn validate(&self) -> Result<()>;

    /// Get `Entry` of the inode.
    fn get_entry(&self) -> Entry;

    /// Get `Attr` of the inode.
    fn get_attr(&self) -> Attr;

    /// Get file name size of the inode.
    fn get_name_size(&self) -> u16;

    /// Get symlink target of the inode if it's a symlink.
    fn get_symlink(&self) -> Result<OsString>;

    /// Get size of symlink.
    fn get_symlink_size(&self) -> u16;

    /// Get child inode of a directory by name.
    fn get_child_by_name(&self, name: &OsStr) -> Result<Arc<dyn RafsInode>>;

    /// Get child inode of a directory by child index, child index starting at 0.
    fn get_child_by_index(&self, idx: u32) -> Result<Arc<dyn RafsInode>>;

    /// Get number of directory's child inode.
    fn get_child_count(&self) -> u32;

    /// Get the index into the inode table of the directory's first child.
    fn get_child_index(&self) -> Result<u32>;

    /// Get number of data chunk of a normal file.
    fn get_chunk_count(&self) -> u32;

    /// Get chunk info object for a chunk.
    fn get_chunk_info(&self, idx: u32) -> Result<Arc<dyn BlobV5ChunkInfo>>;

    /// Check whether the inode has extended attributes.
    fn has_xattr(&self) -> bool;

    /// Get the value of xattr with key `name`.
    fn get_xattr(&self, name: &OsStr) -> Result<Option<XattrValue>>;

    /// Get all xattr keys.
    fn get_xattrs(&self) -> Result<Vec<XattrName>>;

    /// Check whether the inode is a directory.
    fn is_dir(&self) -> bool;

    /// Check whether the inode is a symlink.
    fn is_symlink(&self) -> bool;

    /// Check whether the inode is a regular file.
    fn is_reg(&self) -> bool;

    /// Check whether the inode is a hardlink.
    fn is_hardlink(&self) -> bool;

    /// Get the inode number of the inode.
    fn ino(&self) -> u64;

    /// Get file name of the inode.
    fn name(&self) -> OsString;

    /// Get inode number of the parent directory.
    fn parent(&self) -> u64;

    /// Get real device number of the inode.
    fn rdev(&self) -> u32;

    /// Get flags of the inode.
    fn flags(&self) -> u64;

    /// Get project id associated with the inode.
    fn projid(&self) -> u32;

    /// Get data size of the inode.
    fn size(&self) -> u64;

    /// Check whether the inode has no content.
    fn is_empty_size(&self) -> bool {
        self.size() == 0
    }

    /// Get digest value of the inode metadata.
    fn get_digest(&self) -> RafsDigest;

    /// Collect all descendants of the inode for image building.
    fn collect_descendants_inodes(
        &self,
        descendants: &mut Vec<Arc<dyn RafsInode>>,
    ) -> Result<usize>;

    /// Allocate blob io vectors to read file data in range [offset, offset + size).
    fn alloc_bio_vecs(&self, offset: u64, size: usize, user_io: bool) -> Result<Vec<BlobIoVec>>;
}

/// Trait to store Rafs meta block and validate alignment.
pub trait RafsStore {
    /// Write the Rafs filesystem metadata to a writer.
    fn store(&self, w: &mut RafsIoWriter) -> Result<usize>;
}

/// Rafs filesystem meta-data cached from on disk RAFS super block.
#[serde_as]
#[derive(Clone, Copy, Debug, Serialize)]
pub struct RafsSuperMeta {
    /// Filesystem magic number.
    pub magic: u32,
    /// Filesystem version number.
    pub version: u32,
    /// Size of on disk super block.
    pub sb_size: u32,
    /// Inode number of root inode.
    pub root_inode: Inode,
    /// Filesystem block size.
    pub block_size: u32,
    /// Number of inodes in the filesystem.
    pub inodes_count: u64,
    #[serde_as(as = "DisplayFromStr")]
    /// V5: superblock flags for Rafs v5.
    pub flags: RafsV5SuperFlags,
    /// Number of inode entries in inode offset table.
    pub inode_table_entries: u32,
    /// Offset of the inode offset table into the metadata blob.
    pub inode_table_offset: u64,
    /// Size of blob information table.
    pub blob_table_size: u32,
    /// Offset of the blob information table into the metadata blob.
    pub blob_table_offset: u64,
    /// Size of extended blob information table.
    pub extended_blob_table_offset: u64,
    /// Offset of the extended blob information table into the metadata blob.
    pub extended_blob_table_entries: u32,
    /// Start of data prefetch range.
    pub blob_readahead_offset: u32,
    /// Size of data prefetch range.
    pub blob_readahead_size: u32,
    /// Offset of the inode prefetch table into the metadata blob.
    pub prefetch_table_offset: u64,
    /// Size of the inode prefetch table.
    pub prefetch_table_entries: u32,
    /// Default attribute timeout value.
    pub attr_timeout: Duration,
    /// Default inode timeout value.
    pub entry_timeout: Duration,
}

impl RafsSuperMeta {
    /// Check whether the explicit UID/GID feature has been enable or not.
    pub fn explicit_uidgid(&self) -> bool {
        if self.is_v4_v5() {
            self.flags.contains(RafsV5SuperFlags::EXPLICIT_UID_GID)
        } else {
            false
        }
    }

    /// Check whether the filesystem supports extended attribute or not.
    pub fn has_xattr(&self) -> bool {
        if self.is_v4_v5() {
            self.flags.contains(RafsV5SuperFlags::HAS_XATTR)
        } else {
            false
        }
    }
}

impl Default for RafsSuperMeta {
    fn default() -> Self {
        RafsSuperMeta {
            magic: 0,
            version: 0,
            sb_size: 0,
            inodes_count: 0,
            root_inode: 0,
            block_size: 0,
            flags: RafsV5SuperFlags::empty(),
            inode_table_entries: 0,
            inode_table_offset: 0,
            blob_table_size: 0,
            blob_table_offset: 0,
            extended_blob_table_offset: 0,
            extended_blob_table_entries: 0,
            blob_readahead_offset: 0,
            blob_readahead_size: 0,
            prefetch_table_offset: 0,
            prefetch_table_entries: 0,
            attr_timeout: Duration::from_secs(RAFS_DEFAULT_ATTR_TIMEOUT),
            entry_timeout: Duration::from_secs(RAFS_DEFAULT_ENTRY_TIMEOUT),
        }
    }
}

/// Rafs metadata working mode.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RafsMode {
    /// Directly mapping and accessing metadata into process by mmap().
    Direct,
    /// Read metadata into memory before using.
    Cached,
}

impl FromStr for RafsMode {
    type Err = Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "direct" => Ok(Self::Direct),
            "cached" => Ok(Self::Cached),
            _ => Err(einval!("rafs mode should be direct or cached")),
        }
    }
}

impl Display for RafsMode {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            Self::Direct => write!(f, "direct"),
            Self::Cached => write!(f, "cached"),
        }
    }
}

/// Cached Rafs super block and inode information.
pub struct RafsSuper {
    /// Rafs metadata working mode.
    pub mode: RafsMode,
    /// Whether validate data read from storage backend.
    pub validate_digest: bool,
    /// Cached metadata.
    pub meta: RafsSuperMeta,
    /// Rafs filesystem super block.
    pub superblock: Arc<dyn RafsSuperBlock>,
}

impl Default for RafsSuper {
    fn default() -> Self {
        Self {
            mode: RafsMode::Direct,
            validate_digest: false,
            meta: RafsSuperMeta::default(),
            superblock: Arc::new(NoopSuperBlock::new()),
        }
    }
}

impl RafsSuper {
    /// Create a new `RafsSuper` instance from a `RafsConfig` object.
    pub fn new(conf: &RafsConfig) -> Result<Self> {
        let mut rs = Self::default();

        match conf.mode.as_str() {
            "direct" => rs.mode = RafsMode::Direct,
            "cached" => rs.mode = RafsMode::Cached,
            _ => return Err(einval!("Rafs mode should be 'direct' or 'cached'")),
        }

        rs.validate_digest = conf.digest_validate;

        Ok(rs)
    }

    /// Update the filesystem metadata and storage backend.
    pub fn update(&self, r: &mut RafsIoReader) -> RafsResult<()> {
        let mut sb = RafsV5SuperBlock::new();

        r.read_exact(sb.as_mut())
            .map_err(|e| RafsError::ReadMetadata(e, "Updating meta".to_string()))?;
        self.superblock.update(r)
    }

    /// Destroy the filesystem super block.
    pub fn destroy(&mut self) {
        Arc::get_mut(&mut self.superblock)
            .expect("Inodes are no longer used.")
            .destroy();
    }

    /// Load RAFS metadata and optionally cache inodes.
    pub fn load(&mut self, r: &mut RafsIoReader) -> Result<()> {
        let mut sb = RafsV5SuperBlock::new();
        r.read_exact(sb.as_mut())?;
        if sb.detect() {
            if sb.is_rafs_v4v5() {
                return self.load_v4v5(r, &sb);
            }
        }

        Err(einval!("invalid superblock version number"))
    }

    /// Store RAFS metadata to backend storage.
    pub fn store(&self, w: &mut RafsIoWriter) -> Result<usize> {
        if self.meta.is_v4_v5() {
            return self.store_v4v5(w);
        }

        Err(einval!("invalid superblock version number"))
    }

    /// Get an inode from an inode number, optionally validating the inode metadata.
    pub fn get_inode(&self, ino: Inode, digest_validate: bool) -> Result<Arc<dyn RafsInode>> {
        self.superblock.get_inode(ino, digest_validate)
    }

    /// Get the maximum inode number supported by the filesystem instance.
    pub fn get_max_ino(&self) -> Inode {
        self.superblock.get_max_ino()
    }

    /// Convert an inode number to a file path.
    pub fn path_from_ino(&self, ino: Inode) -> Result<PathBuf> {
        if ino == ROOT_ID {
            return Ok(self.get_inode(ino, false)?.name().into());
        }

        let mut path = PathBuf::new();
        let mut cur_ino = ino;
        let mut inode;

        loop {
            inode = self.get_inode(cur_ino, false)?;
            let e: PathBuf = inode.name().into();
            path = e.join(path);

            if inode.ino() == ROOT_ID {
                break;
            } else {
                cur_ino = inode.parent();
            }
        }

        Ok(path)
    }

    /// Convert a file path to an inode number.
    pub fn ino_from_path(&self, f: &Path) -> Result<u64> {
        if f == Path::new("/") {
            return Ok(ROOT_ID);
        }

        if !f.starts_with("/") {
            return Err(einval!());
        }

        let mut parent = self.get_inode(ROOT_ID, self.validate_digest)?;

        let entries = f
            .components()
            .filter(|comp| *comp != Component::RootDir)
            .map(|comp| match comp {
                Component::Normal(name) => Some(name),
                Component::ParentDir => Some(OsStr::from_bytes(DOTDOT.as_bytes())),
                Component::CurDir => Some(OsStr::from_bytes(DOT.as_bytes())),
                _ => None,
            })
            .collect::<Vec<_>>();

        if entries.is_empty() {
            warn!("Path can't be parsed {:?}", f);
            return Err(enoent!());
        }

        for p in entries {
            if p.is_none() {
                error!("Illegal specified path {:?}", f);
                return Err(einval!());
            }

            // Safe because it already checks if p is None above.
            match parent.get_child_by_name(p.unwrap()) {
                Ok(p) => parent = p,
                Err(_) => {
                    warn!("File {:?} not in rafs", p.unwrap());
                    return Err(enoent!());
                }
            }
        }

        Ok(parent.ino())
    }

    //<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
    /// Prefetch filesystem data to improve performance.
    ///
    /// This is fs layer prefetch entry point where 2 kinds of prefetch can be started:
    /// 1. Static method from prefetch table hint:
    ///     Base on prefetch table which is persisted to bootstrap when building image.
    /// 2. Dynamic method from hint directory list specified when nydusd starts.
    ///     Specify as a directory list when rafs is being imported. No prefetch table has to be
    ///     involved.
    /// Each inode passed into should correspond to directory. And it already does the file type
    /// check inside.
    pub fn prefetch_hint_files(
        &self,
        r: &mut RafsIoReader,
        files: Option<Vec<Inode>>,
        fetcher: &dyn Fn(&mut BlobIoVec),
    ) -> RafsResult<()> {
        // Prefer to use the file list specified by daemon for prefetching, then
        // use the file list specified by builder for prefetching.
        if let Some(files) = files {
            // No need to prefetch blob data for each alias as they share the same range,
            // we do it once.
            let mut hardlinks: HashSet<u64> = HashSet::new();
            let mut head_desc = BlobIoVec {
                bi_size: 0,
                bi_flags: 0,
                bi_vec: Vec::new(),
            };

            // Try to prefetch according to the list of files specified by the
            // daemon's `--prefetch-files` option.
            for f_ino in files {
                self.prefetch_data(f_ino, &mut head_desc, &mut hardlinks, fetcher)
                    .map_err(|e| RafsError::Prefetch(e.to_string()))?;
            }
            // The left chunks whose size is smaller than 4MB will be fetched here.
            fetcher(&mut head_desc);
        } else if self.meta.is_v4_v5() {
            self.prefetch_data_v4v5(r, fetcher)?;
        } else {
            return Err(RafsError::Prefetch(
                "Unknown filesystem version, prefetch disabled".to_string(),
            ));
        }

        Ok(())
    }

    #[inline]
    fn prefetch_inode<F>(
        inode: &Arc<dyn RafsInode>,
        head_desc: &mut BlobIoVec,
        hardlinks: &mut HashSet<u64>,
        prefetcher: F,
    ) -> Result<()>
    where
        F: Fn(&mut BlobIoVec, bool),
    {
        // Check for duplicated hardlinks.
        if inode.is_hardlink() {
            if hardlinks.contains(&inode.ino()) {
                return Ok(());
            } else {
                hardlinks.insert(inode.ino());
            }
        }

        let descs = inode.alloc_bio_vecs(0, inode.size() as usize, false)?;
        for desc in descs {
            // Flush the pending prefetch if the next desc target a different blob.
            if !head_desc.has_same_blob(&desc) {
                prefetcher(head_desc, true);
            }
            head_desc.append(desc);
            prefetcher(head_desc, false);
        }

        Ok(())
    }

    fn prefetch_data<F>(
        &self,
        ino: u64,
        head_desc: &mut BlobIoVec,
        hardlinks: &mut HashSet<u64>,
        fetcher: F,
    ) -> Result<()>
    where
        F: Fn(&mut BlobIoVec),
    {
        let try_prefetch = |desc: &mut BlobIoVec, flush: bool| {
            // Issue a prefetch request since target is large enough.
            // As files belonging to the same directory are arranged in adjacent,
            // it should fetch a range of blob in batch.
            if flush || desc.bi_size >= (4 * RAFS_DEFAULT_BLOCK_SIZE) as usize {
                trace!("fetching head bio size {}", desc.bi_size);
                fetcher(desc);
                desc.reset();
            }
        };

        let inode = self
            .superblock
            .get_inode(ino, self.validate_digest)
            .map_err(|_e| enoent!("Can't find inode"))?;

        if inode.is_dir() {
            let mut descendants = Vec::new();
            // FIXME: Collecting descendants in DFS(Deep-First-Search) way impacts merging
            // possibility, which means a single Merging Request spans multiple directories.
            // But only files in the same directory are located closely in blob.
            let _ = inode.collect_descendants_inodes(&mut descendants)?;
            for i in descendants.iter() {
                Self::prefetch_inode(i, head_desc, hardlinks, try_prefetch)?;
            }
        } else if !inode.is_empty_size() {
            Self::prefetch_inode(&inode, head_desc, hardlinks, try_prefetch)?;
        }

        Ok(())
    }

    // The total size of all chunks carried by `desc` might exceed `expected_size`, this
    // method ensures the total size mustn't exceed `expected_size`. If it truly does,
    // just trim several trailing chunks from `desc`.
    fn steal_chunks(desc: &mut BlobIoVec, expected_size: u32) -> Option<&mut BlobIoVec> {
        enum State {
            All,
            None,
            Partial(usize),
        }

        let mut total = 0;
        let mut final_index = State::All;
        let len = desc.bi_vec.len();

        for (i, b) in desc.bi_vec.iter().enumerate() {
            let compressed_size = b.chunkinfo.compress_size();

            if compressed_size + total <= expected_size {
                total += compressed_size;
                continue;
            } else {
                if i != 0 {
                    final_index = State::Partial(i - 1);
                } else {
                    final_index = State::None;
                }
                break;
            }
        }

        match final_index {
            State::None => None,
            State::All => Some(desc),
            State::Partial(fi) => {
                for i in (fi + 1..len).rev() {
                    desc.bi_size -= std::cmp::min(desc.bi_vec[i].chunkinfo.uncompress_size() as usize, desc.bi_size);
                    desc.bi_vec.remove(i as usize);
                }
                Some(desc)
            }
        }
    }

    // For some kinds of storage backend, IO of size smaller than a certain size similar time.
    // Below method tries to amplify current rafs user io by appending more non-user io.
    // It checks whether left part of the file can fullfil `expected_size`.
    // If not, in rafs the file whose inode number is INO and another file whose inode number
    // is INO + 1 's are very likely to be arranged continuously. So we try to amply the user
    // IO by merge another file into.
    //
    pub fn carry_more_until(
        &self,
        inode: &dyn RafsInode,
        bound: u64,
        tail_chunk: &dyn BlobV5ChunkInfo,
        expected_size: u64,
    ) -> Result<Option<BlobIoVec>> {
        let mut left = expected_size;
        let inode_size = inode.size();
        let mut ra_desc = BlobIoVec::new();

        let extra_file_needed = if let Some(delta) = inode_size.checked_sub(bound) {
            let sz = std::cmp::min(delta, expected_size);
            let mut d = inode.alloc_bio_vecs(bound, sz as usize, false)?;
            assert_eq!(d.len(), 1);

            // It is possible that read size is beyond file size, so chunks vector is zero length.
            if !d[0].bi_vec.is_empty() {
                let ck = d[0].bi_vec[0].chunkinfo.clone();
                // Might be smaller than uncompressed size. It is user part.
                let trimming_size = d[0].bi_vec[0].size;
                let trimming = tail_chunk.compress_offset() == ck.compress_offset();
                // Stolen chunk bigger than expected size will involve more backend IO, thus
                // to slow down current user IO.
                if let Some(cks) = Self::steal_chunks(&mut d[0], left as u32) {
                    if trimming {
                        ra_desc.bi_vec.extend_from_slice(&cks.bi_vec[1..]);
                        ra_desc.bi_size += cks.bi_size;
                        ra_desc.bi_size -= trimming_size;
                    } else {
                        Some(&d.bi_vec[1].chunkinfo)
                    }
                } else {
                    Some(&d.bi_vec[0].chunkinfo)
                };

                if let Some(h) = head_cki {
                    // The first found potentially amplified chunk is not adjacent, abort!
                    if h.compress_offset()
                        != tail_chunk.compress_offset() + tail_chunk.compress_size() as u64
                    {
                        warn!("Discontinuous");
                        return Ok(None);
                    }

                    // Stolen chunk bigger than expected size will involve more backend IO, thus
                    // to slow down current user IO. The total compressed size of chunks from `alloc_bio_desc`
                    // might exceed expected_size, so steal the necessary parts.
                    if let Some(cks) = Self::steal_chunks(&mut d, sz as u32) {
                        if trimming {
                            ra_desc.bi_vec.extend_from_slice(&cks.bi_vec[1..]);
                            ra_desc.bi_size += cks.bi_size;
                            ra_desc.bi_size -= trimming_size;
                        } else {
                            ra_desc.bi_vec.append(&mut cks.bi_vec);
                            ra_desc.bi_size += cks.bi_size;
                        }
                    }
                    // Even all chunks are trimmed by `steal_chunks`, we still minus delta.
                    if delta >= expected_size {
                        false
                    } else {
                        left -= delta;
                        true
                    }
                } else {
                    true
                }
            } else {
                true
            }
        } else {
            true
        };

        if extra_file_needed {
            let mut next_ino = inode.ino() + 1;
            loop {
                let next_inode = self.get_inode(next_ino, false);
                if let Ok(ni) = next_inode {
                    if !ni.is_reg() {
                        next_ino = ni.ino() + 1;
                        continue;
                    }
                    let next_size = ni.size();
                    let sz = std::cmp::min(left, next_size);
                    // It is possible that a file has no contents.
                    if sz == 0 {
                        break;
                    }

                    let mut d = ni.alloc_bio_vecs(0, sz as usize, false)?;

                    if d.bi_vec.is_empty() {
                        warn!("A desc has no chunks appended");
                        break;
                    }

                    // Current file provides noting. The first found potentially amplified chunk is not adjacent, abort!
                    let prior_chunk = if ra_desc.bi_vec.is_empty() {
                        tail_chunk
                    } else {
                        // Safe to unwrap since already checked if empty
                        ra_desc.bi_vec.last().unwrap().chunkinfo.as_ref()
                    };

                    if d.bi_vec[0].chunkinfo.compress_offset()
                        != prior_chunk.compress_offset() + prior_chunk.compress_size() as u64
                    {
                        break;
                    }

                    // Stolen chunk bigger than expected size will involve more backend IO, thus
                    // to slow down current user IO.
                    if let Some(cks) = Self::steal_chunks(&mut d[0], sz as u32) {
                        ra_desc.bi_vec.append(&mut cks.bi_vec);
                        ra_desc.bi_size += cks.bi_size;
                    } else {
                        break;
                    }

                    // Even stolen chunks are truncated, still consume expected size.
                    left -= sz;
                    if left == 0 {
                        break;
                    }
                    next_ino = ni.ino() + 1;
                } else {
                    break;
                }
            }
        }

        if ra_desc.bi_size > 0 {
            assert!(!ra_desc.bi_vec.is_empty());
            Ok(Some(ra_desc))
        } else {
            Ok(None)
        }
    }
    //>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rafs_mode() {
        assert!(RafsMode::from_str("").is_err());
        assert!(RafsMode::from_str("directed").is_err());
        assert!(RafsMode::from_str("Direct").is_err());
        assert!(RafsMode::from_str("Cached").is_err());
        assert_eq!(RafsMode::from_str("direct").unwrap(), RafsMode::Direct);
        assert_eq!(RafsMode::from_str("cached").unwrap(), RafsMode::Cached);
        assert_eq!(&format!("{}", RafsMode::Direct), "direct");
        assert_eq!(&format!("{}", RafsMode::Cached), "cached");
    }
}

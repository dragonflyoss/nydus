// Copyright 2020 Ant Group. All rights reserved.
// Copyright (C) 2020 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Structs and Traits for RAFS file system meta data management.

use std::cmp;
use std::collections::{HashMap, HashSet};
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::io::{Error, Result, Seek, SeekFrom};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use serde_with::{serde_as, DisplayFromStr};

use fuse_rs::abi::linux_abi::Attr;
use fuse_rs::api::filesystem::Entry;
use fuse_rs::api::filesystem::ROOT_ID;

use self::direct::DirectMapping;
use self::layout::*;
use crate::fs::{RafsConfig, RAFS_DEFAULT_ATTR_TIMEOUT, RAFS_DEFAULT_ENTRY_TIMEOUT};
use crate::metadata::cached::CachedInodes;
use storage::compress;
use storage::device::{RafsBio, RafsBioDesc};
// FIXME: Move this definition to metadata crate if we have it some day.
pub use crate::storage::RAFS_DEFAULT_BLOCK_SIZE;
use crate::*;

mod noop;
use noop::NoopInodes;

use nydus_utils::digest::{self, RafsDigest};

pub mod cached;
pub mod direct;
pub mod extended;
pub mod layout;

pub use storage::device::{RafsBlobEntry, RafsChunkFlags, RafsChunkInfo};

pub const RAFS_BLOB_ID_MAX_LENGTH: usize = 72;
pub const RAFS_INODE_BLOCKSIZE: u32 = 4096;
pub const RAFS_MAX_NAME: usize = 255;
pub const RAFS_MAX_METADATA_SIZE: usize = 0x8000_0000;
const DOT: &str = ".";
const DOTDOT: &str = "..";

/// Type of RAFS inode.
pub type Inode = u64;

#[macro_export]
macro_rules! impl_getter_setter {
    ($G: ident, $S: ident, $F: ident, $U: ty) => {
        fn $G(&self) -> $U {
            self.$F
        }

        fn $S(&mut self, $F: $U) {
            self.$F = $F;
        }
    };
}

/// Cached Rafs super block bootstrap.
#[serde_as]
#[derive(Clone, Copy, Default, Debug, Serialize)]
pub struct RafsSuperMeta {
    pub magic: u32,
    pub version: u32,
    pub sb_size: u32,
    pub root_inode: Inode,
    pub block_size: u32,
    pub inodes_count: u64,
    // Use u64 as [u8; 8] => [.., digest::Algorithm, compress::Algorithm]
    #[serde_as(as = "DisplayFromStr")]
    pub flags: RafsSuperFlags,
    pub inode_table_entries: u32,
    pub inode_table_offset: u64,
    pub blob_table_size: u32,
    pub blob_table_offset: u64,
    pub extended_blob_table_offset: u64,
    pub extended_blob_table_entries: u32,
    pub blob_readahead_offset: u32,
    pub blob_readahead_size: u32,
    pub prefetch_table_offset: u64,
    pub prefetch_table_entries: u32,
    pub attr_timeout: Duration,
    pub entry_timeout: Duration,
}

impl RafsSuperMeta {
    pub fn get_compressor(&self) -> compress::Algorithm {
        self.flags.into()
    }
    pub fn get_digester(&self) -> digest::Algorithm {
        self.flags.into()
    }
    pub fn explicit_uidgid(&self) -> bool {
        self.flags.contains(RafsSuperFlags::EXPLICIT_UID_GID)
    }
    pub fn has_xattr(&self) -> bool {
        self.flags.contains(RafsSuperFlags::HAS_XATTR)
    }
}

#[derive(Clone)]
pub enum RafsMode {
    Direct,
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

impl fmt::Display for RafsMode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Direct => write!(f, "direct"),
            Self::Cached => write!(f, "cached"),
        }
    }
}

/// Cached Rafs super block and inode information.
pub struct RafsSuper {
    pub mode: RafsMode,
    pub digest_validate: bool,
    pub meta: RafsSuperMeta,
    pub inodes: Arc<dyn RafsSuperInodes + Sync + Send>,
}

impl Default for RafsSuper {
    fn default() -> Self {
        Self {
            mode: RafsMode::Direct,
            digest_validate: false,
            meta: RafsSuperMeta {
                magic: 0,
                version: 0,
                sb_size: 0,
                inodes_count: 0,
                root_inode: 0,
                block_size: 0,
                flags: RafsSuperFlags::empty(),
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
            },
            inodes: Arc::new(NoopInodes::new()),
        }
    }
}

impl RafsSuper {
    pub fn new(conf: &RafsConfig) -> Result<Self> {
        let mode = conf.mode.as_str();
        let digest_validate = conf.digest_validate;
        let mut rs = Self::default();

        match mode {
            "direct" => {
                rs.mode = RafsMode::Direct;
            }
            "cached" => {
                rs.mode = RafsMode::Cached;
            }
            _ => {
                return Err(einval!("Rafs mode should be 'direct' or 'cached'"));
            }
        }

        rs.digest_validate = digest_validate;

        Ok(rs)
    }

    pub fn destroy(&mut self) {
        Arc::get_mut(&mut self.inodes)
            .expect("Inodes are no longer used.")
            .destroy();
    }

    pub fn update(&self, r: &mut RafsIoReader) -> RafsResult<()> {
        let mut sb = OndiskSuperBlock::new();

        r.read_exact(sb.as_mut())
            .map_err(|e| RafsError::ReadMetadata(e, "Updating meta".to_string()))?;
        self.inodes.update(r)
    }

    /// Load RAFS super block and optionally cache inodes.
    pub fn load(&mut self, r: &mut RafsIoReader) -> Result<()> {
        let mut sb = OndiskSuperBlock::new();

        r.read_exact(sb.as_mut())?;
        sb.validate()?;

        self.meta.magic = sb.magic();
        self.meta.version = sb.version();
        self.meta.sb_size = sb.sb_size();
        self.meta.block_size = sb.block_size();
        self.meta.flags = RafsSuperFlags::from_bits(sb.flags())
            .ok_or_else(|| einval!(format!("invalid super flags {:x}", sb.flags())))?;
        self.meta.prefetch_table_offset = sb.prefetch_table_offset();
        self.meta.prefetch_table_entries = sb.prefetch_table_entries();

        info!("rafs superblock features: {}", self.meta.flags);

        match self.meta.version {
            RAFS_SUPER_VERSION_V4 => {
                self.meta.inodes_count = std::u64::MAX;
            }
            RAFS_SUPER_VERSION_V5 => {
                self.meta.inodes_count = sb.inodes_count();
                self.meta.inode_table_entries = sb.inode_table_entries();
                self.meta.inode_table_offset = sb.inode_table_offset();
                self.meta.blob_table_offset = sb.blob_table_offset();
                self.meta.blob_table_size = sb.blob_table_size();
                self.meta.extended_blob_table_offset = sb.extended_blob_table_offset();
                self.meta.extended_blob_table_entries = sb.extended_blob_table_entries();
            }
            _ => return Err(ebadf!("invalid superblock version number")),
        }

        match sb.version() {
            RAFS_SUPER_VERSION_V4 => {
                // TODO: Support Rafs v4
                unimplemented!();
            }
            RAFS_SUPER_VERSION_V5 => match self.mode {
                RafsMode::Direct => {
                    let mut inodes = DirectMapping::new(&self.meta, self.digest_validate);
                    inodes.load(r)?;
                    self.inodes = Arc::new(inodes);
                }
                RafsMode::Cached => {
                    let mut inodes = CachedInodes::new(self.meta, self.digest_validate);
                    inodes.load(r)?;
                    self.inodes = Arc::new(inodes);
                }
            },
            _ => return Err(einval!("invalid superblock version number")),
        }

        Ok(())
    }

    /// Store RAFS bootstrap to backend storage.
    pub fn store(&self, w: &mut RafsIoWriter) -> Result<usize> {
        let mut sb = OndiskSuperBlock::new();

        sb.set_magic(self.meta.magic);
        sb.set_version(self.meta.version);
        sb.set_sb_size(self.meta.sb_size);
        sb.set_block_size(self.meta.block_size);
        sb.set_flags(self.meta.flags.bits());

        match self.meta.version {
            RAFS_SUPER_VERSION_V4 => {}
            RAFS_SUPER_VERSION_V5 => {
                sb.set_inodes_count(self.meta.inodes_count);
                sb.set_inode_table_entries(self.meta.inode_table_entries);
                sb.set_inode_table_offset(self.meta.inode_table_offset);
            }
            _ => return Err(einval!("invalid superblock version number")),
        }

        sb.validate()?;
        w.write_all(sb.as_ref())?;

        trace!("written superblock: {}", &sb);

        Ok(std::mem::size_of::<OndiskSuperBlock>())
    }

    pub fn get_inode(&self, ino: Inode, digest_validate: bool) -> Result<Arc<dyn RafsInode>> {
        self.inodes.get_inode(ino, digest_validate)
    }

    pub fn get_max_ino(&self) -> Inode {
        self.inodes.get_max_ino()
    }

    fn build_prefetch_desc(
        &self,
        ino: u64,
        head_desc: &mut RafsBioDesc,
        hardlinks: &mut HashSet<u64>,
        fetcher: &dyn Fn(&mut RafsBioDesc),
    ) -> Result<()> {
        let try_prefetch = |desc: &mut RafsBioDesc| {
            // Issue a prefetch request since target is large enough.
            // As files belonging to the same directory are arranged in adjacent,
            // it should fetch a range of blob in batch.
            if desc.bi_size >= (4 * RAFS_DEFAULT_BLOCK_SIZE) as usize {
                trace!("fetching head bio size {}", desc.bi_size);
                fetcher(desc);
                desc.bi_size = 0;
                desc.bi_vec.truncate(0);
            }
        };

        match self.inodes.get_inode(ino, self.digest_validate) {
            Ok(inode) => {
                if inode.is_dir() {
                    let mut descendants = Vec::new();
                    // FIXME: Collecting descendants in DFS(Deep-First-Search) way impacts merging
                    // possibility, which means a single Merging Request spans multiple directories.
                    // But only files in the same directory are located closely in blob.
                    let _ = inode.collect_descendants_inodes(&mut descendants)?;
                    for i in descendants {
                        if i.is_hardlink() {
                            if hardlinks.contains(&i.ino()) {
                                continue;
                            } else {
                                hardlinks.insert(i.ino());
                            }
                        }
                        let mut desc = i.alloc_bio_desc(0, i.size() as usize)?;
                        head_desc.bi_vec.append(desc.bi_vec.as_mut());
                        head_desc.bi_size += desc.bi_size;

                        try_prefetch(head_desc);
                    }
                } else {
                    if inode.is_empty_size() {
                        return Ok(());
                    }
                    if inode.is_hardlink() {
                        if hardlinks.contains(&inode.ino()) {
                            return Ok(());
                        } else {
                            hardlinks.insert(inode.ino());
                        }
                    }
                    let mut desc = inode.alloc_bio_desc(0, inode.size() as usize)?;
                    head_desc.bi_vec.append(desc.bi_vec.as_mut());
                    head_desc.bi_size += desc.bi_size;

                    try_prefetch(head_desc);
                }
            }
            Err(_) => {
                return Err(enoent!("Can't find inode"));
            }
        }

        fetcher(head_desc);

        Ok(())
    }

    pub(crate) fn path_from_ino(&self, ino: Inode) -> Result<PathBuf> {
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

    pub(crate) fn ino_from_path(&self, f: &Path) -> Result<u64> {
        if f == Path::new("/") {
            return Ok(ROOT_ID);
        }

        if !f.starts_with("/") {
            return Err(einval!());
        }

        let mut parent = self.get_inode(ROOT_ID, self.digest_validate)?;

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

    /// This is fs layer prefetch entry point where 2 kinds of prefetch can be started:
    /// 1. Static method from prefetch table hint:
    ///     Base on prefetch table which is persisted to bootstrap when building image.
    /// 2. Dynamic method from hint directory list specified when nydusd starts.
    ///     Specify as a directory list when rafs is being imported. No prefetch table has to be
    ///     involved.
    /// Each inode passed into should correspond to directory. And it already does the file type
    /// check inside.
    ///
    pub fn prefetch_hint_files(
        &self,
        r: &mut RafsIoReader,
        files: Option<Vec<Inode>>,
        fetcher: &dyn Fn(&mut RafsBioDesc),
    ) -> RafsResult<()> {
        let hint_entries = self.meta.prefetch_table_entries as usize;

        if hint_entries == 0 && files.is_none() {
            return Err(RafsError::Prefetch(
                "Prefetch table is empty and no file was ever specified".to_string(),
            ));
        }

        // No need to prefetch blob data for each alias as they share the same range,
        // we do it once.
        let mut hardlinks: HashSet<u64> = HashSet::new();
        let mut prefetch_table = PrefetchTable::new();
        let mut head_desc = RafsBioDesc {
            bi_size: 0,
            bi_flags: 0,
            bi_vec: Vec::new(),
        };

        // Prefer to use the file list specified by daemon for prefetching, then
        // use the file list specified by builder for prefetching.
        if let Some(files) = files {
            // Try to prefetch according to the list of files specified by the
            // daemon's `--prefetch-files` option.
            for f_ino in files {
                self.build_prefetch_desc(f_ino, &mut head_desc, &mut hardlinks, fetcher)
                    .map_err(|e| RafsError::Prefetch(e.to_string()))?;
            }
        } else if hint_entries != 0 {
            // Try to prefetch according to the list of files specified by the
            // builder's `--prefetch-policy fs` option.
            prefetch_table
                .load_prefetch_table_from(r, self.meta.prefetch_table_offset, hint_entries)
                .map_err(|e| {
                    RafsError::Prefetch(format!(
                        "Failed in loading hint prefetch table at offset {}. {:?}",
                        self.meta.prefetch_table_offset, e
                    ))
                })?;

            for ino in prefetch_table.inodes {
                // Inode number 0 is invalid,
                // it was added because prefetch table has to be aligned.
                if ino == 0 {
                    break;
                }
                debug!("hint prefetch inode {}", ino);
                self.build_prefetch_desc(ino as u64, &mut head_desc, &mut hardlinks, fetcher)
                    .map_err(|e| RafsError::Prefetch(e.to_string()))?;
            }
        }

        Ok(())
    }
}

/// Trait to manage all inodes of a file system.
pub trait RafsSuperInodes {
    fn load(&mut self, r: &mut RafsIoReader) -> Result<()>;

    fn destroy(&mut self);

    fn get_inode(&self, ino: Inode, digest_validate: bool) -> Result<Arc<dyn RafsInode>>;

    fn get_max_ino(&self) -> Inode;

    fn get_blobs(&self) -> Vec<Arc<RafsBlobEntry>> {
        self.get_blob_table().get_all()
    }

    fn get_blob_table(&self) -> Arc<OndiskBlobTable>;

    fn update(&self, r: &mut RafsIoReader) -> RafsResult<()>;

    /// Validate child, chunk and symlink digest on inode tree.
    /// The chunk data digest for regular file will only validate on fs read.
    fn digest_validate(
        &self,
        inode: Arc<dyn RafsInode>,
        recursive: bool,
        digester: digest::Algorithm,
    ) -> Result<bool> {
        let child_count = inode.get_child_count();

        let expected_digest = inode.get_digest();
        let mut hasher = RafsDigest::hasher(digester);

        if inode.is_symlink() {
            hasher.digest_update(inode.get_symlink()?.as_bytes());
        } else if inode.is_reg() || inode.is_dir() {
            for idx in 0..child_count {
                if inode.is_dir() {
                    let child = inode.get_child_by_index(idx as u64)?;
                    if (child.is_reg() || child.is_symlink() || (recursive && child.is_dir()))
                        && !self.digest_validate(child.clone(), recursive, digester)?
                    {
                        return Ok(false);
                    }
                    let child_digest = child.get_digest();
                    let child_digest = child_digest.as_ref().as_ref();
                    hasher.digest_update(child_digest);
                } else {
                    let chunk = inode.get_chunk_info(idx)?;
                    let chunk_digest = chunk.block_id();
                    hasher.digest_update(chunk_digest.as_ref());
                }
            }
        }

        let digest = hasher.digest_finalize();
        let result = expected_digest == digest;
        if !result {
            error!(
                "invalid inode digest {}, expected {}, ino: {} name: {:?}",
                digest,
                expected_digest,
                inode.ino(),
                inode.name()
            );
        }

        Ok(result)
    }
}

/// Trait to access Rafs Inode Information.
pub trait RafsInode {
    /// Validate the object for safety.
    /// The object may be transmuted from a raw buffer read from an external file, so the caller
    /// must validate it before accessing any fields of the object.
    fn validate(&self) -> Result<()>;

    fn name(&self) -> OsString;
    fn get_symlink(&self) -> Result<OsString>;
    fn get_digest(&self) -> RafsDigest;
    fn get_child_by_name(&self, name: &OsStr) -> Result<Arc<dyn RafsInode>>;
    fn get_child_by_index(&self, idx: Inode) -> Result<Arc<dyn RafsInode>>;
    fn get_child_index(&self) -> Result<u32>;
    fn get_child_count(&self) -> u32;
    fn get_chunk_info(&self, idx: u32) -> Result<Arc<dyn RafsChunkInfo>>;
    fn get_blob_by_index(&self, idx: u32) -> Result<Arc<RafsBlobEntry>>;
    fn get_entry(&self) -> Entry;
    fn get_attr(&self) -> Attr;
    fn get_xattr(&self, name: &OsStr) -> Result<Option<XattrValue>>;
    fn get_xattrs(&self) -> Result<Vec<XattrName>>;
    fn get_blocksize(&self) -> u32;

    fn collect_descendants_inodes(
        &self,
        descendants: &mut Vec<Arc<dyn RafsInode>>,
    ) -> Result<usize>;

    fn is_dir(&self) -> bool;
    fn is_symlink(&self) -> bool;
    fn is_reg(&self) -> bool;
    fn is_hardlink(&self) -> bool;
    fn has_xattr(&self) -> bool;
    fn has_hole(&self) -> bool;

    fn rdev(&self) -> u32;
    fn ino(&self) -> u64;
    fn parent(&self) -> u64;
    fn size(&self) -> u64;
    fn is_empty_size(&self) -> bool {
        self.size() == 0
    }

    fn cast_ondisk(&self) -> Result<OndiskInode>;

    fn alloc_bio_desc(&self, offset: u64, size: usize) -> Result<RafsBioDesc> {
        // Do not process zero size bio
        let mut desc = RafsBioDesc::new();
        if size == 0 {
            return Ok(desc);
        }

        let end = offset
            .checked_add(size as u64)
            .ok_or_else(|| einval!("invalid read size"))?;

        let blksize = self.get_blocksize() as u64;
        let (index_start, index_end) = calculate_bio_chunk_index(
            offset,
            end,
            blksize,
            self.get_child_count(),
            self.has_hole(),
        );

        trace!(
            "alloc bio desc offset {} size {} i_size {} blksize {} index_start {} index_end {} i_child_count {}",
            offset, size, self.size(), blksize, index_start, index_end, self.get_child_count()
        );

        for idx in index_start..index_end {
            let chunk = self.get_chunk_info(idx)?;
            let blob = self.get_blob_by_index(chunk.blob_index())?;
            if !add_chunk_to_bio_desc(offset, end, chunk, &mut desc, blksize as u32, blob) {
                break;
            }
        }

        Ok(desc)
    }
}

/// Add a new bio covering the IO range into the provided bio desc. Returns
/// true if caller should continue checking more chunks.
///
/// offset: IO offset to the file start, inclusive.
/// end: IO end to the file start, exclusive.
/// chunk: a data chunk overlapping with the IO range.
/// desc: the targeting bio desc.
/// blksize: chunk size.
/// blob_id: chunk data blob id.
pub(crate) fn add_chunk_to_bio_desc(
    offset: u64,
    end: u64,
    chunk: Arc<dyn RafsChunkInfo>,
    desc: &mut RafsBioDesc,
    blksize: u32,
    blob: Arc<RafsBlobEntry>,
) -> bool {
    if offset >= (chunk.file_offset() + chunk.decompress_size() as u64) {
        return true;
    }
    if end <= chunk.file_offset() {
        return false;
    }

    let chunk_start = if offset > chunk.file_offset() {
        offset - chunk.file_offset()
    } else {
        0
    };
    let chunk_end = if end < (chunk.file_offset() + chunk.decompress_size() as u64) {
        end - chunk.file_offset()
    } else {
        chunk.decompress_size() as u64
    };

    let bio = RafsBio::new(
        chunk,
        blob,
        chunk_start as u32,
        (chunk_end - chunk_start) as usize,
        blksize,
    );

    desc.bi_size += bio.size;
    desc.bi_vec.push(bio);
    true
}

/// Calculate bio chunk indices that overlaps with the provided IO range.
///
/// offset: IO offset to the file start, inclusive.
/// end: IO end to the file start, exclusive.
/// blksize: chunk block size.
/// has_hole: whether a file has holes in it.
pub(crate) fn calculate_bio_chunk_index(
    offset: u64,
    end: u64,
    blksize: u64,
    chunk_cnt: u32,
    has_hole: bool,
) -> (u32, u32) {
    debug_assert!(offset < end);

    let index_start = if !has_hole {
        (offset / blksize) as u32
    } else {
        0
    };
    let index_end = if !has_hole {
        cmp::min(((end - 1) / blksize) as u32 + 1, chunk_cnt)
    } else {
        chunk_cnt
    };

    (index_start, index_end)
}

/// Trait to store Rafs meta block and validate alignment.
pub trait RafsStore {
    fn store_inner(&self, w: &mut RafsIoWriter) -> Result<usize>;
    fn store(&self, w: &mut RafsIoWriter) -> Result<usize> {
        let size = self.store_inner(w)?;
        let cur = w.seek(SeekFrom::Current(0))?;
        if (size & (RAFS_ALIGNMENT - 1) != 0) || (cur & (RAFS_ALIGNMENT as u64 - 1) != 0) {
            return Err(einval!("unaligned data"));
        }
        Ok(size)
    }
}

#[cfg(test)]
mod tests {
    use crate::metadata::{add_chunk_to_bio_desc, calculate_bio_chunk_index};
    use nydus_utils::digest::RafsDigest;
    use std::sync::Arc;
    use storage::device::RafsBioDesc;
    use storage::device::{RafsBlobEntry, RafsChunkFlags, RafsChunkInfo};
    use storage::impl_getter;

    #[derive(Default, Copy, Clone)]
    struct MockChunkInfo {
        pub block_id: RafsDigest,
        pub blob_index: u32,
        pub flags: RafsChunkFlags,
        pub compress_size: u32,
        pub decompress_size: u32,
        pub compress_offset: u64,
        pub decompress_offset: u64,
        pub file_offset: u64,
        pub index: u32,
        pub reserved: u32,
    }

    impl MockChunkInfo {
        fn new() -> Self {
            MockChunkInfo::default()
        }
    }

    impl RafsChunkInfo for MockChunkInfo {
        fn block_id(&self) -> &RafsDigest {
            &self.block_id
        }
        fn is_compressed(&self) -> bool {
            self.flags.contains(RafsChunkFlags::COMPRESSED)
        }
        fn is_hole(&self) -> bool {
            self.flags.contains(RafsChunkFlags::HOLECHUNK)
        }
        impl_getter!(blob_index, blob_index, u32);
        impl_getter!(index, index, u32);
        impl_getter!(compress_offset, compress_offset, u64);
        impl_getter!(compress_size, compress_size, u32);
        impl_getter!(decompress_offset, decompress_offset, u64);
        impl_getter!(decompress_size, decompress_size, u32);
        impl_getter!(file_offset, file_offset, u64);
        impl_getter!(flags, flags, RafsChunkFlags);
    }

    #[test]
    fn test_add_chunk_to_bio_desc() {
        let mut chunk = MockChunkInfo::new();
        let offset = 4096;
        let size: u64 = 1024;
        // [offset, offset + size)
        chunk.file_offset = offset;
        chunk.decompress_size = size as u32;

        // (offset, end, expected_chunk_start, expected_size)
        let data = vec![
            // Non-overlapping IO
            (0, 0, 0, 0, false),
            (0, offset, 0, 0, false),
            (offset + size, 0, 0, 0, true),
            (offset + size + 1, 0, 0, 0, true),
            // Overlapping IO
            (0, offset + 1, 0, 1, true),
            (0, offset + size, 0, size, true),
            (0, offset + size + 1, 0, size, true),
            (0, offset + size - 1, 0, size - 1, true),
            (offset, offset + 1, 0, 1, true),
            (offset, offset + size, 0, size, true),
            (offset, offset + size - 1, 0, size - 1, true),
            (offset, offset + size + 1, 0, size, true),
            (offset + 1, offset + 2, 1, 1, true),
            (offset + 1, offset + size, 1, size - 1, true),
            (offset + 1, offset + size - 1, 1, size - 2, true),
            (offset + 1, offset + size + 1, 1, size - 1, true),
        ];

        for (offset, end, expected_chunk_start, expected_size, result) in data.iter() {
            let mut desc = RafsBioDesc::new();
            let res = add_chunk_to_bio_desc(
                *offset,
                *end,
                Arc::new(chunk),
                &mut desc,
                100,
                Arc::new(RafsBlobEntry {
                    chunk_count: 0,
                    readahead_offset: 0,
                    readahead_size: 0,
                    blob_id: String::from("blobid"),
                    blob_index: 0,
                    blob_cache_size: 0,
                }),
            );
            assert_eq!(*result, res);
            if !desc.bi_vec.is_empty() {
                assert_eq!(desc.bi_vec.len(), 1);
                let bio = &desc.bi_vec[0];
                assert_eq!(*expected_chunk_start, bio.offset);
                assert_eq!(*expected_size as usize, bio.size);
            }
        }
    }

    #[test]
    fn test_calculate_bio_chunk_index() {
        let (blksize, chunk_cnt) = (1024, 4);

        let io_range: Vec<(u64, u64, u32, u64)> = vec![
            (0, 1, 0, 1),
            (0, blksize - 1, 0, 1),
            (0, blksize, 0, 1),
            (0, blksize + 1, 0, 2),
            (0, blksize * chunk_cnt, 0, chunk_cnt),
            (0, blksize * chunk_cnt + 1, 0, chunk_cnt),
            (0, blksize * chunk_cnt - 1, 0, chunk_cnt),
            (blksize - 1, 1, 0, 1),
            (blksize - 1, 2, 0, 2),
            (blksize - 1, 3, 0, 2),
            (blksize - 1, blksize - 1, 0, 2),
            (blksize - 1, blksize, 0, 2),
            (blksize - 1, blksize + 1, 0, 2),
            (blksize - 1, blksize * chunk_cnt, 0, chunk_cnt),
            (blksize, 1, 1, 2),
            (blksize, 2, 1, 2),
            (blksize, blksize - 1, 1, 2),
            (blksize, blksize + 1, 1, 3),
            (blksize, blksize + 2, 1, 3),
            (blksize, blksize * chunk_cnt, 1, chunk_cnt),
            (blksize + 1, 1, 1, 2),
            (blksize + 1, blksize - 2, 1, 2),
            (blksize + 1, blksize - 1, 1, 2),
            (blksize + 1, blksize, 1, 3),
            (blksize + 1, blksize * chunk_cnt, 1, chunk_cnt),
        ];

        for (io_start, io_size, expected_start, expected_end) in io_range.iter() {
            let (start, end) = calculate_bio_chunk_index(
                *io_start,
                *io_start + *io_size,
                blksize,
                chunk_cnt as u32,
                false,
            );

            assert_eq!(start, *expected_start);
            assert_eq!(end, *expected_end as u32);
        }
    }
}

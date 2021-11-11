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

use serde::Serialize;
use serde_with::{serde_as, DisplayFromStr};

use fuse_backend_rs::abi::linux_abi::Attr;
use fuse_backend_rs::api::filesystem::{Entry, ROOT_ID};
use nydus_utils::digest::{self, RafsDigest};
use storage::compress;
use storage::device::{RafsBioDesc, RafsBlobEntry, RafsChunkInfo};

use self::cached_v5::CachedSuperBlockV5;
use self::direct_v5::DirectSuperBlockV5;
use self::layout::v5::{RafsV5BlobTable, RafsV5PrefetchTable, RafsV5SuperBlock};
use self::layout::{XattrName, XattrValue, RAFS_SUPER_VERSION_V4, RAFS_SUPER_VERSION_V5};
use self::noop::NoopSuperBlock;
use crate::fs::{RafsConfig, RAFS_DEFAULT_ATTR_TIMEOUT, RAFS_DEFAULT_ENTRY_TIMEOUT};
use crate::{RafsError, RafsIoReader, RafsIoWriter, RafsResult};

pub mod cached_v5;
pub mod direct_v5;
pub mod layout;
mod noop;

pub use crate::storage::{RAFS_DEFAULT_BLOCK_SIZE, RAFS_MAX_BLOCK_SIZE};

pub const RAFS_BLOB_ID_MAX_LENGTH: usize = 72;
pub const RAFS_INODE_BLOCKSIZE: u32 = 4096;
pub const RAFS_MAX_NAME: usize = 255;
pub const RAFS_MAX_METADATA_SIZE: usize = 0x8000_0000;
pub const DOT: &str = ".";
pub const DOTDOT: &str = "..";

/// Type of RAFS inode.
pub type Inode = u64;

bitflags! {
    #[derive(Serialize)]
    pub struct RafsSuperFlags: u64 {
        /// Data chunks are not compressed.
        const COMPRESS_NONE = 0x0000_0001;
        /// Data chunks are compressed with lz4_block.
        const COMPRESS_LZ4_BLOCK = 0x0000_0002;
        /// Use blake3 hash algorithm to calculate digest.
        const DIGESTER_BLAKE3 = 0x0000_0004;
        /// Use sha256 hash algorithm to calculate digest.
        const DIGESTER_SHA256 = 0x0000_0008;
        /// Inode has explicit uid gid fields.
        /// If unset, use nydusd process euid/egid for all
        /// inodes at runtime.
        const EXPLICIT_UID_GID = 0x0000_0010;
        /// Some inode has xattr.
        /// Rafs may return ENOSYS for getxattr/listxattr calls if unset.
        const HAS_XATTR = 0x0000_0020;
        // Data chunks are compressed with gzip
        const COMPRESS_GZIP = 0x0000_0040;
    }
}

impl Default for RafsSuperFlags {
    fn default() -> Self {
        RafsSuperFlags::empty()
    }
}

impl Display for RafsSuperFlags {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "{}", format!("{:?}", self))?;
        Ok(())
    }
}

impl From<RafsSuperFlags> for digest::Algorithm {
    fn from(flags: RafsSuperFlags) -> Self {
        match flags {
            x if x.contains(RafsSuperFlags::DIGESTER_BLAKE3) => digest::Algorithm::Blake3,
            x if x.contains(RafsSuperFlags::DIGESTER_SHA256) => digest::Algorithm::Sha256,
            _ => digest::Algorithm::Blake3,
        }
    }
}

impl From<digest::Algorithm> for RafsSuperFlags {
    fn from(d: digest::Algorithm) -> RafsSuperFlags {
        match d {
            digest::Algorithm::Blake3 => RafsSuperFlags::DIGESTER_BLAKE3,
            digest::Algorithm::Sha256 => RafsSuperFlags::DIGESTER_SHA256,
        }
    }
}

impl From<RafsSuperFlags> for compress::Algorithm {
    fn from(flags: RafsSuperFlags) -> Self {
        match flags {
            x if x.contains(RafsSuperFlags::COMPRESS_NONE) => compress::Algorithm::None,
            x if x.contains(RafsSuperFlags::COMPRESS_LZ4_BLOCK) => compress::Algorithm::Lz4Block,
            x if x.contains(RafsSuperFlags::COMPRESS_GZIP) => compress::Algorithm::GZip,
            _ => compress::Algorithm::Lz4Block,
        }
    }
}

impl From<compress::Algorithm> for RafsSuperFlags {
    fn from(c: compress::Algorithm) -> RafsSuperFlags {
        match c {
            compress::Algorithm::None => RafsSuperFlags::COMPRESS_NONE,
            compress::Algorithm::Lz4Block => RafsSuperFlags::COMPRESS_LZ4_BLOCK,
            compress::Algorithm::GZip => RafsSuperFlags::COMPRESS_GZIP,
        }
    }
}

/// Rafs filesystem meta-data cached from RAFS super block on disk.
#[serde_as]
#[derive(Clone, Copy, Debug, Serialize)]
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
    pub fn is_v4_v5(&self) -> bool {
        self.version == RAFS_SUPER_VERSION_V4 || self.version == RAFS_SUPER_VERSION_V5
    }

    pub fn get_compressor(&self) -> compress::Algorithm {
        if self.is_v4_v5() {
            self.flags.into()
        } else {
            compress::Algorithm::None
        }
    }

    pub fn get_digester(&self) -> digest::Algorithm {
        if self.is_v4_v5() {
            self.flags.into()
        } else {
            digest::Algorithm::Blake3
        }
    }

    pub fn explicit_uidgid(&self) -> bool {
        if self.is_v4_v5() {
            self.flags.contains(RafsSuperFlags::EXPLICIT_UID_GID)
        } else {
            false
        }
    }

    pub fn has_xattr(&self) -> bool {
        if self.is_v4_v5() {
            self.flags.contains(RafsSuperFlags::HAS_XATTR)
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
        }
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
    pub mode: RafsMode,
    pub validate_digest: bool,
    pub meta: RafsSuperMeta,
    pub superblock: Arc<dyn RafsSuperBlock + Sync + Send>,
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
    pub fn new(conf: &RafsConfig) -> Result<Self> {
        let mut rs = Self::default();

        match conf.mode.as_str() {
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

        rs.validate_digest = conf.digest_validate;

        Ok(rs)
    }

    pub fn destroy(&mut self) {
        Arc::get_mut(&mut self.superblock)
            .expect("Inodes are no longer used.")
            .destroy();
    }

    pub fn update(&self, r: &mut RafsIoReader) -> RafsResult<()> {
        let mut sb = RafsV5SuperBlock::new();

        r.read_exact(sb.as_mut())
            .map_err(|e| RafsError::ReadMetadata(e, "Updating meta".to_string()))?;
        self.superblock.update(r)
    }

    /// Load RAFS super block and optionally cache inodes.
    pub fn load(&mut self, r: &mut RafsIoReader) -> Result<()> {
        let mut sb = RafsV5SuperBlock::new();
        r.read_exact(sb.as_mut())?;
        if sb.detect() {
            return self.load_v4v5(r, &sb);
        }

        Err(einval!("invalid superblock version number"))
    }

    /// Store RAFS bootstrap to backend storage.
    pub fn store(&self, w: &mut RafsIoWriter) -> Result<usize> {
        if self.meta.is_v4_v5() {
            return self.store_v4v5(w);
        }

        Err(einval!("invalid superblock version number"))
    }

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
        fetcher: &dyn Fn(&mut RafsBioDesc),
    ) -> RafsResult<()> {
        // Prefer to use the file list specified by daemon for prefetching, then
        // use the file list specified by builder for prefetching.
        if let Some(files) = files {
            // No need to prefetch blob data for each alias as they share the same range,
            // we do it once.
            let mut hardlinks: HashSet<u64> = HashSet::new();
            let mut head_desc = RafsBioDesc {
                bi_size: 0,
                bi_flags: 0,
                bi_vec: Vec::new(),
            };

            // Try to prefetch according to the list of files specified by the
            // daemon's `--prefetch-files` option.
            for f_ino in files {
                self.build_prefetch_desc_v4v5(f_ino, &mut head_desc, &mut hardlinks, fetcher)
                    .map_err(|e| RafsError::Prefetch(e.to_string()))?;
            }
            // The left chunks whose size is smaller than 4MB will be fetched here.
            fetcher(&mut head_desc);
            Ok(())
        } else if self.meta.is_v4_v5() {
            self.prefetch_v4v5(r, fetcher)
        } else {
            Err(RafsError::Prefetch(
                "Unknown filesystem version, prefetch disabled".to_string(),
            ))
        }
    }

    pub fn get_inode(&self, ino: Inode, digest_validate: bool) -> Result<Arc<dyn RafsInode>> {
        self.superblock.get_inode(ino, digest_validate)
    }

    pub fn get_max_ino(&self) -> Inode {
        self.superblock.get_max_ino()
    }

    fn load_v4v5(&mut self, r: &mut RafsIoReader, sb: &RafsV5SuperBlock) -> Result<()> {
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
                    let mut inodes = DirectSuperBlockV5::new(&self.meta, self.validate_digest);
                    inodes.load(r)?;
                    self.superblock = Arc::new(inodes);
                }
                RafsMode::Cached => {
                    let mut inodes = CachedSuperBlockV5::new(self.meta, self.validate_digest);
                    inodes.load(r)?;
                    self.superblock = Arc::new(inodes);
                }
            },
            _ => return Err(einval!("invalid superblock version number")),
        }

        Ok(())
    }

    fn store_v4v5(&self, w: &mut RafsIoWriter) -> Result<usize> {
        let mut sb = RafsV5SuperBlock::new();

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

        Ok(std::mem::size_of::<RafsV5SuperBlock>())
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

    fn build_prefetch_desc_v4v5(
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

        match self.superblock.get_inode(ino, self.validate_digest) {
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
                        let mut desc = i.alloc_bio_desc(0, i.size() as usize, false)?;
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
                    let mut desc = inode.alloc_bio_desc(0, inode.size() as usize, false)?;
                    head_desc.bi_vec.append(desc.bi_vec.as_mut());
                    head_desc.bi_size += desc.bi_size;

                    try_prefetch(head_desc);
                }
            }
            Err(_) => {
                return Err(enoent!("Can't find inode"));
            }
        }

        Ok(())
    }

    fn prefetch_v4v5(
        &self,
        r: &mut RafsIoReader,
        fetcher: &dyn Fn(&mut RafsBioDesc),
    ) -> RafsResult<()> {
        let hint_entries = self.meta.prefetch_table_entries as usize;
        if hint_entries == 0 {
            return Err(RafsError::Prefetch(
                "Prefetch table is empty and no file was ever specified".to_string(),
            ));
        }

        let mut prefetch_table = RafsV5PrefetchTable::new();
        let mut hardlinks: HashSet<u64> = HashSet::new();
        let mut head_desc = RafsBioDesc {
            bi_size: 0,
            bi_flags: 0,
            bi_vec: Vec::new(),
        };

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
            self.build_prefetch_desc_v4v5(ino as u64, &mut head_desc, &mut hardlinks, fetcher)
                .map_err(|e| RafsError::Prefetch(e.to_string()))?;
        }
        // The left chunks whose size is smaller than 4MB will be fetched here.
        fetcher(&mut head_desc);

        Ok(())
    }

    // The total size of all chunks carried by `desc` might exceed `expected_size`, this
    // method ensures the total size mustn't exceed `expected_size`. If it truly does,
    // just trim several trailing chunks from `desc`.
    fn steal_chunks(desc: &mut RafsBioDesc, expected_size: u32) -> Option<&mut RafsBioDesc> {
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
                    desc.bi_size -= std::cmp::min(desc.bi_vec[i].size, desc.bi_size);
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
        tail_chunk: &dyn RafsChunkInfo,
        expected_size: u64,
    ) -> Result<Option<RafsBioDesc>> {
        let mut left = expected_size;
        let inode_size = inode.size();
        let mut ra_desc = RafsBioDesc::new();

        let extra_file_needed = if let Some(delta) = inode_size.checked_sub(bound) {
            let sz = std::cmp::min(delta, expected_size);
            let mut d = inode.alloc_bio_desc(bound, sz as usize, false)?;

            // It is possible that read size is beyond file size, so chunks vector is zero length.
            if !d.bi_vec.is_empty() {
                let ck = d.bi_vec[0].chunkinfo.clone();
                // Might be smaller than decompress size. It is user part.
                let trimming_size = d.bi_vec[0].size;
                let head_chunk = ck.as_ref();
                let trimming = tail_chunk.compress_offset() == head_chunk.compress_offset();

                let head_cki = if trimming {
                    if d.bi_vec.len() == 1 {
                        // The first chunk is already requested by user IO. For amplification, we
                        // must move on to next file to find more continuous chunks
                        None
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

                    let mut d = ni.alloc_bio_desc(0, sz as usize, false)?;

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
                    if let Some(cks) = Self::steal_chunks(&mut d, sz as u32) {
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
}

pub trait RafsSuperInodes {
    fn get_max_ino(&self) -> Inode;

    fn get_inode(&self, ino: Inode, digest_validate: bool) -> Result<Arc<dyn RafsInode>>;

    fn validate_digest(
        &self,
        inode: Arc<dyn RafsInode>,
        recursive: bool,
        digester: digest::Algorithm,
    ) -> Result<bool>;
}

pub trait RafsSuperBlobs {
    fn get_blobs(&self) -> Vec<Arc<RafsBlobEntry>> {
        self.get_blob_table().get_all()
    }

    fn get_blob_table(&self) -> Arc<RafsV5BlobTable>;
}

pub trait RafsSuperBlock: RafsSuperBlobs + RafsSuperInodes {
    fn load(&mut self, r: &mut RafsIoReader) -> Result<()>;

    fn update(&self, r: &mut RafsIoReader) -> RafsResult<()>;

    fn destroy(&mut self);
}

/// Readonly accessors for RAFS filesystem inodes.
///
/// The RAFS filesystem is a readonly filesystem, so does its inodes. The `RafsInode` trait acts
/// as field accessors for those readonly inodes, to hide implementation details.
pub trait RafsInode {
    /// Validate the node for data integrity.
    ///
    /// The inode object may be transmuted from a raw buffer, read from an external file, so the
    /// caller must validate it before accessing any fields.
    fn validate(&self) -> Result<()>;

    fn get_entry(&self) -> Entry;
    fn get_attr(&self) -> Attr;
    fn get_name_size(&self) -> u16;
    fn get_symlink(&self) -> Result<OsString>;
    fn get_symlink_size(&self) -> u16;
    fn get_child_by_name(&self, name: &OsStr) -> Result<Arc<dyn RafsInode>>;
    fn get_child_by_index(&self, idx: Inode) -> Result<Arc<dyn RafsInode>>;
    fn get_child_index(&self) -> Result<u32>;
    fn get_child_count(&self) -> u32;
    fn get_chunk_info(&self, idx: u32) -> Result<Arc<dyn RafsChunkInfo>>;
    fn has_xattr(&self) -> bool;
    fn get_xattr(&self, name: &OsStr) -> Result<Option<XattrValue>>;
    fn get_xattrs(&self) -> Result<Vec<XattrName>>;

    fn is_dir(&self) -> bool;
    fn is_symlink(&self) -> bool;
    fn is_reg(&self) -> bool;
    fn is_hardlink(&self) -> bool;

    fn ino(&self) -> u64;
    fn name(&self) -> OsString;
    fn parent(&self) -> u64;
    fn rdev(&self) -> u32;
    fn flags(&self) -> u64;
    fn projid(&self) -> u32;
    fn size(&self) -> u64;
    fn is_empty_size(&self) -> bool {
        self.size() == 0
    }

    fn get_digest(&self) -> RafsDigest;
    fn collect_descendants_inodes(
        &self,
        descendants: &mut Vec<Arc<dyn RafsInode>>,
    ) -> Result<usize>;

    fn alloc_bio_desc(&self, offset: u64, size: usize, user_io: bool) -> Result<RafsBioDesc>;
}

/// Trait to store Rafs meta block and validate alignment.
pub trait RafsStore {
    fn store(&self, w: &mut RafsIoWriter) -> Result<usize>;
}

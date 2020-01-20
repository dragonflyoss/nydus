// Copyright 2020 Ant Financial. All rights reserved.
// Copyright (C) 2020 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Structs and Traits for RAFS file system meta data management.

use std::collections::{HashMap, HashSet};
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::io::{Error, Result, Seek, SeekFrom};
use std::os::unix::ffi::OsStrExt;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use fuse_rs::abi::linux_abi::Attr;
use fuse_rs::api::filesystem::Entry;

use self::digest::RafsDigest;
use self::direct::DirectMapping;
use self::layout::*;
use self::noop::NoopInodes;
use crate::fs::{RafsConfig, RAFS_DEFAULT_ATTR_TIMEOUT, RAFS_DEFAULT_ENTRY_TIMEOUT};
use crate::metadata::cached::CachedInodes;
use crate::storage::compress;
use crate::storage::device::{RafsBio, RafsBioDesc};
use crate::*;

use nydus_utils::{ebadf, einval, enoent};

pub mod cached;
pub mod digest;
pub mod direct;
pub mod layout;
pub mod noop;

pub const RAFS_DIGEST_LENGTH: usize = 32;
pub const RAFS_BLOB_ID_MAX_LENGTH: usize = 72;
pub const RAFS_INODE_BLOCKSIZE: u32 = 4096;
pub const RAFS_MAX_NAME: usize = 255;
pub const RAFS_DEFAULT_BLOCK_SIZE: u64 = 1024 * 1024;
pub const RAFS_MAX_METADATA_SIZE: usize = 0x8000_0000;

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

#[macro_export]
macro_rules! impl_getter {
    ($G: ident, $F: ident, $U: ty) => {
        fn $G(&self) -> $U {
            self.$F
        }
    };
}

/// Cached Rafs super block bootstrap.
#[derive(Clone, Copy, Default, Debug)]
pub struct RafsSuperMeta {
    pub magic: u32,
    pub version: u32,
    pub sb_size: u32,
    pub root_inode: Inode,
    pub block_size: u32,
    pub inodes_count: u64,
    // Use u64 as [u8; 8] => [.., digest::Algorithm, compress::Algorithm]
    pub flags: RafsSuperFlags,
    pub inode_table_entries: u32,
    pub inode_table_offset: u64,
    pub blob_table_size: u32,
    pub blob_table_offset: u64,
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
    pub inodes: Box<dyn RafsSuperInodes + Sync + Send>,
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
                blob_readahead_offset: 0,
                blob_readahead_size: 0,
                prefetch_table_offset: 0,
                prefetch_table_entries: 0,
                attr_timeout: Duration::from_secs(RAFS_DEFAULT_ATTR_TIMEOUT),
                entry_timeout: Duration::from_secs(RAFS_DEFAULT_ENTRY_TIMEOUT),
            },
            inodes: Box::new(NoopInodes::new()),
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
        self.inodes.destroy();
    }

    pub fn update(&self, r: &mut RafsIoReader) -> Result<()> {
        let mut sb = OndiskSuperBlock::new();

        r.read_exact(sb.as_mut())?;
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
                    let mut inodes = Box::new(DirectMapping::new(&self.meta, self.digest_validate));
                    inodes.load(r)?;
                    self.inodes = inodes;
                }
                RafsMode::Cached => {
                    r.seek(SeekFrom::Start(sb.blob_table_offset()))?;
                    let mut blob_table = OndiskBlobTable::new();
                    blob_table.load(r, sb.blob_table_size() as usize)?;

                    let mut inodes = Box::new(CachedInodes::new(
                        self.meta,
                        blob_table,
                        self.digest_validate,
                    ));
                    inodes.load(r)?;
                    self.inodes = inodes;
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
    ) -> Result<()> {
        match self.inodes.get_inode(ino, self.digest_validate) {
            Ok(inode) => {
                if inode.is_dir() {
                    let mut descendants = Vec::new();
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
                    }
                } else {
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
                }
            }
            Err(_) => {
                return Err(enoent!("Can't find inode"));
            }
        }

        Ok(())
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
    ) -> Result<RafsBioDesc> {
        let hint_entries = self.meta.prefetch_table_entries as usize;

        if hint_entries == 0 && files.is_none() {
            return Err(enoent!("Prefetch table is empty!"));
        }

        let mut prefetch_table = PrefetchTable::new();
        if prefetch_table
            .load_from(r, self.meta.prefetch_table_offset, hint_entries)
            .is_err()
        {
            einval!(format!(
                "Failed in load hint prefetch table at {}",
                self.meta.prefetch_table_offset
            ));
        }

        let mut head_desc = RafsBioDesc {
            bi_size: 0,
            bi_flags: 0,
            bi_vec: Vec::new(),
        };

        // No need to prefetch blob data for each alias as they share the same range,
        // we do it once.
        let mut hardlinks: HashSet<u64> = HashSet::new();

        for inode_idx in prefetch_table.inode_indexes.iter() {
            // index 0 is invalid, it was added because prefetch table has to be aligned.
            if *inode_idx == 0 {
                break;
            }
            debug!("hint prefetch inode {}", inode_idx);
            self.build_prefetch_desc(*inode_idx as u64, &mut head_desc, &mut hardlinks)?;
        }

        if let Some(files) = files {
            for f_ino in files {
                self.build_prefetch_desc(f_ino, &mut head_desc, &mut hardlinks)?;
            }
        }

        Ok(head_desc)
    }
}

/// Trait to manage all inodes of a file system.
pub trait RafsSuperInodes {
    fn load(&mut self, r: &mut RafsIoReader) -> Result<()>;

    fn destroy(&mut self);

    fn get_inode(&self, ino: Inode, digest_validate: bool) -> Result<Arc<dyn RafsInode>>;

    fn get_max_ino(&self) -> Inode;

    fn get_blobs(&self) -> Vec<OndiskBlobTableEntry> {
        self.get_blob_table().get_all()
    }

    fn get_blob_table(&self) -> Arc<OndiskBlobTable>;

    fn update(&self, r: &mut RafsIoReader) -> Result<()>;

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
            // trace!("\tdigest symlink {}", inode.get_symlink()?);
            hasher.digest_update(inode.get_symlink()?.as_os_str().as_bytes());
        } else {
            for idx in 0..child_count {
                if inode.is_dir() {
                    // trace!("\tdigest child {}", idx);
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
                    // trace!("\tdigest chunk {}", idx);
                    let chunk = inode.get_chunk_info(idx as u32)?;
                    let chunk_digest = chunk.block_id();
                    let chunk_digest = chunk_digest.as_ref().as_ref();
                    hasher.digest_update(chunk_digest);
                }
            }
        }

        let digest = hasher.digest_finalize();
        let result = expected_digest == digest;
        if !result {
            error!(
                "invalid inode digest {}, ino: {} name: {:?}",
                digest,
                inode.ino(),
                inode.name()?
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

    fn name(&self) -> Result<OsString>;
    fn get_symlink(&self) -> Result<OsString>;
    fn get_digest(&self) -> RafsDigest;
    fn get_child_by_name(&self, name: &OsStr) -> Result<Arc<dyn RafsInode>>;
    fn get_child_by_index(&self, idx: Inode) -> Result<Arc<dyn RafsInode>>;
    fn get_child_index(&self) -> Result<u32>;
    fn get_child_count(&self) -> u32;
    fn get_chunk_info(&self, idx: u32) -> Result<Arc<dyn RafsChunkInfo>>;
    fn get_chunk_blob_id(&self, idx: u32) -> Result<String>;
    fn get_entry(&self) -> Entry;
    fn get_attr(&self) -> Attr;
    fn get_xattr(&self, name: &OsStr) -> Result<Option<XattrValue>>;
    fn get_xattrs(&self) -> Result<Vec<XattrName>>;
    fn alloc_bio_desc(&self, offset: u64, size: usize) -> Result<RafsBioDesc>;
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

    fn ino(&self) -> u64;
    fn parent(&self) -> u64;
    fn size(&self) -> u64;

    fn cast_ondisk(&self) -> Result<OndiskInode>;
}

/// Trait to access Rafs Data Chunk Information.
pub trait RafsChunkInfo: Sync + Send {
    fn validate(&self, sb: &RafsSuperMeta) -> Result<()>;

    fn block_id(&self) -> Arc<RafsDigest>;
    fn blob_index(&self) -> u32;

    fn compress_offset(&self) -> u64;
    fn compress_size(&self) -> u32;
    fn decompress_offset(&self) -> u64;
    fn decompress_size(&self) -> u32;

    fn file_offset(&self) -> u64;
    fn is_compressed(&self) -> bool;

    fn cast_ondisk(&self) -> Result<OndiskChunkInfo>;
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

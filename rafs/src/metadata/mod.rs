// Copyright 2020 Ant Group. All rights reserved.
// Copyright (C) 2020-2022 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Enums, Structs and Traits to access and manage Rafs filesystem metadata.

use std::any::Any;
use std::collections::{HashMap, HashSet};
use std::convert::{TryFrom, TryInto};
use std::ffi::{OsStr, OsString};
use std::fmt::{Debug, Display, Formatter, Result as FmtResult};
use std::fs::OpenOptions;
use std::io::{Error, ErrorKind, Result};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::bail;
use fuse_backend_rs::abi::fuse_abi::Attr;
use fuse_backend_rs::api::filesystem::Entry;
use nydus_api::{ConfigV2, RafsConfigV2};
use nydus_storage::device::{
    BlobChunkInfo, BlobDevice, BlobFeatures, BlobInfo, BlobIoMerge, BlobIoVec,
};
use nydus_storage::meta::toc::TocEntryList;
use nydus_utils::digest::{self, RafsDigest};
use nydus_utils::{compress, crypt};
use serde::Serialize;

use self::layout::v5::RafsV5PrefetchTable;
use self::layout::v6::RafsV6PrefetchTable;
use self::layout::{XattrName, XattrValue, RAFS_SUPER_VERSION_V5, RAFS_SUPER_VERSION_V6};
use self::noop::NoopSuperBlock;
use crate::fs::{RAFS_DEFAULT_ATTR_TIMEOUT, RAFS_DEFAULT_ENTRY_TIMEOUT};
use crate::{RafsError, RafsIoReader, RafsIoWrite, RafsResult};

mod md_v5;
mod md_v6;
mod noop;

pub mod cached_v5;
pub mod chunk;
pub mod direct_v5;
pub mod direct_v6;
pub mod inode;
pub mod layout;

// Reexport from nydus_storage crate.
pub use nydus_storage::{RAFS_DEFAULT_CHUNK_SIZE, RAFS_MAX_CHUNK_SIZE};

/// Maximum size of blob identifier string.
pub const RAFS_BLOB_ID_MAX_LENGTH: usize = 64;
/// Block size reported by get_attr().
pub const RAFS_ATTR_BLOCK_SIZE: u32 = 4096;
/// Maximum size of file name supported by RAFS.
pub const RAFS_MAX_NAME: usize = 255;
/// Maximum size of RAFS filesystem metadata blobs.
pub const RAFS_MAX_METADATA_SIZE: usize = 0x8000_0000;
/// File name for Unix current directory.
pub const DOT: &str = ".";
/// File name for Unix parent directory.
pub const DOTDOT: &str = "..";

/// Type for RAFS filesystem inode number.
pub type Inode = u64;
pub type ArcRafsInodeExt = Arc<dyn RafsInodeExt>;

#[derive(Debug, Clone)]
pub struct RafsBlobExtraInfo {
    /// Mapped block address from RAFS v6 devslot table.
    ///
    /// It's the offset of the uncompressed blob used to convert an image into a disk.
    pub mapped_blkaddr: u32,
}

/// Trait to access filesystem inodes managed by a RAFS filesystem.
pub trait RafsSuperInodes {
    /// Get the maximum inode number managed by the RAFS filesystem.
    fn get_max_ino(&self) -> Inode;

    /// Get the `RafsInode` trait object corresponding to the inode number `ino`.
    fn get_inode(&self, ino: Inode, validate_inode: bool) -> Result<Arc<dyn RafsInode>>;

    /// Get the `RafsInodeExt` trait object corresponding to the 'ino`.
    fn get_extended_inode(&self, ino: Inode, validate_inode: bool)
        -> Result<Arc<dyn RafsInodeExt>>;
}

/// Trait to access RAFS filesystem metadata, including the RAFS super block and inodes.
pub trait RafsSuperBlock: RafsSuperInodes + Send + Sync {
    /// Load and validate the RAFS filesystem super block from the specified reader.
    fn load(&mut self, r: &mut RafsIoReader) -> Result<()>;

    /// Update/reload the RAFS filesystem super block from the specified reader.
    fn update(&self, r: &mut RafsIoReader) -> RafsResult<()>;

    /// Destroy the RAFS filesystem super block object.
    fn destroy(&mut self);

    /// Get all blob objects referenced by the RAFS filesystem.
    fn get_blob_infos(&self) -> Vec<Arc<BlobInfo>>;

    /// Get extra information associated with blob objects.
    fn get_blob_extra_infos(&self) -> Result<HashMap<String, RafsBlobExtraInfo>> {
        Ok(HashMap::new())
    }

    /// Get the inode number of the RAFS filesystem root.
    fn root_ino(&self) -> u64;

    /// Get the `BlobChunkInfo` object by a chunk index, used by RAFS v6.
    fn get_chunk_info(&self, _idx: usize) -> Result<Arc<dyn BlobChunkInfo>>;

    /// Associate `BlobDevice` object with the `RafsSuperBlock` object, used by RAFS v6.
    fn set_blob_device(&self, blob_device: BlobDevice);
}

/// Result codes for `RafsInodeWalkHandler`.
pub enum RafsInodeWalkAction {
    /// Indicates the need to continue iterating
    Continue,
    /// Indicates that it is necessary to stop continuing to iterate
    Break,
}

/// Callback handler for RafsInode::walk_children_inodes().
pub type RafsInodeWalkHandler<'a> = &'a mut dyn FnMut(
    Option<Arc<dyn RafsInode>>,
    OsString,
    u64,
    u64,
) -> Result<RafsInodeWalkAction>;

/// Trait to provide readonly accessors for RAFS filesystem inode.
///
/// The RAFS filesystem is a readonly filesystem, so does its inodes. The `RafsInode` trait provides
/// readonly accessors for RAFS filesystem inode. The `nydus-image` crate provides its own
/// InodeWrapper to generate RAFS filesystem inodes.
pub trait RafsInode: Any {
    /// RAFS: validate format and integrity of the RAFS filesystem inode.
    ///
    /// Inodes objects may be transmuted from raw buffers or loaded from untrusted source.
    /// It must be validated for integrity before accessing any of its data fields .
    fn validate(&self, max_inode: Inode, chunk_size: u64) -> Result<()>;

    /// RAFS: allocate blob io vectors to read file data in range [offset, offset + size).
    fn alloc_bio_vecs(
        &self,
        device: &BlobDevice,
        offset: u64,
        size: usize,
        user_io: bool,
    ) -> Result<Vec<BlobIoVec>>;

    /// RAFS: collect all descendants of the inode for image building.
    fn collect_descendants_inodes(
        &self,
        descendants: &mut Vec<Arc<dyn RafsInode>>,
    ) -> Result<usize>;

    /// Posix: generate a `Entry` object required by libc/fuse from the inode.
    fn get_entry(&self) -> Entry;

    /// Posix: generate a posix `Attr` object required by libc/fuse from the inode.
    fn get_attr(&self) -> Attr;

    /// Posix: get the inode number.
    fn ino(&self) -> u64;

    /// Posix: get real device number.
    fn rdev(&self) -> u32;

    /// Posix: get project id associated with the inode.
    fn projid(&self) -> u32;

    /// Mode: check whether the inode is a directory.
    fn is_dir(&self) -> bool;

    /// Mode: check whether the inode is a symlink.
    fn is_symlink(&self) -> bool;

    /// Mode: check whether the inode is a regular file.
    fn is_reg(&self) -> bool;

    /// Mode: check whether the inode is a hardlink.
    fn is_hardlink(&self) -> bool;

    /// Xattr: check whether the inode has extended attributes.
    fn has_xattr(&self) -> bool;

    /// Xattr: get the value of xattr with key `name`.
    fn get_xattr(&self, name: &OsStr) -> Result<Option<XattrValue>>;

    /// Xattr: get all xattr keys.
    fn get_xattrs(&self) -> Result<Vec<XattrName>>;

    /// Symlink: get the symlink target.
    fn get_symlink(&self) -> Result<OsString>;

    /// Symlink: get size of the symlink target path.
    fn get_symlink_size(&self) -> u16;

    /// Directory: walk/enumerate child inodes.
    fn walk_children_inodes(&self, entry_offset: u64, handler: RafsInodeWalkHandler) -> Result<()>;

    /// Directory: get child inode by name.
    fn get_child_by_name(&self, name: &OsStr) -> Result<Arc<dyn RafsInodeExt>>;

    /// Directory: get child inode by child index, child index starts from 0.
    fn get_child_by_index(&self, idx: u32) -> Result<Arc<dyn RafsInodeExt>>;

    /// Directory: get number of child inodes.
    fn get_child_count(&self) -> u32;

    /// Directory: get the inode number corresponding to the first child inode.
    fn get_child_index(&self) -> Result<u32>;

    /// Regular: get size of file content
    fn size(&self) -> u64;

    /// Regular: check whether the inode has no content.
    fn is_empty_size(&self) -> bool {
        self.size() == 0
    }

    /// Regular: get number of data chunks.
    fn get_chunk_count(&self) -> u32;

    fn as_any(&self) -> &dyn Any;
}

/// Extended inode information for builder and directory walker.
pub trait RafsInodeExt: RafsInode {
    /// Convert to the base type `RafsInode`.
    fn as_inode(&self) -> &dyn RafsInode;

    /// Posix: get inode number of the parent inode.
    fn parent(&self) -> u64;

    /// Posix: get file name.
    fn name(&self) -> OsString;

    /// Posix: get file name size.
    fn get_name_size(&self) -> u16;

    /// RAFS V5: get RAFS v5 specific inode flags.
    fn flags(&self) -> u64;

    /// RAFS v5: get digest value of the inode metadata.
    fn get_digest(&self) -> RafsDigest;

    /// RAFS v5: get chunk info object by chunk index, chunk index starts from 0.
    fn get_chunk_info(&self, idx: u32) -> Result<Arc<dyn BlobChunkInfo>>;
}

/// Trait to write out RAFS filesystem meta objects into the metadata blob.
pub trait RafsStore {
    /// Write out the Rafs filesystem meta object to the writer.
    fn store(&self, w: &mut dyn RafsIoWrite) -> Result<usize>;
}

bitflags! {
    /// Rafs filesystem feature flags.
    #[derive(Serialize)]
    pub struct RafsSuperFlags: u64 {
        /// Data chunks are not compressed.
        const COMPRESSION_NONE = 0x0000_0001;
        /// Data chunks are compressed with lz4_block.
        const COMPRESSION_LZ4 = 0x0000_0002;
        /// Use blake3 hash algorithm to calculate digest.
        const HASH_BLAKE3 = 0x0000_0004;
        /// Use sha256 hash algorithm to calculate digest.
        const HASH_SHA256 = 0x0000_0008;
        /// Inode has explicit uid gid fields.
        ///
        /// If unset, use nydusd process euid/egid for all inodes at runtime.
        const EXPLICIT_UID_GID = 0x0000_0010;
        /// Inode may have associated extended attributes.
        const HAS_XATTR = 0x0000_0020;
        /// Data chunks are compressed with gzip
        const COMPRESSION_GZIP = 0x0000_0040;
        /// Data chunks are compressed with zstd
        const COMPRESSION_ZSTD = 0x0000_0080;
        /// Chunk digests are inlined in RAFS v6 data blob.
        const INLINED_CHUNK_DIGEST = 0x0000_0100;
        /// RAFS works in Tarfs mode, which directly uses tar streams as data blobs.
        const TARTFS_MODE = 0x0000_0200;
        /// Data chunks are not encrypted.
        const ENCRYPTION_NONE = 0x0100_0000;
        /// Data chunks are encrypted with AES-128-XTS.
        const ENCRYPTION_ASE_128_XTS = 0x0200_0000;

        // Reserved for future compatible changes.
        const PRESERVED_COMPAT_5 = 0x0400_0000;
        const PRESERVED_COMPAT_4 = 0x0800_0000;
        const PRESERVED_COMPAT_3 = 0x1000_0000;
        const PRESERVED_COMPAT_2 = 0x2000_0000;
        const PRESERVED_COMPAT_1 = 0x4000_0000;
        const PRESERVED_COMPAT_0 = 0x8000_0000;
    }
}

impl Default for RafsSuperFlags {
    fn default() -> Self {
        RafsSuperFlags::empty()
    }
}

impl Display for RafsSuperFlags {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "{:?}", self)?;
        Ok(())
    }
}

impl From<RafsSuperFlags> for digest::Algorithm {
    fn from(flags: RafsSuperFlags) -> Self {
        match flags {
            x if x.contains(RafsSuperFlags::HASH_BLAKE3) => digest::Algorithm::Blake3,
            x if x.contains(RafsSuperFlags::HASH_SHA256) => digest::Algorithm::Sha256,
            _ => digest::Algorithm::Blake3,
        }
    }
}

impl From<digest::Algorithm> for RafsSuperFlags {
    fn from(d: digest::Algorithm) -> RafsSuperFlags {
        match d {
            digest::Algorithm::Blake3 => RafsSuperFlags::HASH_BLAKE3,
            digest::Algorithm::Sha256 => RafsSuperFlags::HASH_SHA256,
        }
    }
}

impl From<RafsSuperFlags> for compress::Algorithm {
    fn from(flags: RafsSuperFlags) -> Self {
        match flags {
            x if x.contains(RafsSuperFlags::COMPRESSION_NONE) => compress::Algorithm::None,
            x if x.contains(RafsSuperFlags::COMPRESSION_LZ4) => compress::Algorithm::Lz4Block,
            x if x.contains(RafsSuperFlags::COMPRESSION_GZIP) => compress::Algorithm::GZip,
            x if x.contains(RafsSuperFlags::COMPRESSION_ZSTD) => compress::Algorithm::Zstd,
            _ => compress::Algorithm::Lz4Block,
        }
    }
}

impl From<compress::Algorithm> for RafsSuperFlags {
    fn from(c: compress::Algorithm) -> RafsSuperFlags {
        match c {
            compress::Algorithm::None => RafsSuperFlags::COMPRESSION_NONE,
            compress::Algorithm::Lz4Block => RafsSuperFlags::COMPRESSION_LZ4,
            compress::Algorithm::GZip => RafsSuperFlags::COMPRESSION_GZIP,
            compress::Algorithm::Zstd => RafsSuperFlags::COMPRESSION_ZSTD,
        }
    }
}

impl From<RafsSuperFlags> for crypt::Algorithm {
    fn from(flags: RafsSuperFlags) -> Self {
        match flags {
            // NOTE: only aes-128-xts encryption algorithm supported.
            x if x.contains(RafsSuperFlags::ENCRYPTION_ASE_128_XTS) => crypt::Algorithm::Aes128Xts,
            _ => crypt::Algorithm::None,
        }
    }
}

impl From<crypt::Algorithm> for RafsSuperFlags {
    fn from(c: crypt::Algorithm) -> RafsSuperFlags {
        match c {
            // NOTE: only aes-128-xts encryption algorithm supported.
            crypt::Algorithm::Aes128Xts => RafsSuperFlags::ENCRYPTION_ASE_128_XTS,
            _ => RafsSuperFlags::ENCRYPTION_NONE,
        }
    }
}

/// Configuration information to check compatibility between RAFS filesystems.
#[derive(Clone, Copy, Debug)]
pub struct RafsSuperConfig {
    /// RAFS filesystem version.
    pub version: RafsVersion,
    /// Compression algorithm.
    pub compressor: compress::Algorithm,
    /// Digest algorithm.
    pub digester: digest::Algorithm,
    /// Size of data chunks.
    pub chunk_size: u32,
    /// Size of batch data chunks.
    pub batch_size: u32,
    /// Whether `explicit_uidgid` enabled or not.
    pub explicit_uidgid: bool,
    /// RAFS in TARFS mode.
    pub is_tarfs_mode: bool,
}

impl RafsSuperConfig {
    /// Check compatibility for two RAFS filesystems.
    pub fn check_compatibility(&self, meta: &RafsSuperMeta) -> Result<()> {
        if self.chunk_size != meta.chunk_size {
            return Err(einval!(format!(
                "Inconsistent configuration of chunk_size: {} vs {}",
                self.chunk_size, meta.chunk_size
            )));
        }

        if self.explicit_uidgid != meta.explicit_uidgid() {
            return Err(einval!(format!(
                "Using inconsistent explicit_uidgid setting {:?}, target explicit_uidgid setting {:?}",
                self.explicit_uidgid,
                meta.explicit_uidgid()
            )));
        }

        if u32::from(self.version) != meta.version {
            return Err(einval!(format!(
                "Using inconsistent RAFS version {:?}, target RAFS version {:?}",
                self.version,
                RafsVersion::try_from(meta.version)?
            )));
        }

        if self.version == RafsVersion::V5 && self.digester != meta.get_digester() {
            return Err(einval!(format!(
                "RAFS v5 can not support different digest algorithm due to inode digest, {} vs {}",
                self.digester,
                meta.get_digester()
            )));
        }

        let is_tarfs_mode = meta.flags.contains(RafsSuperFlags::TARTFS_MODE);
        if is_tarfs_mode != self.is_tarfs_mode {
            return Err(einval!(format!("Using inconsistent RAFS TARFS mode")));
        }

        Ok(())
    }
}

/// Rafs filesystem meta-data cached from on disk RAFS super block.
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
    /// Chunk size.
    pub chunk_size: u32,
    /// Batch chunk size.
    pub batch_size: u32,
    /// Number of inodes in the filesystem.
    pub inodes_count: u64,
    /// V5: superblock flags for Rafs v5.
    pub flags: RafsSuperFlags,
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
    /// Number of RAFS v6 blob device entries in the devslot table.
    pub blob_device_table_count: u32,
    /// Offset of the RAFS v6 devslot table.
    pub blob_device_table_offset: u64,
    /// Offset of the inode prefetch table into the metadata blob.
    pub prefetch_table_offset: u64,
    /// Size of the inode prefetch table.
    pub prefetch_table_entries: u32,
    /// Default attribute timeout value.
    pub attr_timeout: Duration,
    /// Default inode timeout value.
    pub entry_timeout: Duration,
    /// Whether the RAFS instance is a chunk dictionary.
    pub is_chunk_dict: bool,
    /// Metadata block address for RAFS v6.
    pub meta_blkaddr: u32,
    /// Root nid for RAFS v6.
    pub root_nid: u16,
    /// Offset of the chunk table for RAFS v6.
    pub chunk_table_offset: u64,
    /// Size  of the chunk table for RAFS v6.
    pub chunk_table_size: u64,
}

impl RafsSuperMeta {
    /// Check whether the superblock is for Rafs v5 filesystems.
    pub fn is_v5(&self) -> bool {
        self.version == RAFS_SUPER_VERSION_V5
    }

    /// Check whether the superblock is for Rafs v6 filesystems.
    pub fn is_v6(&self) -> bool {
        self.version == RAFS_SUPER_VERSION_V6
    }

    /// Check whether the RAFS instance is a chunk dictionary.
    pub fn is_chunk_dict(&self) -> bool {
        self.is_chunk_dict
    }

    /// Check whether the explicit UID/GID feature has been enable or not.
    pub fn explicit_uidgid(&self) -> bool {
        self.flags.contains(RafsSuperFlags::EXPLICIT_UID_GID)
    }

    /// Check whether the filesystem supports extended attribute or not.
    pub fn has_xattr(&self) -> bool {
        self.flags.contains(RafsSuperFlags::HAS_XATTR)
    }

    /// Check whether data blobs have inlined chunk digest array.
    pub fn has_inlined_chunk_digest(&self) -> bool {
        self.is_v6() && self.flags.contains(RafsSuperFlags::INLINED_CHUNK_DIGEST)
    }

    /// Get compression algorithm to handle chunk data for the filesystem.
    pub fn get_compressor(&self) -> compress::Algorithm {
        if self.is_v5() || self.is_v6() {
            self.flags.into()
        } else {
            compress::Algorithm::None
        }
    }

    /// V5: get message digest algorithm to validate chunk data for the filesystem.
    pub fn get_digester(&self) -> digest::Algorithm {
        if self.is_v5() || self.is_v6() {
            self.flags.into()
        } else {
            digest::Algorithm::Blake3
        }
    }

    /// V6: Check whether any data blobs may be encrypted.
    pub fn get_cipher(&self) -> crypt::Algorithm {
        if self.is_v6() {
            self.flags.into()
        } else {
            crypt::Algorithm::None
        }
    }

    /// Get `RafsSuperConfig` object to check compatibility.
    pub fn get_config(&self) -> RafsSuperConfig {
        RafsSuperConfig {
            version: self.version.try_into().unwrap_or_default(),
            compressor: self.get_compressor(),
            digester: self.get_digester(),
            chunk_size: self.chunk_size,
            batch_size: self.batch_size,
            explicit_uidgid: self.explicit_uidgid(),
            is_tarfs_mode: self.flags.contains(RafsSuperFlags::TARTFS_MODE),
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
            chunk_size: 0,
            batch_size: 0,
            flags: RafsSuperFlags::empty(),
            inode_table_entries: 0,
            inode_table_offset: 0,
            blob_table_size: 0,
            blob_table_offset: 0,
            extended_blob_table_offset: 0,
            extended_blob_table_entries: 0,
            blob_device_table_count: 0,
            blob_device_table_offset: 0,
            prefetch_table_offset: 0,
            prefetch_table_entries: 0,
            attr_timeout: Duration::from_secs(RAFS_DEFAULT_ATTR_TIMEOUT),
            entry_timeout: Duration::from_secs(RAFS_DEFAULT_ENTRY_TIMEOUT),
            meta_blkaddr: 0,
            root_nid: 0,
            is_chunk_dict: false,
            chunk_table_offset: 0,
            chunk_table_size: 0,
        }
    }
}

/// RAFS filesystem versions.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub enum RafsVersion {
    /// RAFS v5
    #[default]
    V5,
    /// RAFS v6
    V6,
}

impl TryFrom<u32> for RafsVersion {
    type Error = Error;

    fn try_from(version: u32) -> std::result::Result<Self, Self::Error> {
        if version == RAFS_SUPER_VERSION_V5 {
            return Ok(RafsVersion::V5);
        } else if version == RAFS_SUPER_VERSION_V6 {
            return Ok(RafsVersion::V6);
        }
        Err(einval!(format!("invalid RAFS version number {}", version)))
    }
}

impl From<RafsVersion> for u32 {
    fn from(v: RafsVersion) -> Self {
        match v {
            RafsVersion::V5 => RAFS_SUPER_VERSION_V5,
            RafsVersion::V6 => RAFS_SUPER_VERSION_V6,
        }
    }
}

impl RafsVersion {
    /// Check whether it's RAFS v5.
    pub fn is_v5(&self) -> bool {
        self == &Self::V5
    }

    /// Check whether it's RAFS v6.
    pub fn is_v6(&self) -> bool {
        self == &Self::V6
    }
}

/// Rafs metadata working mode.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum RafsMode {
    /// Directly mapping and accessing metadata into process by mmap().
    #[default]
    Direct,
    /// Read metadata into memory before using, for RAFS v5.
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
    /// Cached metadata from on disk super block.
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
    /// Create a new `RafsSuper` instance from a `RafsConfigV2` object.
    pub fn new(conf: &RafsConfigV2) -> Result<Self> {
        Ok(Self {
            mode: RafsMode::from_str(conf.mode.as_str())?,
            validate_digest: conf.validate,
            ..Default::default()
        })
    }

    /// Destroy the filesystem super block.
    pub fn destroy(&mut self) {
        Arc::get_mut(&mut self.superblock)
            .expect("Inodes are no longer used.")
            .destroy();
    }

    /// Load Rafs super block from a metadata file.
    pub fn load_from_file<P: AsRef<Path>>(
        path: P,
        config: Arc<ConfigV2>,
        is_chunk_dict: bool,
    ) -> Result<(Self, RafsIoReader)> {
        let validate_digest = config
            .rafs
            .as_ref()
            .map(|rafs| rafs.validate)
            .unwrap_or_default();
        let mut rs = RafsSuper {
            mode: RafsMode::Direct,
            validate_digest,
            ..Default::default()
        };
        rs.meta.is_chunk_dict = is_chunk_dict;

        // open bootstrap file
        let file = OpenOptions::new()
            .read(true)
            .write(false)
            .open(path.as_ref())?;
        let mut reader = Box::new(file) as RafsIoReader;
        let mut blob_accessible = config.internal.blob_accessible();

        if let Err(e) = rs.load(&mut reader) {
            let id = BlobInfo::get_blob_id_from_meta_path(path.as_ref())?;
            let new_path = match TocEntryList::extract_rafs_meta(&id, config.clone()) {
                Ok(v) => v,
                Err(_e) => {
                    debug!("failed to load inlined RAFS meta, {}", _e);
                    return Err(e);
                }
            };
            let file = OpenOptions::new().read(true).write(false).open(new_path)?;
            reader = Box::new(file) as RafsIoReader;
            rs.load(&mut reader)?;
            rs.set_blob_id_from_meta_path(path.as_ref())?;
            blob_accessible = true;
        } else {
            // Backward compatibility: try to fix blob id for old converters.
            // Old converters extracts bootstraps from data blobs with inlined bootstrap
            // use blob digest as the bootstrap file name. The last blob in the blob table from
            // the bootstrap has wrong blod id, so we need to fix it.
            let blobs = rs.superblock.get_blob_infos();
            for blob in blobs.iter() {
                // Fix blob id for new images with old converters.
                if blob.has_feature(BlobFeatures::INLINED_FS_META) {
                    blob.set_blob_id_from_meta_path(path.as_ref())?;
                }
            }
        }

        if !config.is_fs_cache()
            && blob_accessible
            && (validate_digest || config.is_chunk_validation_enabled())
            && rs.meta.has_inlined_chunk_digest()
        {
            rs.create_blob_device(config)?;
        }

        Ok((rs, reader))
    }

    /// Load RAFS metadata and optionally cache inodes.
    pub(crate) fn load(&mut self, r: &mut RafsIoReader) -> Result<()> {
        // Try to load the filesystem as Rafs v5
        if self.try_load_v5(r)? {
            return Ok(());
        }

        if self.try_load_v6(r)? {
            return Ok(());
        }

        Err(Error::new(ErrorKind::Other, "invalid RAFS superblock"))
    }

    /// Set meta blob file path from which the `RafsSuper` object is loaded from.
    ///
    /// It's used to support inlined-meta and ZRan blobs.
    pub fn set_blob_id_from_meta_path(&self, meta_path: &Path) -> Result<()> {
        let blobs = self.superblock.get_blob_infos();
        for blob in blobs.iter() {
            if blob.has_feature(BlobFeatures::INLINED_FS_META)
                || !blob.has_feature(BlobFeatures::CAP_TAR_TOC)
            {
                blob.set_blob_id_from_meta_path(meta_path)?;
            }
        }
        Ok(())
    }

    /// Create a `BlobDevice` object and associated it with the `RafsSuper` object.
    ///
    /// The `BlobDevice` object is needed to get meta information from RAFS V6 data blobs.
    pub fn create_blob_device(&self, config: Arc<ConfigV2>) -> Result<()> {
        let blobs = self.superblock.get_blob_infos();
        let device = BlobDevice::new(&config, &blobs)?;
        self.superblock.set_blob_device(device);
        Ok(())
    }

    /// Update the filesystem metadata and storage backend.
    pub fn update(&self, r: &mut RafsIoReader) -> RafsResult<()> {
        if self.meta.is_v5() {
            self.skip_v5_superblock(r)
                .map_err(RafsError::FillSuperblock)?;
        }

        self.superblock.update(r)
    }

    /// Get the maximum inode number supported by the filesystem instance.
    pub fn get_max_ino(&self) -> Inode {
        self.superblock.get_max_ino()
    }

    /// Get the `RafsInode` object corresponding to `ino`.
    pub fn get_inode(&self, ino: Inode, validate_inode: bool) -> Result<Arc<dyn RafsInode>> {
        self.superblock.get_inode(ino, validate_inode)
    }

    /// Get the `RafsInodeExt` object corresponding to `ino`.
    pub fn get_extended_inode(
        &self,
        ino: Inode,
        validate_inode: bool,
    ) -> Result<Arc<dyn RafsInodeExt>> {
        self.superblock.get_extended_inode(ino, validate_inode)
    }

    /// Convert a file path to an inode number.
    pub fn ino_from_path(&self, f: &Path) -> Result<Inode> {
        let root_ino = self.superblock.root_ino();
        if f == Path::new("/") {
            return Ok(root_ino);
        } else if !f.starts_with("/") {
            return Err(einval!());
        }

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

        let mut parent = self.get_extended_inode(root_ino, self.validate_digest)?;
        for p in entries {
            match p {
                None => {
                    error!("Illegal specified path {:?}", f);
                    return Err(einval!());
                }
                Some(name) => {
                    parent = parent.get_child_by_name(name).map_err(|e| {
                        warn!("File {:?} not in RAFS filesystem, {}", name, e);
                        enoent!()
                    })?;
                }
            }
        }

        Ok(parent.ino())
    }

    /// Prefetch filesystem and file data to improve performance.
    ///
    /// To improve application filesystem access performance, the filesystem may prefetch file or
    /// metadata in advance. There are ways to configure the file list to be prefetched.
    /// 1. Static file prefetch list configured during image building, recorded in prefetch list
    ///    in Rafs v5 file system metadata.
    ///     Base on prefetch table which is persisted to bootstrap when building image.
    /// 2. Dynamic file prefetch list configured by command line. The dynamic file prefetch list
    ///    has higher priority and the static file prefetch list will be ignored if there's dynamic
    ///    prefetch list. When a directory is specified for dynamic prefetch list, all sub directory
    ///    and files under the directory will be prefetched.
    ///
    /// Each inode passed into should correspond to directory. And it already does the file type
    /// check inside.
    pub fn prefetch_files(
        &self,
        device: &BlobDevice,
        r: &mut RafsIoReader,
        root_ino: Inode,
        files: Option<Vec<Inode>>,
        fetcher: &dyn Fn(&mut BlobIoVec, bool),
    ) -> RafsResult<bool> {
        // Try to prefetch files according to the list specified by the `--prefetch-files` option.
        if let Some(files) = files {
            // Avoid prefetching multiple times for hardlinks to the same file.
            let mut hardlinks: HashSet<u64> = HashSet::new();
            let mut state = BlobIoMerge::default();
            for f_ino in files {
                self.prefetch_data(device, f_ino, &mut state, &mut hardlinks, fetcher)
                    .map_err(|e| RafsError::Prefetch(e.to_string()))?;
            }
            for (_id, mut desc) in state.drain() {
                fetcher(&mut desc, true);
            }
            // Flush the pending prefetch requests.
            Ok(false)
        } else if self.meta.is_v5() {
            self.prefetch_data_v5(device, r, root_ino, fetcher)
        } else if self.meta.is_v6() {
            self.prefetch_data_v6(device, r, root_ino, fetcher)
        } else {
            Err(RafsError::Prefetch(
                "Unknown filesystem version, prefetch disabled".to_string(),
            ))
        }
    }

    #[inline]
    fn prefetch_inode(
        device: &BlobDevice,
        inode: &Arc<dyn RafsInode>,
        state: &mut BlobIoMerge,
        hardlinks: &mut HashSet<u64>,
        fetcher: &dyn Fn(&mut BlobIoVec, bool),
    ) -> Result<()> {
        // Check for duplicated hardlinks.
        if inode.is_hardlink() {
            if hardlinks.contains(&inode.ino()) {
                return Ok(());
            } else {
                hardlinks.insert(inode.ino());
            }
        }

        let descs = inode.alloc_bio_vecs(device, 0, inode.size() as usize, false)?;
        for desc in descs {
            state.append(desc);
            if let Some(desc) = state.get_current_element() {
                fetcher(desc, false);
            }
        }

        Ok(())
    }

    fn prefetch_data(
        &self,
        device: &BlobDevice,
        ino: u64,
        state: &mut BlobIoMerge,
        hardlinks: &mut HashSet<u64>,
        fetcher: &dyn Fn(&mut BlobIoVec, bool),
    ) -> Result<()> {
        let inode = self
            .superblock
            .get_inode(ino, self.validate_digest)
            .map_err(|_e| enoent!("Can't find inode"))?;

        if inode.is_dir() {
            let mut descendants = Vec::new();
            let _ = inode.collect_descendants_inodes(&mut descendants)?;
            for i in descendants.iter() {
                Self::prefetch_inode(device, i, state, hardlinks, fetcher)?;
            }
        } else if !inode.is_empty_size() && inode.is_reg() {
            // An empty regular file will also be packed into nydus image,
            // then it has a size of zero.
            // Moreover, for rafs v5, symlink has size of zero but non-zero size
            // for symlink size. For rafs v6, symlink size is also represented by i_size.
            // So we have to restrain the condition here.
            Self::prefetch_inode(device, &inode, state, hardlinks, fetcher)?;
        }

        Ok(())
    }
}

// For nydus-image
impl RafsSuper {
    /// Convert an inode number to a file path.
    pub fn path_from_ino(&self, ino: Inode) -> Result<PathBuf> {
        if ino == self.superblock.root_ino() {
            return Ok(self.get_extended_inode(ino, false)?.name().into());
        }

        let mut path = PathBuf::new();
        let mut cur_ino = ino;
        let mut inode;

        loop {
            inode = self.get_extended_inode(cur_ino, false)?;
            let e: PathBuf = inode.name().into();
            path = e.join(path);

            if inode.ino() == self.superblock.root_ino() {
                break;
            } else {
                cur_ino = inode.parent();
            }
        }

        Ok(path)
    }

    /// Get prefetched inos
    pub fn get_prefetched_inos(&self, bootstrap: &mut RafsIoReader) -> Result<Vec<u32>> {
        if self.meta.is_v5() {
            let mut pt = RafsV5PrefetchTable::new();
            pt.load_prefetch_table_from(
                bootstrap,
                self.meta.prefetch_table_offset,
                self.meta.prefetch_table_entries as usize,
            )?;
            Ok(pt.inodes)
        } else {
            let mut pt = RafsV6PrefetchTable::new();
            pt.load_prefetch_table_from(
                bootstrap,
                self.meta.prefetch_table_offset,
                self.meta.prefetch_table_entries as usize,
            )?;
            Ok(pt.inodes)
        }
    }

    /// Walk through the file tree rooted at ino, calling cb for each file or directory
    /// in the tree by DFS order, including ino, please ensure ino is a directory.
    pub fn walk_directory<P: AsRef<Path>>(
        &self,
        ino: Inode,
        parent: Option<P>,
        cb: &mut dyn FnMut(ArcRafsInodeExt, &Path) -> anyhow::Result<()>,
    ) -> anyhow::Result<()> {
        let inode = self.get_extended_inode(ino, false)?;
        if !inode.is_dir() {
            bail!("inode {} is not a directory", ino);
        }
        self.do_walk_directory(inode, parent, cb)
    }

    #[allow(clippy::only_used_in_recursion)]
    fn do_walk_directory<P: AsRef<Path>>(
        &self,
        inode: Arc<dyn RafsInodeExt>,
        parent: Option<P>,
        cb: &mut dyn FnMut(ArcRafsInodeExt, &Path) -> anyhow::Result<()>,
    ) -> anyhow::Result<()> {
        let path = if let Some(parent) = parent {
            parent.as_ref().join(inode.name())
        } else {
            PathBuf::from("/")
        };
        cb(inode.clone(), &path)?;
        if inode.is_dir() {
            for idx in 0..inode.get_child_count() {
                let child = inode.get_child_by_index(idx)?;
                self.do_walk_directory(child, Some(&path), cb)?;
            }
        }
        Ok(())
    }
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

    #[test]
    fn test_rafs_compressor() {
        assert_eq!(
            compress::Algorithm::from(RafsSuperFlags::COMPRESSION_NONE),
            compress::Algorithm::None
        );
        assert_eq!(
            compress::Algorithm::from(RafsSuperFlags::COMPRESSION_GZIP),
            compress::Algorithm::GZip
        );
        assert_eq!(
            compress::Algorithm::from(RafsSuperFlags::COMPRESSION_LZ4),
            compress::Algorithm::Lz4Block
        );
        assert_eq!(
            compress::Algorithm::from(RafsSuperFlags::COMPRESSION_ZSTD),
            compress::Algorithm::Zstd
        );
        assert_eq!(
            compress::Algorithm::from(
                RafsSuperFlags::COMPRESSION_ZSTD | RafsSuperFlags::COMPRESSION_LZ4,
            ),
            compress::Algorithm::Lz4Block
        );
        assert_eq!(
            compress::Algorithm::from(RafsSuperFlags::empty()),
            compress::Algorithm::Lz4Block
        );
    }

    #[test]
    fn test_rafs_digestor() {
        assert_eq!(
            digest::Algorithm::from(RafsSuperFlags::HASH_BLAKE3),
            digest::Algorithm::Blake3
        );
        assert_eq!(
            digest::Algorithm::from(RafsSuperFlags::HASH_SHA256),
            digest::Algorithm::Sha256
        );
        assert_eq!(
            digest::Algorithm::from(RafsSuperFlags::HASH_SHA256 | RafsSuperFlags::HASH_BLAKE3,),
            digest::Algorithm::Blake3
        );
        assert_eq!(
            digest::Algorithm::from(RafsSuperFlags::empty()),
            digest::Algorithm::Blake3
        );
    }
}

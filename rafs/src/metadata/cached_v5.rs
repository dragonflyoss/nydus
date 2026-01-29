// Copyright 2020 Ant Group. All rights reserved.
// Copyright (C) 2020-2022 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! A RAFS metadata manager to cache all file system metadata into memory.
//!
//! All filesystem metadata will be loaded, validated and cached into memory when loading the
//! file system. And currently the cache layer only supports readonly file systems.

use std::any::Any;
use std::collections::{BTreeMap, HashMap};
use std::ffi::{OsStr, OsString};
use std::io::SeekFrom;
use std::io::{ErrorKind, Read, Result};
use std::mem::size_of;
use std::ops::Deref;
use std::os::unix::ffi::OsStrExt;
use std::str::FromStr;
use std::sync::Arc;

use fuse_backend_rs::abi::fuse_abi;
use fuse_backend_rs::api::filesystem::Entry;
use nydus_storage::device::v5::BlobV5ChunkInfo;
use nydus_storage::device::{BlobChunkFlags, BlobChunkInfo, BlobDevice, BlobInfo};
use nydus_utils::digest::RafsDigest;
use nydus_utils::ByteSize;

use crate::metadata::inode::RafsInodeFlags;
use crate::metadata::layout::v5::{
    rafsv5_alloc_bio_vecs, rafsv5_validate_inode, RafsV5BlobTable, RafsV5ChunkInfo, RafsV5Inode,
    RafsV5InodeChunkOps, RafsV5InodeOps, RafsV5XAttrsTable, RAFSV5_ALIGNMENT,
};
use crate::metadata::layout::{bytes_to_os_str, parse_xattr, RAFS_V5_ROOT_INODE};
use crate::metadata::{
    BlobIoVec, Inode, RafsError, RafsInode, RafsInodeExt, RafsInodeWalkAction,
    RafsInodeWalkHandler, RafsResult, RafsSuperBlock, RafsSuperInodes, RafsSuperMeta, XattrName,
    XattrValue, DOT, DOTDOT, RAFS_ATTR_BLOCK_SIZE, RAFS_MAX_NAME,
};
use crate::RafsIoReader;

/// Cached Rafs v5 super block.
pub struct CachedSuperBlockV5 {
    s_blob: Arc<RafsV5BlobTable>,
    s_meta: Arc<RafsSuperMeta>,
    s_inodes: BTreeMap<Inode, Arc<CachedInodeV5>>,
    max_inode: Inode,
    validate_inode: bool,
}

impl CachedSuperBlockV5 {
    /// Create a new instance of `CachedSuperBlockV5`.
    pub fn new(meta: RafsSuperMeta, validate_inode: bool) -> Self {
        CachedSuperBlockV5 {
            s_blob: Arc::new(RafsV5BlobTable::new()),
            s_meta: Arc::new(meta),
            s_inodes: BTreeMap::new(),
            max_inode: RAFS_V5_ROOT_INODE,
            validate_inode,
        }
    }

    /// Load all inodes into memory.
    ///
    /// Rafs v5 layout is based on BFS, which means parents always are in front of children.
    fn load_all_inodes(&mut self, r: &mut RafsIoReader) -> Result<()> {
        let mut dir_ino_set = Vec::with_capacity(self.s_meta.inode_table_entries as usize);

        for _idx in 0..self.s_meta.inode_table_entries {
            let mut inode = CachedInodeV5::new(self.s_blob.clone(), self.s_meta.clone());
            match inode.load(&self.s_meta, r) {
                Ok(_) => {
                    trace!(
                        "got inode ino {} parent {} size {} child_idx {} child_cnt {}",
                        inode.ino(),
                        inode.parent(),
                        inode.size(),
                        inode.i_child_idx,
                        inode.i_child_cnt,
                    );
                }
                Err(ref e) if e.kind() == ErrorKind::UnexpectedEof => break,
                Err(e) => {
                    error!("error when loading CachedInode {:?}", e);
                    return Err(e);
                }
            }

            let child_inode = self.hash_inode(Arc::new(inode))?;
            if child_inode.is_dir() {
                // Delay associating dir inode to its parent because that will take
                // a cloned inode object, which preventing us from using `Arc::get_mut`.
                // Without `Arc::get_mut` during Cached meta setup(loading all inodes),
                // we have to lock inode everywhere for mutability. It really hurts.
                dir_ino_set.push(child_inode.i_ino);
            } else {
                self.add_into_parent(child_inode);
            }
        }

        // Add directories to its parent in reverse order.
        for ino in dir_ino_set.iter().rev() {
            self.add_into_parent(self.get_node(*ino)?);
        }
        debug!("all {} inodes loaded", self.s_inodes.len());

        Ok(())
    }

    fn get_node(&self, ino: Inode) -> Result<Arc<CachedInodeV5>> {
        Ok(self.s_inodes.get(&ino).ok_or_else(|| enoent!())?.clone())
    }

    fn get_node_mut(&mut self, ino: Inode) -> Result<&mut Arc<CachedInodeV5>> {
        self.s_inodes.get_mut(&ino).ok_or_else(|| enoent!())
    }

    fn hash_inode(&mut self, inode: Arc<CachedInodeV5>) -> Result<Arc<CachedInodeV5>> {
        if self.max_inode < inode.ino() {
            self.max_inode = inode.ino();
        }

        if inode.is_hardlink() {
            if let Some(i) = self.s_inodes.get(&inode.i_ino) {
                // Keep it as is, directory digest algorithm has dependency on it.
                if !i.i_data.is_empty() {
                    return Ok(inode);
                }
            }
        }
        self.s_inodes.insert(inode.ino(), inode.clone());

        Ok(inode)
    }

    fn add_into_parent(&mut self, child_inode: Arc<CachedInodeV5>) {
        if let Ok(parent_inode) = self.get_node_mut(child_inode.parent()) {
            Arc::get_mut(parent_inode).unwrap().add_child(child_inode);
        }
    }
}

impl RafsSuperInodes for CachedSuperBlockV5 {
    fn get_max_ino(&self) -> u64 {
        self.max_inode
    }

    fn get_inode(&self, ino: Inode, _validate_digest: bool) -> Result<Arc<dyn RafsInode>> {
        self.s_inodes
            .get(&ino)
            .map_or(Err(enoent!()), |i| Ok(i.clone()))
    }

    fn get_extended_inode(
        &self,
        ino: Inode,
        _validate_digest: bool,
    ) -> Result<Arc<dyn RafsInodeExt>> {
        self.s_inodes
            .get(&ino)
            .map_or(Err(enoent!()), |i| Ok(i.clone()))
    }
}

impl RafsSuperBlock for CachedSuperBlockV5 {
    fn load(&mut self, r: &mut RafsIoReader) -> Result<()> {
        let meta = &self.s_meta;

        // FIXME: add validator for all load operations.

        // Now the seek offset points to inode table, so we can easily find first inode offset.
        r.seek(SeekFrom::Start(meta.inode_table_offset))?;
        let mut offset = [0u8; size_of::<u32>()];
        r.read_exact(&mut offset)?;
        // The offset is aligned with 8 bytes to make it easier to validate RafsV5Inode.
        let inode_offset = u32::from_le_bytes(offset) << 3;

        // Load blob table and extended blob table if there is one.
        let mut blob_table = RafsV5BlobTable::new();
        if meta.extended_blob_table_offset > 0 {
            r.seek(SeekFrom::Start(meta.extended_blob_table_offset))?;
            blob_table
                .extended
                .load(r, meta.extended_blob_table_entries as usize)?;
        }
        r.seek(SeekFrom::Start(meta.blob_table_offset))?;
        blob_table.load(r, meta.blob_table_size, meta.chunk_size, meta.flags)?;
        self.s_blob = Arc::new(blob_table);

        // Load all inodes started from first inode offset.
        r.seek(SeekFrom::Start(inode_offset as u64))?;
        self.load_all_inodes(r)?;

        // Validate inode digest tree
        let digester = self.s_meta.get_digester();
        let inode = self.get_extended_inode(RAFS_V5_ROOT_INODE, false)?;
        if self.validate_inode && !rafsv5_validate_inode(inode.deref(), true, digester)? {
            return Err(einval!("invalid inode digest"));
        }

        Ok(())
    }

    fn update(&self, _r: &mut RafsIoReader) -> RafsResult<()> {
        Err(RafsError::Unsupported)
    }

    fn destroy(&mut self) {
        self.s_inodes.clear();
    }

    fn get_blob_infos(&self) -> Vec<Arc<BlobInfo>> {
        self.s_blob.entries.clone()
    }

    fn root_ino(&self) -> u64 {
        RAFS_V5_ROOT_INODE
    }

    fn get_chunk_info(&self, _idx: usize) -> Result<Arc<dyn BlobChunkInfo>> {
        unimplemented!("used by RAFS v6 only")
    }

    fn set_blob_device(&self, _blob_device: BlobDevice) {
        unimplemented!("used by RAFS v6 only")
    }
}

/// Cached RAFS v5 inode object.
#[derive(Default, Clone, Debug)]
pub struct CachedInodeV5 {
    i_ino: Inode,
    i_name: OsString,
    i_digest: RafsDigest,
    i_parent: u64,
    i_mode: u32,
    i_projid: u32,
    i_uid: u32,
    i_gid: u32,
    i_flags: RafsInodeFlags,
    i_size: u64,
    i_blocks: u64,
    i_nlink: u32,
    i_child_idx: u32,
    i_child_cnt: u32,
    // extra info need cache
    i_chunksize: u32,
    i_rdev: u32,
    i_mtime_nsec: u32,
    i_mtime: u64,
    i_target: OsString, // for symbol link
    i_xattr: HashMap<OsString, Vec<u8>>,
    i_data: Vec<Arc<CachedChunkInfoV5>>,
    i_child: Vec<Arc<CachedInodeV5>>,
    i_blob_table: Arc<RafsV5BlobTable>,
    i_meta: Arc<RafsSuperMeta>,
}

impl CachedInodeV5 {
    /// Create a new instance of `CachedInodeV5`.
    pub fn new(blob_table: Arc<RafsV5BlobTable>, meta: Arc<RafsSuperMeta>) -> Self {
        CachedInodeV5 {
            i_blob_table: blob_table,
            i_meta: meta,
            ..Default::default()
        }
    }

    fn load_name(&mut self, name_size: usize, r: &mut RafsIoReader) -> Result<()> {
        if name_size > 0 {
            let mut name_buf = vec![0u8; name_size];
            r.read_exact(name_buf.as_mut_slice())?;
            r.seek_to_next_aligned(name_size, RAFSV5_ALIGNMENT)?;
            self.i_name = bytes_to_os_str(&name_buf).to_os_string();
        }

        Ok(())
    }

    fn load_symlink(&mut self, symlink_size: usize, r: &mut RafsIoReader) -> Result<()> {
        if self.is_symlink() && symlink_size > 0 {
            let mut symbol_buf = vec![0u8; symlink_size];
            r.read_exact(symbol_buf.as_mut_slice())?;
            r.seek_to_next_aligned(symlink_size, RAFSV5_ALIGNMENT)?;
            self.i_target = bytes_to_os_str(&symbol_buf).to_os_string();
        }

        Ok(())
    }

    fn load_xattr(&mut self, r: &mut RafsIoReader) -> Result<()> {
        if self.has_xattr() {
            let mut xattrs = RafsV5XAttrsTable::new();
            r.read_exact(xattrs.as_mut())?;
            xattrs.size = u64::from_le(xattrs.size);

            let mut xattr_buf = vec![0u8; xattrs.aligned_size()];
            r.read_exact(xattr_buf.as_mut_slice())?;
            parse_xattr(&xattr_buf, xattrs.size(), |name, value| {
                self.i_xattr.insert(name.to_os_string(), value);
                true
            })?;
        }

        Ok(())
    }

    fn load_chunk_info(&mut self, r: &mut RafsIoReader) -> Result<()> {
        if self.is_reg() && self.i_child_cnt > 0 {
            let mut chunk = RafsV5ChunkInfo::new();
            for _ in 0..self.i_child_cnt {
                chunk.load(r)?;
                self.i_data.push(Arc::new(CachedChunkInfoV5::from(&chunk)));
            }
        }

        Ok(())
    }

    /// Load an inode metadata from a reader.
    pub fn load(&mut self, sb: &RafsSuperMeta, r: &mut RafsIoReader) -> Result<()> {
        // RafsV5Inode...name...symbol link...xattrs...chunks
        let mut inode = RafsV5Inode::new();

        // parse ondisk inode: RafsV5Inode|name|symbol|xattr|chunks
        r.read_exact(inode.as_mut())?;
        self.copy_from_ondisk(&inode);
        self.load_name(inode.i_name_size as usize, r)?;
        self.load_symlink(inode.i_symlink_size as usize, r)?;
        self.load_xattr(r)?;
        self.load_chunk_info(r)?;
        self.i_chunksize = sb.chunk_size;
        self.validate(sb.inodes_count, self.i_chunksize as u64)?;

        Ok(())
    }

    fn copy_from_ondisk(&mut self, inode: &RafsV5Inode) {
        self.i_ino = inode.i_ino;
        self.i_digest = inode.i_digest;
        self.i_parent = inode.i_parent;
        self.i_mode = inode.i_mode;
        self.i_projid = inode.i_projid;
        self.i_uid = inode.i_uid;
        self.i_gid = inode.i_gid;
        self.i_flags = inode.i_flags;
        self.i_size = inode.i_size;
        self.i_nlink = inode.i_nlink;
        self.i_blocks = inode.i_blocks;
        self.i_child_idx = inode.i_child_index;
        self.i_child_cnt = inode.i_child_count;
        self.i_rdev = inode.i_rdev;
        self.i_mtime = inode.i_mtime;
        self.i_mtime_nsec = inode.i_mtime_nsec;
    }

    fn add_child(&mut self, child: Arc<CachedInodeV5>) {
        self.i_child.push(child);
        if self.i_child.len() == (self.i_child_cnt as usize) {
            // all children are ready, do sort
            self.i_child.sort_by(|c1, c2| c1.i_name.cmp(&c2.i_name));
        }
    }
}

impl RafsInode for CachedInodeV5 {
    // Somehow we got invalid `inode_count` from superblock.
    fn validate(&self, _inode_count: u64, chunk_size: u64) -> Result<()> {
        if self.i_ino == 0
            // || self.i_ino > inode_count
            || self.i_nlink == 0
            || (self.i_ino != RAFS_V5_ROOT_INODE && self.i_parent == 0)
            || self.i_name.len() > RAFS_MAX_NAME
            || self.i_name.is_empty()
        {
            return Err(einval!("invalid inode"));
        }
        if !self.is_hardlink() && self.i_parent >= self.i_ino {
            return Err(einval!("invalid parent inode"));
        }
        if self.is_reg() {
            let chunks = self.i_size.div_ceil(chunk_size);
            if !self.has_hole() && chunks != self.i_data.len() as u64 {
                return Err(einval!("invalid chunk count"));
            }
            let blocks = self.i_size.div_ceil(512);
            // Old stargz builder generates inode with 0 blocks
            if blocks != self.i_blocks && self.i_blocks != 0 {
                return Err(einval!("invalid block count"));
            }
        } else if self.is_dir() {
            if self.i_child_cnt != 0 && (self.i_child_idx as Inode) <= self.i_ino {
                return Err(einval!("invalid directory"));
            }
        } else if self.is_symlink() && self.i_target.is_empty() {
            return Err(einval!("invalid symlink target"));
        }

        Ok(())
    }

    fn alloc_bio_vecs(
        &self,
        _device: &BlobDevice,
        offset: u64,
        size: usize,
        user_io: bool,
    ) -> Result<Vec<BlobIoVec>> {
        rafsv5_alloc_bio_vecs(self, offset, size, user_io)
    }

    fn collect_descendants_inodes(
        &self,
        descendants: &mut Vec<Arc<dyn RafsInode>>,
    ) -> Result<usize> {
        if !self.is_dir() {
            return Err(enotdir!());
        }

        let mut child_dirs: Vec<Arc<dyn RafsInode>> = Vec::new();

        for child_inode in &self.i_child {
            if child_inode.is_dir() {
                child_dirs.push(child_inode.clone());
            } else if !child_inode.is_empty_size() {
                descendants.push(child_inode.clone());
            }
        }

        for d in child_dirs {
            d.collect_descendants_inodes(descendants)?;
        }

        Ok(0)
    }

    #[inline]
    fn get_entry(&self) -> Entry {
        Entry {
            attr: self.get_attr().into(),
            inode: self.i_ino,
            generation: 0,
            attr_flags: 0,
            attr_timeout: self.i_meta.attr_timeout,
            entry_timeout: self.i_meta.entry_timeout,
        }
    }

    #[inline]
    fn get_attr(&self) -> fuse_abi::Attr {
        fuse_abi::Attr {
            ino: self.i_ino,
            size: self.i_size,
            blocks: self.i_blocks,
            mode: self.i_mode,
            nlink: self.i_nlink as u32,
            blksize: RAFS_ATTR_BLOCK_SIZE,
            rdev: self.i_rdev,
            ..Default::default()
        }
    }

    #[inline]
    fn is_blkdev(&self) -> bool {
        self.i_mode & libc::S_IFMT as u32 == libc::S_IFBLK as u32
    }

    #[inline]
    fn is_chrdev(&self) -> bool {
        self.i_mode & libc::S_IFMT as u32 == libc::S_IFCHR as u32
    }

    #[inline]
    fn is_sock(&self) -> bool {
        self.i_mode & libc::S_IFMT as u32 == libc::S_IFSOCK as u32
    }

    #[inline]
    fn is_fifo(&self) -> bool {
        self.i_mode & libc::S_IFMT as u32 == libc::S_IFIFO as u32
    }

    #[inline]
    fn is_dir(&self) -> bool {
        self.i_mode & libc::S_IFMT as u32 == libc::S_IFDIR as u32
    }

    #[inline]
    fn is_symlink(&self) -> bool {
        self.i_mode & libc::S_IFMT as u32 == libc::S_IFLNK as u32
    }

    #[inline]
    fn is_reg(&self) -> bool {
        self.i_mode & libc::S_IFMT as u32 == libc::S_IFREG as u32
    }

    #[inline]
    fn is_hardlink(&self) -> bool {
        !self.is_dir() && self.i_nlink > 1
    }

    #[inline]
    fn has_xattr(&self) -> bool {
        self.i_flags.contains(RafsInodeFlags::XATTR)
    }

    #[inline]
    fn get_xattr(&self, name: &OsStr) -> Result<Option<XattrValue>> {
        Ok(self.i_xattr.get(name).cloned())
    }

    fn get_xattrs(&self) -> Result<Vec<XattrName>> {
        Ok(self
            .i_xattr
            .keys()
            .map(|k| k.as_bytes().to_vec())
            .collect::<Vec<XattrName>>())
    }

    #[inline]
    fn get_symlink(&self) -> Result<OsString> {
        if !self.is_symlink() {
            Err(einval!("inode is not a symlink"))
        } else {
            Ok(self.i_target.clone())
        }
    }

    #[inline]
    fn get_symlink_size(&self) -> u16 {
        if self.is_symlink() {
            self.i_target.byte_size() as u16
        } else {
            0
        }
    }

    fn walk_children_inodes(&self, entry_offset: u64, handler: RafsInodeWalkHandler) -> Result<()> {
        // offset 0 and 1 is for "." and ".." respectively.
        let mut cur_offset = entry_offset;

        if cur_offset == 0 {
            cur_offset += 1;
            // Safe to unwrap since conversion from DOT to os string can't fail.
            match handler(
                None,
                OsString::from_str(DOT).unwrap(),
                self.ino(),
                cur_offset,
            ) {
                Ok(RafsInodeWalkAction::Continue) => {}
                Ok(RafsInodeWalkAction::Break) => return Ok(()),
                Err(e) => return Err(e),
            }
        }

        if cur_offset == 1 {
            let parent = if self.ino() == 1 { 1 } else { self.parent() };
            cur_offset += 1;
            // Safe to unwrap since conversion from DOTDOT to os string can't fail.
            match handler(
                None,
                OsString::from_str(DOTDOT).unwrap(),
                parent,
                cur_offset,
            ) {
                Ok(RafsInodeWalkAction::Continue) => {}
                Ok(RafsInodeWalkAction::Break) => return Ok(()),
                Err(e) => return Err(e),
            };
        }

        let mut idx = cur_offset - 2;
        while idx < self.get_child_count() as u64 {
            assert!(idx <= u32::MAX as u64);
            let child = self.get_child_by_index(idx as u32)?;
            cur_offset += 1;
            match handler(None, child.name(), child.ino(), cur_offset) {
                Ok(RafsInodeWalkAction::Continue) => idx += 1,
                Ok(RafsInodeWalkAction::Break) => break,
                Err(e) => return Err(e),
            }
        }

        Ok(())
    }

    fn get_child_by_name(&self, name: &OsStr) -> Result<Arc<dyn RafsInodeExt>> {
        let idx = self
            .i_child
            .binary_search_by(|c| c.i_name.as_os_str().cmp(name))
            .map_err(|_| enoent!())?;
        Ok(self.i_child[idx].clone())
    }

    #[inline]
    fn get_child_by_index(&self, index: u32) -> Result<Arc<dyn RafsInodeExt>> {
        if (index as usize) < self.i_child.len() {
            Ok(self.i_child[index as usize].clone())
        } else {
            Err(einval!("invalid child index"))
        }
    }

    #[inline]
    fn get_child_count(&self) -> u32 {
        self.i_child_cnt
    }

    #[inline]
    fn get_child_index(&self) -> Result<u32> {
        Ok(self.i_child_idx)
    }

    #[inline]
    fn get_chunk_count(&self) -> u32 {
        self.get_child_count()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    impl_getter!(ino, i_ino, u64);
    impl_getter!(size, i_size, u64);
    impl_getter!(rdev, i_rdev, u32);
    impl_getter!(projid, i_projid, u32);
}

impl RafsInodeExt for CachedInodeV5 {
    fn as_inode(&self) -> &dyn RafsInode {
        self
    }

    #[inline]
    fn name(&self) -> OsString {
        self.i_name.clone()
    }

    #[inline]
    fn get_name_size(&self) -> u16 {
        self.i_name.byte_size() as u16
    }

    #[inline]
    fn flags(&self) -> u64 {
        self.i_flags.bits()
    }

    #[inline]
    fn get_digest(&self) -> RafsDigest {
        self.i_digest
    }

    #[inline]
    fn get_chunk_info(&self, idx: u32) -> Result<Arc<dyn BlobChunkInfo>> {
        if (idx as usize) < self.i_data.len() {
            Ok(self.i_data[idx as usize].clone())
        } else {
            Err(einval!("invalid chunk index"))
        }
    }

    impl_getter!(parent, i_parent, u64);
}

impl RafsV5InodeChunkOps for CachedInodeV5 {
    fn get_chunk_info_v5(&self, idx: u32) -> Result<Arc<dyn BlobV5ChunkInfo>> {
        if (idx as usize) < self.i_data.len() {
            Ok(self.i_data[idx as usize].clone() as Arc<dyn BlobV5ChunkInfo>)
        } else {
            Err(einval!("invalid chunk index"))
        }
    }
}

impl RafsV5InodeOps for CachedInodeV5 {
    fn get_blob_by_index(&self, idx: u32) -> Result<Arc<BlobInfo>> {
        self.i_blob_table.get(idx)
    }

    fn get_chunk_size(&self) -> u32 {
        self.i_chunksize
    }

    fn has_hole(&self) -> bool {
        self.i_flags.contains(RafsInodeFlags::HAS_HOLE)
    }
}

/// Cached information about an Rafs Data Chunk.
#[derive(Clone, Default, Debug)]
pub struct CachedChunkInfoV5 {
    // block hash
    block_id: Arc<RafsDigest>,
    // blob containing the block
    blob_index: u32,
    // chunk index in blob
    index: u32,
    // position of the block within the file
    file_offset: u64,
    // offset of the block within the blob
    compressed_offset: u64,
    uncompressed_offset: u64,
    // size of the block, compressed
    compressed_size: u32,
    uncompressed_size: u32,
    flags: BlobChunkFlags,
    crc32: u32,
}

impl CachedChunkInfoV5 {
    /// Create a new instance of `CachedChunkInfoV5`.
    pub fn new() -> Self {
        CachedChunkInfoV5 {
            ..Default::default()
        }
    }

    /// Load a chunk metadata from a reader.
    pub fn load(&mut self, r: &mut RafsIoReader) -> Result<()> {
        let mut chunk = RafsV5ChunkInfo::new();

        r.read_exact(chunk.as_mut())?;
        self.copy_from_ondisk(&chunk);

        Ok(())
    }

    fn copy_from_ondisk(&mut self, chunk: &RafsV5ChunkInfo) {
        self.block_id = Arc::new(chunk.block_id);
        self.blob_index = chunk.blob_index;
        self.index = chunk.index;
        self.compressed_offset = chunk.compressed_offset;
        self.uncompressed_offset = chunk.uncompressed_offset;
        self.uncompressed_size = chunk.uncompressed_size;
        self.file_offset = chunk.file_offset;
        self.compressed_size = chunk.compressed_size;
        self.flags = chunk.flags;
    }
}

impl BlobChunkInfo for CachedChunkInfoV5 {
    fn chunk_id(&self) -> &RafsDigest {
        &self.block_id
    }

    fn id(&self) -> u32 {
        self.index()
    }

    fn is_batch(&self) -> bool {
        false
    }

    fn is_compressed(&self) -> bool {
        self.flags.contains(BlobChunkFlags::COMPRESSED)
    }

    fn is_encrypted(&self) -> bool {
        false
    }

    fn has_crc32(&self) -> bool {
        self.flags.contains(BlobChunkFlags::HAS_CRC32)
    }

    fn crc32(&self) -> u32 {
        if self.has_crc32() {
            self.crc32
        } else {
            0
        }
    }
    fn as_any(&self) -> &dyn Any {
        self
    }

    impl_getter!(blob_index, blob_index, u32);
    impl_getter!(compressed_offset, compressed_offset, u64);
    impl_getter!(compressed_size, compressed_size, u32);
    impl_getter!(uncompressed_offset, uncompressed_offset, u64);
    impl_getter!(uncompressed_size, uncompressed_size, u32);
}

impl BlobV5ChunkInfo for CachedChunkInfoV5 {
    fn as_base(&self) -> &dyn BlobChunkInfo {
        self
    }

    impl_getter!(index, index, u32);
    impl_getter!(file_offset, file_offset, u64);
    impl_getter!(flags, flags, BlobChunkFlags);
}

impl From<&RafsV5ChunkInfo> for CachedChunkInfoV5 {
    fn from(info: &RafsV5ChunkInfo) -> Self {
        let mut chunk = CachedChunkInfoV5::new();
        chunk.copy_from_ondisk(info);
        chunk
    }
}

#[cfg(test)]
mod cached_tests {
    use std::cmp;
    use std::ffi::{OsStr, OsString};
    use std::fs::OpenOptions;
    use std::io::Seek;
    use std::io::SeekFrom::Start;
    use std::os::unix::ffi::OsStrExt;
    use std::sync::Arc;

    use nydus_storage::device::{BlobDevice, BlobFeatures};
    use nydus_utils::digest::{Algorithm, RafsDigest};
    use nydus_utils::ByteSize;
    use storage::device::v5::BlobV5ChunkInfo;
    use storage::device::{BlobChunkFlags, BlobChunkInfo};

    use crate::metadata::cached_v5::{CachedInodeV5, CachedSuperBlockV5};
    use crate::metadata::inode::RafsInodeFlags;
    use crate::metadata::layout::v5::{
        rafsv5_align, RafsV5BlobTable, RafsV5ChunkInfo, RafsV5Inode, RafsV5InodeWrapper,
    };
    use crate::metadata::layout::{RafsXAttrs, RAFS_V5_ROOT_INODE};
    use crate::metadata::{
        RafsInode, RafsInodeWalkAction, RafsStore, RafsSuperBlock, RafsSuperInodes, RafsSuperMeta,
        RAFS_MAX_NAME,
    };
    use crate::{BufWriter, RafsInodeExt, RafsIoRead, RafsIoReader};
    use vmm_sys_util::tempfile::TempFile;

    use super::CachedChunkInfoV5;

    #[test]
    fn test_load_inode() {
        let mut f = OpenOptions::new()
            .truncate(true)
            .create(true)
            .write(true)
            .read(true)
            .open("/tmp/buf_1")
            .unwrap();
        let mut writer = BufWriter::new(f.try_clone().unwrap());
        let mut reader = Box::new(f.try_clone().unwrap()) as RafsIoReader;

        let mut ondisk_inode = RafsV5Inode::new();
        let file_name = OsString::from("c_inode_1");
        let mut xattr = RafsXAttrs::default();
        xattr
            .add(OsString::from("user.k1"), vec![1u8, 2u8, 3u8, 4u8])
            .unwrap();
        xattr
            .add(OsString::from("user.k2"), vec![10u8, 11u8, 12u8])
            .unwrap();
        ondisk_inode.i_name_size = file_name.byte_size() as u16;
        ondisk_inode.i_child_count = 1;
        ondisk_inode.i_ino = 3;
        ondisk_inode.i_parent = RAFS_V5_ROOT_INODE;
        ondisk_inode.i_size = 8192;
        ondisk_inode.i_mode = libc::S_IFREG as u32;
        ondisk_inode.i_nlink = 1;
        ondisk_inode.i_blocks = 16;
        let mut chunk = RafsV5ChunkInfo::new();
        chunk.uncompressed_size = 8192;
        chunk.uncompressed_offset = 0;
        chunk.compressed_offset = 0;
        chunk.compressed_size = 4096;
        let inode = RafsV5InodeWrapper {
            name: file_name.as_os_str(),
            symlink: None,
            inode: &ondisk_inode,
        };
        inode.store(&mut writer).unwrap();
        chunk.store(&mut writer).unwrap();
        xattr.store_v5(&mut writer).unwrap();

        f.seek(Start(0)).unwrap();
        let md = RafsSuperMeta {
            inodes_count: 100,
            chunk_size: 1024 * 1024,
            ..Default::default()
        };
        let meta = Arc::new(md);
        let blob_table = Arc::new(RafsV5BlobTable::new());
        let mut cached_inode = CachedInodeV5::new(blob_table, meta.clone());
        cached_inode.load(&meta, &mut reader).unwrap();
        // check data
        assert_eq!(cached_inode.i_name, file_name.to_str().unwrap());
        assert_eq!(cached_inode.i_child_cnt, 1);
        let attr = cached_inode.get_attr();
        assert_eq!(attr.ino, 3);
        assert_eq!(attr.size, 8192);
        let cached_chunk = cached_inode.get_chunk_info(0).unwrap();
        assert_eq!(cached_chunk.compressed_size(), 4096);
        assert_eq!(cached_chunk.uncompressed_size(), 8192);
        assert_eq!(cached_chunk.compressed_offset(), 0);
        assert_eq!(cached_chunk.uncompressed_offset(), 0);
        let c_xattr = cached_inode.get_xattrs().unwrap();
        for k in c_xattr.iter() {
            let k = OsStr::from_bytes(k);
            let v = cached_inode.get_xattr(k).unwrap();
            assert_eq!(xattr.get(k).cloned().unwrap(), v.unwrap());
        }

        // close file
        drop(f);
        std::fs::remove_file("/tmp/buf_1").unwrap();
    }

    #[test]
    fn test_load_symlink() {
        let mut f = OpenOptions::new()
            .truncate(true)
            .create(true)
            .write(true)
            .read(true)
            .open("/tmp/buf_2")
            .unwrap();
        let mut writer = BufWriter::new(f.try_clone().unwrap());
        let mut reader = Box::new(f.try_clone().unwrap()) as RafsIoReader;
        let file_name = OsString::from("c_inode_2");
        let symlink_name = OsString::from("c_inode_1");
        let mut ondisk_inode = RafsV5Inode::new();
        ondisk_inode.i_name_size = file_name.byte_size() as u16;
        ondisk_inode.i_ino = 3;
        ondisk_inode.i_parent = RAFS_V5_ROOT_INODE;
        ondisk_inode.i_nlink = 1;
        ondisk_inode.i_symlink_size = symlink_name.byte_size() as u16;
        ondisk_inode.i_mode = libc::S_IFLNK as u32;

        let inode = RafsV5InodeWrapper {
            name: file_name.as_os_str(),
            symlink: Some(symlink_name.as_os_str()),
            inode: &ondisk_inode,
        };
        inode.store(&mut writer).unwrap();

        f.seek(Start(0)).unwrap();
        let mut meta = Arc::new(RafsSuperMeta::default());
        Arc::get_mut(&mut meta).unwrap().chunk_size = 1024 * 1024;
        Arc::get_mut(&mut meta).unwrap().inodes_count = 4;
        let blob_table = Arc::new(RafsV5BlobTable::new());
        let mut cached_inode = CachedInodeV5::new(blob_table, meta.clone());
        cached_inode.load(&meta, &mut reader).unwrap();

        assert_eq!(cached_inode.i_name, "c_inode_2");
        assert_eq!(cached_inode.get_symlink().unwrap(), symlink_name);

        drop(f);
        std::fs::remove_file("/tmp/buf_2").unwrap();
    }

    #[test]
    fn test_alloc_bio_desc() {
        let mut f = OpenOptions::new()
            .truncate(true)
            .create(true)
            .write(true)
            .read(true)
            .open("/tmp/buf_3")
            .unwrap();
        let mut writer = BufWriter::new(f.try_clone().unwrap());
        let mut reader = Box::new(f.try_clone().unwrap()) as RafsIoReader;
        let file_name = OsString::from("c_inode_3");
        let mut ondisk_inode = RafsV5Inode::new();
        ondisk_inode.i_name_size = rafsv5_align(file_name.len()) as u16;
        ondisk_inode.i_ino = 3;
        ondisk_inode.i_parent = RAFS_V5_ROOT_INODE;
        ondisk_inode.i_nlink = 1;
        ondisk_inode.i_child_count = 4;
        ondisk_inode.i_mode = libc::S_IFREG as u32;
        ondisk_inode.i_size = 1024 * 1024 * 3 + 8192;
        ondisk_inode.i_blocks = 6160;

        let inode = RafsV5InodeWrapper {
            name: file_name.as_os_str(),
            symlink: None,
            inode: &ondisk_inode,
        };
        inode.store(&mut writer).unwrap();

        let mut size = ondisk_inode.i_size;
        for i in 0..ondisk_inode.i_child_count {
            let mut chunk = RafsV5ChunkInfo::new();
            chunk.uncompressed_size = cmp::min(1024 * 1024, size as u32);
            chunk.uncompressed_offset = (i * 1024 * 1024) as u64;
            chunk.compressed_size = chunk.uncompressed_size / 2;
            chunk.compressed_offset = ((i * 1024 * 1024) / 2) as u64;
            chunk.file_offset = chunk.uncompressed_offset;
            chunk.store(&mut writer).unwrap();
            size -= chunk.uncompressed_size as u64;
        }
        f.seek(Start(0)).unwrap();
        let mut meta = Arc::new(RafsSuperMeta::default());
        Arc::get_mut(&mut meta).unwrap().chunk_size = 1024 * 1024;
        Arc::get_mut(&mut meta).unwrap().inodes_count = 4;
        let mut blob_table = Arc::new(RafsV5BlobTable::new());
        Arc::get_mut(&mut blob_table).unwrap().add(
            String::from("123333"),
            0,
            0,
            0,
            0,
            0,
            0,
            BlobFeatures::_V5_NO_EXT_BLOB_TABLE,
            meta.flags,
            false,
        );
        let mut cached_inode = CachedInodeV5::new(blob_table, meta.clone());
        cached_inode.load(&meta, &mut reader).unwrap();
        let device = BlobDevice::default();
        let descs = cached_inode.alloc_bio_vecs(&device, 0, 100, true).unwrap();
        let desc1 = &descs[0];
        assert_eq!(desc1.size(), 100);
        assert_eq!(desc1.len(), 1);
        assert_eq!(desc1.blob_io_desc(0).unwrap().offset, 0);
        assert_eq!(desc1.blob_io_desc(0).unwrap().blob.blob_id(), "123333");

        let descs = cached_inode
            .alloc_bio_vecs(&device, 1024 * 1024 - 100, 200, true)
            .unwrap();
        let desc2 = &descs[0];
        assert_eq!(desc2.size(), 200);
        assert_eq!(desc2.len(), 2);
        assert_eq!(desc2.blob_io_desc(0).unwrap().offset, 1024 * 1024 - 100);
        assert_eq!(desc2.blob_io_desc(0).unwrap().size, 100);
        assert_eq!(desc2.blob_io_desc(1).unwrap().offset, 0);
        assert_eq!(desc2.blob_io_desc(1).unwrap().size, 100);

        let descs = cached_inode
            .alloc_bio_vecs(&device, 1024 * 1024 + 8192, 1024 * 1024 * 4, true)
            .unwrap();
        let desc3 = &descs[0];
        assert_eq!(desc3.size(), 1024 * 1024 * 2);
        assert_eq!(desc3.len(), 3);
        assert_eq!(desc3.blob_io_desc(2).unwrap().size, 8192);

        drop(f);
        std::fs::remove_file("/tmp/buf_3").unwrap();
    }

    #[test]
    fn test_rafsv5_superblock() {
        let md = RafsSuperMeta::default();
        let mut sb = CachedSuperBlockV5::new(md, true);

        assert_eq!(sb.max_inode, RAFS_V5_ROOT_INODE);
        assert_eq!(sb.s_inodes.len(), 0);
        assert!(sb.validate_inode);

        let mut inode = CachedInodeV5::new(sb.s_blob.clone(), sb.s_meta.clone());
        inode.i_ino = 1;
        inode.i_nlink = 1;
        inode.i_child_idx = 2;
        inode.i_child_cnt = 3;
        inode.i_mode = libc::S_IFDIR as u32;
        sb.hash_inode(Arc::new(inode)).unwrap();
        assert_eq!(sb.max_inode, 1);
        assert_eq!(sb.s_inodes.len(), 1);

        let mut inode = CachedInodeV5::new(sb.s_blob.clone(), sb.s_meta.clone());
        inode.i_ino = 2;
        inode.i_mode = libc::S_IFDIR as u32;
        inode.i_nlink = 2;
        inode.i_parent = RAFS_V5_ROOT_INODE;
        sb.hash_inode(Arc::new(inode)).unwrap();
        assert_eq!(sb.max_inode, 2);
        assert_eq!(sb.s_inodes.len(), 2);

        let mut inode = CachedInodeV5::new(sb.s_blob.clone(), sb.s_meta.clone());
        inode.i_ino = 2;
        inode.i_mode = libc::S_IFDIR as u32;
        inode.i_nlink = 2;
        inode.i_parent = RAFS_V5_ROOT_INODE;
        sb.hash_inode(Arc::new(inode)).unwrap();
        assert_eq!(sb.max_inode, 2);
        assert_eq!(sb.s_inodes.len(), 2);

        let mut inode = CachedInodeV5::new(sb.s_blob.clone(), sb.s_meta.clone());
        inode.i_ino = 4;
        inode.i_mode = libc::S_IFDIR as u32;
        inode.i_nlink = 1;
        inode.i_parent = RAFS_V5_ROOT_INODE;
        sb.hash_inode(Arc::new(inode)).unwrap();
        assert_eq!(sb.max_inode, 4);
        assert_eq!(sb.s_inodes.len(), 3);
    }

    fn get_streams() -> (Box<dyn RafsIoRead>, BufWriter<std::fs::File>) {
        let temp = TempFile::new().unwrap();
        let w = OpenOptions::new()
            .read(true)
            .write(true)
            .open(temp.as_path())
            .unwrap();
        let r = OpenOptions::new()
            .read(true)
            .write(false)
            .open(temp.as_path())
            .unwrap();
        let writer: BufWriter<std::fs::File> = BufWriter::new(w);
        let reader: Box<dyn RafsIoRead> = Box::new(r);
        (reader, writer)
    }

    #[test]
    fn test_cached_super_block_v5() {
        let digest = RafsDigest::from_buf("foobar".as_bytes(), Algorithm::Blake3);
        let meta = RafsSuperMeta::default();
        let mut node = CachedInodeV5 {
            i_ino: 0,
            ..CachedInodeV5::default()
        };
        node.i_mode |= libc::S_IFDIR as u32;
        node.i_child_idx = 2;
        node.i_flags = RafsInodeFlags::SYMLINK;
        node.i_name = OsStr::new("foo").into();
        node.i_digest = digest;
        let mut child_node = CachedInodeV5::default();
        child_node.i_mode |= libc::S_IFDIR as u32;
        child_node.i_ino = 1;
        child_node.i_name = OsStr::new("bar").into();
        let mut blk = CachedSuperBlockV5::new(meta, false);
        let (r, _w) = get_streams();
        let mut r = r as RafsIoReader;
        assert!(blk.load_all_inodes(&mut r).is_ok());
        assert_eq!(blk.get_max_ino(), RAFS_V5_ROOT_INODE);
        assert!(blk.get_inode(0, false).is_err());
        assert!(blk.get_extended_inode(0, false).is_err());

        blk.s_inodes.insert(0, Arc::new(node.clone()));
        assert!(blk.get_inode(0, false).is_ok());
        assert!(blk.get_extended_inode(0, false).is_ok());

        blk.destroy();
        assert!(blk.s_inodes.is_empty());
        let blobs = blk.get_blob_extra_infos();
        assert!(blobs.unwrap().is_empty());
        assert_eq!(blk.root_ino(), RAFS_V5_ROOT_INODE);

        node.add_child(Arc::new(child_node));
        assert_eq!(node.i_child.len(), 1);

        let mut descendants = Vec::<Arc<dyn RafsInode>>::new();
        node.collect_descendants_inodes(&mut descendants).unwrap();
        assert!(node.collect_descendants_inodes(&mut descendants).is_ok());
        assert_eq!(node.get_entry().inode, node.ino());
        assert_eq!(node.get_xattr(OsStr::new("foobar")).unwrap(), None);
        assert!(!node.is_blkdev());
        assert!(!node.is_chrdev());
        assert!(!node.is_sock());
        assert!(!node.is_fifo());
        assert_eq!(node.get_symlink_size(), 0);

        node.i_child_cnt = 1;
        let mut found = false;
        node.walk_children_inodes(0, &mut |_node, _child_name, child_ino, _offset| {
            if child_ino == 1 {
                found = true;
                Ok(RafsInodeWalkAction::Break)
            } else {
                Ok(RafsInodeWalkAction::Continue)
            }
        })
        .unwrap();
        assert!(found);
        let rafsinode = node.as_inode();
        assert!(rafsinode.get_child_by_name(OsStr::new("bar")).is_ok());
        assert!(rafsinode.get_child_by_index(0).is_ok());
        assert!(rafsinode.get_child_by_index(1).is_err());
        assert_eq!(rafsinode.get_child_index().unwrap(), 2);

        assert_eq!(node.name(), "foo");
        assert_eq!(node.get_name_size(), "foo".len() as u16);
        assert_eq!(node.flags(), RafsInodeFlags::SYMLINK.bits());
        assert_eq!(node.get_digest(), digest);
    }

    #[test]
    fn test_cached_chunk_info_v5() {
        let mut info = CachedChunkInfoV5::new();
        info.index = 1024;
        info.blob_index = 1;
        info.flags = BlobChunkFlags::COMPRESSED;

        assert_eq!(info.index(), 1024 as u32);
        assert!(info.is_compressed());
        assert!(!info.is_encrypted());
        let info = info.as_base();

        assert_eq!(info.blob_index(), 1 as u32);
        assert!(info.is_compressed());
        assert!(!info.is_encrypted());
    }

    #[test]
    fn test_cached_inode_v5_validation_errors() {
        let meta = Arc::new(RafsSuperMeta::default());
        let blob_table = Arc::new(RafsV5BlobTable::new());

        // Test invalid inode number (0)
        let mut inode = CachedInodeV5::new(blob_table.clone(), meta.clone());
        inode.i_ino = 0;
        assert!(inode.validate(100, 1024).is_err());

        // Test invalid nlink (0)
        let mut inode = CachedInodeV5::new(blob_table.clone(), meta.clone());
        inode.i_ino = 1;
        inode.i_nlink = 0;
        assert!(inode.validate(100, 1024).is_err());

        // Test invalid parent for non-root inode
        let mut inode = CachedInodeV5::new(blob_table.clone(), meta.clone());
        inode.i_ino = 2;
        inode.i_nlink = 1;
        inode.i_parent = 0;
        assert!(inode.validate(100, 1024).is_err());

        // Test invalid name length
        let mut inode = CachedInodeV5::new(blob_table.clone(), meta.clone());
        inode.i_ino = 1;
        inode.i_nlink = 1;
        inode.i_name = OsString::from("a".repeat(RAFS_MAX_NAME + 1));
        assert!(inode.validate(100, 1024).is_err());

        // Test empty name
        let mut inode = CachedInodeV5::new(blob_table.clone(), meta.clone());
        inode.i_ino = 1;
        inode.i_nlink = 1;
        inode.i_name = OsString::new();
        assert!(inode.validate(100, 1024).is_err());

        // Test invalid parent inode (parent >= child for non-hardlink)
        let mut inode = CachedInodeV5::new(blob_table.clone(), meta.clone());
        inode.i_ino = 5;
        inode.i_nlink = 1;
        inode.i_parent = 10;
        inode.i_name = OsString::from("test");
        assert!(inode.validate(100, 1024).is_err());
    }

    #[test]
    fn test_cached_inode_v5_file_type_validation() {
        let meta = Arc::new(RafsSuperMeta::default());
        let blob_table = Arc::new(RafsV5BlobTable::new());

        // Test regular file with invalid chunk count
        let mut inode = CachedInodeV5::new(blob_table.clone(), meta.clone());
        inode.i_ino = 1;
        inode.i_nlink = 1;
        inode.i_name = OsString::from("test");
        inode.i_mode = libc::S_IFREG as u32;
        inode.i_size = 2048; // 2 chunks of 1024 bytes
        inode.i_data = vec![]; // But no chunks
        assert!(inode.validate(100, 1024).is_err());

        // Test regular file with invalid block count
        let mut inode = CachedInodeV5::new(blob_table.clone(), meta.clone());
        inode.i_ino = 1;
        inode.i_nlink = 1;
        inode.i_name = OsString::from("test");
        inode.i_mode = libc::S_IFREG as u32;
        inode.i_size = 1024;
        inode.i_blocks = 100; // Invalid block count
        inode.i_data = vec![Arc::new(CachedChunkInfoV5::new())];
        assert!(inode.validate(100, 1024).is_err());

        // Test directory with invalid child index
        let mut inode = CachedInodeV5::new(blob_table.clone(), meta.clone());
        inode.i_ino = 5;
        inode.i_nlink = 1;
        inode.i_name = OsString::from("test_dir");
        inode.i_mode = libc::S_IFDIR as u32;
        inode.i_child_cnt = 1;
        inode.i_child_idx = 3; // child_idx <= inode number is invalid
        assert!(inode.validate(100, 1024).is_err());

        // Test symlink with empty target
        let mut inode = CachedInodeV5::new(blob_table.clone(), meta.clone());
        inode.i_ino = 1;
        inode.i_nlink = 1;
        inode.i_name = OsString::from("test_link");
        inode.i_mode = libc::S_IFLNK as u32;
        inode.i_target = OsString::new(); // Empty target
        assert!(inode.validate(100, 1024).is_err());
    }

    #[test]
    fn test_cached_inode_v5_file_type_checks() {
        let meta = Arc::new(RafsSuperMeta::default());
        let blob_table = Arc::new(RafsV5BlobTable::new());
        let mut inode = CachedInodeV5::new(blob_table, meta);

        // Test block device
        inode.i_mode = libc::S_IFBLK as u32;
        assert!(inode.is_blkdev());
        assert!(!inode.is_chrdev());
        assert!(!inode.is_sock());
        assert!(!inode.is_fifo());
        assert!(!inode.is_dir());
        assert!(!inode.is_symlink());
        assert!(!inode.is_reg());

        // Test character device
        inode.i_mode = libc::S_IFCHR as u32;
        assert!(!inode.is_blkdev());
        assert!(inode.is_chrdev());
        assert!(!inode.is_sock());
        assert!(!inode.is_fifo());

        // Test socket
        inode.i_mode = libc::S_IFSOCK as u32;
        assert!(!inode.is_blkdev());
        assert!(!inode.is_chrdev());
        assert!(inode.is_sock());
        assert!(!inode.is_fifo());

        // Test FIFO
        inode.i_mode = libc::S_IFIFO as u32;
        assert!(!inode.is_blkdev());
        assert!(!inode.is_chrdev());
        assert!(!inode.is_sock());
        assert!(inode.is_fifo());

        // Test hardlink detection
        inode.i_mode = libc::S_IFREG as u32;
        inode.i_nlink = 2;
        assert!(inode.is_hardlink());

        inode.i_mode = libc::S_IFDIR as u32;
        inode.i_nlink = 2;
        assert!(!inode.is_hardlink()); // Directories are not considered hardlinks
    }

    #[test]
    fn test_cached_inode_v5_xattr_operations() {
        let meta = Arc::new(RafsSuperMeta::default());
        let blob_table = Arc::new(RafsV5BlobTable::new());
        let mut inode = CachedInodeV5::new(blob_table, meta);

        // Test xattr flag
        inode.i_flags = RafsInodeFlags::XATTR;
        assert!(inode.has_xattr());

        // Add some xattrs
        inode
            .i_xattr
            .insert(OsString::from("user.test1"), vec![1, 2, 3]);
        inode
            .i_xattr
            .insert(OsString::from("user.test2"), vec![4, 5, 6]);

        // Test get_xattr
        let value = inode.get_xattr(OsStr::new("user.test1")).unwrap();
        assert_eq!(value, Some(vec![1, 2, 3]));

        let value = inode.get_xattr(OsStr::new("user.nonexistent")).unwrap();
        assert_eq!(value, None);

        // Test get_xattrs
        let xattrs = inode.get_xattrs().unwrap();
        assert_eq!(xattrs.len(), 2);
        assert!(xattrs.contains(&b"user.test1".to_vec()));
        assert!(xattrs.contains(&b"user.test2".to_vec()));
    }

    #[test]
    fn test_cached_inode_v5_symlink_operations() {
        let meta = Arc::new(RafsSuperMeta::default());
        let blob_table = Arc::new(RafsV5BlobTable::new());
        let mut inode = CachedInodeV5::new(blob_table, meta);

        // Test non-symlink
        inode.i_mode = libc::S_IFREG as u32;
        assert!(inode.get_symlink().is_err());
        assert_eq!(inode.get_symlink_size(), 0);

        // Test symlink
        inode.i_mode = libc::S_IFLNK as u32;
        inode.i_target = OsString::from("/path/to/target");

        let target = inode.get_symlink().unwrap();
        assert_eq!(target, OsString::from("/path/to/target"));
        assert_eq!(inode.get_symlink_size(), "/path/to/target".len() as u16);
    }

    #[test]
    fn test_cached_inode_v5_child_operations() {
        let meta = Arc::new(RafsSuperMeta::default());
        let blob_table = Arc::new(RafsV5BlobTable::new());
        let mut parent = CachedInodeV5::new(blob_table.clone(), meta.clone());
        parent.i_ino = 1;
        parent.i_mode = libc::S_IFDIR as u32;
        parent.i_child_cnt = 2;

        // Create child inodes
        let mut child1 = CachedInodeV5::new(blob_table.clone(), meta.clone());
        child1.i_ino = 2;
        child1.i_name = OsString::from("child_b");
        child1.i_mode = libc::S_IFREG as u32;

        let mut child2 = CachedInodeV5::new(blob_table.clone(), meta.clone());
        child2.i_ino = 3;
        child2.i_name = OsString::from("child_a");
        child2.i_mode = libc::S_IFREG as u32;

        // Add children (they should be sorted by name)
        parent.add_child(Arc::new(child1));
        parent.add_child(Arc::new(child2));

        // Test children are sorted
        assert_eq!(parent.i_child[0].i_name, OsString::from("child_a"));
        assert_eq!(parent.i_child[1].i_name, OsString::from("child_b"));

        // Test get_child_by_name
        let child = parent.get_child_by_name(OsStr::new("child_a")).unwrap();
        assert_eq!(child.ino(), 3);

        assert!(parent.get_child_by_name(OsStr::new("nonexistent")).is_err());

        // Test get_child_by_index
        let child = parent.get_child_by_index(0).unwrap();
        assert_eq!(child.ino(), 3);

        let child = parent.get_child_by_index(1).unwrap();
        assert_eq!(child.ino(), 2);

        assert!(parent.get_child_by_index(2).is_err());

        // Test get_child_count
        assert_eq!(parent.get_child_count(), 2);
    }

    #[test]
    fn test_cached_inode_v5_walk_children() {
        let meta = Arc::new(RafsSuperMeta::default());
        let blob_table = Arc::new(RafsV5BlobTable::new());
        let mut parent = CachedInodeV5::new(blob_table.clone(), meta.clone());
        parent.i_ino = 1;
        parent.i_mode = libc::S_IFDIR as u32;
        parent.i_child_cnt = 1;

        let mut child = CachedInodeV5::new(blob_table, meta);
        child.i_ino = 2;
        child.i_name = OsString::from("test_child");
        parent.add_child(Arc::new(child));

        // Test walking from offset 0 (should see ".", "..", and "test_child")
        let mut entries = Vec::new();
        parent
            .walk_children_inodes(0, &mut |_node, name, ino, offset| {
                entries.push((name, ino, offset));
                Ok(RafsInodeWalkAction::Continue)
            })
            .unwrap();

        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].0, OsString::from("."));
        assert_eq!(entries[0].1, 1); // parent inode
        assert_eq!(entries[1].0, OsString::from(".."));
        assert_eq!(entries[1].1, 1); // root case
        assert_eq!(entries[2].0, OsString::from("test_child"));
        assert_eq!(entries[2].1, 2);

        // Test walking from offset 1 (should skip ".")
        let mut entries = Vec::new();
        parent
            .walk_children_inodes(1, &mut |_node, name, ino, _offset| {
                entries.push((name, ino));
                Ok(RafsInodeWalkAction::Continue)
            })
            .unwrap();

        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].0, OsString::from(".."));
        assert_eq!(entries[1].0, OsString::from("test_child"));

        // Test early break
        let mut count = 0;
        parent
            .walk_children_inodes(0, &mut |_node, _name, _ino, _offset| {
                count += 1;
                if count == 1 {
                    Ok(RafsInodeWalkAction::Break)
                } else {
                    Ok(RafsInodeWalkAction::Continue)
                }
            })
            .unwrap();

        assert_eq!(count, 1);
    }

    #[test]
    fn test_cached_inode_v5_chunk_operations() {
        let meta = Arc::new(RafsSuperMeta::default());
        let blob_table = Arc::new(RafsV5BlobTable::new());
        let mut inode = CachedInodeV5::new(blob_table, meta);

        // Add some chunks
        let mut chunk1 = CachedChunkInfoV5::new();
        chunk1.index = 0;
        chunk1.file_offset = 0;
        chunk1.uncompressed_size = 1024;

        let mut chunk2 = CachedChunkInfoV5::new();
        chunk2.index = 1;
        chunk2.file_offset = 1024;
        chunk2.uncompressed_size = 1024;

        inode.i_data.push(Arc::new(chunk1));
        inode.i_data.push(Arc::new(chunk2));

        // Note: get_chunk_count() currently returns i_child_cnt, not i_data.len()
        // This appears to be a bug in the implementation, but we test current behavior
        assert_eq!(inode.get_chunk_count(), 0); // i_child_cnt is 0 by default

        // Test get_chunk_info
        let chunk = inode.get_chunk_info(0).unwrap();
        assert_eq!(chunk.uncompressed_size(), 1024);

        let chunk = inode.get_chunk_info(1).unwrap();
        assert_eq!(chunk.uncompressed_size(), 1024);

        assert!(inode.get_chunk_info(2).is_err());

        // Test actual data length
        assert_eq!(inode.i_data.len(), 2);
    }

    #[test]
    fn test_cached_inode_v5_collect_descendants() {
        let meta = Arc::new(RafsSuperMeta::default());
        let blob_table = Arc::new(RafsV5BlobTable::new());

        // Create a directory structure
        let mut root = CachedInodeV5::new(blob_table.clone(), meta.clone());
        root.i_ino = 1;
        root.i_mode = libc::S_IFDIR as u32;
        root.i_size = 0;

        let mut subdir = CachedInodeV5::new(blob_table.clone(), meta.clone());
        subdir.i_ino = 2;
        subdir.i_mode = libc::S_IFDIR as u32;
        subdir.i_size = 0;

        let mut file1 = CachedInodeV5::new(blob_table.clone(), meta.clone());
        file1.i_ino = 3;
        file1.i_mode = libc::S_IFREG as u32;
        file1.i_size = 1024;

        let mut file2 = CachedInodeV5::new(blob_table.clone(), meta.clone());
        file2.i_ino = 4;
        file2.i_mode = libc::S_IFREG as u32;
        file2.i_size = 0; // Empty file should be skipped

        let mut file3 = CachedInodeV5::new(blob_table.clone(), meta.clone());
        file3.i_ino = 5;
        file3.i_mode = libc::S_IFREG as u32;
        file3.i_size = 2048;

        // Build structure: root -> [subdir, file1, file2], subdir -> [file3]
        subdir.i_child.push(Arc::new(file3));
        root.i_child.push(Arc::new(subdir));
        root.i_child.push(Arc::new(file1));
        root.i_child.push(Arc::new(file2));

        let mut descendants = Vec::new();
        root.collect_descendants_inodes(&mut descendants).unwrap();

        // Should collect file1 (non-empty) and file3 (from subdirectory)
        // file2 should be skipped because it's empty
        assert_eq!(descendants.len(), 2);
        let inodes: Vec<u64> = descendants.iter().map(|d| d.ino()).collect();
        assert!(inodes.contains(&3)); // file1
        assert!(inodes.contains(&5)); // file3
        assert!(!inodes.contains(&4)); // file2 (empty)

        // Test with non-directory
        let file = CachedInodeV5::new(blob_table, meta);
        let mut descendants = Vec::new();
        assert!(file.collect_descendants_inodes(&mut descendants).is_err());
    }

    #[test]
    fn test_cached_chunk_info_v5_detailed() {
        let mut info = CachedChunkInfoV5::new();
        info.block_id = Arc::new(RafsDigest::from_buf("test".as_bytes(), Algorithm::Blake3));
        info.blob_index = 42;
        info.index = 100;
        info.file_offset = 2048;
        info.compressed_offset = 1024;
        info.uncompressed_offset = 3072;
        info.compressed_size = 512;
        info.uncompressed_size = 1024;
        info.flags = BlobChunkFlags::COMPRESSED | BlobChunkFlags::HAS_CRC32;
        info.crc32 = 0x12345678;

        // Test basic properties
        assert_eq!(info.id(), 100);
        assert!(!info.is_batch());
        assert!(info.is_compressed());
        assert!(!info.is_encrypted());
        assert!(info.has_crc32());
        assert_eq!(info.crc32(), 0x12345678);

        // Test getters
        assert_eq!(info.blob_index(), 42);
        assert_eq!(info.compressed_offset(), 1024);
        assert_eq!(info.compressed_size(), 512);
        assert_eq!(info.uncompressed_offset(), 3072);
        assert_eq!(info.uncompressed_size(), 1024);

        // Test V5-specific getters
        assert_eq!(info.index(), 100);
        assert_eq!(info.file_offset(), 2048);
        assert_eq!(
            info.flags(),
            BlobChunkFlags::COMPRESSED | BlobChunkFlags::HAS_CRC32
        );

        // Test CRC32 without flag
        info.flags = BlobChunkFlags::COMPRESSED;
        assert!(!info.has_crc32());
        assert_eq!(info.crc32(), 0);

        // Test as_base
        let base_info = info.as_base();
        assert_eq!(base_info.blob_index(), 42);
        assert!(base_info.is_compressed());
    }

    #[test]
    fn test_cached_superblock_v5_inode_management() {
        let md = RafsSuperMeta::default();
        let mut sb = CachedSuperBlockV5::new(md, false);

        // Test empty superblock
        assert_eq!(sb.get_max_ino(), RAFS_V5_ROOT_INODE);
        assert!(sb.get_inode(1, false).is_err());
        assert!(sb.get_extended_inode(1, false).is_err());

        // Test adding regular inode
        let mut inode1 = CachedInodeV5::new(sb.s_blob.clone(), sb.s_meta.clone());
        inode1.i_ino = 10;
        inode1.i_nlink = 1;
        inode1.i_mode = libc::S_IFREG as u32;
        let inode1_arc = Arc::new(inode1);
        sb.hash_inode(inode1_arc.clone()).unwrap();

        assert_eq!(sb.get_max_ino(), 10);
        assert!(sb.get_inode(10, false).is_ok());
        assert!(sb.get_extended_inode(10, false).is_ok());

        // Test adding hardlink with data (should not replace existing)
        let mut hardlink = CachedInodeV5::new(sb.s_blob.clone(), sb.s_meta.clone());
        hardlink.i_ino = 10; // Same inode number
        hardlink.i_nlink = 2; // Hardlink
        hardlink.i_mode = libc::S_IFREG as u32;
        hardlink.i_data = vec![Arc::new(CachedChunkInfoV5::new())]; // Has data

        let hardlink_arc = Arc::new(hardlink);
        let _result = sb.hash_inode(hardlink_arc.clone()).unwrap();

        // Since original inode has no data, the hardlink with data should replace it
        let stored_inode = sb.get_inode(10, false).unwrap();
        assert_eq!(
            stored_inode
                .as_any()
                .downcast_ref::<CachedInodeV5>()
                .unwrap()
                .i_data
                .len(),
            1
        );

        // Test root inode
        assert_eq!(sb.root_ino(), RAFS_V5_ROOT_INODE);

        // Test destroy
        sb.destroy();
        assert_eq!(sb.s_inodes.len(), 0);
    }

    #[test]
    fn test_cached_superblock_v5_blob_operations() {
        let md = RafsSuperMeta::default();
        let sb = CachedSuperBlockV5::new(md, false);

        // Test get_blob_infos with empty blob table
        let blobs = sb.get_blob_infos();
        assert!(blobs.is_empty());

        // Note: get_chunk_info() and set_blob_device() both panic with
        // "not implemented: used by RAFS v6 only" so we can't test them directly
    }

    #[test]
    fn test_cached_superblock_v5_hardlink_handling() {
        let md = RafsSuperMeta::default();
        let mut sb = CachedSuperBlockV5::new(md, false);

        // Add inode without data
        let mut inode1 = CachedInodeV5::new(sb.s_blob.clone(), sb.s_meta.clone());
        inode1.i_ino = 5;
        inode1.i_nlink = 1;
        inode1.i_mode = libc::S_IFREG as u32;
        sb.hash_inode(Arc::new(inode1)).unwrap();

        // Add hardlink with same inode number but no data - should replace
        let mut hardlink = CachedInodeV5::new(sb.s_blob.clone(), sb.s_meta.clone());
        hardlink.i_ino = 5;
        hardlink.i_nlink = 2;
        hardlink.i_mode = libc::S_IFREG as u32;
        hardlink.i_data = vec![]; // No data

        sb.hash_inode(Arc::new(hardlink)).unwrap();

        // Should have replaced the original
        let stored = sb.get_inode(5, false).unwrap();
        assert_eq!(
            stored
                .as_any()
                .downcast_ref::<CachedInodeV5>()
                .unwrap()
                .i_nlink,
            2
        );
    }

    #[test]
    fn test_from_rafs_v5_chunk_info() {
        let mut ondisk_chunk = RafsV5ChunkInfo::new();
        ondisk_chunk.block_id = RafsDigest::from_buf("test".as_bytes(), Algorithm::Blake3);
        ondisk_chunk.blob_index = 1;
        ondisk_chunk.index = 42;
        ondisk_chunk.file_offset = 1024;
        ondisk_chunk.compressed_offset = 512;
        ondisk_chunk.uncompressed_offset = 2048;
        ondisk_chunk.compressed_size = 256;
        ondisk_chunk.uncompressed_size = 512;
        ondisk_chunk.flags = BlobChunkFlags::COMPRESSED;

        let cached_chunk = CachedChunkInfoV5::from(&ondisk_chunk);

        assert_eq!(cached_chunk.blob_index(), 1);
        assert_eq!(cached_chunk.index(), 42);
        assert_eq!(cached_chunk.file_offset(), 1024);
        assert_eq!(cached_chunk.compressed_offset(), 512);
        assert_eq!(cached_chunk.uncompressed_offset(), 2048);
        assert_eq!(cached_chunk.compressed_size(), 256);
        assert_eq!(cached_chunk.uncompressed_size(), 512);
        assert_eq!(cached_chunk.flags(), BlobChunkFlags::COMPRESSED);
        assert!(cached_chunk.is_compressed());
    }

    #[test]
    fn test_cached_inode_v5_accessor_methods() {
        let meta = Arc::new(RafsSuperMeta::default());
        let blob_table = Arc::new(RafsV5BlobTable::new());
        let mut inode = CachedInodeV5::new(blob_table, meta);

        // Set test values
        inode.i_ino = 42;
        inode.i_size = 8192;

        inode.i_rdev = 0x0801; // Example device number
        inode.i_projid = 1000;
        inode.i_parent = 1;
        inode.i_name = OsString::from("test_file");
        inode.i_flags = RafsInodeFlags::XATTR;
        inode.i_digest = RafsDigest::from_buf("test".as_bytes(), Algorithm::Blake3);
        inode.i_child_idx = 10;

        // Test basic getters
        assert_eq!(inode.ino(), 42);
        assert_eq!(inode.size(), 8192);
        assert_eq!(inode.rdev(), 0x0801);
        assert_eq!(inode.projid(), 1000);
        assert_eq!(inode.parent(), 1);
        assert_eq!(inode.name(), OsString::from("test_file"));
        assert_eq!(inode.get_name_size(), "test_file".len() as u16);
        assert_eq!(inode.flags(), RafsInodeFlags::XATTR.bits());
        assert_eq!(inode.get_digest(), inode.i_digest);
        assert_eq!(inode.get_child_index().unwrap(), 10);

        // Test as_inode
        let as_inode = inode.as_inode();
        assert_eq!(as_inode.ino(), 42);
    }

    #[test]
    fn test_cached_inode_v5_edge_cases() {
        let meta = Arc::new(RafsSuperMeta::default());
        let blob_table = Arc::new(RafsV5BlobTable::new());
        let mut inode = CachedInodeV5::new(blob_table, meta);

        // Test very large inode number
        inode.i_ino = u64::MAX;
        assert_eq!(inode.ino(), u64::MAX);

        // Test edge case file modes
        inode.i_mode = 0o777 | libc::S_IFREG as u32;
        assert!(inode.is_reg());
        assert_eq!(inode.i_mode & 0o777, 0o777);

        // Test empty symlink target (should be invalid but we test getter)
        inode.i_mode = libc::S_IFLNK as u32;
        inode.i_target = OsString::new();
        assert_eq!(inode.get_symlink_size(), 0);

        // Test maximum name length
        let max_name = "a".repeat(RAFS_MAX_NAME);
        inode.i_name = OsString::from(max_name.clone());
        assert_eq!(inode.name(), OsString::from(max_name));
        assert_eq!(inode.get_name_size(), RAFS_MAX_NAME as u16);
    }

    #[test]
    fn test_cached_inode_v5_zero_values() {
        let meta = Arc::new(RafsSuperMeta::default());
        let blob_table = Arc::new(RafsV5BlobTable::new());
        let inode = CachedInodeV5::new(blob_table, meta);

        // Test all zero/default values
        assert_eq!(inode.ino(), 0);
        assert_eq!(inode.size(), 0);
        assert_eq!(inode.rdev(), 0);
        assert_eq!(inode.projid(), 0);
        assert_eq!(inode.parent(), 0);
        assert_eq!(inode.flags(), 0);
        assert_eq!(inode.get_name_size(), 0);
        assert!(!inode.has_xattr());
        assert!(!inode.is_hardlink());

        // Test get_child operations on empty inode
        assert_eq!(inode.get_child_count(), 0);
        assert!(inode.get_child_by_index(0).is_err());
        assert!(inode.get_child_by_name(OsStr::new("test")).is_err());

        // Test chunk operations on empty inode
        assert_eq!(inode.i_data.len(), 0);
        assert!(inode.get_chunk_info(0).is_err());
    }

    #[test]
    fn test_cached_chunk_info_v5_boundary_values() {
        let mut info = CachedChunkInfoV5::new();

        // Test maximum values
        info.blob_index = u32::MAX;
        info.index = u32::MAX;
        info.file_offset = u64::MAX;
        info.compressed_offset = u64::MAX;
        info.uncompressed_offset = u64::MAX;
        info.compressed_size = u32::MAX;
        info.uncompressed_size = u32::MAX;
        info.crc32 = u32::MAX;

        assert_eq!(info.blob_index(), u32::MAX);
        assert_eq!(info.index(), u32::MAX);
        assert_eq!(info.file_offset(), u64::MAX);
        assert_eq!(info.compressed_offset(), u64::MAX);
        assert_eq!(info.uncompressed_offset(), u64::MAX);
        assert_eq!(info.compressed_size(), u32::MAX);
        assert_eq!(info.uncompressed_size(), u32::MAX);

        // Test zero values
        info.blob_index = 0;
        info.index = 0;
        info.file_offset = 0;
        info.compressed_offset = 0;
        info.uncompressed_offset = 0;
        info.compressed_size = 0;
        info.uncompressed_size = 0;
        info.crc32 = 0;

        assert_eq!(info.blob_index(), 0);
        assert_eq!(info.index(), 0);
        assert_eq!(info.file_offset(), 0);
        assert_eq!(info.compressed_offset(), 0);
        assert_eq!(info.uncompressed_offset(), 0);
        assert_eq!(info.compressed_size(), 0);
        assert_eq!(info.uncompressed_size(), 0);
        assert_eq!(info.crc32(), 0);
    }

    #[test]
    fn test_cached_inode_v5_special_names() {
        let meta = Arc::new(RafsSuperMeta::default());
        let blob_table = Arc::new(RafsV5BlobTable::new());
        let mut inode = CachedInodeV5::new(blob_table, meta);

        // Test special characters in names
        let special_names = vec![
            ".",
            "..",
            "file with spaces",
            "file\twith\ttabs",
            "file\nwith\nnewlines",
            "file-with-dashes",
            "file_with_underscores",
            "file.with.dots",
            "UPPERCASE_FILE",
            "MiXeD_cAsE_fIlE",
            "123456789",
            "中文文件名", // Chinese characters
            "файл",       // Cyrillic
            "🦀🦀🦀",     // Emojis
        ];

        for name in special_names {
            inode.i_name = OsString::from(name);
            assert_eq!(inode.name(), OsString::from(name));
            assert_eq!(inode.get_name_size(), name.len() as u16);
        }
    }

    #[test]
    fn test_cached_superblock_v5_edge_cases() {
        let md = RafsSuperMeta::default();
        let mut sb = CachedSuperBlockV5::new(md, false);

        // Test with validation enabled
        let md_validated = RafsSuperMeta::default();
        let sb_validated = CachedSuperBlockV5::new(md_validated, true);
        assert!(sb_validated.validate_inode);

        // Test maximum inode number
        let mut inode = CachedInodeV5::new(sb.s_blob.clone(), sb.s_meta.clone());
        inode.i_ino = u64::MAX;
        inode.i_nlink = 1;
        inode.i_mode = libc::S_IFREG as u32;
        inode.i_name = OsString::from("max_inode");

        sb.hash_inode(Arc::new(inode)).unwrap();
        assert_eq!(sb.get_max_ino(), u64::MAX);

        // Test getting non-existent inode
        assert!(sb.get_inode(u64::MAX - 1, false).is_err());
        assert!(sb.get_extended_inode(u64::MAX - 1, false).is_err());

        // Test blob operations
        let blob_infos = sb.get_blob_infos();
        assert!(blob_infos.is_empty());

        let blob_extra_infos = sb.get_blob_extra_infos().unwrap();
        assert!(blob_extra_infos.is_empty());
    }

    #[test]
    fn test_cached_inode_v5_complex_directory_structure() {
        let meta = Arc::new(RafsSuperMeta::default());
        let blob_table = Arc::new(RafsV5BlobTable::new());

        // Create a complex directory with many children
        let mut root_dir = CachedInodeV5::new(blob_table.clone(), meta.clone());
        root_dir.i_ino = 1;
        root_dir.i_mode = libc::S_IFDIR as u32;
        root_dir.i_name = OsString::from("root");

        // Add many children with different names to test sorting
        let child_names = [
            "zzz_last",
            "aaa_first",
            "mmm_middle",
            "000_numeric",
            "ZZZ_upper",
            "___underscore",
            "...dots",
            "111_mixed",
            "yyy_second_last",
            "bbb_second",
        ];

        // Set the correct child count for sorting to trigger
        root_dir.i_child_cnt = child_names.len() as u32;

        for (i, name) in child_names.iter().enumerate() {
            let mut child = CachedInodeV5::new(blob_table.clone(), meta.clone());
            child.i_ino = i as u64 + 2;
            child.i_name = OsString::from(*name);
            child.i_mode = if i % 2 == 0 {
                libc::S_IFREG as u32
            } else {
                libc::S_IFDIR as u32
            };
            root_dir.add_child(Arc::new(child));
        }

        // Verify children are sorted by name (after all children are added)
        assert_eq!(root_dir.i_child.len(), child_names.len());
        for i in 1..root_dir.i_child.len() {
            let prev_name = &root_dir.i_child[i - 1].i_name;
            let curr_name = &root_dir.i_child[i].i_name;
            assert!(
                prev_name <= curr_name,
                "Children not sorted: {:?} > {:?}",
                prev_name,
                curr_name
            );
        }

        // Test walking all children
        let mut visited_count = 0;
        root_dir
            .walk_children_inodes(0, &mut |_node, _name, _ino, _offset| {
                visited_count += 1;
                Ok(RafsInodeWalkAction::Continue)
            })
            .unwrap();

        // Should visit ".", "..", and all children
        assert_eq!(visited_count, 2 + child_names.len());

        // Test collecting descendants
        let mut descendants = Vec::new();
        root_dir
            .collect_descendants_inodes(&mut descendants)
            .unwrap();
        // Only regular files with size > 0 are collected, so should be empty
        assert!(descendants.is_empty());
    }
}

// Copyright 2020 Ant Group. All rights reserved.
// Copyright (C) 2020 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! A manager to cache all file system bootstrap into memory.
//!
//! All file system bootstrap will be loaded, validated and cached into memory when loading the
//! file system. And currently the cache layer only supports readonly file systems.

use std::collections::{BTreeMap, HashMap};
use std::ffi::{OsStr, OsString};
use std::io::SeekFrom;
use std::io::{ErrorKind, Read, Result};
use std::mem::size_of;
use std::os::unix::ffi::OsStrExt;
use std::sync::Arc;

use fuse_backend_rs::abi::linux_abi;
use fuse_backend_rs::api::filesystem::Entry;

use crate::metadata::layout::v5::{
    rafsv5_alloc_bio_desc, rafsv5_validate_digest, RafsBlobEntry, RafsChunkFlags, RafsChunkInfo,
    RafsV5BlobTable, RafsV5ChunkInfo, RafsV5Inode, RafsV5InodeFlags, RafsV5InodeOps,
    RafsV5XAttrsTable, RAFSV5_ALIGNMENT,
};
use crate::metadata::layout::{bytes_to_os_str, parse_xattr, RAFS_ROOT_INODE};
use crate::metadata::{
    Inode, RafsBioDesc, RafsError, RafsInode, RafsResult, RafsSuperBlobs, RafsSuperBlock,
    RafsSuperInodes, RafsSuperMeta, XattrName, XattrValue, RAFS_INODE_BLOCKSIZE,
};
use crate::RafsIoReader;

use nydus_utils::digest::Algorithm;
use nydus_utils::{digest::RafsDigest, ByteSize};

pub struct CachedSuperBlockV5 {
    s_blob: Arc<RafsV5BlobTable>,
    s_meta: Arc<RafsSuperMeta>,
    s_inodes: BTreeMap<Inode, Arc<CachedInodeV5>>,
    digest_validate: bool,
}

impl CachedSuperBlockV5 {
    pub fn new(meta: RafsSuperMeta, digest_validate: bool) -> Self {
        CachedSuperBlockV5 {
            s_blob: Arc::new(RafsV5BlobTable::new()),
            s_inodes: BTreeMap::new(),
            s_meta: Arc::new(meta),
            digest_validate,
        }
    }

    /// v5 layout is based on BFS, which means parents always are in front of children
    fn load_all_inodes(&mut self, r: &mut RafsIoReader) -> Result<()> {
        let mut dir_ino_set = Vec::new();
        let mut entries = 0;
        loop {
            // Stopping after loading all inodes helps to append possible
            // new structure to the tail of bootstrap in the future.
            if entries >= self.s_meta.inode_table_entries {
                break;
            }
            let mut inode = CachedInodeV5::new(self.s_blob.clone(), self.s_meta.clone());
            match inode.load(&self.s_meta, r) {
                Ok(_) => {
                    entries += 1;
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
                continue;
            }
            self.add_into_parent(child_inode);
        }
        while !dir_ino_set.is_empty() {
            let ino = dir_ino_set.pop().unwrap();
            self.add_into_parent(self.get_node(ino)?);
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
        if inode.is_hardlink() {
            if let Some(i) = self.s_inodes.get(&inode.i_ino) {
                if !i.i_data.is_empty() {
                    return Ok(inode);
                }
            }
        }
        let ino = inode.ino();
        self.s_inodes.insert(inode.i_ino, inode);
        self.get_node(ino)
    }

    fn add_into_parent(&mut self, child_inode: Arc<CachedInodeV5>) {
        if let Ok(parent_inode) = self.get_node_mut(child_inode.parent()) {
            Arc::get_mut(parent_inode)
                .unwrap()
                .add_child(child_inode.clone());
        }
    }
}

impl RafsSuperInodes for CachedSuperBlockV5 {
    fn get_max_ino(&self) -> u64 {
        self.s_inodes.len() as u64
    }

    fn get_inode(&self, ino: Inode, _digest_validate: bool) -> Result<Arc<dyn RafsInode>> {
        self.s_inodes
            .get(&ino)
            .map_or(Err(enoent!()), |i| Ok(i.clone()))
    }

    fn validate_digest(
        &self,
        inode: Arc<dyn RafsInode>,
        recursive: bool,
        digester: Algorithm,
    ) -> Result<bool> {
        rafsv5_validate_digest(inode, recursive, digester)
    }
}

impl RafsSuperBlobs for CachedSuperBlockV5 {
    fn get_blob_table(&self) -> Arc<RafsV5BlobTable> {
        self.s_blob.clone()
    }
}

impl RafsSuperBlock for CachedSuperBlockV5 {
    fn load(&mut self, r: &mut RafsIoReader) -> Result<()> {
        // FIXME: add validator for all load operations.

        // Now the seek offset points to inode table, so we can easily
        // find first inode offset.
        r.seek(SeekFrom::Start(self.s_meta.inode_table_offset))?;
        let mut offset = [0u8; size_of::<u32>()];
        r.read_exact(&mut offset)?;
        // The offset is aligned with 8 bytes to make it easier to
        // validate RafsV5Inode.
        let inode_offset = u32::from_le_bytes(offset) << 3;

        // Load blob table.
        r.seek(SeekFrom::Start(self.s_meta.blob_table_offset))?;
        let mut blob_table = RafsV5BlobTable::new();
        let meta = &self.s_meta;

        // Load extended blob table if the bootstrap including
        // extended blob table.
        if meta.extended_blob_table_offset > 0 {
            r.seek(SeekFrom::Start(meta.extended_blob_table_offset))?;
            blob_table
                .extended
                .load(r, meta.extended_blob_table_entries as usize)?;
        }

        r.seek(SeekFrom::Start(meta.blob_table_offset))?;
        blob_table.load(r, meta.blob_table_size)?;

        self.s_blob = Arc::new(blob_table);

        // Load all inodes started from first inode offset.
        r.seek(SeekFrom::Start(inode_offset as u64))?;
        self.load_all_inodes(r)?;

        // Validate inode digest tree
        let digester = self.s_meta.get_digester();
        if self.digest_validate
            && !self.validate_digest(self.get_inode(RAFS_ROOT_INODE, false)?, true, digester)?
        {
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
}

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
    i_flags: RafsV5InodeFlags,
    i_size: u64,
    i_blocks: u64,
    i_nlink: u32,
    i_child_idx: u32,
    i_child_cnt: u32,
    // extra info need cache
    i_blksize: u32,
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
            self.i_name = bytes_to_os_str(&name_buf).to_os_string();
        }
        r.seek_to_next_aligned(name_size, RAFSV5_ALIGNMENT)?;
        Ok(())
    }

    fn load_symlink(&mut self, symlink_size: usize, r: &mut RafsIoReader) -> Result<()> {
        if self.is_symlink() && symlink_size > 0 {
            let mut symbol_buf = vec![0u8; symlink_size];
            r.read_exact(symbol_buf.as_mut_slice())?;
            self.i_target = bytes_to_os_str(&symbol_buf).to_os_string();
        }
        r.seek_to_next_aligned(symlink_size, RAFSV5_ALIGNMENT)?;
        Ok(())
    }

    fn load_xattr(&mut self, r: &mut RafsIoReader) -> Result<()> {
        if self.has_xattr() {
            let mut xattrs = RafsV5XAttrsTable::new();
            r.read_exact(xattrs.as_mut())?;
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
            for _i in 0..self.i_child_cnt {
                chunk.load(r)?;
                self.i_data.push(Arc::new(CachedChunkInfoV5::from(&chunk)));
            }
        }
        Ok(())
    }

    pub fn load(&mut self, sb: &RafsSuperMeta, r: &mut RafsIoReader) -> Result<()> {
        // RafsV5Inode...name...symbol link...chunks
        let mut inode = RafsV5Inode::new();

        // parse ondisk inode
        // RafsV5Inode|name|symbol|xattr|chunks
        r.read_exact(inode.as_mut())?;
        self.copy_from_ondisk(&inode);
        self.load_name(inode.i_name_size as usize, r)?;
        self.load_symlink(inode.i_symlink_size as usize, r)?;
        self.load_xattr(r)?;
        self.load_chunk_info(r)?;
        self.i_blksize = sb.block_size;
        self.validate()?;

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
    fn validate(&self) -> Result<()> {
        // TODO: validate
        if self.is_symlink() && self.i_target.is_empty() {
            return Err(einval!("invalid inode"));
        }
        Ok(())
    }

    #[inline]
    fn get_entry(&self) -> Entry {
        Entry {
            attr: self.get_attr().into(),
            inode: self.i_ino,
            generation: 0,
            attr_timeout: self.i_meta.attr_timeout,
            entry_timeout: self.i_meta.entry_timeout,
        }
    }

    #[inline]
    fn get_attr(&self) -> linux_abi::Attr {
        linux_abi::Attr {
            ino: self.i_ino,
            size: self.i_size,
            blocks: self.i_blocks,
            mode: self.i_mode,
            nlink: self.i_nlink as u32,
            blksize: RAFS_INODE_BLOCKSIZE,
            rdev: self.i_rdev,
            ..Default::default()
        }
    }

    fn get_symlink(&self) -> Result<OsString> {
        if !self.is_symlink() {
            Err(einval!("inode is not a symlink"))
        } else {
            Ok(self.i_target.clone())
        }
    }

    fn get_child_by_name(&self, name: &OsStr) -> Result<Arc<dyn RafsInode>> {
        let idx = self
            .i_child
            .binary_search_by(|c| c.i_name.as_os_str().cmp(name))
            .map_err(|_| enoent!())?;
        Ok(self.i_child[idx].clone())
    }

    #[inline]
    fn get_child_by_index(&self, index: Inode) -> Result<Arc<dyn RafsInode>> {
        Ok(self.i_child[index as usize].clone())
    }

    fn get_child_index(&self) -> Result<u32> {
        Ok(self.i_child_idx)
    }

    #[inline]
    fn get_child_count(&self) -> u32 {
        self.i_child_cnt
    }

    #[inline]
    fn get_chunk_info(&self, idx: u32) -> Result<Arc<dyn RafsChunkInfo>> {
        Ok(self.i_data[idx as usize].clone())
    }

    fn has_xattr(&self) -> bool {
        self.i_flags.contains(RafsV5InodeFlags::XATTR)
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

    fn is_dir(&self) -> bool {
        self.i_mode & libc::S_IFMT == libc::S_IFDIR
    }

    fn is_symlink(&self) -> bool {
        self.i_mode & libc::S_IFMT == libc::S_IFLNK
    }

    fn is_reg(&self) -> bool {
        self.i_mode & libc::S_IFMT == libc::S_IFREG
    }

    fn is_hardlink(&self) -> bool {
        !self.is_dir() && self.i_nlink > 1
    }

    fn name(&self) -> OsString {
        self.i_name.clone()
    }

    fn flags(&self) -> u64 {
        self.i_flags.bits()
    }

    fn get_digest(&self) -> RafsDigest {
        self.i_digest
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
                trace!("Got dir {:?}", child_inode.name());
                child_dirs.push(child_inode.clone());
            } else {
                if child_inode.is_empty_size() {
                    continue;
                }
                descendants.push(child_inode.clone());
            }
        }

        for d in child_dirs {
            d.collect_descendants_inodes(descendants)?;
        }

        Ok(0)
    }

    fn alloc_bio_desc(&self, offset: u64, size: usize, user_io: bool) -> Result<RafsBioDesc> {
        rafsv5_alloc_bio_desc(self, offset, size, user_io)
    }

    fn get_name_size(&self) -> u16 {
        self.i_name.byte_size() as u16
    }

    fn get_symlink_size(&self) -> u16 {
        if self.is_symlink() {
            self.i_target.byte_size() as u16
        } else {
            0
        }
    }

    impl_getter!(ino, i_ino, u64);
    impl_getter!(parent, i_parent, u64);
    impl_getter!(size, i_size, u64);
    impl_getter!(rdev, i_rdev, u32);
    impl_getter!(projid, i_projid, u32);
}

impl RafsV5InodeOps for CachedInodeV5 {
    fn get_blob_by_index(&self, idx: u32) -> Result<Arc<RafsBlobEntry>> {
        self.i_blob_table.get(idx)
    }

    fn get_blocksize(&self) -> u32 {
        self.i_blksize
    }

    fn has_hole(&self) -> bool {
        self.i_flags.contains(RafsV5InodeFlags::HAS_HOLE)
    }

    fn cast_ondisk(&self) -> Result<RafsV5Inode> {
        let i_symlink_size = if self.is_symlink() {
            self.get_symlink()?.byte_size() as u16
        } else {
            0
        };
        Ok(RafsV5Inode {
            i_digest: self.i_digest,
            i_parent: self.i_parent,
            i_ino: self.i_ino,
            i_projid: self.i_projid,
            i_uid: self.i_uid,
            i_gid: self.i_gid,
            i_mode: self.i_mode,
            i_size: self.i_size,
            i_nlink: self.i_nlink,
            i_blocks: self.i_blocks,
            i_flags: self.i_flags,
            i_child_index: self.i_child_idx,
            i_child_count: self.i_child_cnt,
            i_name_size: self.i_name.len() as u16,
            i_symlink_size,
            i_rdev: self.i_rdev,
            i_mtime: self.i_mtime,
            i_mtime_nsec: self.i_mtime_nsec,
            i_reserved: [0; 8],
        })
    }
}

/// Cached information about an Rafs Data Chunk.
#[derive(Clone, Default, Debug)]
pub struct CachedChunkInfoV5 {
    // block hash
    c_block_id: Arc<RafsDigest>,
    // blob containing the block
    c_blob_index: u32,
    // chunk index in blob
    c_index: u32,
    // position of the block within the file
    c_file_offset: u64,
    // offset of the block within the blob
    c_compress_offset: u64,
    c_decompress_offset: u64,
    // size of the block, compressed
    c_compr_size: u32,
    c_decompress_size: u32,
    c_flags: RafsChunkFlags,
}

impl CachedChunkInfoV5 {
    pub fn new() -> Self {
        CachedChunkInfoV5 {
            ..Default::default()
        }
    }

    pub fn load(&mut self, r: &mut RafsIoReader) -> Result<()> {
        let mut chunk = RafsV5ChunkInfo::new();

        r.read_exact(chunk.as_mut())?;
        self.copy_from_ondisk(&chunk);

        Ok(())
    }

    fn copy_from_ondisk(&mut self, chunk: &RafsV5ChunkInfo) {
        self.c_block_id = Arc::new(chunk.block_id);
        self.c_blob_index = chunk.blob_index;
        self.c_index = chunk.index;
        self.c_compress_offset = chunk.compress_offset;
        self.c_decompress_offset = chunk.decompress_offset;
        self.c_decompress_size = chunk.decompress_size;
        self.c_file_offset = chunk.file_offset;
        self.c_compr_size = chunk.compress_size;
        self.c_flags = chunk.flags;
    }
}

impl RafsChunkInfo for CachedChunkInfoV5 {
    fn block_id(&self) -> &RafsDigest {
        &self.c_block_id
    }

    fn is_compressed(&self) -> bool {
        self.c_flags.contains(RafsChunkFlags::COMPRESSED)
    }

    fn is_hole(&self) -> bool {
        self.c_flags.contains(RafsChunkFlags::HOLECHUNK)
    }

    impl_getter!(blob_index, c_blob_index, u32);
    impl_getter!(index, c_index, u32);
    impl_getter!(compress_offset, c_compress_offset, u64);
    impl_getter!(compress_size, c_compr_size, u32);
    impl_getter!(decompress_offset, c_decompress_offset, u64);
    impl_getter!(decompress_size, c_decompress_size, u32);
    impl_getter!(file_offset, c_file_offset, u64);
    impl_getter!(flags, c_flags, RafsChunkFlags);
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

    use nydus_utils::ByteSize;

    use crate::metadata::cached_v5::CachedInodeV5;
    use crate::metadata::layout::v5::{
        rafsv5_align, RafsV5BlobTable, RafsV5ChunkInfo, RafsV5Inode, RafsV5InodeWrapper,
        RafsV5XAttrs,
    };
    use crate::metadata::{RafsInode, RafsStore, RafsSuperMeta};
    use crate::{RafsIoReader, RafsIoWriter};

    #[test]
    fn test_load_inode() {
        let mut f = OpenOptions::new()
            .truncate(true)
            .create(true)
            .write(true)
            .read(true)
            .open("/tmp/buf_1")
            .unwrap();
        let mut writer = Box::new(f.try_clone().unwrap()) as RafsIoWriter;
        let mut reader = Box::new(f.try_clone().unwrap()) as RafsIoReader;
        let mut ondisk_inode = RafsV5Inode::new();
        let file_name = OsString::from("c_inode_1");
        let mut xattr = RafsV5XAttrs::default();
        xattr.add(OsString::from("k1"), vec![1u8, 2u8, 3u8, 4u8]);
        xattr.add(OsString::from("k2"), vec![10u8, 11u8, 12u8]);
        ondisk_inode.i_name_size = file_name.byte_size() as u16;
        ondisk_inode.i_child_count = 1;
        ondisk_inode.i_ino = 3;
        ondisk_inode.i_size = 8192;
        ondisk_inode.i_mode = libc::S_IFREG;
        let mut chunk = RafsV5ChunkInfo::new();
        chunk.decompress_size = 8192;
        chunk.decompress_offset = 0;
        chunk.compress_offset = 0;
        chunk.compress_size = 4096;
        let inode = RafsV5InodeWrapper {
            name: file_name.as_os_str(),
            symlink: None,
            inode: &ondisk_inode,
        };
        inode.store(&mut writer).unwrap();
        chunk.store(&mut writer).unwrap();
        xattr.store(&mut writer).unwrap();

        f.seek(Start(0)).unwrap();
        let meta = Arc::new(RafsSuperMeta::default());
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
        assert_eq!(cached_chunk.compress_size(), 4096);
        assert_eq!(cached_chunk.decompress_size(), 8192);
        assert_eq!(cached_chunk.compress_offset(), 0);
        assert_eq!(cached_chunk.decompress_offset(), 0);
        let c_xattr = cached_inode.get_xattrs().unwrap();
        for k in c_xattr.iter() {
            let k = OsStr::from_bytes(&k);
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
        let mut writer = Box::new(f.try_clone().unwrap()) as RafsIoWriter;
        let mut reader = Box::new(f.try_clone().unwrap()) as RafsIoReader;
        let file_name = OsString::from("c_inode_2");
        let symlink_name = OsString::from("c_inode_1");
        let mut ondisk_inode = RafsV5Inode::new();
        ondisk_inode.i_name_size = file_name.byte_size() as u16;
        ondisk_inode.i_symlink_size = symlink_name.byte_size() as u16;
        ondisk_inode.i_mode = libc::S_IFLNK;

        let inode = RafsV5InodeWrapper {
            name: file_name.as_os_str(),
            symlink: Some(symlink_name.as_os_str()),
            inode: &ondisk_inode,
        };
        inode.store(&mut writer).unwrap();

        f.seek(Start(0)).unwrap();
        let meta = Arc::new(RafsSuperMeta::default());
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
        let mut writer = Box::new(f.try_clone().unwrap()) as RafsIoWriter;
        let mut reader = Box::new(f.try_clone().unwrap()) as RafsIoReader;
        let file_name = OsString::from("c_inode_3");
        let mut ondisk_inode = RafsV5Inode::new();
        ondisk_inode.i_name_size = rafsv5_align(file_name.len()) as u16;
        ondisk_inode.i_child_count = 4;
        ondisk_inode.i_mode = libc::S_IFREG;
        ondisk_inode.i_size = 1024 * 1024 * 3 + 8192;

        let inode = RafsV5InodeWrapper {
            name: file_name.as_os_str(),
            symlink: None,
            inode: &ondisk_inode,
        };
        inode.store(&mut writer).unwrap();

        let mut size = ondisk_inode.i_size;
        for i in 0..ondisk_inode.i_child_count {
            let mut chunk = RafsV5ChunkInfo::new();
            chunk.decompress_size = cmp::min(1024 * 1024, size as u32);
            chunk.decompress_offset = (i * 1024 * 1024) as u64;
            chunk.compress_size = chunk.decompress_size / 2;
            chunk.compress_offset = ((i * 1024 * 1024) / 2) as u64;
            chunk.file_offset = chunk.decompress_offset;
            chunk.store(&mut writer).unwrap();
            size -= chunk.decompress_size as u64;
        }
        f.seek(Start(0)).unwrap();
        let mut meta = Arc::new(RafsSuperMeta::default());
        Arc::get_mut(&mut meta).unwrap().block_size = 1024 * 1024;
        let mut blob_table = Arc::new(RafsV5BlobTable::new());
        Arc::get_mut(&mut blob_table)
            .unwrap()
            .add(String::from("123333"), 0, 0, 0, 0, 0);
        let mut cached_inode = CachedInodeV5::new(blob_table, meta.clone());
        cached_inode.load(&meta, &mut reader).unwrap();
        let desc1 = cached_inode.alloc_bio_desc(0, 100, true).unwrap();
        assert_eq!(desc1.bi_size, 100);
        assert_eq!(desc1.bi_vec.len(), 1);
        assert_eq!(desc1.bi_vec[0].offset, 0);
        assert_eq!(desc1.bi_vec[0].blob.blob_id, "123333");

        let desc2 = cached_inode
            .alloc_bio_desc(1024 * 1024 - 100, 200, true)
            .unwrap();
        assert_eq!(desc2.bi_size, 200);
        assert_eq!(desc2.bi_vec.len(), 2);
        assert_eq!(desc2.bi_vec[0].offset, 1024 * 1024 - 100);
        assert_eq!(desc2.bi_vec[0].size, 100);
        assert_eq!(desc2.bi_vec[1].offset, 0);
        assert_eq!(desc2.bi_vec[1].size, 100);

        let desc3 = cached_inode
            .alloc_bio_desc(1024 * 1024 + 8192, 1024 * 1024 * 4, true)
            .unwrap();
        assert_eq!(desc3.bi_size, 1024 * 1024 * 2);
        assert_eq!(desc3.bi_vec.len(), 3);
        assert_eq!(desc3.bi_vec[2].size, 8192);

        drop(f);
        std::fs::remove_file("/tmp/buf_3").unwrap();
    }
}

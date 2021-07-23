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
use std::io::{ErrorKind, Read, Result};
use std::mem::size_of;
use std::sync::Arc;

use fuse_rs::abi::linux_abi;
use fuse_rs::api::filesystem::Entry;

use crate::metadata::layout::*;
use crate::metadata::*;
use crate::RafsIoReader;

use nydus_utils::{digest::RafsDigest, ByteSize};

pub struct CachedInodes {
    s_blob: Arc<OndiskBlobTable>,
    s_meta: Arc<RafsSuperMeta>,
    s_inodes: BTreeMap<Inode, Arc<CachedInode>>,
    digest_validate: bool,
}

impl CachedInodes {
    pub fn new(meta: RafsSuperMeta, digest_validate: bool) -> Self {
        CachedInodes {
            s_blob: Arc::new(OndiskBlobTable::new()),
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
            let mut inode = CachedInode::new(self.s_blob.clone(), self.s_meta.clone());
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

    fn get_node(&self, ino: Inode) -> Result<Arc<CachedInode>> {
        Ok(self.s_inodes.get(&ino).ok_or_else(|| enoent!())?.clone())
    }

    fn get_node_mut(&mut self, ino: Inode) -> Result<&mut Arc<CachedInode>> {
        self.s_inodes.get_mut(&ino).ok_or_else(|| enoent!())
    }

    fn hash_inode(&mut self, inode: Arc<CachedInode>) -> Result<Arc<CachedInode>> {
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

    fn add_into_parent(&mut self, child_inode: Arc<CachedInode>) {
        if let Ok(parent_inode) = self.get_node_mut(child_inode.parent()) {
            Arc::get_mut(parent_inode)
                .unwrap()
                .add_child(child_inode.clone());
        }
    }
}

impl RafsSuperInodes for CachedInodes {
    fn load(&mut self, r: &mut RafsIoReader) -> Result<()> {
        // FIXME: add validator for all load operations.

        // Now the seek offset points to inode table, so we can easily
        // find first inode offset.
        r.seek(SeekFrom::Start(self.s_meta.inode_table_offset))?;
        let mut offset = [0u8; size_of::<u32>()];
        r.read_exact(&mut offset)?;
        // The offset is aligned with 8 bytes to make it easier to
        // validate OndiskInode.
        let inode_offset = u32::from_le_bytes(offset) << 3;

        // Load blob table.
        r.seek(SeekFrom::Start(self.s_meta.blob_table_offset))?;
        let mut blob_table = OndiskBlobTable::new();
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
            && !self.digest_validate(self.get_inode(RAFS_ROOT_INODE, false)?, true, digester)?
        {
            return Err(einval!("invalid inode digest"));
        }

        Ok(())
    }

    fn destroy(&mut self) {
        self.s_inodes.clear();
    }

    fn get_inode(&self, ino: Inode, _digest_validate: bool) -> Result<Arc<dyn RafsInode>> {
        self.s_inodes
            .get(&ino)
            .map_or(Err(enoent!()), |i| Ok(i.clone()))
    }

    fn get_max_ino(&self) -> u64 {
        self.s_inodes.len() as u64
    }

    fn get_blob_table(&self) -> Arc<OndiskBlobTable> {
        self.s_blob.clone()
    }

    fn update(&self, _r: &mut RafsIoReader) -> RafsResult<()> {
        Err(RafsError::Unsupported)
    }
}

#[derive(Default, Clone, Debug)]
pub struct CachedInode {
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
    i_blksize: u32,
    i_rdev: u32,
    i_target: OsString, // for symbol link
    i_xattr: HashMap<OsString, Vec<u8>>,
    i_data: Vec<Arc<CachedChunkInfo>>,
    i_child: Vec<Arc<CachedInode>>,
    i_blob_table: Arc<OndiskBlobTable>,
    i_meta: Arc<RafsSuperMeta>,
}

impl CachedInode {
    pub fn new(blob_table: Arc<OndiskBlobTable>, meta: Arc<RafsSuperMeta>) -> Self {
        CachedInode {
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
        r.seek_to_next_aligned(name_size)?;
        Ok(())
    }

    fn load_symlink(&mut self, symlink_size: usize, r: &mut RafsIoReader) -> Result<()> {
        if self.is_symlink() && symlink_size > 0 {
            let mut symbol_buf = vec![0u8; symlink_size];
            r.read_exact(symbol_buf.as_mut_slice())?;
            self.i_target = bytes_to_os_str(&symbol_buf).to_os_string();
        }
        r.seek_to_next_aligned(symlink_size)?;
        Ok(())
    }

    fn load_xattr(&mut self, r: &mut RafsIoReader) -> Result<()> {
        if self.has_xattr() {
            let mut xattrs = OndiskXAttrs::new();
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
            let mut chunk = OndiskChunkInfo::new();
            for _i in 0..self.i_child_cnt {
                chunk.load(r)?;
                self.i_data.push(Arc::new(CachedChunkInfo::from(&chunk)));
            }
        }
        Ok(())
    }

    pub fn load(&mut self, sb: &RafsSuperMeta, r: &mut RafsIoReader) -> Result<()> {
        // OndiskInode...name...symbol link...chunks
        let mut inode = OndiskInode::new();

        // parse ondisk inode
        // OndiskInode|name|symbol|xattr|chunks
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

    fn copy_from_ondisk(&mut self, inode: &OndiskInode) {
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
    }

    fn add_child(&mut self, child: Arc<CachedInode>) {
        self.i_child.push(child);
        if self.i_child.len() == (self.i_child_cnt as usize) {
            // all children are ready, do sort
            self.i_child.sort_by(|c1, c2| c1.i_name.cmp(&c2.i_name));
        }
    }
}

impl RafsInode for CachedInode {
    fn validate(&self) -> Result<()> {
        // TODO: validate
        if self.is_symlink() && self.i_target.is_empty() {
            return Err(einval!("invalid inode"));
        }
        Ok(())
    }

    fn name(&self) -> OsString {
        self.i_name.clone()
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

    #[inline]
    fn get_digest(&self) -> RafsDigest {
        self.i_digest
    }

    #[inline]
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

    #[inline]
    fn get_blob_by_index(&self, idx: u32) -> Result<Arc<RafsBlobEntry>> {
        Ok(self.i_blob_table.get(idx)?)
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

    fn get_blocksize(&self) -> u32 {
        self.i_blksize
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

    fn has_xattr(&self) -> bool {
        self.i_flags.contains(RafsInodeFlags::XATTR)
    }

    fn has_hole(&self) -> bool {
        self.i_flags.contains(RafsInodeFlags::HAS_HOLE)
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

    fn cast_ondisk(&self) -> Result<OndiskInode> {
        let i_symlink_size = if self.is_symlink() {
            self.get_symlink()?.byte_size() as u16
        } else {
            0
        };
        Ok(OndiskInode {
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
            i_reserved: [0; 20],
        })
    }

    impl_getter!(ino, i_ino, u64);
    impl_getter!(parent, i_parent, u64);
    impl_getter!(size, i_size, u64);
    impl_getter!(rdev, i_rdev, u32);
}

/// Cached information about an Rafs Data Chunk.
#[derive(Clone, Default, Debug)]
pub struct CachedChunkInfo {
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

impl CachedChunkInfo {
    pub fn new() -> Self {
        CachedChunkInfo {
            ..Default::default()
        }
    }

    pub fn load(&mut self, r: &mut RafsIoReader) -> Result<()> {
        let mut chunk = OndiskChunkInfo::new();

        r.read_exact(chunk.as_mut())?;
        self.copy_from_ondisk(&chunk);

        Ok(())
    }

    fn copy_from_ondisk(&mut self, chunk: &OndiskChunkInfo) {
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

impl RafsChunkInfo for CachedChunkInfo {
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

impl From<&OndiskChunkInfo> for CachedChunkInfo {
    fn from(info: &OndiskChunkInfo) -> Self {
        let mut chunk = CachedChunkInfo::new();
        chunk.copy_from_ondisk(info);
        chunk
    }
}

#[cfg(test)]
mod cached_tests {
    use crate::metadata::cached::CachedInode;
    use crate::metadata::layout::{
        OndiskBlobTable, OndiskChunkInfo, OndiskInode, OndiskInodeWrapper, XAttrs,
    };
    use crate::metadata::{align_to_rafs, RafsInode, RafsStore, RafsSuperMeta};
    use crate::{RafsIoReader, RafsIoWriter};
    use nydus_utils::ByteSize;
    use std::cmp;
    use std::ffi::{OsStr, OsString};
    use std::fs::OpenOptions;
    use std::io::Seek;
    use std::io::SeekFrom::Start;
    use std::os::unix::ffi::OsStrExt;
    use std::sync::Arc;

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
        let mut ondisk_inode = OndiskInode::new();
        let file_name = OsString::from("c_inode_1");
        let mut xattr = XAttrs::default();
        xattr.add(OsString::from("k1"), vec![1u8, 2u8, 3u8, 4u8]);
        xattr.add(OsString::from("k2"), vec![10u8, 11u8, 12u8]);
        ondisk_inode.i_name_size = file_name.byte_size() as u16;
        ondisk_inode.i_child_count = 1;
        ondisk_inode.i_ino = 3;
        ondisk_inode.i_size = 8192;
        ondisk_inode.i_mode = libc::S_IFREG;
        let mut chunk = OndiskChunkInfo::new();
        chunk.decompress_size = 8192;
        chunk.decompress_offset = 0;
        chunk.compress_offset = 0;
        chunk.compress_size = 4096;
        let inode = OndiskInodeWrapper {
            name: file_name.as_os_str(),
            symlink: None,
            inode: &ondisk_inode,
        };
        inode.store(&mut writer).unwrap();
        chunk.store(&mut writer).unwrap();
        xattr.store(&mut writer).unwrap();

        f.seek(Start(0)).unwrap();
        let meta = Arc::new(RafsSuperMeta::default());
        let blob_table = Arc::new(OndiskBlobTable::new());
        let mut cached_inode = CachedInode::new(blob_table, meta.clone());
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
        let mut ondisk_inode = OndiskInode::new();
        ondisk_inode.i_name_size = file_name.byte_size() as u16;
        ondisk_inode.i_symlink_size = symlink_name.byte_size() as u16;
        ondisk_inode.i_mode = libc::S_IFLNK;

        let inode = OndiskInodeWrapper {
            name: file_name.as_os_str(),
            symlink: Some(symlink_name.as_os_str()),
            inode: &ondisk_inode,
        };
        inode.store(&mut writer).unwrap();

        f.seek(Start(0)).unwrap();
        let meta = Arc::new(RafsSuperMeta::default());
        let blob_table = Arc::new(OndiskBlobTable::new());
        let mut cached_inode = CachedInode::new(blob_table, meta.clone());
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
        let mut ondisk_inode = OndiskInode::new();
        ondisk_inode.i_name_size = align_to_rafs(file_name.len()) as u16;
        ondisk_inode.i_child_count = 4;
        ondisk_inode.i_mode = libc::S_IFREG;
        ondisk_inode.i_size = 1024 * 1024 * 3 + 8192;

        let inode = OndiskInodeWrapper {
            name: file_name.as_os_str(),
            symlink: None,
            inode: &ondisk_inode,
        };
        inode.store(&mut writer).unwrap();

        let mut size = ondisk_inode.i_size;
        for i in 0..ondisk_inode.i_child_count {
            let mut chunk = OndiskChunkInfo::new();
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
        let mut blob_table = Arc::new(OndiskBlobTable::new());
        Arc::get_mut(&mut blob_table)
            .unwrap()
            .add(String::from("123333"), 0, 0, 0, 0, 0);
        let mut cached_inode = CachedInode::new(blob_table, meta.clone());
        cached_inode.load(&meta, &mut reader).unwrap();
        let desc1 = cached_inode.alloc_bio_desc(0, 100).unwrap();
        assert_eq!(desc1.bi_size, 100);
        assert_eq!(desc1.bi_vec.len(), 1);
        assert_eq!(desc1.bi_vec[0].offset, 0);
        assert_eq!(desc1.bi_vec[0].blob.blob_id, "123333");

        let desc2 = cached_inode.alloc_bio_desc(1024 * 1024 - 100, 200).unwrap();
        assert_eq!(desc2.bi_size, 200);
        assert_eq!(desc2.bi_vec.len(), 2);
        assert_eq!(desc2.bi_vec[0].offset, 1024 * 1024 - 100);
        assert_eq!(desc2.bi_vec[0].size, 100);
        assert_eq!(desc2.bi_vec[1].offset, 0);
        assert_eq!(desc2.bi_vec[1].size, 100);

        let desc3 = cached_inode
            .alloc_bio_desc(1024 * 1024 + 8192, 1024 * 1024 * 4)
            .unwrap();
        assert_eq!(desc3.bi_size, 1024 * 1024 * 2);
        assert_eq!(desc3.bi_vec.len(), 3);
        assert_eq!(desc3.bi_vec[2].size, 8192);

        drop(f);
        std::fs::remove_file("/tmp/buf_3").unwrap();
    }
}

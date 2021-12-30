// Copyright (C) 2021 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0
/// A bootstrap driver to directly use on disk bootstrap as runtime in-memory bootstrap.
///
/// To reduce memory footprint and speed up filesystem initialization, the V5 on disk bootstrap
/// layout has been designed to support directly mapping as runtime bootstrap. So we don't need to
/// define another set of runtime data structures to cache on-disk bootstrap in memory.
///
/// To support modification to the runtime bootstrap, several technologies have been adopted:
/// * - arc-swap is used to support RCU-like update instead of Mutex/RwLock.
/// * - `offset` instead of `pointer` is used to record data structure position.
/// * - reference count to the referenced resources/objects.
///
/// # Security
/// The bootstrap file may be provided by untrusted parties, so we must ensure strong validations
/// before making use of any bootstrap, especially we are using them in memory-mapped mode. The
/// rule is to call validate() after creating any data structure from the on-disk bootstrap.
use std::any::Any;
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{Result, SeekFrom};
use std::mem::size_of;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::{FromRawFd, IntoRawFd, RawFd};
use std::sync::Arc;

use arc_swap::ArcSwap;

use crate::metadata::layout::MetaRange;
use crate::metadata::{
    layout::{
        bytes_to_os_str,
        v6::{
            RafsV6BlobTable, RafsV6Dirent, RafsV6InodeChunkAddr, RafsV6InodeCompact,
            RafsV6InodeExtended, RafsV6OndiskInode, EROFS_BLOCK_SIZE, EROFS_INODE_CHUNK_BASED,
            EROFS_INODE_FLAT_INLINE, EROFS_INODE_FLAT_PLAIN, EROFS_INODE_SLOT_SIZE,
            EROFS_I_DATALAYOUT_BITS, EROFS_I_VERSION_BIT, EROFS_I_VERSION_BITS,
        },
        XattrName, XattrValue,
    },
    {
        Attr, ChildInodeHandler, Entry, Inode, RafsInode, RafsSuperBlobs, RafsSuperBlock,
        RafsSuperInodes, RafsSuperMeta, RAFS_INODE_BLOCKSIZE,
    },
};
use crate::{RafsError, RafsIoReader, RafsResult};
use nydus_utils::{
    digest::{Algorithm, RafsDigest},
    div_round_up,
};
use storage::device::{BlobChunkInfo, BlobInfo, BlobIoChunk, BlobIoDesc, BlobIoVec};
use storage::utils::readahead;

// Safe to Send/Sync because the underlying data structures are readonly
unsafe impl Send for DirectSuperBlockV6 {}
unsafe impl Sync for DirectSuperBlockV6 {}

/// The underlying struct to maintain memory mapped bootstrap for a file system.
///
/// Only the DirectMappingState may store raw pointers.
/// Other data structures should not store raw pointers, instead they should hold a reference to
/// the DirectMappingState object and store an offset, so a `pointer` could be reconstruct by
/// `DirectMappingState.base + offset`.
#[derive(Clone)]
struct DirectMappingState {
    meta: RafsSuperMeta,
    blob_table: Arc<RafsV6BlobTable>,
    base: *const u8,
    end: *const u8,
    size: usize,
    fd: RawFd,
    validate_digest: bool,
}

impl DirectMappingState {
    fn new(meta: &RafsSuperMeta, validate_digest: bool) -> Self {
        DirectMappingState {
            meta: *meta,
            blob_table: Arc::new(RafsV6BlobTable::default()),
            fd: -1,
            base: std::ptr::null(),
            end: std::ptr::null(),
            size: 0,
            // mmapped_inode_table: false,
            validate_digest,
        }
    }

    // /// Mmap to bootstrap ondisk data directly.
    // fn cast_to_ref<T>(&self, base: *const u8, offset: usize) -> Result<&T> {
    //     let start = base.wrapping_add(offset);
    //     let end = start.wrapping_add(size_of::<T>());

    //     if start > end
    //         || start < self.base
    //         || end < self.base
    //         || end > self.end
    //         || start as usize & (std::mem::align_of::<T>() - 1) != 0
    //     {
    //         return Err(einval!("invalid mmap offset"));
    //     }

    //     Ok(unsafe { &*(start as *const T) })
    // }

    // #[inline]
    // fn validate_range(&self, offset: usize, size: usize) -> Result<()> {
    //     let start = self.base.wrapping_add(offset);
    //     let end = start.wrapping_add(size);

    //     if start > end || start < self.base || end < self.base || end > self.end {
    //         return Err(einval!("invalid range"));
    //     }

    //     Ok(())
    // }
}
impl Drop for DirectMappingState {
    fn drop(&mut self) {
        if !self.base.is_null() {
            unsafe { libc::munmap(self.base as *mut u8 as *mut libc::c_void, self.size) };
            self.base = std::ptr::null();
            self.end = std::ptr::null();
            self.size = 0;
        }
        if self.fd >= 0 {
            let _ = nix::unistd::close(self.fd);
            self.fd = -1;
        }
    }
}

/// Directly mmapped Rafs v6 super block.
#[derive(Clone)]
pub struct DirectSuperBlockV6 {
    state: ArcSwap<DirectMappingState>,
}

impl DirectSuperBlockV6 {
    /// Create a new instance of `DirectSuperBlockV6`.
    pub fn new(meta: &RafsSuperMeta, validate_digest: bool) -> Self {
        let state = DirectMappingState::new(meta, validate_digest);

        Self {
            state: ArcSwap::new(Arc::new(state)),
        }
    }

    fn disk_inode(&self, offset: usize) -> &dyn RafsV6OndiskInode {
        let m = self.state.load();
        let i = unsafe { &*(m.base.add(offset) as *const RafsV6InodeExtended) };

        if i.format() & EROFS_I_VERSION_BITS != 0 {
            i
        } else {
            unsafe { &*(m.base.add(offset) as *const RafsV6InodeCompact) }
        }
    }

    pub fn inode_wrapper(&self, nid: u64) -> Result<Arc<OndiskInodeWrapper>> {
        // TODO(chge): ensure safety
        let offset = self.calculate_inode_offset(nid) as usize;
        let inode = self.disk_inode(offset);
        let blocks_count = div_round_up(inode.size(), EROFS_BLOCK_SIZE);
        Ok(Arc::new(OndiskInodeWrapper {
            mapping: self.clone(),
            offset,
            blocks_count,
        }))
    }

    fn calculate_inode_offset(&self, nid: u64) -> u64 {
        let meta_offset = self.state.load().meta.meta_blkaddr as u64 * EROFS_BLOCK_SIZE;
        meta_offset + nid * EROFS_INODE_SLOT_SIZE as u64
    }

    #[allow(clippy::cast_ptr_alignment)]
    fn update_state(&self, r: &mut RafsIoReader) -> Result<()> {
        let old_state = self.state.load();

        // Validate file size
        let fd = unsafe { libc::dup(r.as_raw_fd()) };
        if fd < 0 {
            return Err(last_error!("failed to dup bootstrap file fd"));
        }
        let file = unsafe { File::from_raw_fd(fd) };
        let md = file.metadata()?;
        let len = md.len();
        let size = len as usize;

        let md_range =
            MetaRange::new(EROFS_BLOCK_SIZE as u64, len - EROFS_BLOCK_SIZE as u64, true)?;

        // Validate blob table layout as blob_table_start and
        // blob_table_offset is read from bootstrap.
        let blob_table_size = old_state.meta.blob_table_size as u64;
        let blob_table_start = old_state.meta.blob_table_offset;
        let blob_table_range = MetaRange::new(blob_table_start, blob_table_size, false)?;
        if !blob_table_range.is_subrange_of(&md_range) {
            return Err(ebadf!("invalid blob table"));
        }

        // Prefetch the bootstrap file
        readahead(fd, 0, len);

        // Mmap the bootstrap file into current process for direct access
        let base = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                size,
                libc::PROT_READ,
                libc::MAP_NORESERVE | libc::MAP_PRIVATE,
                fd,
                0,
            )
        } as *const u8;
        if base as *mut core::ffi::c_void == libc::MAP_FAILED {
            return Err(last_error!("failed to mmap bootstrap"));
        }
        if base.is_null() {
            return Err(ebadf!("failed to mmap bootstrap"));
        }
        // Safe because the mmap area should covered the range [start, end)
        let end = unsafe { base.add(size) };

        // Load blob table. Safe because we have validated the blob table layout.
        let mut blob_table = RafsV6BlobTable::new();
        let meta = &old_state.meta;

        // Load extended blob table if the bootstrap including extended blob table.
        r.seek(SeekFrom::Start(meta.blob_table_offset))?;
        blob_table.load(r, meta.blob_table_size, meta.chunk_size, meta.flags)?;

        let validate_digest = old_state.validate_digest;

        let state = DirectMappingState {
            meta: old_state.meta,
            blob_table: Arc::new(blob_table),
            fd: file.into_raw_fd(),
            base,
            end,
            size,
            validate_digest,
        };

        // Swap new and old DirectMappingState object,
        // the old object will be destroyed when the reference count reaches zero.
        self.state.store(Arc::new(state));

        Ok(())
    }
}

impl RafsSuperInodes for DirectSuperBlockV6 {
    fn get_max_ino(&self) -> Inode {
        // Library fuse-rs has limit of underlying file system's maximum inode number.
        // FIXME: So we rafs v6 should record it when building.
        0xff_ffff_ffff_ffff - 1
    }

    /// Find inode offset by ino from inode table and mmap to OndiskInode.
    fn get_inode(&self, ino: Inode, _validate_digest: bool) -> Result<Arc<dyn RafsInode>> {
        let wrapper = self.inode_wrapper(ino)?;
        Ok(wrapper as Arc<dyn RafsInode>)
    }

    fn validate_digest(
        &self,
        _inode: Arc<dyn RafsInode>,
        _recursive: bool,
        _digester: Algorithm,
    ) -> Result<bool> {
        todo!()
    }
}

impl RafsSuperBlobs for DirectSuperBlockV6 {
    fn get_blobs(&self) -> Vec<Arc<BlobInfo>> {
        self.state.load().blob_table.get_all()
    }
}

impl RafsSuperBlock for DirectSuperBlockV6 {
    fn load(&mut self, r: &mut RafsIoReader) -> Result<()> {
        self.update_state(r)
    }

    fn update(&self, r: &mut RafsIoReader) -> RafsResult<()> {
        self.update_state(r).map_err(RafsError::SwapBackend)
    }

    fn destroy(&mut self) {
        let state = DirectMappingState::new(&RafsSuperMeta::default(), false);

        self.state.store(Arc::new(state));
    }

    fn get_blob_infos(&self) -> Vec<Arc<BlobInfo>> {
        self.state.load().blob_table.entries.clone()
    }

    fn root_ino(&self) -> u64 {
        self.state.load().meta.root_nid as u64
    }
}

pub struct OndiskInodeWrapper {
    pub mapping: DirectSuperBlockV6,
    pub offset: usize,
    pub blocks_count: u64,
}

impl OndiskInodeWrapper {
    fn disk_inode(&self) -> &dyn RafsV6OndiskInode {
        let i = self.mapping.disk_inode(self.offset);
        trace!("erofs disk inode loaded nid={} {:?}", i.ino(), i);
        i
    }

    fn blocks_count(&self) -> u64 {
        self.blocks_count
    }

    // COPIED from kernel code:
    // >
    // erofs inode data layout (i_format in on-disk inode):
    // 0 - inode plain without inline data A:
    // inode, [xattrs], ... | ... | no-holed data
    // 1 - inode VLE compression B (legacy):
    // inode, [xattrs], extents ... | ...
    // 2 - inode plain with inline data C:
    // inode, [xattrs], last_inline_data, ... | ... | no-holed data
    // 3 - inode compression D:
    // inode, [xattrs], map_header, extents ... | ...
    // 4 - inode chunk-based E:
    // inode, [xattrs], chunk indexes ... | ...
    // 5~7 - reserved
    fn data_block_mapping(&self, index: usize) -> RafsResult<*const u8> {
        let inode = self.disk_inode();

        if (inode.format() & (!(((1 << EROFS_I_DATALAYOUT_BITS) - 1) << 1 | EROFS_I_VERSION_BITS)))
            != 0
        {
            return Err(RafsError::Incompatible(inode.format()));
        }

        let s = if (inode.format() & 1 << EROFS_I_VERSION_BIT) != 0 {
            64
        } else {
            32
        };

        let layout = inode.format() >> EROFS_I_VERSION_BITS;
        assert!(layout == 0 || layout == 2 || layout == 4);
        // With legal format set, we can reliably refer `i_u` as raw blocks pointer.
        let m = self.mapping.state.load();

        let r = match layout {
            EROFS_INODE_FLAT_PLAIN => {
                unsafe {
                    m.base.add(
                        // `i_u` points to the Nth block
                        (inode.union() as u64 * EROFS_BLOCK_SIZE) as usize
                            + index * EROFS_BLOCK_SIZE as usize,
                    )
                }
            }
            EROFS_INODE_FLAT_INLINE => {
                // FIXME: load xattr size
                // FIXME: Ensure the correctness of locate inline data (tail packing)
                let xattr_size = 0;
                if index as u64 != self.blocks_count() - 1 {
                    unsafe {
                        m.base.add(
                            // `i_u` points to the Nth block
                            (inode.union() as u64 * EROFS_BLOCK_SIZE) as usize
                                + index * EROFS_BLOCK_SIZE as usize,
                        )
                    }
                } else {
                    unsafe { m.base.add(self.offset as usize + s + xattr_size) }
                }
            }
            EROFS_INODE_CHUNK_BASED => {
                let xattr_size = 0;
                unsafe { m.base.add(self.offset as usize + s + xattr_size) }
            }
            _ => {
                panic!("layout is {}", layout)
            }
        };

        Ok(r)
    }

    fn get_entry(&self, block_index: usize, index: usize) -> &RafsV6Dirent {
        // TODO: We indeed need safety check here.
        // FIXME: unwrap
        let block_mapping = self.data_block_mapping(block_index).unwrap();
        unsafe { &*(block_mapping.add(size_of::<RafsV6Dirent>() * index) as *const RafsV6Dirent) }
    }

    // `entries_per_block` indicates the quantity of entries residing in a single block.
    // Both `block_index` and `index` start from 0.
    fn entry_name(
        &self,
        block_index: usize,
        index: usize,
        entries_per_block: usize,
        pos: u32,
    ) -> &OsStr {
        // FIXME: unwrap
        let block_mapping = self.data_block_mapping(block_index).unwrap();
        let de = self.get_entry(block_index, index);
        debug!("entry index {} block index {}", index, block_index);
        // `index` starts from zero
        if index < entries_per_block - 1 {
            let next_de = self.get_entry(block_index, index + 1);
            // FIXME: unwrap
            let len = next_de
                .e_nameoff
                .checked_sub(de.e_nameoff)
                .ok_or_else(|| {
                    error!(
                        "nid {} entry index {} block index {} next dir entry {:?} current dir entry {:?}",
                        self.ino(), index, block_index, next_de, de
                    );
                })
                .unwrap();

            unsafe {
                bytes_to_os_str(std::slice::from_raw_parts(
                    block_mapping.add(de.e_nameoff as usize),
                    len as usize,
                ))
            }
        } else {
            unsafe {
                let e = std::slice::from_raw_parts(
                    block_mapping.add(de.e_nameoff as usize),
                    (EROFS_BLOCK_SIZE - de.e_nameoff as u64) as usize,
                );

                // Use this trick to temporarily decide entry name's length. Improve this?
                // TODO: Replace this use `libc::strncpy`
                let mut l: usize = 0;
                for i in e {
                    if *i != 0 {
                        l += 1;
                        let v = pos as u64 + l as u64 + size_of::<RafsV6Dirent>() as u64;
                        if v == self.size() || v % EROFS_BLOCK_SIZE == 0 {
                            break;
                        }
                    } else {
                        break;
                    }
                }
                bytes_to_os_str(&e[0..l])
            }
        }
    }

    fn mode_format_bits(&self) -> u32 {
        let i = self.disk_inode();
        i.mode() as u32 & libc::S_IFMT
    }
}

// TODO(chge): Still work on this trait implementation. Remove below `allow` attribute.
#[allow(unused_variables)]
impl RafsInode for OndiskInodeWrapper {
    #[allow(clippy::collapsible_if)]
    fn validate(&self, _inode_count: u64, chunk_size: u64) -> Result<()> {
        todo!()
    }

    fn get_entry(&self) -> Entry {
        let state = self.mapping.state.load();
        let inode = self.disk_inode();

        Entry {
            attr: self.get_attr().into(),
            inode: self.ino(),
            generation: 0,
            attr_timeout: state.meta.attr_timeout,
            entry_timeout: state.meta.entry_timeout,
            ..Default::default()
        }
    }

    fn get_attr(&self) -> Attr {
        let inode = self.disk_inode();

        // TODO(chge): Calculate blocks count from isize later.
        // TODO(chge): Include `rdev` into ondisk v6 extended inode.
        Attr {
            ino: self.ino(),
            size: inode.size(),
            mode: inode.mode() as u32,
            nlink: inode.nlink(),
            blocks: div_round_up(inode.size(), 512),
            uid: inode.ugid().0,
            gid: inode.ugid().1,
            mtime: inode.mtime_s_ns().0,
            mtimensec: inode.mtime_s_ns().1,
            blksize: RAFS_INODE_BLOCKSIZE,
            ..Default::default()
        }
    }

    /// Check whether the inode has extended attributes.
    fn has_xattr(&self) -> bool {
        todo!()
    }

    /// Get symlink target of the inode.
    ///
    /// # Safety
    /// It depends on Self::validate() to ensure valid memory layout.
    fn get_symlink(&self) -> Result<OsString> {
        // FIXME: assume that symlink can't be that long, tail packing is ignored
        let inode = self.disk_inode();
        // FIXME: Unwrap
        let data = self.data_block_mapping(0).unwrap();
        let s = unsafe {
            bytes_to_os_str(std::slice::from_raw_parts(data, inode.size() as usize)).to_os_string()
        };
        Ok(s)
    }

    /// Get the child with the specified name.
    ///
    /// # Safety
    /// It depends on Self::validate() to ensure valid memory layout.
    fn get_child_by_name(&self, name: &OsStr) -> Result<Arc<dyn RafsInode>> {
        let inode = self.disk_inode();

        if inode.size() == 0 {
            return Err(enoent!());
        }

        let blocks_count = div_round_up(inode.size(), EROFS_BLOCK_SIZE);
        let mut target: Option<u64> = None;

        let mut pos: usize = 0;

        let nid = 'outer: for i in 0..blocks_count {
            let head_entry = self.get_entry(i as usize, 0);
            // `e_nameoff` is offset from each single block?
            let head_name_offset = head_entry.e_nameoff;
            let entries_count = head_name_offset / size_of::<RafsV6Dirent>() as u16;

            let d_name = self.entry_name(i as usize, 0, entries_count as usize, pos as u32);
            pos += d_name.as_bytes().len() + size_of::<RafsV6Dirent>();

            if d_name == name {
                target = Some(head_entry.e_nid);
                break 'outer;
            }

            // TODO: Let binary search optimize this in the future.
            for j in 1..entries_count {
                let de = self.get_entry(i as usize, j as usize);
                let d_name =
                    self.entry_name(i as usize, j as usize, entries_count as usize, pos as u32);
                pos += d_name.as_bytes().len() + size_of::<RafsV6Dirent>();

                if d_name == name {
                    target = Some(de.e_nid);
                    break 'outer;
                }
            }
        };

        if let Some(nid) = target {
            Ok(self.mapping.inode_wrapper(nid)? as Arc<dyn RafsInode>)
        } else {
            Err(enoent!())
        }
    }

    /// Get the child with the specified index.
    ///
    /// # Safety
    /// It depends on Self::validate() to ensure valid memory layout.
    /// `idx` is the number of child files in line. So we can keep the term `idx`
    /// in super crate and keep it consistent with layout v5.
    fn get_child_by_index(&self, idx: u32) -> Result<Arc<dyn RafsInode>> {
        todo!()
    }

    #[inline]
    fn get_child_count(&self) -> u32 {
        todo!()
    }

    fn get_child_index(&self) -> Result<u32> {
        todo!()
    }

    fn walk_children_inodes(&self, entry_offset: u64, handler: ChildInodeHandler) -> Result<()> {
        let inode = self.disk_inode();

        if inode.size() == 0 {
            return Err(enoent!());
        }

        let blocks_count = div_round_up(inode.size(), EROFS_BLOCK_SIZE);

        let mut cur_offset = entry_offset;
        let mut skipped = entry_offset;

        trace!(
            "Total blocks count {} skipped {} current offset {} nid {} inode {:?}",
            blocks_count,
            skipped,
            cur_offset,
            self.ino(),
            inode,
        );

        let mut pos: usize = 0;
        for i in 0..blocks_count {
            let head_entry = self.get_entry(i as usize, 0);
            let name_offset = head_entry.e_nameoff;
            let entries_count = name_offset / size_of::<RafsV6Dirent>() as u16;

            for j in 0..entries_count {
                // Skip specified offset
                if skipped != 0 {
                    skipped -= 1;
                    continue;
                }
                let de = self.get_entry(i as usize, j as usize);
                let name =
                    self.entry_name(i as usize, j as usize, entries_count as usize, pos as u32);
                pos += name.as_bytes().len() + size_of::<RafsV6Dirent>();

                let nid = de.e_nid;
                let inode = self.mapping.inode_wrapper(nid)? as Arc<dyn RafsInode>;
                trace!("found file {:?}, nid {}", name, nid);
                cur_offset += 1;
                handler(Some(inode), name.to_os_string(), nid, cur_offset).unwrap();
            }
        }

        Ok(())
    }

    #[inline]
    fn get_chunk_count(&self) -> u32 {
        self.get_child_count()
    }

    /// Get chunk information with index `idx`
    ///
    /// # Safety
    /// It depends on Self::validate() to ensure valid memory layout.
    #[allow(clippy::cast_ptr_alignment)]
    fn get_chunk_info(&self, idx: u32) -> Result<Arc<dyn BlobChunkInfo>> {
        todo!()
    }

    fn get_xattr(&self, name: &OsStr) -> Result<Option<XattrValue>> {
        todo!()
    }

    fn get_xattrs(&self) -> Result<Vec<XattrName>> {
        todo!()
    }

    fn ino(&self) -> u64 {
        let meta_blkaddr = self.mapping.state.load().meta.meta_blkaddr as u64;
        (self.offset as u64 - meta_blkaddr * EROFS_BLOCK_SIZE) / EROFS_INODE_SLOT_SIZE as u64
    }

    /// Get name of the inode.
    ///
    /// # Safety
    /// It depends on Self::validate() to ensure valid memory layout.
    fn name(&self) -> OsString {
        todo!()
    }

    fn flags(&self) -> u64 {
        todo!()
    }

    fn get_digest(&self) -> RafsDigest {
        todo!()
    }

    fn is_dir(&self) -> bool {
        self.mode_format_bits() == libc::S_IFDIR
    }

    /// Check whether the inode is a symlink.
    fn is_symlink(&self) -> bool {
        self.mode_format_bits() == libc::S_IFLNK
    }

    /// Check whether the inode is a regular file.
    fn is_reg(&self) -> bool {
        self.mode_format_bits() == libc::S_IFREG
    }

    /// Check whether the inode is a hardlink.
    fn is_hardlink(&self) -> bool {
        todo!()
    }

    /// Get inode number of the parent directory.
    fn parent(&self) -> u64 {
        todo!()
    }

    /// Get real device number of the inode.
    fn rdev(&self) -> u32 {
        todo!()
    }

    /// Get project id associated with the inode.
    fn projid(&self) -> u32 {
        todo!()
    }

    /// Get data size of the inode.
    fn size(&self) -> u64 {
        let i = self.disk_inode();
        i.size()
    }

    /// Get file name size of the inode.
    fn get_name_size(&self) -> u16 {
        todo!()
    }

    fn get_symlink_size(&self) -> u16 {
        let inode = self.disk_inode();
        inode.size() as u16
    }

    fn collect_descendants_inodes(
        &self,
        descendants: &mut Vec<Arc<dyn RafsInode>>,
    ) -> Result<usize> {
        todo!()
    }

    fn alloc_bio_vecs(&self, offset: u64, size: usize, user_io: bool) -> Result<Vec<BlobIoVec>> {
        let blk_size = self.mapping.state.load().meta.chunk_size as u32;
        let chunks_per_blk = EROFS_BLOCK_SIZE / size_of::<RafsV6InodeChunkAddr>() as u64;

        let mut left = std::cmp::min(self.size(), size as u64) as u32;
        let head_chunk_index = offset / blk_size as u64;

        // TODO: Validate chunk format by checking its `i_u`

        let mut vec: Vec<BlobIoVec> = Vec::new();
        // FIXME: unwrap
        let block_mapping = self.data_block_mapping(0).unwrap();
        let chunks: &[RafsV6InodeChunkAddr] = unsafe {
            std::slice::from_raw_parts(
                block_mapping.add(head_chunk_index as usize * size_of::<RafsV6InodeChunkAddr>())
                    as *const RafsV6InodeChunkAddr,
                (div_round_up(self.size(), blk_size as u64) - head_chunk_index) as usize,
            )
        };

        let mut descs = BlobIoVec::new();
        let content_offset = (offset % blk_size as u64) as u32;
        let mut content_len = std::cmp::min(blk_size - content_offset, left);

        let blob_table = &self.mapping.state.load().blob_table.entries;

        // FIXME: unwrap
        let first_chunk = chunks.first().unwrap();
        let blob_index = first_chunk.blob_index() - 1;
        let chunk_index = first_chunk.blob_comp_index();
        let blob = blob_table[blob_index as usize].clone();
        let cki = BlobIoChunk::Address(blob_index as u32, chunk_index);

        let desc = BlobIoDesc::new(blob, cki, content_offset, content_len as usize, user_io);

        descs.bi_vec.push(desc);
        descs.bi_size += content_len as usize;
        left -= content_len;

        if left != 0 {
            // Handle the rest of chunks since they shares the same content length = 0.
            for c in chunks.iter().skip(1) {
                let blob_index = c.blob_index() - 1;
                let chunk_index = c.blob_comp_index();
                let cki = BlobIoChunk::Address(blob_index as u32, chunk_index);
                let blob = blob_table[blob_index as usize].clone();

                content_len = std::cmp::min(blk_size, left);
                let desc = BlobIoDesc::new(blob, cki, 0, content_len as usize, user_io);

                if blob_index as u32 != descs.bi_vec[0].blob.blob_index() {
                    vec.push(descs);
                    descs = BlobIoVec::new();
                }

                descs.bi_vec.push(desc);
                // TODO: change type of bi_size to u32
                descs.bi_size += content_len as usize;
                left -= content_len;

                if left == 0 {
                    break;
                }
            }
        }

        if !descs.bi_vec.is_empty() {
            vec.push(descs)
        }

        assert_eq!(left, 0);

        Ok(vec)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

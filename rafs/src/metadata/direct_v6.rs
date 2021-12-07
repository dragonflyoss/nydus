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
// use std::mem::size_of;
use std::os::unix::io::{FromRawFd, IntoRawFd, RawFd};
use std::sync::Arc;

use arc_swap::ArcSwap;

use crate::metadata::layout::v6::EROFS_BLOCK_SIZE;
use crate::metadata::layout::MetaRange;
use crate::metadata::{
    layout::{
        v6::{RafsV6BlobTable, RafsV6InodeExtended, EROFS_INODE_SLOT_SIZE},
        XattrName, XattrValue,
    },
    {
        Attr, Entry, Inode, RafsInode, RafsSuperBlobs, RafsSuperBlock, RafsSuperInodes,
        RafsSuperMeta, RAFS_INODE_BLOCKSIZE,
    },
};
use crate::{RafsError, RafsIoReader, RafsResult};
use nydus_utils::digest::{Algorithm, RafsDigest};
use storage::device::{BlobChunkInfo, BlobInfo, BlobIoVec};
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

    pub fn get_inode_wrapper(&self, nid: u64) -> Result<OndiskInodeWrapper> {
        Ok(OndiskInodeWrapper {
            mapping: self.clone(),
            // TODO(chge): ensure safety
            offset: self.calculate_inode_offset(nid) as usize,
        })
    }

    fn calculate_inode_offset(&self, nid: u64) -> u64 {
        let meta_offset = self.state.load().meta.meta_blkaddr;
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
        todo!()
    }

    /// Find inode offset by ino from inode table and mmap to OndiskInode.
    fn get_inode(&self, ino: Inode, _validate_digest: bool) -> Result<Arc<dyn RafsInode>> {
        let wrapper = self.get_inode_wrapper(ino)?;
        Ok(Arc::new(wrapper) as Arc<dyn RafsInode>)
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
}

pub struct OndiskInodeWrapper {
    pub mapping: DirectSuperBlockV6,
    pub offset: usize,
}

impl OndiskInodeWrapper {
    fn disk_inode(&self) -> &RafsV6InodeExtended {
        let m = self.mapping.state.load();
        unsafe { &*(m.base.add(self.offset) as *const RafsV6InodeExtended) }
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
            inode: inode.i_ino as u64,
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
            ino: inode.i_ino as u64,
            size: inode.i_size,
            mode: inode.i_mode as u32,
            nlink: inode.i_nlink,
            uid: inode.i_uid,
            gid: inode.i_gid,
            mtime: inode.i_mtime,
            mtimensec: inode.i_mtime_nsec,
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
        todo!()
    }

    /// Get the child with the specified name.
    ///
    /// # Safety
    /// It depends on Self::validate() to ensure valid memory layout.
    fn get_child_by_name(&self, name: &OsStr) -> Result<Arc<dyn RafsInode>> {
        todo!()
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
        todo!()
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
        todo!()
    }

    /// Check whether the inode is a symlink.
    fn is_symlink(&self) -> bool {
        todo!()
    }

    /// Check whether the inode is a regular file.
    fn is_reg(&self) -> bool {
        todo!()
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
        todo!()
    }

    /// Get file name size of the inode.
    fn get_name_size(&self) -> u16 {
        todo!()
    }

    fn get_symlink_size(&self) -> u16 {
        todo!()
    }

    fn collect_descendants_inodes(
        &self,
        descendants: &mut Vec<Arc<dyn RafsInode>>,
    ) -> Result<usize> {
        todo!()
    }

    fn alloc_bio_vecs(&self, offset: u64, size: usize, user_io: bool) -> Result<Vec<BlobIoVec>> {
        todo!()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

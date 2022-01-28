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
use std::fs::File;
use std::io::{Result, SeekFrom};
// use std::mem::size_of;
use std::os::unix::io::{FromRawFd, IntoRawFd, RawFd};
use std::sync::Arc;

use arc_swap::ArcSwap;

use crate::metadata::layout::v6::{RafsV6BlobTable, EROFS_BLOCK_SIZE};
use crate::metadata::layout::MetaRange;
use crate::metadata::{
    Inode, RafsInode, RafsSuperBlobs, RafsSuperBlock, RafsSuperInodes, RafsSuperMeta,
};
use crate::{RafsError, RafsIoReader, RafsResult};
use nydus_utils::digest::Algorithm;
use storage::device::BlobInfo;
use storage::utils::readahead;

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
        // Drop the inode_table if it's not a memory-mapped one.
        // if !self.mmapped_inode_table {
        //     unsafe {
        //         ManuallyDrop::drop(&mut self.inode_table);
        //     }
        // }
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

// Safe to Send/Sync because the underlying data structures are readonly
unsafe impl Send for DirectSuperBlockV6 {}
unsafe impl Sync for DirectSuperBlockV6 {}

impl DirectSuperBlockV6 {
    /// Create a new instance of `DirectSuperBlockV6`.
    pub fn new(meta: &RafsSuperMeta, validate_digest: bool) -> Self {
        let state = DirectMappingState::new(meta, validate_digest);

        Self {
            state: ArcSwap::new(Arc::new(state)),
        }
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

        // Swap new and old DirectMappingState object, the old object will be destroyed when the
        // reference count reaches zero.
        self.state.store(Arc::new(state));

        Ok(())
    }
}

impl RafsSuperInodes for DirectSuperBlockV6 {
    fn get_max_ino(&self) -> Inode {
        todo!()
    }

    /// Find inode offset by ino from inode table and mmap to OndiskInode.
    fn get_inode(&self, _ino: Inode, _validate_digest: bool) -> Result<Arc<dyn RafsInode>> {
        todo!()
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

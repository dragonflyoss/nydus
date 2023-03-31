// Copyright (C) 2020 Alibaba Cloud. All rights reserved.
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
use std::io::Result;
use std::io::SeekFrom;
use std::mem::{size_of, ManuallyDrop};
use std::ops::Deref;
use std::os::unix::io::AsRawFd;
use std::sync::Arc;

use arc_swap::{ArcSwap, Guard};
use nydus_storage::device::v5::BlobV5ChunkInfo;
use nydus_storage::device::{BlobChunkFlags, BlobChunkInfo, BlobDevice, BlobInfo, BlobIoVec};
use nydus_storage::utils::readahead;
use nydus_utils::digest::RafsDigest;
use nydus_utils::filemap::{clone_file, FileMapState};

use crate::metadata::layout::v5::{
    rafsv5_align, rafsv5_alloc_bio_vecs, rafsv5_validate_inode, RafsV5BlobTable, RafsV5ChunkInfo,
    RafsV5Inode, RafsV5InodeChunkOps, RafsV5InodeOps, RafsV5InodeTable, RafsV5XAttrsTable,
    RAFSV5_ALIGNMENT, RAFSV5_EXT_BLOB_ENTRY_SIZE, RAFSV5_SUPERBLOCK_SIZE,
};
use crate::metadata::layout::{
    bytes_to_os_str, parse_xattr_names, parse_xattr_value, MetaRange, XattrName, XattrValue,
    RAFS_V5_ROOT_INODE,
};
use crate::metadata::{
    Attr, Entry, Inode, RafsInode, RafsInodeWalkAction, RafsInodeWalkHandler, RafsSuperBlock,
    RafsSuperInodes, RafsSuperMeta, DOT, DOTDOT, RAFS_ATTR_BLOCK_SIZE, RAFS_MAX_METADATA_SIZE,
    RAFS_MAX_NAME,
};
use crate::{RafsError, RafsInodeExt, RafsIoReader, RafsResult};

/// Impl get accessor for inode object.
macro_rules! impl_inode_getter {
    ($G: ident, $F: ident, $U: ty) => {
        #[inline]
        fn $G(&self) -> $U {
            let state = self.state();
            let inode = self.inode(state.deref());

            inode.$F
        }
    };
}

/// Impl get accessor for inode object.
macro_rules! impl_inode_wrapper {
    ($G: ident, $U: ty) => {
        #[inline]
        fn $G(&self) -> $U {
            let state = self.state();
            let inode = self.inode(state.deref());

            inode.$G()
        }
    };
}

/// Impl get accessor for chunkinfo object.
macro_rules! impl_chunkinfo_getter {
    ($G: ident, $U: ty) => {
        #[inline]
        fn $G(&self) -> $U {
            let state = self.state();

            self.chunk(state.deref()).$G
        }
    };
}

/// The underlying struct to maintain memory mapped bootstrap for a file system.
///
/// Only the DirectMappingState may store raw pointers.
/// Other data structures should not store raw pointers, instead they should hold a reference to
/// the DirectMappingState object and store an offset, so a `pointer` could be reconstruct by
/// `DirectMappingState.base + offset`.
struct DirectMappingState {
    meta: RafsSuperMeta,
    inode_table: ManuallyDrop<RafsV5InodeTable>,
    blob_table: RafsV5BlobTable,
    file_map: FileMapState,
    mmapped_inode_table: bool,
    validate_inode: bool,
}

impl DirectMappingState {
    fn new(meta: &RafsSuperMeta, validate_inode: bool) -> Self {
        DirectMappingState {
            meta: *meta,
            inode_table: ManuallyDrop::new(RafsV5InodeTable::default()),
            blob_table: RafsV5BlobTable::default(),
            file_map: FileMapState::default(),
            mmapped_inode_table: false,
            validate_inode,
        }
    }
}

impl Drop for DirectMappingState {
    fn drop(&mut self) {
        if !self.mmapped_inode_table {
            // Safe because it's a allocated vector.
            unsafe { ManuallyDrop::drop(&mut self.inode_table) };
        }
    }
}

/// Direct-mapped Rafs v5 super block.
#[derive(Clone)]
pub struct DirectSuperBlockV5 {
    state: Arc<ArcSwap<DirectMappingState>>,
}

impl DirectSuperBlockV5 {
    /// Create a new instance of `DirectSuperBlockV5`.
    pub fn new(meta: &RafsSuperMeta, validate_inode: bool) -> Self {
        let state = DirectMappingState::new(meta, validate_inode);

        Self {
            state: Arc::new(ArcSwap::new(Arc::new(state))),
        }
    }

    #[inline]
    fn get_inode_wrapper(
        &self,
        ino: Inode,
        state: &DirectMappingState,
        validate_inode: bool,
    ) -> Result<OndiskInodeWrapper> {
        let offset = state.inode_table.get(ino)? as usize;
        let _inode = state.file_map.get_ref::<RafsV5Inode>(offset)?;
        let wrapper = OndiskInodeWrapper {
            mapping: self.clone(),
            offset,
        };

        if let Err(e) = wrapper.validate(state.meta.inodes_count, state.meta.chunk_size as u64) {
            if e.raw_os_error().unwrap_or(0) != libc::EOPNOTSUPP {
                return Err(e);
            }
            // ignore unsupported err
        }

        if validate_inode {
            let digester = state.meta.get_digester();
            if !rafsv5_validate_inode(&wrapper, false, digester)? {
                return Err(einval!("invalid inode digest"));
            }
        }

        Ok(wrapper)
    }

    fn update_state(&self, r: &mut RafsIoReader) -> Result<()> {
        let old_state = self.state();

        // Validate file size
        let file = clone_file(r.as_raw_fd())?;
        let md = file.metadata()?;
        let len = md.len();
        let size = len as usize;
        if len < RAFSV5_SUPERBLOCK_SIZE as u64
            || len > RAFS_MAX_METADATA_SIZE as u64
            || len & (RAFSV5_ALIGNMENT as u64 - 1) != 0
        {
            return Err(ebadf!("invalid bootstrap file"));
        }
        let md_range = MetaRange::new(
            RAFSV5_SUPERBLOCK_SIZE as u64,
            len - RAFSV5_SUPERBLOCK_SIZE as u64,
            true,
        )?;

        // Validate inode table layout
        let inode_table_start = old_state.meta.inode_table_offset;
        let inode_table_size = old_state.meta.inode_table_entries as u64 * size_of::<u32>() as u64;
        let inode_table_range = MetaRange::new(inode_table_start, inode_table_size, false)?;
        if !inode_table_range.is_subrange_of(&md_range) {
            return Err(ebadf!("invalid inode table"));
        }

        // Validate blob table layout
        let blob_table_start = old_state.meta.blob_table_offset;
        let blob_table_size = old_state.meta.blob_table_size as u64;
        let blob_table_range = MetaRange::new(blob_table_start, blob_table_size, false)?;
        if !blob_table_range.is_subrange_of(&md_range)
            || blob_table_range.intersect_with(&inode_table_range)
        {
            return Err(ebadf!("invalid blob table"));
        }

        // Validate extended blob table layout
        let extended_blob_table_offset = old_state.meta.extended_blob_table_offset;
        let extended_blob_table_size =
            old_state.meta.extended_blob_table_entries as u64 * RAFSV5_EXT_BLOB_ENTRY_SIZE as u64;
        let extended_blob_table_range =
            MetaRange::new(extended_blob_table_offset, extended_blob_table_size, true)?;
        if extended_blob_table_offset > 0
            && extended_blob_table_size > 0
            && (!extended_blob_table_range.is_subrange_of(&md_range)
                || extended_blob_table_range.intersect_with(&inode_table_range)
                || extended_blob_table_range.intersect_with(&blob_table_range))
        {
            return Err(ebadf!("invalid extended blob table"));
        }

        // Prefetch the bootstrap file
        readahead(file.as_raw_fd(), 0, len);

        // Mmap the bootstrap file into current process for direct access
        let file_map = FileMapState::new(file, 0, size, false)?;

        // Load blob table. Safe because we have validated the blob table layout.
        let mut blob_table = RafsV5BlobTable::new();
        let meta = &old_state.meta;

        // Load extended blob table if the bootstrap including extended blob table.
        if extended_blob_table_offset > 0 && extended_blob_table_size > 0 {
            r.seek(SeekFrom::Start(extended_blob_table_offset))?;
            blob_table
                .extended
                .load(r, meta.extended_blob_table_entries as usize)?;
        }
        r.seek(SeekFrom::Start(meta.blob_table_offset))?;
        blob_table.load(r, meta.blob_table_size, meta.chunk_size, meta.flags)?;

        // Load(Map) inode table. Safe because we have validated the inode table layout.
        // Though we have passed *mut u32 to Vec::from_raw_parts(), it will trigger invalid memory
        // access if the underlying memory is written to.
        let inode_table = unsafe {
            RafsV5InodeTable {
                data: Vec::from_raw_parts(
                    file_map.offset(inode_table_start as usize) as *const u32 as *mut u32,
                    old_state.meta.inode_table_entries as usize,
                    old_state.meta.inode_table_entries as usize,
                ),
            }
        };

        let validate_inode = old_state.validate_inode;

        let state = DirectMappingState {
            meta: old_state.meta,
            inode_table: ManuallyDrop::new(inode_table),
            blob_table,
            file_map,
            mmapped_inode_table: true,
            validate_inode,
        };

        // Swap new and old DirectMappingState object, the old object will be destroyed when the
        // reference count reaches zero.
        self.state.store(Arc::new(state));

        Ok(())
    }

    #[inline]
    fn state(&self) -> Guard<Arc<DirectMappingState>> {
        self.state.load()
    }
}

impl RafsSuperInodes for DirectSuperBlockV5 {
    fn get_max_ino(&self) -> Inode {
        self.state().inode_table.len() as u64
    }

    /// Find inode offset by ino from inode table and mmap to OndiskInode.
    fn get_inode(&self, ino: Inode, validate_inode: bool) -> Result<Arc<dyn RafsInode>> {
        let state = self.state();
        let wrapper = self.get_inode_wrapper(ino, state.deref(), validate_inode)?;
        Ok(Arc::new(wrapper))
    }

    fn get_extended_inode(
        &self,
        ino: Inode,
        validate_inode: bool,
    ) -> Result<Arc<dyn RafsInodeExt>> {
        let state = self.state();
        let wrapper = self.get_inode_wrapper(ino, state.deref(), validate_inode)?;
        Ok(Arc::new(wrapper))
    }
}

impl RafsSuperBlock for DirectSuperBlockV5 {
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
        self.state().blob_table.entries.clone()
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

/// Direct-mapped RAFS v5 inode object.
pub struct OndiskInodeWrapper {
    pub mapping: DirectSuperBlockV5,
    pub offset: usize,
}

impl OndiskInodeWrapper {
    #[inline]
    fn state(&self) -> Guard<Arc<DirectMappingState>> {
        self.mapping.state()
    }

    /// Convert `OndiskInodeWrapper` to an `RafsV5Inode` object.
    ///
    /// # Safety
    /// It depends on Self::validate() to ensure valid memory layout.
    #[inline]
    fn inode<'a>(&self, state: &'a DirectMappingState) -> &'a RafsV5Inode {
        state.file_map.get_ref::<RafsV5Inode>(self.offset).unwrap()
    }

    /// Get an reference to the file name string.
    ///
    /// # Safety
    /// It depends on Self::validate() to ensure valid memory layout.
    fn name_ref<'a>(&self, state: &'a DirectMappingState) -> &'a OsStr {
        let offset = self.offset + size_of::<RafsV5Inode>();
        let size = self.inode(state).i_name_size as usize;
        let name = state.file_map.get_slice(offset, size).unwrap();
        bytes_to_os_str(name)
    }

    fn get_xattr_data<'a>(
        &self,
        state: &'a Guard<Arc<DirectMappingState>>,
    ) -> Result<(&'a [u8], usize)> {
        let inode = self.inode(state.deref());

        if !inode.has_xattr() {
            return Ok((&[], 0));
        }

        let offset = self.offset + inode.size();
        let xattrs = state.file_map.get_ref::<RafsV5XAttrsTable>(offset)?;
        let xattr_size = xattrs.size();
        let xattr_data = state
            .file_map
            .get_slice(offset + size_of::<RafsV5XAttrsTable>(), xattr_size)?;

        Ok((xattr_data, xattr_size))
    }

    fn _get_chunk_info(&self, idx: u32) -> Result<Arc<DirectChunkInfoV5>> {
        let state = self.state();
        let inode = self.inode(state.deref());

        if !inode.is_reg() || inode.i_child_count == 0 || idx >= inode.i_child_count {
            return Err(enoent!("invalid chunk info"));
        }

        let mut offset = self.offset + inode.size();
        if inode.has_xattr() {
            let xattrs = state.file_map.get_ref::<RafsV5XAttrsTable>(offset)?;
            offset += size_of::<RafsV5XAttrsTable>() + xattrs.aligned_size();
        }
        offset += size_of::<RafsV5ChunkInfo>() * idx as usize;

        let chunk = state.file_map.get_ref::<RafsV5ChunkInfo>(offset)?;
        let wrapper = DirectChunkInfoV5::new(&state, chunk, self.mapping.clone(), offset)?;

        Ok(Arc::new(wrapper))
    }
}

impl RafsInode for OndiskInodeWrapper {
    // Somehow we got invalid `inode_count` from superblock.
    fn validate(&self, _inode_count: u64, chunk_size: u64) -> Result<()> {
        let state = self.state();
        let inode = state.file_map.get_ref::<RafsV5Inode>(self.offset)?;
        let max_inode = state.inode_table.len() as u64;
        let xattr_size = if inode.has_xattr() {
            let offset = self.offset + inode.size();
            let xattrs = state.file_map.get_ref::<RafsV5XAttrsTable>(offset)?;
            size_of::<RafsV5XAttrsTable>() + xattrs.aligned_size()
        } else {
            0
        };

        // * - parent inode number must be less than child inode number unless child is a hardlink.
        // * - inode link count must not be zero.
        // * - name_size must be less than 255. Due to alignment, the check is not so strict.
        // * - name_size and symlink_size must be correctly aligned.
        // Should we store raw size instead of aligned size for name and symlink?
        if inode.i_ino == 0
            || inode.i_ino > max_inode
            // || inode.i_ino > _inode_count
            || (inode.i_ino != RAFS_V5_ROOT_INODE && inode.i_parent == 0)
            || inode.i_nlink == 0
            || inode.i_name_size as usize > (RAFS_MAX_NAME + 1)
            || inode.i_name_size == 0
        {
            return Err(ebadf!(format!(
                "inode validation failure, inode {:?}",
                inode
            )));
        }
        if !inode.is_hardlink() && inode.i_parent >= inode.i_ino {
            return Err(einval!("invalid parent inode"));
        }

        let chunk_count = 0;
        if inode.is_reg() {
            if self.state().meta.is_chunk_dict() {
                // chunk-dict doesn't support chunk_count check
                return Err(std::io::Error::from_raw_os_error(libc::EOPNOTSUPP));
            }
            let chunks = (inode.i_size + chunk_size - 1) / chunk_size;
            if !inode.has_hole() && chunks != inode.i_child_count as u64 {
                return Err(einval!(format!(
                    "invalid chunk count, ino {}, expected {}, actual {}",
                    inode.i_ino, chunks, inode.i_child_count,
                )));
            }
            let size = inode.size()
                + xattr_size
                + inode.i_child_count as usize * size_of::<RafsV5ChunkInfo>();
            state.file_map.validate_range(self.offset, size)?;
        } else if inode.is_dir() {
            // Only valid i_child_index, i_child_count when we have children.
            if inode.i_child_count > 0
                && ((inode.i_child_index as Inode) <= inode.i_ino
                    || inode.i_child_count as u64 >= max_inode
                    || inode.i_child_count as u64 + inode.i_child_index as u64 - 1 > max_inode)
            {
                return Err(einval!("invalid directory"));
            }
            let size = inode.size() + xattr_size;
            state.file_map.validate_range(self.offset, size)?;
        } else if inode.is_symlink() && inode.i_symlink_size == 0 {
            return Err(einval!("invalid symlink target"));
        }
        if !inode.is_hardlink() && inode.i_parent >= inode.i_ino {
            return Err(einval!("invalid parent inode"));
        }

        let size = inode.size() + xattr_size + chunk_count * size_of::<RafsV5ChunkInfo>();
        state.file_map.validate_range(self.offset, size)?;

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

        let state = self.state();
        let inode = self.inode(state.deref());
        let child_count = inode.i_child_count as u64;
        let child_index = inode.i_child_index as u64;
        let mut child_dirs: Vec<Arc<dyn RafsInode>> = Vec::new();

        for idx in child_index..(child_index + child_count) {
            let child_inode = self.mapping.get_inode(idx, false)?;
            if child_inode.is_dir() {
                child_dirs.push(child_inode);
            } else if !child_inode.is_empty_size() {
                descendants.push(child_inode);
            }
        }

        for d in child_dirs {
            d.collect_descendants_inodes(descendants)?;
        }

        Ok(0)
    }

    fn get_entry(&self) -> Entry {
        let state = self.state();
        let inode = self.inode(state.deref());

        Entry {
            attr: self.get_attr().into(),
            inode: inode.i_ino,
            generation: 0,
            attr_flags: 0,
            attr_timeout: state.meta.attr_timeout,
            entry_timeout: state.meta.entry_timeout,
        }
    }

    fn get_attr(&self) -> Attr {
        let state = self.state();
        let inode = self.inode(state.deref());

        Attr {
            ino: inode.i_ino,
            size: inode.i_size,
            blocks: inode.i_blocks,
            mode: inode.i_mode,
            nlink: inode.i_nlink as u32,
            uid: inode.i_uid,
            gid: inode.i_gid,
            mtime: inode.i_mtime,
            mtimensec: inode.i_mtime_nsec,
            blksize: RAFS_ATTR_BLOCK_SIZE,
            rdev: inode.i_rdev,
            ..Default::default()
        }
    }

    fn get_xattr(&self, name: &OsStr) -> Result<Option<XattrValue>> {
        let state = self.state();
        let (xattr_data, xattr_size) = self.get_xattr_data(&state)?;
        parse_xattr_value(xattr_data, xattr_size, name)
    }

    fn get_xattrs(&self) -> Result<Vec<XattrName>> {
        let state = self.state();
        let (xattr_data, xattr_size) = self.get_xattr_data(&state)?;
        parse_xattr_names(xattr_data, xattr_size)
    }

    /// Get symlink target of the inode.
    ///
    /// # Safety
    /// It depends on Self::validate() to ensure valid memory layout.
    fn get_symlink(&self) -> Result<OsString> {
        let state = self.state();
        let inode = self.inode(state.deref());
        let offset =
            self.offset + size_of::<RafsV5Inode>() + rafsv5_align(inode.i_name_size as usize);
        let size = inode.i_symlink_size as usize;
        let symlink = state.file_map.get_slice(offset, size).unwrap();
        Ok(bytes_to_os_str(symlink).to_os_string())
    }

    fn walk_children_inodes(&self, entry_offset: u64, handler: RafsInodeWalkHandler) -> Result<()> {
        // offset 0 and 1 is for "." and ".." respectively.
        let mut cur_offset = entry_offset;

        if cur_offset == 0 {
            cur_offset += 1;
            // Safe to unwrap since conversion from DOT to os string can't fail.
            match handler(None, OsString::from(DOT), self.ino(), cur_offset) {
                Ok(RafsInodeWalkAction::Continue) => {}
                Ok(RafsInodeWalkAction::Break) => return Ok(()),
                Err(e) => return Err(e),
            }
        }

        if cur_offset == 1 {
            let parent = if self.ino() == 1 { 1 } else { self.parent() };
            cur_offset += 1;
            // Safe to unwrap since conversion from DOTDOT to os string can't fail.
            match handler(None, OsString::from(DOTDOT), parent, cur_offset) {
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

    /// Get the child with the specified name.
    ///
    /// # Safety
    /// It depends on Self::validate() to ensure valid memory layout.
    fn get_child_by_name(&self, name: &OsStr) -> Result<Arc<dyn RafsInodeExt>> {
        let state = self.state();
        let inode = self.inode(state.deref());

        if !inode.is_dir() {
            return Err(einval!("inode is not a directory"));
        } else if inode.i_child_count == 0 {
            return Err(enoent!());
        }

        let mut first = 0i32;
        let mut last = (inode.i_child_count - 1) as i32;

        // Binary search by child name.
        // This implementation is more convenient and slightly outperforms than slice::binary_search.
        while first <= last {
            let pivot = first + ((last - first) >> 1);
            let wrapper = self.mapping.get_inode_wrapper(
                (inode.i_child_index as i32 + pivot) as u64,
                state.deref(),
                state.validate_inode,
            )?;
            let target = wrapper.name_ref(state.deref());
            if target == name {
                return Ok(Arc::new(wrapper));
            }
            if target > name {
                last = pivot - 1;
            } else {
                first = pivot + 1;
            }
        }

        Err(enoent!())
    }

    /// Get the child with the specified index.
    ///
    /// # Safety
    /// It depends on Self::validate() to ensure valid memory layout.
    fn get_child_by_index(&self, idx: u32) -> Result<Arc<dyn RafsInodeExt>> {
        let state = self.state();
        let inode = self.inode(state.deref());
        let child_count = inode.i_child_count;
        let child_index = inode.i_child_index;

        if !inode.is_dir() {
            return Err(einval!("inode is not a directory"));
        } else if idx >= child_count {
            return Err(enoent!("invalid child index"));
        }

        let wrapper = self.mapping.get_inode_wrapper(
            (idx + child_index) as Inode,
            state.deref(),
            state.validate_inode,
        )?;
        Ok(Arc::new(wrapper))
    }

    #[inline]
    fn get_child_count(&self) -> u32 {
        let state = self.state();
        let inode = self.inode(state.deref());
        inode.i_child_count
    }

    #[inline]
    fn get_child_index(&self) -> Result<u32> {
        let state = self.state();
        let inode = self.inode(state.deref());
        Ok(inode.i_child_index)
    }

    #[inline]
    fn get_chunk_count(&self) -> u32 {
        self.get_child_count()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    impl_inode_wrapper!(is_dir, bool);
    impl_inode_wrapper!(is_reg, bool);
    impl_inode_wrapper!(is_symlink, bool);
    impl_inode_wrapper!(is_hardlink, bool);
    impl_inode_wrapper!(has_xattr, bool);
    impl_inode_getter!(ino, i_ino, u64);
    impl_inode_getter!(size, i_size, u64);
    impl_inode_getter!(rdev, i_rdev, u32);
    impl_inode_getter!(projid, i_projid, u32);
    impl_inode_getter!(get_symlink_size, i_symlink_size, u16);
}

impl RafsInodeExt for OndiskInodeWrapper {
    fn as_inode(&self) -> &dyn RafsInode {
        self
    }

    /// Get name of the inode.
    ///
    /// # Safety
    /// It depends on Self::validate() to ensure valid memory layout.
    fn name(&self) -> OsString {
        let state = self.state();
        self.name_ref(state.deref()).to_owned()
    }

    fn flags(&self) -> u64 {
        let state = self.state();
        let inode = self.inode(state.deref());

        inode.i_flags.bits()
    }

    fn get_digest(&self) -> RafsDigest {
        let state = self.state();
        let inode = self.inode(state.deref());
        inode.i_digest
    }

    /// Get chunk information with index `idx`
    ///
    /// # Safety
    /// It depends on Self::validate() to ensure valid memory layout.
    fn get_chunk_info(&self, idx: u32) -> Result<Arc<dyn BlobChunkInfo>> {
        self._get_chunk_info(idx)
            .map(|v| v as Arc<dyn BlobChunkInfo>)
    }

    impl_inode_getter!(get_name_size, i_name_size, u16);
    impl_inode_getter!(parent, i_parent, u64);
}

impl RafsV5InodeChunkOps for OndiskInodeWrapper {
    fn get_chunk_info_v5(&self, idx: u32) -> Result<Arc<dyn BlobV5ChunkInfo>> {
        self._get_chunk_info(idx)
            .map(|v| v as Arc<dyn BlobV5ChunkInfo>)
    }
}

impl RafsV5InodeOps for OndiskInodeWrapper {
    fn get_blob_by_index(&self, idx: u32) -> Result<Arc<BlobInfo>> {
        self.state().blob_table.get(idx)
    }

    fn get_chunk_size(&self) -> u32 {
        self.mapping.state().meta.chunk_size
    }

    impl_inode_wrapper!(has_hole, bool);
}

pub struct DirectChunkInfoV5 {
    mapping: DirectSuperBlockV5,
    offset: usize,
    digest: RafsDigest,
}

// This is *direct* metadata mode in-memory chunk info object.
impl DirectChunkInfoV5 {
    #[inline]
    fn new(
        state: &DirectMappingState,
        chunk: &RafsV5ChunkInfo,
        mapping: DirectSuperBlockV5,
        offset: usize,
    ) -> Result<Self> {
        state.file_map.get_ref::<RafsV5ChunkInfo>(offset)?;
        Ok(Self {
            mapping,
            offset,
            digest: chunk.block_id,
        })
    }

    #[inline]
    fn state(&self) -> Guard<Arc<DirectMappingState>> {
        self.mapping.state()
    }

    /// Dereference the underlying OndiskChunkInfo object.
    ///
    /// # Safety
    /// It depends on Self::validate() to ensure valid memory layout.
    /// The OndiskChunkInfoWrapper could only be constructed from a valid OndiskChunkInfo pointer,
    /// so it's safe to dereference the underlying OndiskChunkInfo object.
    fn chunk<'a>(&self, state: &'a DirectMappingState) -> &'a RafsV5ChunkInfo {
        state
            .file_map
            .get_ref::<RafsV5ChunkInfo>(self.offset)
            .unwrap()
    }
}

impl BlobChunkInfo for DirectChunkInfoV5 {
    fn chunk_id(&self) -> &RafsDigest {
        &self.digest
    }

    fn id(&self) -> u32 {
        self.index()
    }

    fn is_compressed(&self) -> bool {
        self.chunk(self.state().deref())
            .flags
            .contains(BlobChunkFlags::COMPRESSED)
    }

    fn is_encrypted(&self) -> bool {
        false
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    impl_chunkinfo_getter!(blob_index, u32);
    impl_chunkinfo_getter!(compressed_offset, u64);
    impl_chunkinfo_getter!(compressed_size, u32);
    impl_chunkinfo_getter!(uncompressed_offset, u64);
    impl_chunkinfo_getter!(uncompressed_size, u32);
}

impl BlobV5ChunkInfo for DirectChunkInfoV5 {
    fn as_base(&self) -> &dyn BlobChunkInfo {
        self
    }

    impl_chunkinfo_getter!(index, u32);
    impl_chunkinfo_getter!(file_offset, u64);
    impl_chunkinfo_getter!(flags, BlobChunkFlags);
}

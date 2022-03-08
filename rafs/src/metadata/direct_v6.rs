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
use std::ops::Deref;
use std::os::unix::{
    ffi::{OsStrExt, OsStringExt},
    io::{FromRawFd, IntoRawFd, RawFd},
};
use std::slice;
use std::sync::Arc;

use arc_swap::{ArcSwap, Guard};

use crate::metadata::layout::MetaRange;
use crate::metadata::{
    layout::{
        bytes_to_os_str,
        v5::RafsV5ChunkInfo,
        v6::{
            recover_namespace, RafsV6BlobTable, RafsV6Dirent, RafsV6InodeChunkAddr,
            RafsV6InodeCompact, RafsV6InodeExtended, RafsV6OndiskInode, RafsV6XattrEntry,
            RafsV6XattrIbodyHeader, EROFS_BLOCK_SIZE, EROFS_INODE_CHUNK_BASED,
            EROFS_INODE_FLAT_INLINE, EROFS_INODE_FLAT_PLAIN, EROFS_INODE_SLOT_SIZE,
            EROFS_I_DATALAYOUT_BITS, EROFS_I_VERSION_BIT, EROFS_I_VERSION_BITS,
        },
        XattrName, XattrValue,
    },
    {
        Attr, ChildInodeHandler, Entry, Inode, PostWalkAction, RafsInode, RafsSuperBlobs,
        RafsSuperBlock, RafsSuperInodes, RafsSuperMeta, RAFS_ATTR_BLOCK_SIZE,
    },
};
use crate::{MetaType, RafsError, RafsIoReader, RafsResult};
use nydus_utils::{
    digest::{Algorithm, RafsDigest},
    div_round_up, round_up,
};
use storage::device::{
    v5::BlobV5ChunkInfo, BlobChunkFlags, BlobChunkInfo, BlobInfo, BlobIoChunk, BlobIoDesc,
    BlobIoVec,
};
use storage::utils::readahead;

// Safe to Send/Sync because the underlying data structures are readonly
unsafe impl Send for DirectSuperBlockV6 {}
unsafe impl Sync for DirectSuperBlockV6 {}

fn err_invalidate_data(rafs_err: RafsError) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, rafs_err)
}

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
            validate_digest,
        }
    }

    /// Mmap to bootstrap ondisk data directly.
    fn cast_to_ref<T>(&self, base: *const u8, offset: usize) -> Result<&T> {
        let start = base.wrapping_add(offset);
        let end = start.wrapping_add(size_of::<T>());

        if start > end
            || start < self.base
            || end < self.base
            || end > self.end
            || start as usize & (std::mem::align_of::<T>() - 1) != 0
        {
            return Err(einval!("invalid mmap offset"));
        }

        Ok(unsafe { &*(start as *const T) })
    }

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

    fn get_chunk_info(&self, idx: usize) -> Result<Arc<dyn BlobChunkInfo>> {
        let state = self.state.load();
        let unit_size = size_of::<RafsV5ChunkInfo>();

        let offset = state.meta.chunk_table_offset as usize + idx * unit_size;
        if offset + unit_size
            > (state.meta.chunk_table_offset + state.meta.chunk_table_size) as usize
        {
            return Err(einval!(format!(
                "invalid chunk offset {} chunk table {} {}",
                offset, state.meta.chunk_table_offset, state.meta.chunk_table_size
            )));
        }

        let chunk = state.cast_to_ref::<RafsV5ChunkInfo>(state.base, offset)?;
        let wrapper = DirectChunkInfoV6::new(chunk, self.clone(), offset);
        Ok(Arc::new(wrapper) as Arc<dyn BlobChunkInfo>)
    }
}

pub struct OndiskInodeWrapper {
    pub mapping: DirectSuperBlockV6,
    pub offset: usize,
    pub blocks_count: u64,
}

impl OndiskInodeWrapper {
    fn disk_inode(&self) -> &dyn RafsV6OndiskInode {
        self.mapping.disk_inode(self.offset)
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

    // Mapping file data blocks to in-memory address.
    // Not only for data blocks so chunks' addresses are not covered.
    fn data_block_mapping(&self, index: usize) -> RafsResult<*const u8> {
        let inode = self.disk_inode();

        if (inode.format() & (!(((1 << EROFS_I_DATALAYOUT_BITS) - 1) << 1 | EROFS_I_VERSION_BITS)))
            != 0
        {
            return Err(RafsError::Incompatible(inode.format()));
        }

        let s = self.this_inode_size();

        let layout = inode.format() >> EROFS_I_VERSION_BITS;
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
                // FIXME: Ensure the correctness of locate inline data (tail packing)
                if index as u64 != self.blocks_count() - 1 {
                    unsafe {
                        m.base.add(
                            // `i_u` points to the Nth block
                            (inode.union() as u64 * EROFS_BLOCK_SIZE) as usize
                                + index * EROFS_BLOCK_SIZE as usize,
                        )
                    }
                } else {
                    unsafe {
                        m.base
                            .add(self.offset as usize + s + self.xattr_size() as usize)
                    }
                }
            }
            _ => {
                panic!("layout is {}", layout)
            }
        };

        Ok(r)
    }

    fn get_entry(&self, block_index: usize, index: usize) -> RafsResult<&RafsV6Dirent> {
        // TODO: We indeed need safety check here.
        let block_mapping = self.data_block_mapping(block_index)?;
        Ok(unsafe {
            &*(block_mapping.add(size_of::<RafsV6Dirent>() * index) as *const RafsV6Dirent)
        })
    }

    // `max_entries` indicates the quantity of entries residing in a single block including tail packing.
    // Both `block_index` and `index` start from 0.
    fn entry_name(
        &self,
        block_index: usize,
        index: usize,
        max_entries: usize,
    ) -> RafsResult<&OsStr> {
        let block_mapping = self.data_block_mapping(block_index)?;
        let de = self.get_entry(block_index, index)?;
        if index < max_entries - 1 {
            let next_de = self.get_entry(block_index, index + 1)?;
            let (next_de_name_off, de_name_off) = (next_de.e_nameoff, de.e_nameoff);
            let len = next_de.e_nameoff.checked_sub(de.e_nameoff).ok_or_else(|| {
                error!(
                    "nid {} entry index {} block index {} next dir entry {:?} current dir entry {:?}",
                    self.ino(), index, block_index, next_de, de
                );
                RafsError::IllegalMetaStruct(
                    MetaType::Dir,
                    format!("cur {} next {}", next_de_name_off, de_name_off),
                )
            })?;

            let n = unsafe {
                bytes_to_os_str(std::slice::from_raw_parts(
                    block_mapping.add(de.e_nameoff as usize),
                    len as usize,
                ))
            };

            Ok(n)
        } else {
            unsafe {
                let head_de = self.get_entry(block_index, 0)?;
                let s = (de.e_nameoff - head_de.e_nameoff) as u64
                    + (size_of::<RafsV6Dirent>() * max_entries) as u64;

                let e = slice::from_raw_parts(
                    block_mapping.add(de.e_nameoff as usize),
                    (self.size() % EROFS_BLOCK_SIZE - s) as usize,
                );
                // Use this trick to temporarily decide entry name's length. Improve this?
                let mut l: usize = 0;
                for i in e {
                    if *i != 0 {
                        l += 1;
                        if self.size() % EROFS_BLOCK_SIZE - s == l as u64 {
                            break;
                        }
                    } else {
                        break;
                    }
                }

                let n = bytes_to_os_str(&e[0..l]);
                Ok(n)
            }
        }
    }

    fn mode_format_bits(&self) -> u32 {
        let i = self.disk_inode();
        i.mode() as u32 & libc::S_IFMT as u32
    }

    fn make_chunk_io(
        &self,
        chunk_addr: &RafsV6InodeChunkAddr,
        content_offset: u32,
        content_len: u32,
        user_io: bool,
    ) -> BlobIoDesc {
        let state = self.mapping.state.load();
        let blob_table = &state.blob_table.entries;

        let blob_index = chunk_addr.blob_index() - 1;
        let chunk_index = chunk_addr.blob_comp_index();
        let io_chunk = BlobIoChunk::Address(blob_index as u32, chunk_index);

        let blob = blob_table[blob_index as usize].clone();

        BlobIoDesc::new(
            blob,
            io_chunk,
            content_offset,
            content_len as usize,
            user_io,
        )
    }

    fn chunk_size(&self) -> u32 {
        self.mapping.state.load().meta.chunk_size
    }

    fn this_inode_size(&self) -> usize {
        let inode = self.disk_inode();

        if (inode.format() & 1 << EROFS_I_VERSION_BIT) != 0 {
            size_of::<RafsV6InodeExtended>()
        } else {
            size_of::<RafsV6InodeCompact>()
        }
    }

    fn xattr_size(&self) -> u32 {
        let inode = self.disk_inode();
        // Rafs v6 only supports EROFS inline xattr.
        if inode.xattr_inline_count() > 0 {
            (inode.xattr_inline_count() as u32 - 1) * size_of::<RafsV6XattrEntry>() as u32
                + size_of::<RafsV6XattrIbodyHeader>() as u32
        } else {
            0
        }
    }

    fn chunk_addresses(&self, head_chunk_index: u32) -> RafsResult<&[RafsV6InodeChunkAddr]> {
        let total_chunk_addresses = div_round_up(self.size(), self.chunk_size() as u64) as u32;

        assert_eq!(
            self.disk_inode().format() >> EROFS_I_VERSION_BITS,
            EROFS_INODE_CHUNK_BASED
        );

        let m = self.mapping.state.load();
        let indices = unsafe {
            m.base.add(
                self.offset as usize
                    + round_up(
                        self.this_inode_size() as u64 + self.xattr_size() as u64,
                        size_of::<RafsV6InodeChunkAddr>() as u64,
                    ) as usize,
            )
        };

        let chunks: &[RafsV6InodeChunkAddr] = unsafe {
            std::slice::from_raw_parts(
                indices.add(head_chunk_index as usize * size_of::<RafsV6InodeChunkAddr>())
                    as *const RafsV6InodeChunkAddr,
                (total_chunk_addresses - head_chunk_index) as usize,
            )
        };

        Ok(chunks)
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
            blksize: RAFS_ATTR_BLOCK_SIZE,
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
        let data = self.data_block_mapping(0).map_err(err_invalidate_data)?;
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

        let nid = 'outer: for i in 0..blocks_count {
            let head_entry = self.get_entry(i as usize, 0).map_err(err_invalidate_data)?;
            // `e_nameoff` is offset from each single block?
            let head_name_offset = head_entry.e_nameoff;
            let entries_count = head_name_offset / size_of::<RafsV6Dirent>() as u16;

            let d_name = self
                .entry_name(i as usize, 0, entries_count as usize)
                .map_err(err_invalidate_data)?;

            if d_name == name {
                target = Some(head_entry.e_nid);
                break 'outer;
            }

            // TODO: Let binary search optimize this in the future.
            // So this logic might look similar to `walk_children_inodes`
            for j in 1..entries_count {
                let de = self
                    .get_entry(i as usize, j as usize)
                    .map_err(err_invalidate_data)?;
                let d_name = self
                    .entry_name(i as usize, j as usize, entries_count as usize)
                    .map_err(err_invalidate_data)?;

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

        for i in 0..blocks_count {
            let head_entry = self.get_entry(i as usize, 0).map_err(err_invalidate_data)?;
            let name_offset = head_entry.e_nameoff;
            let entries_count = name_offset / size_of::<RafsV6Dirent>() as u16;

            for j in 0..entries_count {
                let de = self
                    .get_entry(i as usize, j as usize)
                    .map_err(err_invalidate_data)?;
                let name = self
                    .entry_name(i as usize, j as usize, entries_count as usize)
                    .map_err(err_invalidate_data)?;

                // Skip specified offset
                if skipped != 0 {
                    skipped -= 1;
                    continue;
                }

                let nid = de.e_nid;
                let inode = self.mapping.inode_wrapper(nid)? as Arc<dyn RafsInode>;
                trace!("found file {:?}, nid {}", name, nid);
                cur_offset += 1;
                match handler(Some(inode), name.to_os_string(), nid, cur_offset) {
                    Ok(PostWalkAction::Break) => break,
                    Ok(PostWalkAction::Continue) => continue,
                    Err(_) => break,
                };
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
        let inode = self.disk_inode();
        let total = inode.xattr_inline_count();
        if total == 0 {
            return Ok(None);
        }
        let m = self.mapping.state.load();
        let mut cur = unsafe {
            m.base
                .add(self.offset + self.this_inode_size() + size_of::<RafsV6XattrIbodyHeader>())
        };

        let mut size = size_of::<RafsV6XattrIbodyHeader>() as u32;

        while size as usize
            <= total as usize * size_of::<RafsV6XattrEntry>() - size_of::<RafsV6XattrIbodyHeader>()
        {
            let e = unsafe { &*(cur as *const RafsV6XattrEntry) };

            let mut xa_name = recover_namespace(e.name_index())?;

            let suffix = OsStr::from_bytes(unsafe {
                slice::from_raw_parts(
                    cur.add(size_of::<RafsV6XattrEntry>()),
                    e.name_len() as usize,
                )
            });

            xa_name.push(suffix);

            if xa_name == name {
                let value = unsafe {
                    slice::from_raw_parts(
                        cur.add(size_of::<RafsV6XattrEntry>() + e.name_len() as usize),
                        e.value_size() as usize,
                    )
                }
                .to_vec();
                return Ok(Some(value));
            }

            let mut s = e.name_len() + e.value_size() + size_of::<RafsV6XattrEntry>() as u32;
            s = round_up(s as u64, size_of::<RafsV6XattrEntry>() as u64) as u32;
            size += s;
            cur = unsafe { cur.add(s as usize) };
        }

        Ok(None)
    }

    fn get_xattrs(&self) -> Result<Vec<XattrName>> {
        let inode = self.disk_inode();
        let mut xattrs = Vec::new();
        let total = inode.xattr_inline_count();
        if total == 0 {
            return Ok(xattrs);
        }
        let m = self.mapping.state.load();
        let mut cur = unsafe {
            m.base
                .add(self.offset + self.this_inode_size() + size_of::<RafsV6XattrIbodyHeader>())
        };

        let mut size = size_of::<RafsV6XattrIbodyHeader>() as u32;

        while size as usize
            <= total as usize * size_of::<RafsV6XattrEntry>() - size_of::<RafsV6XattrIbodyHeader>()
        {
            let e = unsafe { &*(cur as *const RafsV6XattrEntry) };

            let ns = recover_namespace(e.name_index())?;
            let mut xa = ns.into_vec();
            xa.extend_from_slice(unsafe {
                slice::from_raw_parts(
                    cur.add(size_of::<RafsV6XattrEntry>()),
                    e.name_len() as usize,
                )
            });
            xattrs.push(xa);
            let mut s = e.name_len() + e.value_size() + size_of::<RafsV6XattrEntry>() as u32;
            s = round_up(s as u64, size_of::<RafsV6XattrEntry>() as u64) as u32;
            size += s;
            cur = unsafe { cur.add(s as usize) };
        }

        Ok(xattrs)
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
        self.mode_format_bits() == libc::S_IFDIR as u32
    }

    /// Check whether the inode is a symlink.
    fn is_symlink(&self) -> bool {
        self.mode_format_bits() == libc::S_IFLNK as u32
    }

    /// Check whether the inode is a regular file.
    fn is_reg(&self) -> bool {
        self.mode_format_bits() == libc::S_IFREG as u32
    }

    /// Check whether the inode is a hardlink.
    fn is_hardlink(&self) -> bool {
        let inode = self.disk_inode();
        inode.nlink() > 1 && self.is_reg()
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
        if !self.is_dir() {
            return Err(enotdir!());
        }

        let mut child_dirs: Vec<Arc<dyn RafsInode>> = Vec::new();

        // EROFS packs dot and dotdot, so skip them two.
        self.walk_children_inodes(2, &mut |inode: Option<Arc<dyn RafsInode>>,
                                           name: OsString,
                                           ino,
                                           offset| {
            // Safe to unwrap since it must have child inode.
            if let Some(child_inode) = inode {
                if child_inode.is_dir() {
                    child_dirs.push(child_inode);
                } else if !child_inode.is_empty_size() && child_inode.is_reg() {
                    descendants.push(child_inode);
                }
                Ok(PostWalkAction::Continue)
            } else {
                Ok(PostWalkAction::Continue)
            }
        })
        .unwrap();

        for d in child_dirs {
            d.collect_descendants_inodes(descendants)?;
        }

        Ok(0)
    }

    fn alloc_bio_vecs(&self, offset: u64, size: usize, user_io: bool) -> Result<Vec<BlobIoVec>> {
        let chunk_size = self.chunk_size();
        let head_chunk_index = offset / chunk_size as u64;

        // TODO: Validate chunk format by checking its `i_u`
        let mut vec: Vec<BlobIoVec> = Vec::new();
        let chunks = self
            .chunk_addresses(head_chunk_index as u32)
            .map_err(err_invalidate_data)?;

        if chunks.is_empty() {
            return Ok(vec);
        }

        let content_offset = (offset % chunk_size as u64) as u32;
        let mut left = std::cmp::min(self.size(), size as u64) as u32;
        let mut content_len = std::cmp::min(chunk_size - content_offset, left);

        // Safe to unwrap because chunks is not empty to reach here.
        let first_chunk_addr = chunks.first().unwrap();
        let desc = self.make_chunk_io(first_chunk_addr, content_offset, content_len, user_io);

        let mut descs = BlobIoVec::new();
        descs.bi_vec.push(desc);
        descs.bi_size += content_len as usize;
        left -= content_len;

        if left != 0 {
            // Handle the rest of chunks since they shares the same content length = 0.
            for c in chunks.iter().skip(1) {
                content_len = std::cmp::min(chunk_size, left);
                let desc = self.make_chunk_io(c, 0, content_len, user_io);

                if c.blob_index() as u32 != descs.bi_vec[0].blob.blob_index() {
                    vec.push(descs);
                    descs = BlobIoVec::new();
                }

                // TODO: change type of bi_size to u32
                descs.bi_vec.push(desc);
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

pub struct DirectChunkInfoV6 {
    mapping: DirectSuperBlockV6,
    offset: usize,
    digest: RafsDigest,
}

unsafe impl Send for DirectChunkInfoV6 {}
unsafe impl Sync for DirectChunkInfoV6 {}

// This is *direct* metadata mode in-memory chunk info object.
impl DirectChunkInfoV6 {
    #[inline]
    fn new(chunk: &RafsV5ChunkInfo, mapping: DirectSuperBlockV6, offset: usize) -> Self {
        Self {
            mapping,
            offset,
            digest: chunk.block_id,
        }
    }

    #[inline]
    fn state(&self) -> Guard<Arc<DirectMappingState>> {
        self.mapping.state.load()
    }

    /// Dereference the underlying OndiskChunkInfo object.
    ///
    /// # Safety
    /// The OndiskChunkInfoWrapper could only be constructed from a valid OndiskChunkInfo pointer,
    /// so it's safe to dereference the underlying OndiskChunkInfo object.
    #[allow(clippy::cast_ptr_alignment)]
    fn chunk<'a>(&self, state: &'a DirectMappingState) -> &'a RafsV5ChunkInfo {
        unsafe {
            let ptr = state.base.add(self.offset);
            &*(ptr as *const RafsV5ChunkInfo)
        }
    }
}

impl BlobChunkInfo for DirectChunkInfoV6 {
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

    fn is_hole(&self) -> bool {
        self.chunk(self.state().deref())
            .flags
            .contains(BlobChunkFlags::HOLECHUNK)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    impl_chunkinfo_getter!(blob_index, u32);
    impl_chunkinfo_getter!(compress_offset, u64);
    impl_chunkinfo_getter!(compress_size, u32);
    impl_chunkinfo_getter!(uncompress_offset, u64);
    impl_chunkinfo_getter!(uncompress_size, u32);
}

impl BlobV5ChunkInfo for DirectChunkInfoV6 {
    fn as_base(&self) -> &dyn BlobChunkInfo {
        self
    }

    impl_chunkinfo_getter!(index, u32);
    impl_chunkinfo_getter!(file_offset, u64);
    impl_chunkinfo_getter!(flags, BlobChunkFlags);
}

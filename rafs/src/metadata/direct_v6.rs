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
use std::cmp::Ordering;
use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::io::{Result, SeekFrom};
use std::mem::size_of;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::io::AsRawFd;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use arc_swap::{ArcSwap, Guard};
use nydus_storage::device::{
    v5::BlobV5ChunkInfo, BlobChunkFlags, BlobChunkInfo, BlobDevice, BlobInfo, BlobIoDesc, BlobIoVec,
};
use nydus_storage::utils::readahead;
use nydus_utils::filemap::{clone_file, FileMapState};
use nydus_utils::{digest::RafsDigest, div_round_up, round_up};

use crate::metadata::layout::v5::RafsV5ChunkInfo;
use crate::metadata::layout::v6::{
    rafsv6_load_blob_extra_info, recover_namespace, RafsV6BlobTable, RafsV6Dirent,
    RafsV6InodeChunkAddr, RafsV6InodeCompact, RafsV6InodeExtended, RafsV6OndiskInode,
    RafsV6XattrEntry, RafsV6XattrIbodyHeader, EROFS_BLOCK_BITS_9, EROFS_BLOCK_SIZE_4096,
    EROFS_BLOCK_SIZE_512, EROFS_INODE_CHUNK_BASED, EROFS_INODE_FLAT_INLINE, EROFS_INODE_FLAT_PLAIN,
    EROFS_INODE_SLOT_SIZE, EROFS_I_DATALAYOUT_BITS, EROFS_I_VERSION_BIT, EROFS_I_VERSION_BITS,
};
use crate::metadata::layout::{bytes_to_os_str, MetaRange, XattrName, XattrValue};
use crate::metadata::{
    Attr, Entry, Inode, RafsBlobExtraInfo, RafsInode, RafsInodeWalkAction, RafsInodeWalkHandler,
    RafsSuperBlock, RafsSuperFlags, RafsSuperInodes, RafsSuperMeta, RAFS_ATTR_BLOCK_SIZE,
    RAFS_MAX_NAME,
};
use crate::{MetaType, RafsError, RafsInodeExt, RafsIoReader, RafsResult};

fn err_invalidate_data(rafs_err: RafsError) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, rafs_err)
}

/// The underlying struct to maintain memory mapped bootstrap for a file system.
///
/// Only the DirectMappingState may store raw pointers.
/// Other data structures should not store raw pointers, instead they should hold a reference to
/// the DirectMappingState object and store an offset, so a `pointer` could be reconstruct by
/// `DirectMappingState.base + offset`.
struct DirectMappingState {
    meta: Arc<RafsSuperMeta>,
    blob_table: RafsV6BlobTable,
    blob_extra_infos: HashMap<String, RafsBlobExtraInfo>,
    map: FileMapState,
}

impl DirectMappingState {
    fn new(meta: &RafsSuperMeta) -> Self {
        DirectMappingState {
            meta: Arc::new(*meta),
            blob_table: RafsV6BlobTable::default(),
            blob_extra_infos: HashMap::new(),
            map: FileMapState::default(),
        }
    }

    fn is_tarfs(&self) -> bool {
        self.meta.flags.contains(RafsSuperFlags::TARTFS_MODE)
    }

    fn block_size(&self) -> u64 {
        if self.is_tarfs() {
            EROFS_BLOCK_SIZE_512
        } else {
            EROFS_BLOCK_SIZE_4096
        }
    }
}

struct DirectCachedInfo {
    meta_offset: usize,
    root_ino: Inode,
    chunk_size: u32,
    chunk_map: Mutex<Option<HashMap<RafsV6InodeChunkAddr, usize>>>,
    attr_timeout: Duration,
    entry_timeout: Duration,
}

/// Direct-mapped Rafs v6 super block.
#[derive(Clone)]
pub struct DirectSuperBlockV6 {
    info: Arc<DirectCachedInfo>,
    state: Arc<ArcSwap<DirectMappingState>>,
    device: Arc<Mutex<BlobDevice>>,
}

impl DirectSuperBlockV6 {
    /// Create a new instance of `DirectSuperBlockV6`.
    pub fn new(meta: &RafsSuperMeta) -> Self {
        let state = DirectMappingState::new(meta);
        let block_size = state.block_size();
        let meta_offset = meta.meta_blkaddr as usize * block_size as usize;
        let info = DirectCachedInfo {
            meta_offset,
            root_ino: meta.root_nid as Inode,
            chunk_size: meta.chunk_size,
            chunk_map: Mutex::new(None),
            attr_timeout: meta.attr_timeout,
            entry_timeout: meta.entry_timeout,
        };

        Self {
            info: Arc::new(info),
            state: Arc::new(ArcSwap::new(Arc::new(state))),
            device: Arc::new(Mutex::new(BlobDevice::default())),
        }
    }

    fn disk_inode(
        state: &Guard<Arc<DirectMappingState>>,
        offset: usize,
    ) -> Result<&dyn RafsV6OndiskInode> {
        let i: &RafsV6InodeCompact = state.map.get_ref(offset)?;
        if i.format() & EROFS_I_VERSION_BITS == 0 {
            Ok(i)
        } else {
            let i = state.map.get_ref::<RafsV6InodeExtended>(offset)?;
            Ok(i)
        }
    }

    fn inode_wrapper(
        &self,
        state: &Guard<Arc<DirectMappingState>>,
        nid: u64,
    ) -> Result<OndiskInodeWrapper> {
        if nid >= (usize::MAX / EROFS_INODE_SLOT_SIZE) as u64 {
            Err(einval!(format!("v6: inode number 0x{:x} is too big", nid)))
        } else if let Some(offset) = self
            .info
            .meta_offset
            .checked_add(nid as usize * EROFS_INODE_SLOT_SIZE)
        {
            OndiskInodeWrapper::new(state, self.clone(), offset)
        } else {
            Err(einval!(format!("v6: invalid inode number 0x{:x}", nid)))
        }
    }

    // For RafsV6, we can't get the parent info of a non-dir file with its on-disk inode,
    // so we need to pass corresponding parent info when constructing the child inode.
    fn inode_wrapper_with_info(
        &self,
        state: &Guard<Arc<DirectMappingState>>,
        nid: u64,
        parent_inode: Inode,
        name: OsString,
    ) -> Result<OndiskInodeWrapper> {
        self.inode_wrapper(state, nid).map(|inode| {
            let mut inode = inode;
            inode.parent_inode = Some(parent_inode);
            inode.name = Some(name);
            inode
        })
    }

    fn update_state(&self, r: &mut RafsIoReader) -> Result<()> {
        // Validate file size
        let file = clone_file(r.as_raw_fd())?;
        let md = file.metadata()?;
        let len = md.len();
        let md_range = MetaRange::new(
            EROFS_BLOCK_SIZE_4096 as u64,
            len - EROFS_BLOCK_SIZE_4096 as u64,
            true,
        )?;

        // Validate blob table layout as blob_table_start and blob_table_offset is read from bootstrap.
        let old_state = self.state.load();
        let blob_table_size = old_state.meta.blob_table_size as u64;
        let blob_table_start = old_state.meta.blob_table_offset;
        let blob_table_range = MetaRange::new(blob_table_start, blob_table_size, false)?;
        if !blob_table_range.is_subrange_of(&md_range) {
            return Err(ebadf!("invalid blob table"));
        }

        // Prefetch the bootstrap file
        readahead(file.as_raw_fd(), 0, len);

        // Load extended blob table if the bootstrap including extended blob table.
        let mut blob_table = RafsV6BlobTable::new();
        let meta = &old_state.meta;
        r.seek(SeekFrom::Start(meta.blob_table_offset))?;
        blob_table.load(r, meta.blob_table_size, meta.chunk_size, meta.flags)?;
        let blob_extra_infos = rafsv6_load_blob_extra_info(meta, r)?;

        let file_map = FileMapState::new(file, 0, len as usize, false)?;
        let state = DirectMappingState {
            meta: old_state.meta.clone(),
            blob_table,
            blob_extra_infos,
            map: file_map,
        };

        // Swap new and old DirectMappingState object,
        // the old object will be destroyed when the reference count reaches zero.
        self.state.store(Arc::new(state));

        Ok(())
    }

    // For RafsV6, inode doesn't store detailed chunk info, only a simple RafsV6InodeChunkAddr
    // so we need to use the chunk table at the end of the bootstrap to restore the chunk info of an inode
    fn load_chunk_map(&self) -> Result<HashMap<RafsV6InodeChunkAddr, usize>> {
        let mut chunk_map = HashMap::default();
        let state = self.state.load();
        let size = state.meta.chunk_table_size as usize;
        if size == 0 {
            return Ok(chunk_map);
        }

        let block_size = state.block_size();
        let unit_size = size_of::<RafsV5ChunkInfo>();
        if size % unit_size != 0 {
            return Err(std::io::Error::from_raw_os_error(libc::EINVAL));
        }

        for idx in 0..(size / unit_size) {
            let chunk = DirectChunkInfoV6::new(&state, self.clone(), idx)?;
            let mut v6_chunk = RafsV6InodeChunkAddr::new();
            v6_chunk.set_blob_index(chunk.blob_index());
            v6_chunk.set_blob_ci_index(chunk.id());
            v6_chunk.set_block_addr((chunk.uncompressed_offset() / block_size) as u32);
            chunk_map.insert(v6_chunk, idx);
        }

        Ok(chunk_map)
    }
}

impl RafsSuperInodes for DirectSuperBlockV6 {
    fn get_max_ino(&self) -> Inode {
        let state = self.state.load();
        // The maximum inode number supported by RAFSv6 is smaller than limit of fuse-backend-rs.
        (0xffff_ffffu64) * state.block_size() / EROFS_INODE_SLOT_SIZE as u64
    }

    /// Find inode offset by ino from inode table and mmap to OndiskInode.
    fn get_inode(&self, ino: Inode, _validate_digest: bool) -> Result<Arc<dyn RafsInode>> {
        let state = self.state.load();
        Ok(Arc::new(self.inode_wrapper(&state, ino)?))
    }

    fn get_extended_inode(
        &self,
        ino: Inode,
        _validate_digest: bool,
    ) -> Result<Arc<dyn RafsInodeExt>> {
        let state = self.state.load();
        if ino == state.meta.root_nid as u64 {
            let inode = self.inode_wrapper_with_info(&state, ino, ino, OsString::from("/"))?;
            return Ok(Arc::new(inode));
        }
        let mut inode = self.inode_wrapper(&state, ino)?;
        if inode.is_dir() {
            inode.get_parent()?;
            inode.get_name(&state)?;
            return Ok(Arc::new(inode));
        }
        Err(enoent!(format!(
            "can't get extended inode for {}, root nid {} {:?}",
            ino, state.meta.root_nid, inode.name
        )))
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
        let state = DirectMappingState::new(&RafsSuperMeta::default());
        self.state.store(Arc::new(state));
    }

    fn get_blob_infos(&self) -> Vec<Arc<BlobInfo>> {
        self.state.load().blob_table.get_all()
    }

    fn get_blob_extra_infos(&self) -> Result<HashMap<String, RafsBlobExtraInfo>> {
        Ok(self.state.load().blob_extra_infos.clone())
    }

    fn root_ino(&self) -> u64 {
        self.info.root_ino
    }

    fn get_chunk_info(&self, idx: usize) -> Result<Arc<dyn BlobChunkInfo>> {
        let state = self.state.load();
        let chunk = DirectChunkInfoV6::new(&state, self.clone(), idx)?;
        Ok(Arc::new(chunk))
    }

    fn set_blob_device(&self, blob_device: BlobDevice) {
        *self.device.lock().unwrap() = blob_device;
    }
}

/// Direct-mapped RAFS v6 inode object.
pub struct OndiskInodeWrapper {
    mapping: DirectSuperBlockV6,
    offset: usize,
    blocks_count: u64,
    parent_inode: Option<Inode>,
    name: Option<OsString>,
}

impl OndiskInodeWrapper {
    fn new(
        state: &Guard<Arc<DirectMappingState>>,
        mapping: DirectSuperBlockV6,
        offset: usize,
    ) -> Result<Self> {
        let inode = DirectSuperBlockV6::disk_inode(state, offset)?;
        let blocks_count = div_round_up(inode.size(), state.block_size());

        Ok(OndiskInodeWrapper {
            mapping,
            offset,
            blocks_count,
            parent_inode: None,
            name: None,
        })
    }

    fn state(&self) -> Guard<Arc<DirectMappingState>> {
        self.mapping.state.load()
    }

    fn blocks_count(&self) -> u64 {
        self.blocks_count
    }

    fn disk_inode<'a>(
        &self,
        state: &'a Guard<Arc<DirectMappingState>>,
    ) -> &'a dyn RafsV6OndiskInode {
        // Safe to unwrap() because `self.offset` has been validated in new().
        DirectSuperBlockV6::disk_inode(state, self.offset).unwrap()
    }

    fn get_entry<'a>(
        &self,
        state: &'a Guard<Arc<DirectMappingState>>,
        inode: &dyn RafsV6OndiskInode,
        block_index: usize,
        index: usize,
    ) -> RafsResult<&'a RafsV6Dirent> {
        let offset = self.data_block_offset(state, inode, block_index)?;
        if size_of::<RafsV6Dirent>() * (index + 1) >= state.block_size() as usize {
            Err(RafsError::InvalidImageData)
        } else if let Some(offset) = offset.checked_add(size_of::<RafsV6Dirent>() * index) {
            state
                .map
                .get_ref(offset)
                .map_err(|_e| RafsError::InvalidImageData)
        } else {
            Err(RafsError::InvalidImageData)
        }
    }

    // `max_entries` indicates the quantity of entries residing in a single block including tail packing.
    // Both `block_index` and `index` start from 0.
    fn entry_name<'a>(
        &self,
        state: &'a Guard<Arc<DirectMappingState>>,
        inode: &dyn RafsV6OndiskInode,
        block_index: usize,
        index: usize,
        max_entries: usize,
    ) -> RafsResult<&'a OsStr> {
        assert!(max_entries > 0);
        let block_size = state.block_size();
        let offset = self.data_block_offset(state, inode, block_index)?;
        let de = self.get_entry(state, inode, block_index, index)?;
        let buf: &[u8] = match index.cmp(&(max_entries - 1)) {
            Ordering::Less => {
                let next_de = self.get_entry(state, inode, block_index, index + 1)?;
                if next_de.e_nameoff as u64 >= block_size {
                    return Err(RafsError::InvalidImageData);
                }
                let len = next_de.e_nameoff.checked_sub(de.e_nameoff).ok_or_else(|| {
                    error!(
                        "nid {} entry index {} block index {} next dir entry {:?} current dir entry {:?}",
                        self.ino(), index, block_index, next_de, de
                    );
                    RafsError::IllegalMetaStruct(
                        MetaType::Dir,
                        format!("cur {} next {}", next_de.e_nameoff, de.e_nameoff),
                    )
                })?;

                state
                    .map
                    .get_slice(offset + de.e_nameoff as usize, len as usize)
                    .map_err(|_e| RafsError::InvalidImageData)?
            }
            Ordering::Equal => {
                let base = de.e_nameoff as u64;
                if base >= block_size {
                    return Err(RafsError::InvalidImageData);
                }

                // The possible maximum len of the last dirent's file name should be calculated
                // differently depends on whether the dirent is at the last block of the dir file.
                // Because the other blocks should be fully used, while the last may not.
                let block_count = self.blocks_count() as usize;
                let len = match block_count.cmp(&(block_index + 1)) {
                    Ordering::Greater => (block_size - base) as usize,
                    Ordering::Equal => {
                        if self.size() % block_size == 0 {
                            (block_size - base) as usize
                        } else {
                            (self.size() % block_size - base) as usize
                        }
                    }
                    Ordering::Less => return Err(RafsError::InvalidImageData),
                };

                let buf: &[u8] = state
                    .map
                    .get_slice(offset + base as usize, len)
                    .map_err(|_e| RafsError::InvalidImageData)?;
                // Use this trick to temporarily decide entry name's length. Improve this?
                let mut l: usize = 0;
                for i in buf {
                    if *i != 0 {
                        l += 1;
                        if len == l {
                            break;
                        }
                    } else {
                        break;
                    }
                }
                &buf[..l]
            }
            Ordering::Greater => return Err(RafsError::InvalidImageData),
        };

        Ok(bytes_to_os_str(buf))
    }

    // COPIED from kernel code:
    // erofs inode data layout (i_format in on-disk inode):
    // 0 - inode plain without inline data A: inode, [xattrs], ... | ... | no-holed data
    // 1 - inode VLE compression B (legacy): inode, [xattrs], extents ... | ...
    // 2 - inode plain with inline data C: inode, [xattrs], last_inline_data, ... | ... | no-holed data
    // 3 - inode compression D: inode, [xattrs], map_header, extents ... | ...
    // 4 - inode chunk-based E: inode, [xattrs], chunk indexes ... | ...
    // 5~7 - reserved
    fn data_block_offset(
        &self,
        state: &Guard<Arc<DirectMappingState>>,
        inode: &dyn RafsV6OndiskInode,
        index: usize,
    ) -> RafsResult<usize> {
        const VALID_MODE_BITS: u16 = ((1 << EROFS_I_DATALAYOUT_BITS) - 1) << EROFS_I_VERSION_BITS
            | ((1 << EROFS_I_VERSION_BITS) - 1);
        if inode.format() & !VALID_MODE_BITS != 0 || index > u32::MAX as usize {
            return Err(RafsError::Incompatible(inode.format()));
        }

        let layout = inode.format() >> EROFS_I_VERSION_BITS;
        match layout {
            EROFS_INODE_FLAT_PLAIN => Self::flat_data_block_offset(state, inode, index),
            EROFS_INODE_FLAT_INLINE => match self.blocks_count().cmp(&(index as u64 + 1)) {
                Ordering::Greater => Self::flat_data_block_offset(state, inode, index),
                Ordering::Equal => {
                    Ok(self.offset as usize + Self::inode_size(inode) + Self::xattr_size(inode))
                }
                Ordering::Less => Err(RafsError::InvalidImageData),
            },
            _ => Err(RafsError::InvalidImageData),
        }
    }

    fn flat_data_block_offset(
        state: &Guard<Arc<DirectMappingState>>,
        inode: &dyn RafsV6OndiskInode,
        index: usize,
    ) -> RafsResult<usize> {
        // `i_u` points to the Nth block
        let base = inode.union() as usize;
        if base.checked_add(index).is_none() || base + index > u32::MAX as usize {
            Err(RafsError::InvalidImageData)
        } else {
            Ok((base + index) * state.block_size() as usize)
        }
    }

    fn mode_format_bits(&self) -> u32 {
        let state = self.state();
        let i = self.disk_inode(&state);
        i.mode() as u32 & libc::S_IFMT as u32
    }

    #[allow(clippy::too_many_arguments)]
    fn make_chunk_io(
        &self,
        state: &Guard<Arc<DirectMappingState>>,
        device: &BlobDevice,
        chunk_addr: &RafsV6InodeChunkAddr,
        content_offset: u32,
        content_len: u32,
        user_io: bool,
        is_tarfs_mode: bool,
        is_tail: bool,
    ) -> Option<BlobIoDesc> {
        let blob_index = match chunk_addr.blob_index() {
            Err(e) => {
                warn!(
                    "failed to get blob index for chunk address {:?}, {}",
                    chunk_addr, e
                );
                return None;
            }
            Ok(v) => v,
        };

        match state.blob_table.get(blob_index) {
            Err(e) => {
                warn!(
                    "failed to get blob with index {} for chunk address {:?}, {}",
                    blob_index, chunk_addr, e
                );
                None
            }
            Ok(blob) => {
                if is_tarfs_mode {
                    let size = if is_tail {
                        (self.size() % self.chunk_size() as u64) as u32
                    } else {
                        self.chunk_size()
                    };
                    let chunk = TarfsChunkInfoV6::from_chunk_addr(chunk_addr, size).ok()?;
                    let chunk = Arc::new(chunk) as Arc<dyn BlobChunkInfo>;
                    Some(BlobIoDesc::new(
                        blob,
                        chunk.into(),
                        content_offset,
                        content_len,
                        user_io,
                    ))
                } else {
                    let chunk_index = chunk_addr.blob_ci_index();
                    device
                        .create_io_chunk(blob.blob_index(), chunk_index)
                        .map(|v| BlobIoDesc::new(blob, v, content_offset, content_len, user_io))
                }
            }
        }
    }

    fn chunk_size(&self) -> u32 {
        self.mapping.info.chunk_size
    }

    fn inode_size(inode: &dyn RafsV6OndiskInode) -> usize {
        if (inode.format() & 1 << EROFS_I_VERSION_BIT) != 0 {
            size_of::<RafsV6InodeExtended>()
        } else {
            size_of::<RafsV6InodeCompact>()
        }
    }

    fn xattr_size(inode: &dyn RafsV6OndiskInode) -> usize {
        // Rafs v6 only supports EROFS inline xattr.
        if inode.xattr_inline_count() > 0 {
            (inode.xattr_inline_count() as usize - 1) * size_of::<RafsV6XattrEntry>()
                + size_of::<RafsV6XattrIbodyHeader>()
        } else {
            0
        }
    }

    // Get sum of inode and xattr size aligned to RafsV6InodeChunkAddr.
    fn inode_xattr_size(inode: &dyn RafsV6OndiskInode) -> usize {
        let sz = Self::inode_size(inode) as u64 + Self::xattr_size(inode) as u64;
        round_up(sz, size_of::<RafsV6InodeChunkAddr>() as u64) as usize
    }

    fn chunk_addresses<'a>(
        &self,
        state: &'a Guard<Arc<DirectMappingState>>,
        base_index: u32,
    ) -> RafsResult<&'a [RafsV6InodeChunkAddr]> {
        let total_chunks = div_round_up(self.size(), self.chunk_size() as u64);
        if total_chunks > u32::MAX as u64 || total_chunks <= base_index as u64 {
            return Err(RafsError::InvalidImageData);
        }

        let inode = self.disk_inode(state);
        assert_eq!(
            inode.format() >> EROFS_I_VERSION_BITS,
            EROFS_INODE_CHUNK_BASED
        );

        let base_index = base_index as usize;
        let base = Self::inode_xattr_size(inode) + base_index * size_of::<RafsV6InodeChunkAddr>();
        if let Some(offset) = base.checked_add(self.offset) {
            let count = total_chunks as usize - base_index;
            state
                .map
                .get_slice(offset, count)
                .map_err(|_e| RafsError::InvalidImageData)
        } else {
            Err(RafsError::InvalidImageData)
        }
    }

    fn find_target_block(
        &self,
        state: &Guard<Arc<DirectMappingState>>,
        inode: &dyn RafsV6OndiskInode,
        name: &OsStr,
    ) -> Result<Option<usize>> {
        if inode.size() == 0 || !self.is_dir() {
            return Ok(None);
        }

        let blocks_count = self.blocks_count();
        if blocks_count > u32::MAX as u64 {
            return Err(einval!("v6: invalid block count in directory entry"));
        }

        let mut first = 0;
        let mut last = (blocks_count - 1) as i64;
        while first <= last {
            let pivot = first + ((last - first) >> 1);
            let entries_count = self.get_entry_count(&state, inode, pivot as usize)?;
            let h_name = self
                .entry_name(state, inode, pivot as usize, 0, entries_count)
                .map_err(err_invalidate_data)?;
            let t_name = self
                .entry_name(
                    state,
                    inode,
                    pivot as usize,
                    entries_count - 1,
                    entries_count,
                )
                .map_err(err_invalidate_data)?;
            if h_name <= name && t_name >= name {
                return Ok(Some(pivot as usize));
            } else if h_name > name {
                if pivot == 0 {
                    break;
                }
                last = pivot - 1;
            } else {
                first = pivot + 1;
            }
        }

        Ok(None)
    }

    fn get_parent(&mut self) -> Result<()> {
        assert!(self.is_dir());
        let parent = self.get_child_by_name(OsStr::new(".."))?;
        self.parent_inode = Some(parent.ino());
        Ok(())
    }

    fn get_name(&mut self, state: &Guard<Arc<DirectMappingState>>) -> Result<()> {
        assert!(self.is_dir());
        let cur_ino = self.ino();
        if cur_ino == self.mapping.info.root_ino {
            self.name = Some(OsString::from(""));
        } else {
            let parent = self.mapping.inode_wrapper(state, self.parent())?;
            parent.walk_children_inodes(
                0,
                &mut |_inode: Option<Arc<dyn RafsInode>>, name: OsString, ino, _offset| {
                    if cur_ino == ino {
                        self.name = Some(name);
                        return Ok(RafsInodeWalkAction::Break);
                    }
                    Ok(RafsInodeWalkAction::Continue)
                },
            )?;
            if self.name.is_none() {
                return Err(einval!(format!(
                    "v6: failed to get parent for directory with inode 0x{:x}",
                    cur_ino
                )));
            }
        }

        Ok(())
    }

    fn get_entry_count(
        &self,
        state: &Guard<Arc<DirectMappingState>>,
        inode: &dyn RafsV6OndiskInode,
        block_index: usize,
    ) -> Result<usize> {
        let head_entry = self
            .get_entry(&state, inode, block_index, 0)
            .map_err(err_invalidate_data)?;
        let name_offset = head_entry.e_nameoff as usize;
        if name_offset as u64 >= EROFS_BLOCK_SIZE_4096
            || name_offset % size_of::<RafsV6Dirent>() != 0
        {
            Err(enoent!(format!(
                "v6: invalid e_nameoff {} from directory entry",
                name_offset
            )))
        } else {
            Ok(name_offset / size_of::<RafsV6Dirent>())
        }
    }
}

impl RafsInode for OndiskInodeWrapper {
    fn validate(&self, _inode_count: u64, _chunk_size: u64) -> Result<()> {
        let state = self.state();
        let inode = self.disk_inode(&state);
        let max_inode = self.mapping.get_max_ino();

        if self.ino() > max_inode
            || self.offset > (u32::MAX as usize) * EROFS_BLOCK_SIZE_4096 as usize
            || inode.nlink() == 0
            || self.get_name_size() as usize > (RAFS_MAX_NAME + 1)
        {
            return Err(ebadf!(format!(
                "inode validation failure, inode {:?}",
                inode
            )));
        }

        if self.is_reg() {
            if state.meta.is_chunk_dict() {
                // chunk-dict doesn't support chunk_count check
                return Err(std::io::Error::from_raw_os_error(libc::EOPNOTSUPP));
            }
            let chunks = div_round_up(self.size(), self.chunk_size() as u64) as usize;
            let chunk_size = chunks * size_of::<RafsV6InodeChunkAddr>();
            let size = OndiskInodeWrapper::inode_xattr_size(inode)
                .checked_add(chunk_size)
                .ok_or_else(|| einval!("v6: invalid inode size"))?;
            state.map.validate_range(self.offset, size)?;
        } else if self.is_dir() {
            if self.get_child_count() as u64 >= max_inode {
                return Err(einval!("invalid directory"));
            }
            let xattr_size = Self::xattr_size(inode) as usize;
            let size = Self::inode_size(inode) + xattr_size;
            state.map.validate_range(self.offset, size)?;
        } else if self.is_symlink() && self.size() == 0 {
            return Err(einval!("invalid symlink target"));
        }
        Ok(())
    }

    fn alloc_bio_vecs(
        &self,
        device: &BlobDevice,
        offset: u64,
        size: usize,
        user_io: bool,
    ) -> Result<Vec<BlobIoVec>> {
        let state = self.state();
        let chunk_size = self.chunk_size();
        let head_chunk_index = offset / chunk_size as u64;
        if head_chunk_index > u32::MAX as u64 {
            return Err(einval!(
                "v6: invalid offset or chunk size when calculate chunk index"
            ));
        }
        let mut vec: Vec<BlobIoVec> = Vec::new();
        let chunks = self
            .chunk_addresses(&state, head_chunk_index as u32)
            .map_err(err_invalidate_data)?;
        if chunks.is_empty() {
            return Ok(vec);
        }

        let mut curr_chunk_index = head_chunk_index as u32;
        let tail_chunk_index = self.get_chunk_count() - 1;
        let is_tarfs_mode = state.is_tarfs();
        let content_offset = (offset % chunk_size as u64) as u32;
        let mut left = std::cmp::min(self.size() - offset, size as u64) as u32;
        let mut content_len = std::cmp::min(chunk_size - content_offset, left);
        let desc = self
            .make_chunk_io(
                &state,
                device,
                &chunks[0],
                content_offset,
                content_len,
                user_io,
                is_tarfs_mode,
                curr_chunk_index == tail_chunk_index,
            )
            .ok_or_else(|| einval!("failed to get chunk information"))?;

        let mut descs = BlobIoVec::new(desc.blob.clone());
        descs.push(desc);
        left -= content_len;
        if left != 0 {
            // Handle the rest of chunks since they shares the same content length = 0.
            for c in chunks.iter().skip(1) {
                curr_chunk_index += 1;
                content_len = std::cmp::min(chunk_size, left);
                let desc = self
                    .make_chunk_io(
                        &state,
                        device,
                        c,
                        0,
                        content_len,
                        user_io,
                        is_tarfs_mode,
                        curr_chunk_index == tail_chunk_index,
                    )
                    .ok_or_else(|| einval!("failed to get chunk information"))?;
                if desc.blob.blob_index() != descs.blob_index() {
                    vec.push(descs);
                    descs = BlobIoVec::new(desc.blob.clone());
                }
                descs.push(desc);
                left -= content_len;
                if left == 0 {
                    break;
                }
            }
        }
        if !descs.is_empty() {
            vec.push(descs)
        }
        assert_eq!(left, 0);

        Ok(vec)
    }

    fn collect_descendants_inodes(
        &self,
        descendants: &mut Vec<Arc<dyn RafsInode>>,
    ) -> Result<usize> {
        if !self.is_dir() {
            return Err(enotdir!());
        }

        let mut child_dirs: Vec<Arc<dyn RafsInode>> = Vec::new();
        let callback = &mut |inode: Option<Arc<dyn RafsInode>>, name: OsString, _ino, _offset| {
            if let Some(child_inode) = inode {
                if child_inode.is_dir() {
                    // EROFS packs dot and dotdot, so skip them two.
                    if name != "." && name != ".." {
                        child_dirs.push(child_inode);
                    }
                } else if !child_inode.is_empty_size() && child_inode.is_reg() {
                    descendants.push(child_inode);
                }
                Ok(RafsInodeWalkAction::Continue)
            } else {
                Ok(RafsInodeWalkAction::Continue)
            }
        };

        self.walk_children_inodes(0, callback)?;
        for d in child_dirs {
            d.collect_descendants_inodes(descendants)?;
        }

        Ok(0)
    }

    fn get_entry(&self) -> Entry {
        Entry {
            attr: self.get_attr().into(),
            inode: self.ino(),
            generation: 0,
            attr_timeout: self.mapping.info.attr_timeout,
            entry_timeout: self.mapping.info.entry_timeout,
            ..Default::default()
        }
    }

    fn get_attr(&self) -> Attr {
        let state = self.state();
        let inode = self.disk_inode(&state);

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
            rdev: inode.rdev(),
            ..Default::default()
        }
    }

    fn ino(&self) -> u64 {
        assert!(self.offset > self.mapping.info.meta_offset);
        (self.offset - self.mapping.info.meta_offset) as u64 / EROFS_INODE_SLOT_SIZE as u64
    }

    /// Get real device number of the inode.
    fn rdev(&self) -> u32 {
        let state = self.state();
        self.disk_inode(&state).union()
    }

    /// Get project id associated with the inode.
    fn projid(&self) -> u32 {
        0
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
        let state = self.state();
        let inode = self.disk_inode(&state);
        inode.nlink() > 1 && self.is_reg()
    }

    /// Check whether the inode has extended attributes.
    fn has_xattr(&self) -> bool {
        let state = self.state();
        self.disk_inode(&state).xattr_inline_count() > 0
    }

    fn get_xattr(&self, name: &OsStr) -> Result<Option<XattrValue>> {
        let state = self.state();
        let inode = self.disk_inode(&state);
        let total = inode.xattr_inline_count();
        if total == 0 {
            return Ok(None);
        }

        let mut offset =
            self.offset + Self::inode_size(inode) + size_of::<RafsV6XattrIbodyHeader>();
        let mut remaining = (total - 1) as usize * size_of::<RafsV6XattrEntry>();
        while remaining > 0 {
            let e: &RafsV6XattrEntry = state.map.get_ref(offset)?;
            if e.name_len() as usize + e.value_size() as usize > remaining {
                return Err(einval!(format!(
                    "v6: invalid xattr name size {}",
                    e.name_len()
                )));
            }
            let mut xa_name = recover_namespace(e.name_index())?;
            let suffix: &[u8] = state.map.get_slice(
                offset + size_of::<RafsV6XattrEntry>(),
                e.name_len() as usize,
            )?;
            xa_name.push(OsStr::from_bytes(suffix));
            if xa_name == name {
                let data: &[u8] = state.map.get_slice(
                    offset + size_of::<RafsV6XattrEntry>() + e.name_len() as usize,
                    e.value_size() as usize,
                )?;
                return Ok(Some(data.to_vec()));
            }

            let mut s = e.name_len() + e.value_size() + size_of::<RafsV6XattrEntry>() as u32;
            s = round_up(s as u64, size_of::<RafsV6XattrEntry>() as u64) as u32;
            if s as usize >= remaining {
                break;
            }
            remaining -= s as usize;
            offset += s as usize;
        }

        Ok(None)
    }

    fn get_xattrs(&self) -> Result<Vec<XattrName>> {
        let state = self.state();
        let inode = self.disk_inode(&state);
        let mut xattrs = Vec::new();
        let total = inode.xattr_inline_count();
        if total == 0 {
            return Ok(xattrs);
        }

        let mut offset =
            self.offset + Self::inode_size(inode) + size_of::<RafsV6XattrIbodyHeader>();
        let mut remaining = (total - 1) as usize * size_of::<RafsV6XattrEntry>();
        while remaining > 0 {
            let e: &RafsV6XattrEntry = state.map.get_ref(offset)?;
            if e.name_len() as usize + e.value_size() as usize > remaining {
                return Err(einval!(format!(
                    "v6: invalid xattr name size {}",
                    e.name_len()
                )));
            }
            let name: &[u8] = state.map.get_slice(
                offset + size_of::<RafsV6XattrEntry>(),
                e.name_len() as usize,
            )?;
            let ns = recover_namespace(e.name_index())?;
            let mut xa = ns.into_vec();
            xa.extend_from_slice(name);
            xattrs.push(xa);

            let mut s = e.name_len() + e.value_size() + size_of::<RafsV6XattrEntry>() as u32;
            s = round_up(s as u64, size_of::<RafsV6XattrEntry>() as u64) as u32;
            if s as usize >= remaining {
                break;
            }
            offset += s as usize;
            remaining -= s as usize;
        }

        Ok(xattrs)
    }

    /// Get symlink target of the inode.
    ///
    /// # Safety
    /// It depends on Self::validate() to ensure valid memory layout.
    fn get_symlink(&self) -> Result<OsString> {
        let state = self.state();
        let inode = self.disk_inode(&state);
        if inode.size() > EROFS_BLOCK_SIZE_4096 {
            return Err(einval!(format!(
                "v6: invalid symlink size {}",
                inode.size()
            )));
        }
        let offset = self
            .data_block_offset(&state, inode, 0)
            .map_err(err_invalidate_data)?;
        let buf: &[u8] = state.map.get_slice(offset, inode.size() as usize)?;
        Ok(bytes_to_os_str(buf).to_os_string())
    }

    fn get_symlink_size(&self) -> u16 {
        let state = self.state();
        let inode = self.disk_inode(&state);
        inode.size() as u16
    }

    fn walk_children_inodes(&self, entry_offset: u64, handler: RafsInodeWalkHandler) -> Result<()> {
        let state = self.state();
        let inode = self.disk_inode(&state);
        if inode.size() == 0 {
            return Err(enoent!());
        }

        let blocks_count = self.blocks_count();
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

        for i in 0..blocks_count as usize {
            let entries_count = self.get_entry_count(&state, inode, i)?;
            for j in 0..entries_count {
                // Skip specified offset
                if skipped != 0 {
                    skipped -= 1;
                    continue;
                }

                let de = self
                    .get_entry(&state, inode, i, j)
                    .map_err(err_invalidate_data)?;
                let name = self
                    .entry_name(&state, inode, i, j, entries_count)
                    .map_err(err_invalidate_data)?;
                let nid = de.e_nid;
                let inode = Arc::new(self.mapping.inode_wrapper_with_info(
                    &state,
                    nid,
                    self.ino(),
                    OsString::from(name),
                )?) as Arc<dyn RafsInode>;
                cur_offset += 1;
                match handler(Some(inode), name.to_os_string(), nid, cur_offset) {
                    // Break returned by handler indicates that there is not enough buffer of readdir for entries inreaddir,
                    // such that it has to return. because this is a nested loop,
                    // using break can only jump out of the internal loop, there is no way to jump out of the whole loop.
                    Ok(RafsInodeWalkAction::Break) => return Ok(()),
                    Ok(RafsInodeWalkAction::Continue) => continue,
                    Err(e) => return Err(e),
                };
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
        let inode = self.disk_inode(&state);
        if let Some(target_block) = self.find_target_block(&state, inode, name)? {
            let entries_count = self.get_entry_count(&state, inode, target_block)?;
            let mut first = 0;
            let mut last = (entries_count - 1) as i64;
            while first <= last {
                let pivot = first + ((last - first) >> 1);
                let de = self
                    .get_entry(&state, inode, target_block, pivot as usize)
                    .map_err(err_invalidate_data)?;
                let d_name = self
                    .entry_name(&state, inode, target_block, pivot as usize, entries_count)
                    .map_err(err_invalidate_data)?;
                match d_name.cmp(name) {
                    Ordering::Equal => {
                        let inode = self.mapping.inode_wrapper_with_info(
                            &state,
                            de.e_nid,
                            self.ino(),
                            OsString::from(name),
                        )?;
                        return Ok(Arc::new(inode));
                    }
                    Ordering::Less => first = pivot + 1,
                    Ordering::Greater => last = pivot - 1,
                }
            }
        }
        Err(enoent!())
    }

    /// Get the child with the specified index.
    ///
    /// # Safety
    /// It depends on Self::validate() to ensure valid memory layout.
    /// `idx` is the number of child files in line. So we can keep the term `idx`
    /// in super crate and keep it consistent with layout v5.
    fn get_child_by_index(&self, idx: u32) -> Result<Arc<dyn RafsInodeExt>> {
        let state = self.state();
        let inode = self.disk_inode(&state);
        if !self.is_dir() {
            return Err(einval!("inode is not a directory"));
        }

        let blocks_count = self.blocks_count();
        let mut cur_idx = 0u32;
        for i in 0..blocks_count as usize {
            let entries_count = self.get_entry_count(&state, inode, i)?;
            for j in 0..entries_count {
                let de = self
                    .get_entry(&state, inode, i, j)
                    .map_err(err_invalidate_data)?;
                let name = self
                    .entry_name(&state, inode, i, j, entries_count)
                    .map_err(err_invalidate_data)?;
                if name == "." || name == ".." {
                    continue;
                }
                if cur_idx == idx {
                    let inode = self.mapping.inode_wrapper_with_info(
                        &state,
                        de.e_nid,
                        self.ino(),
                        OsString::from(name),
                    )?;
                    return Ok(Arc::new(inode));
                }
                cur_idx += 1;
            }
        }

        Err(enoent!("invalid child index"))
    }

    fn get_child_count(&self) -> u32 {
        // For regular file, return chunk info count.
        if !self.is_dir() {
            return div_round_up(self.size(), self.chunk_size() as u64) as u32;
        }

        let mut child_cnt = 0;
        let state = self.state();
        let inode = self.disk_inode(&state);
        let blocks_count = self.blocks_count();
        for i in 0..blocks_count as usize {
            let entries_count = self.get_entry_count(&state, inode, i).unwrap_or(0);
            child_cnt += entries_count;
        }

        if child_cnt >= 2 && child_cnt <= u32::MAX as usize {
            // Skip DOT and DOTDOT
            child_cnt as u32 - 2
        } else {
            0
        }
    }

    fn get_child_index(&self) -> Result<u32> {
        Ok(0)
    }

    /// Get data size of the inode.
    fn size(&self) -> u64 {
        let state = self.state();
        let i = self.disk_inode(&state);
        i.size()
    }

    #[inline]
    fn get_chunk_count(&self) -> u32 {
        self.get_child_count()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl RafsInodeExt for OndiskInodeWrapper {
    fn as_inode(&self) -> &dyn RafsInode {
        self
    }

    /// Get inode number of the parent directory.
    fn parent(&self) -> u64 {
        self.parent_inode.unwrap()
    }

    /// Get name of the inode.
    ///
    /// # Safety
    /// It depends on Self::validate() to ensure valid memory layout.
    fn name(&self) -> OsString {
        assert!(self.name.is_some());
        self.name.clone().unwrap_or_else(OsString::new)
    }

    /// Get file name size of the inode.
    fn get_name_size(&self) -> u16 {
        self.name().len() as u16
    }

    // RafsV5 flags, not used by v6, return 0
    fn flags(&self) -> u64 {
        0
    }

    fn get_digest(&self) -> RafsDigest {
        RafsDigest::default()
    }

    /// Get chunk information with index `idx`
    ///
    /// # Safety
    /// It depends on Self::validate() to ensure valid memory layout.
    fn get_chunk_info(&self, idx: u32) -> Result<Arc<dyn BlobChunkInfo>> {
        let state = self.state();
        let inode = self.disk_inode(&state);
        if !self.is_reg() || idx >= self.get_chunk_count() {
            return Err(enoent!("invalid chunk info"));
        }

        let base = OndiskInodeWrapper::inode_xattr_size(inode)
            + (idx as usize * size_of::<RafsV6InodeChunkAddr>());
        let offset = base
            .checked_add(self.offset as usize)
            .ok_or_else(|| einval!("v6: invalid offset or index to calculate chunk address"))?;
        let chunk_addr = state.map.get_ref::<RafsV6InodeChunkAddr>(offset)?;
        let has_device = self.mapping.device.lock().unwrap().has_device();

        if state.meta.has_inlined_chunk_digest() && has_device {
            let blob_index = chunk_addr.blob_index()?;
            let chunk_index = chunk_addr.blob_ci_index();
            let device = self.mapping.device.lock().unwrap();
            device
                .get_chunk_info(blob_index, chunk_index)
                .ok_or_else(|| {
                    enoent!(format!(
                        "no chunk information object for blob {} chunk {}",
                        blob_index, chunk_index
                    ))
                })
        } else if state.is_tarfs() {
            let size = if idx == self.get_chunk_count() - 1 {
                (self.size() % self.chunk_size() as u64) as u32
            } else {
                self.chunk_size()
            };
            let chunk_info = TarfsChunkInfoV6::from_chunk_addr(chunk_addr, size)?;
            Ok(Arc::new(chunk_info))
        } else {
            let mut chunk_map = self.mapping.info.chunk_map.lock().unwrap();
            if chunk_map.is_none() {
                *chunk_map = Some(self.mapping.load_chunk_map()?);
            }
            match chunk_map.as_ref().unwrap().get(chunk_addr) {
                None => Err(enoent!(format!(
                    "failed to get chunk info for chunk {}/{}/{}",
                    chunk_addr.blob_index().unwrap_or_default(),
                    chunk_addr.blob_ci_index(),
                    chunk_addr.block_addr()
                ))),
                Some(idx) => DirectChunkInfoV6::new(&state, self.mapping.clone(), *idx)
                    .map(|v| Arc::new(v) as Arc<dyn BlobChunkInfo>),
            }
        }
    }
}

/// Impl get accessor for chunkinfo object.
macro_rules! impl_chunkinfo_getter {
    ($G: ident, $U: ty) => {
        #[inline]
        fn $G(&self) -> $U {
            let state = self.state();

            self.v5_chunk(&state).$G
        }
    };
}

/// RAFS v6 chunk information object.
pub(crate) struct DirectChunkInfoV6 {
    mapping: DirectSuperBlockV6,
    offset: usize,
    digest: RafsDigest,
}

// This is *direct* metadata mode in-memory chunk info object.
impl DirectChunkInfoV6 {
    fn new(state: &DirectMappingState, mapping: DirectSuperBlockV6, idx: usize) -> Result<Self> {
        let unit_size = size_of::<RafsV5ChunkInfo>();
        let offset = state.meta.chunk_table_offset as usize + idx * unit_size;
        let chunk_tbl_end = state.meta.chunk_table_offset + state.meta.chunk_table_size;
        if (offset as u64) < state.meta.chunk_table_offset
            || (offset + unit_size) as u64 > chunk_tbl_end
        {
            return Err(einval!(format!(
                "invalid chunk offset {} chunk table {} {}",
                offset, state.meta.chunk_table_offset, state.meta.chunk_table_size
            )));
        }
        let chunk = state.map.get_ref::<RafsV5ChunkInfo>(offset)?;
        Ok(Self {
            mapping,
            offset,
            digest: chunk.block_id,
        })
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
    fn v5_chunk<'a>(&self, state: &'a DirectMappingState) -> &'a RafsV5ChunkInfo {
        // Safe to unwrap() because we have validated the offset in DirectChunkInfoV6::new().
        state.map.get_ref::<RafsV5ChunkInfo>(self.offset).unwrap()
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
        let state = self.state();
        self.v5_chunk(&state)
            .flags
            .contains(BlobChunkFlags::COMPRESSED)
    }

    fn is_encrypted(&self) -> bool {
        let state = self.state();
        self.v5_chunk(&state)
            .flags
            .contains(BlobChunkFlags::ENCYPTED)
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

impl BlobV5ChunkInfo for DirectChunkInfoV6 {
    fn as_base(&self) -> &dyn BlobChunkInfo {
        self
    }

    impl_chunkinfo_getter!(index, u32);
    impl_chunkinfo_getter!(file_offset, u64);
    impl_chunkinfo_getter!(flags, BlobChunkFlags);
}

/// Rafs v6 fake ChunkInfo for Tarfs.
pub(crate) struct TarfsChunkInfoV6 {
    blob_index: u32,
    chunk_index: u32,
    offset: u64,
    size: u32,
}

impl TarfsChunkInfoV6 {
    /// Create a new instance of [TarfsChunkInfoV6].
    pub fn new(blob_index: u32, chunk_index: u32, offset: u64, size: u32) -> Self {
        TarfsChunkInfoV6 {
            blob_index,
            chunk_index,
            offset,
            size,
        }
    }

    fn from_chunk_addr(chunk_addr: &RafsV6InodeChunkAddr, size: u32) -> Result<Self> {
        let blob_index = chunk_addr.blob_index()?;
        let chunk_index = chunk_addr.blob_ci_index();
        let offset = (chunk_addr.block_addr() as u64) << EROFS_BLOCK_BITS_9;
        Ok(TarfsChunkInfoV6::new(blob_index, chunk_index, offset, size))
    }
}

const TARFS_DIGEST: RafsDigest = RafsDigest { data: [0u8; 32] };

impl BlobChunkInfo for TarfsChunkInfoV6 {
    fn chunk_id(&self) -> &RafsDigest {
        &TARFS_DIGEST
    }

    fn id(&self) -> u32 {
        self.chunk_index
    }

    fn blob_index(&self) -> u32 {
        self.blob_index
    }

    fn compressed_offset(&self) -> u64 {
        self.offset
    }

    fn compressed_size(&self) -> u32 {
        self.size
    }

    fn uncompressed_offset(&self) -> u64 {
        self.offset
    }

    fn uncompressed_size(&self) -> u32 {
        self.size
    }

    fn is_compressed(&self) -> bool {
        false
    }

    fn is_encrypted(&self) -> bool {
        false
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl BlobV5ChunkInfo for TarfsChunkInfoV6 {
    fn index(&self) -> u32 {
        self.chunk_index
    }

    fn file_offset(&self) -> u64 {
        0
    }

    fn flags(&self) -> BlobChunkFlags {
        BlobChunkFlags::empty()
    }

    fn as_base(&self) -> &dyn BlobChunkInfo {
        self
    }
}

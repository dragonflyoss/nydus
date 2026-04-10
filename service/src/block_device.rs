// Copyright (C) 2023 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0)

//! Represent a RAFSv6 image as a block device.
//!
//! Metadata of RAFSv6 image has two address encoding schemes:
//! - blob address: data is located by (blob_index, chunk_index)
//! - block address: data is located by (block_addr)
//!
//! Based on the block address scheme, an RAFSv6 image can be converted into/represented as a block
//! device, so it can be directly mounted by Linux EROFS fs driver.

use std::cmp::{max, min};
use std::fs::OpenOptions;
use std::io::Result;
use std::os::fd::{AsRawFd, RawFd};
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::thread::JoinHandle;

use dbs_allocator::{Constraint, IntervalTree, NodeState, Range};
use nydus_api::BlobCacheEntry;
use nydus_rafs::metadata::layout::v6::{
    EROFS_BLOCK_BITS_12, EROFS_BLOCK_BITS_9, EROFS_BLOCK_SIZE_4096, EROFS_BLOCK_SIZE_512,
};
use nydus_storage::utils::alloc_buf;
use nydus_utils::digest::{self, RafsDigest};
use nydus_utils::round_up;
use nydus_utils::verity::VerityGenerator;
use tokio_uring::buf::IoBufMut;

use crate::blob_cache::{generate_blob_key, BlobCacheMgr, BlobConfig, DataBlob, MetaBlob};

const BLOCK_DEVICE_EXPORT_BATCH_SIZE: usize = 0x80000;

enum BlockRange {
    Hole,
    MetaBlob(Rc<MetaBlob>),
    DataBlob(Rc<DataBlob>),
}

/// A block device composed up from a RAFSv6 image.
///
/// RAFSv6 metadata has two encoding schemes:
/// - blob address: data is located by (blob_index, chunk_index)
/// - block address: data is located by (block_addr)
///
/// Based on the block address scheme, an RAFSv6 image can be converted into/represented as a block
/// device, so it can be directly mounted by Linux EROFS fs driver.
pub struct BlockDevice {
    blocks: u32,
    blob_id: String,
    cache_mgr: Arc<BlobCacheMgr>,
    ranges: IntervalTree<BlockRange>,
    is_tarfs_mode: bool,
}

impl BlockDevice {
    /// Create a new instance of [BlockDevice].
    pub fn new(blob_entry: BlobCacheEntry) -> Result<Self> {
        let cache_mgr = Arc::new(BlobCacheMgr::new());
        cache_mgr.add_blob_entry(&blob_entry).map_err(|e| {
            eother!(format!(
                "block_device: failed to add blob into CacheMgr, {}",
                e
            ))
        })?;
        let blob_id = generate_blob_key(&blob_entry.domain_id, &blob_entry.blob_id);

        BlockDevice::new_with_cache_manager(blob_id, cache_mgr)
    }

    /// Create a new instance of [BlockDevice] with provided blob cache manager.
    pub fn new_with_cache_manager(blob_id: String, cache_mgr: Arc<BlobCacheMgr>) -> Result<Self> {
        let mut ranges = IntervalTree::new();
        ranges.insert(Range::new(0, u32::MAX - 1), None);

        let meta_blob_config = match cache_mgr.get_config(&blob_id) {
            None => {
                return Err(enoent!(format!(
                    "block_device: can not find blob {} in blob cache manager",
                    blob_id
                )))
            }
            Some(BlobConfig::DataBlob(_v)) => {
                return Err(einval!(format!(
                    "block_device: blob {} is not a metadata blob",
                    blob_id
                )))
            }
            Some(BlobConfig::MetaBlob(v)) => v,
        };
        let is_tarfs_mode = meta_blob_config.is_tarfs_mode();
        let meta_blob = MetaBlob::new(meta_blob_config.path())?;
        let meta_blob = Rc::new(meta_blob);
        let blocks = if is_tarfs_mode {
            meta_blob.blocks() * 8
        } else {
            meta_blob.blocks()
        };
        let constraint = Constraint::new(blocks).min(0u32).max(blocks - 1);
        let range = ranges.allocate(&constraint).ok_or_else(|| {
            enoent!(format!(
                "block_device: failed to allocate address range for meta blob {}",
                meta_blob_config.blob_id()
            ))
        })?;
        ranges.update(&range, BlockRange::MetaBlob(meta_blob));

        let mut pos = blocks;
        let data_blobs = meta_blob_config.get_blobs();
        for blob in data_blobs.iter() {
            let blob_info = blob.blob_info();
            let blob_id = blob_info.blob_id();
            let extra_info = meta_blob_config
                .get_blob_extra_info(&blob_id)
                .ok_or_else(|| {
                    let msg = format!(
                        "block_device: can not get extra information for blob {}",
                        blob_id
                    );
                    enoent!(msg)
                })?;
            if extra_info.mapped_blkaddr == 0 {
                let msg = format!(
                    "block_device: mapped block address for blob {} is zero",
                    blob_id
                );
                return Err(einval!(msg));
            }
            if is_tarfs_mode != blob_info.features().is_tarfs() {
                let msg = format!(
                    "block_device: inconsistent `TARFS` mode from meta and data blob {}",
                    blob_id
                );
                return Err(einval!(msg));
            }

            if pos < extra_info.mapped_blkaddr {
                let constraint = Constraint::new(extra_info.mapped_blkaddr - pos)
                    .min(pos)
                    .max(extra_info.mapped_blkaddr - 1);
                let range = ranges.allocate(&constraint).ok_or_else(|| {
                    enoent!("block_device: failed to allocate address range for hole between blobs")
                })?;
                ranges.update(&range, BlockRange::Hole);
            }

            let blocks = if is_tarfs_mode {
                blob_info.uncompressed_size() >> EROFS_BLOCK_BITS_9
            } else {
                blob_info.uncompressed_size() >> EROFS_BLOCK_BITS_12
            };
            if blocks > u32::MAX as u64
                || blocks + extra_info.mapped_blkaddr as u64 > u32::MAX as u64
            {
                return Err(einval!(format!(
                    "block_device: uncompressed size 0x{:x} of blob {} is invalid",
                    blob_info.uncompressed_size(),
                    blob_info.blob_id()
                )));
            }
            let data_blob = DataBlob::new(blob)?;
            let constraint = Constraint::new(blocks as u32)
                .min(extra_info.mapped_blkaddr)
                .max(extra_info.mapped_blkaddr + blocks as u32 - 1);
            let range = ranges.allocate(&constraint).ok_or_else(|| {
                enoent!(format!(
                    "block_device: can not allocate address range for blob {}",
                    blob_info.blob_id()
                ))
            })?;
            ranges.update(&range, BlockRange::DataBlob(Rc::new(data_blob)));
            pos = extra_info.mapped_blkaddr + blocks as u32;
        }

        Ok(BlockDevice {
            blocks: pos,
            blob_id,
            cache_mgr,
            ranges,
            is_tarfs_mode,
        })
    }

    /// Get blob id of the metadata blob.
    pub fn meta_blob_id(&self) -> &str {
        &self.blob_id
    }

    /// Get the [BlobCacheMgr](../blob_cache/struct.BlobCacheMgr.html) associated with the block device.
    pub fn cache_mgr(&self) -> Arc<BlobCacheMgr> {
        self.cache_mgr.clone()
    }

    /// Get number of blocks of the block device.
    pub fn blocks(&self) -> u32 {
        self.blocks
    }

    /// Get block size of block device.
    pub fn block_size(&self) -> u64 {
        if self.is_tarfs_mode {
            EROFS_BLOCK_SIZE_512
        } else {
            EROFS_BLOCK_SIZE_4096
        }
    }

    /// Convert data size to number of blocks.
    pub fn size_to_blocks(&self, sz: u64) -> u64 {
        if self.is_tarfs_mode {
            sz >> EROFS_BLOCK_BITS_9
        } else {
            sz >> EROFS_BLOCK_BITS_12
        }
    }

    /// Convert number of blocks to data size.
    pub fn blocks_to_size(&self, blocks: u32) -> u64 {
        if self.is_tarfs_mode {
            (blocks as u64) << EROFS_BLOCK_BITS_9
        } else {
            (blocks as u64) << EROFS_BLOCK_BITS_12
        }
    }

    /// Read block range [start, start + blocks) from the block device.
    pub async fn async_read<T: IoBufMut>(
        &self,
        mut start: u32,
        mut blocks: u32,
        mut buf: T,
    ) -> (Result<usize>, T) {
        let sz = self.blocks_to_size(blocks);
        if start.checked_add(blocks).is_none() || sz > buf.bytes_total() as u64 {
            return (
                Err(einval!("block_device: invalid parameters to read()")),
                buf,
            );
        }

        let total_size = sz as usize;
        let mut pos = 0;
        while blocks > 0 {
            let (range, node) = match self.ranges.get_superset(&Range::new_point(start)) {
                Some(v) => v,
                None => {
                    return (
                        Err(eio!(format!(
                            "block_device: can not locate block 0x{:x} for meta blob {}",
                            start, self.blob_id
                        ))),
                        buf,
                    );
                }
            };

            if let NodeState::Valued(r) = node {
                let count = min(range.max as u32 - start + 1, blocks);
                let sz = self.blocks_to_size(count) as usize;
                let mut s = buf.slice(pos..pos + sz);
                let (res, s) = match r {
                    BlockRange::Hole => {
                        s.fill(0);
                        (Ok(sz), s)
                    }
                    BlockRange::MetaBlob(m) => {
                        let offset = self.blocks_to_size(start);
                        m.async_read(offset, s).await
                    }
                    BlockRange::DataBlob(d) => {
                        let offset = start - range.min as u32;
                        let offset = self.blocks_to_size(offset);
                        d.async_read(offset, s).await
                    }
                };

                buf = s.into_inner();
                if res.is_err() {
                    return (res, buf);
                }
                start += count;
                blocks -= count;
                pos += sz;
            } else {
                return (
                    Err(eio!(format!(
                        "block_device: block range 0x{:x}/0x{:x} of meta blob {} is unhandled",
                        start, blocks, self.blob_id,
                    ))),
                    buf,
                );
            }
        }

        (Ok(total_size), buf)
    }

    /// Fetch block ranges (fd, offset, len, block_offset) for direct mmap access.
    ///
    /// Holes are always skipped (no data to return).
    /// When `probe_only` is true, only ready chunks are returned.
    pub async fn fetch_ranges(
        &self,
        mut start: u32,
        mut blocks: u32,
        probe_only: bool,
    ) -> Result<Vec<(RawFd, u64, usize, u64)>> {
        if start.checked_add(blocks).is_none() {
            return Err(einval!(
                "block_device: invalid parameters to fetch_ranges()"
            ));
        }

        let mut ranges = Vec::new();
        while blocks > 0 {
            let (range, node) = match self.ranges.get_superset(&Range::new_point(start)) {
                Some(v) => v,
                None => {
                    return Err(eio!(format!(
                        "block_device: can not locate block 0x{:x} for meta blob {}",
                        start, self.blob_id
                    )));
                }
            };

            if let NodeState::Valued(r) = node {
                let count = min(range.max as u32 - start + 1, blocks);

                match r {
                    BlockRange::Hole => {
                        // Skip holes - no data to return
                    }
                    BlockRange::MetaBlob(m) => {
                        // Meta blob doesn't have chunk map, treat as fully ready
                        let offset = self.blocks_to_size(start - range.min as u32);
                        let sz = self.blocks_to_size(count) as usize;
                        let block_offset = self.blocks_to_size(range.min as u32) + offset;
                        ranges.push((m.file().as_raw_fd(), offset, sz, block_offset));
                    }
                    BlockRange::DataBlob(b) => {
                        if probe_only {
                            let data_ranges =
                                self.probe_blob_ranges(b, start - range.min as u32, count)?;
                            let fd = b.file().as_raw_fd();
                            let base_offset = self.blocks_to_size(range.min as u32);
                            for (blob_offset, blob_len) in data_ranges {
                                ranges.push((fd, blob_offset, blob_len, base_offset + blob_offset));
                            }
                        } else {
                            let offset = self.blocks_to_size(start - range.min as u32);
                            let sz = self.blocks_to_size(count) as usize;
                            b.async_fetch(offset, sz).await?;
                            let block_offset = self.blocks_to_size(range.min as u32) + offset;
                            ranges.push((b.file().as_raw_fd(), offset, sz, block_offset));
                        }
                    }
                }

                start += count;
                blocks -= count;
            } else {
                return Err(eio!(format!(
                    "block_device: block range 0x{:x}/0x{:x} of meta blob {} is unhandled",
                    start, blocks, self.blob_id,
                )));
            }
        }

        Ok(ranges)
    }

    /// Probe ready ranges in a data blob.
    fn probe_blob_ranges(
        &self,
        blob: &DataBlob,
        start_block: u32,
        num_blocks: u32,
    ) -> Result<Vec<(u64, usize)>> {
        let blob_info = blob.blob_info();
        let chunk_size = blob_info.chunk_size() as u64;
        let blob_size = blob_info.uncompressed_size();
        let chunk_count = blob_info.chunk_count() as u64;

        if chunk_size == 0 || chunk_count == 0 {
            return Ok(Vec::new());
        }

        let byte_start = self.blocks_to_size(start_block);
        let byte_end = self.blocks_to_size(start_block + num_blocks).min(blob_size);
        let start_chunk = (byte_start / chunk_size) as u32;
        let end_chunk = (byte_end.div_ceil(chunk_size)).min(chunk_count) as u32;

        let blob_cache = blob.blob();
        let chunk_map = blob_cache.get_chunk_map();

        let mut ranges = Vec::new();
        let mut range_start: Option<u32> = None;

        for chunk_idx in start_chunk..end_chunk {
            let is_ready = blob_cache
                .get_chunk_info(chunk_idx)
                .map(|c| chunk_map.is_ready(c.as_ref()).unwrap_or(false))
                .unwrap_or(false);

            match (range_start, is_ready) {
                (Some(start), false) => {
                    let blob_offset = start as u64 * chunk_size;
                    let blob_len =
                        ((chunk_idx as u64 * chunk_size).min(blob_size) - blob_offset) as usize;
                    if blob_len > 0 {
                        ranges.push((blob_offset, blob_len));
                    }
                    range_start = None;
                }
                (None, true) => range_start = Some(chunk_idx),
                _ => {}
            }
        }

        // Handle the last range
        if let Some(start) = range_start {
            let blob_offset = start as u64 * chunk_size;
            let blob_len = ((end_chunk as u64 * chunk_size).min(blob_size) - blob_offset) as usize;
            if blob_len > 0 {
                ranges.push((blob_offset, blob_len));
            }
        }

        Ok(ranges)
    }

    /// Export a RAFS filesystem as a raw block disk image.
    pub fn export(
        blob_entry: BlobCacheEntry,
        output: Option<String>,
        data_dir: Option<String>,
        threads: u32,
        verity: bool,
    ) -> Result<()> {
        let block_device = BlockDevice::new(blob_entry)?;
        let block_device = Rc::new(block_device);
        let blocks = block_device.blocks();
        let blob_id = block_device.meta_blob_id();

        let path = match output {
            Some(v) => PathBuf::from(v),
            None => {
                let path = match block_device.cache_mgr.get_config(blob_id) {
                    Some(BlobConfig::MetaBlob(meta)) => meta.path().to_path_buf(),
                    _ => return Err(enoent!("block_device: failed to get meta blob")),
                };
                if !path.is_file() {
                    return Err(eother!(format!(
                        "block_device: meta blob {} is not a file",
                        path.display()
                    )));
                }
                let name = path
                    .file_name()
                    .ok_or_else(|| {
                        eother!(format!(
                            "block_device: failed to get file name from {}",
                            path.display()
                        ))
                    })?
                    .to_str()
                    .ok_or_else(|| {
                        eother!(format!(
                            "block_device: failed to get file name from {}",
                            path.display()
                        ))
                    })?;
                let dir = data_dir
                    .ok_or_else(|| einval!("block_device: parameter `data_dir` is missing"))?;
                let path = PathBuf::from(dir);
                path.join(name.to_string() + ".disk")
            }
        };

        let output_file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&path)
            .map_err(|e| {
                eother!(format!(
                    "block_device: failed to create output file {}, {}",
                    path.display(),
                    e
                ))
            })?;
        let output_file = Rc::new(tokio_uring::fs::File::from_std(output_file));

        let mut verity_offset = 0;
        let generator = if verity {
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
                .map_err(|e| {
                    eother!(format!(
                        "block_device: failed to create output file {}, {}",
                        path.display(),
                        e
                    ))
                })?;
            verity_offset = round_up(block_device.blocks_to_size(blocks), 4096);
            let mut generator = VerityGenerator::new(file, verity_offset, blocks)?;
            generator.initialize()?;
            Some(Arc::new(Mutex::new(generator)))
        } else {
            None
        };

        let batch_size = BLOCK_DEVICE_EXPORT_BATCH_SIZE as u32 / block_device.block_size() as u32;
        assert_eq!(batch_size.count_ones(), 1);
        let threads = max(threads, 1);
        let mut threads = min(threads, 32);
        while blocks / threads < batch_size && threads > 1 {
            threads /= 2;
        }

        if threads == 1 {
            let generator = generator.clone();
            let block_device = block_device.clone();
            tokio_uring::start(async move {
                Self::do_export(block_device, output_file, 0, blocks, generator).await
            })?;
        } else {
            let mut thread_handlers: Vec<JoinHandle<Result<()>>> =
                Vec::with_capacity(threads as usize);
            let step = (blocks + batch_size - 1) & !(batch_size - 1);
            let mut pos = 0;

            for _i in 0..threads {
                let count = min(blocks - pos, step);
                let mgr = block_device.cache_mgr.clone();
                let id = blob_id.to_string();
                let path = path.to_path_buf();
                let generator = generator.clone();

                let handler = thread::spawn(move || {
                    let output_file = OpenOptions::new()
                        .read(true)
                        .write(true)
                        .open(&path)
                        .map_err(|e| {
                            eother!(format!(
                                "block_device: failed to create output file {}, {}",
                                path.display(),
                                e
                            ))
                        })?;
                    let file = Rc::new(tokio_uring::fs::File::from_std(output_file));
                    let block_device =
                        BlockDevice::new_with_cache_manager(id, mgr).map_err(|e| {
                            eother!(format!(
                                "block_device: failed to create block device object, {}",
                                e
                            ))
                        })?;
                    let device = Rc::new(block_device);

                    tokio_uring::start(async move {
                        Self::do_export(device, file, pos, count, generator).await
                    })?;
                    Ok(())
                });
                pos += count;
                thread_handlers.push(handler);
            }
            assert_eq!(pos, blocks);
            assert_eq!(thread_handlers.len(), threads as usize);

            for handler in thread_handlers {
                handler
                    .join()
                    .map_err(|e| {
                        eother!(format!(
                            "block_device: failed to wait for worker thread, {:?}",
                            e
                        ))
                    })?
                    .map_err(|e| {
                        eother!(format!("block_device: failed to export disk image, {}", e))
                    })?;
            }
        }

        if let Some(generator) = generator.as_ref() {
            let mut guard = generator.lock().unwrap();
            let root_digest = guard.generate_all_digests()?;
            let root_digest: String = root_digest
                .data
                .iter()
                .fold(String::new(), |acc, v| acc + &format!("{:02x}", v));
            println!(
                "dm-verity options: --no-superblock --format=1 -s \"\" --hash=sha256 --data-block-size={} --hash-block-size=4096 --data-blocks {} --hash-offset {} {}",
                block_device.block_size(), blocks, verity_offset, root_digest
            );
        }

        Ok(())
    }

    async fn do_export(
        block_device: Rc<BlockDevice>,
        output_file: Rc<tokio_uring::fs::File>,
        start: u32,
        mut blocks: u32,
        generator: Option<Arc<Mutex<VerityGenerator>>>,
    ) -> Result<()> {
        let batch_size = BLOCK_DEVICE_EXPORT_BATCH_SIZE as u32 / block_device.block_size() as u32;
        let block_size = block_device.block_size() as usize;
        let mut pos = start;
        let mut buf = alloc_buf(BLOCK_DEVICE_EXPORT_BATCH_SIZE);

        while blocks > 0 {
            let count = min(batch_size, blocks);
            let (res, buf1) = block_device.async_read(pos, count, buf).await;
            let sz = res?;
            if sz != count as usize * block_size {
                return Err(eio!(
                    "block_device: failed to read data, got less data than requested"
                ));
            }
            buf = buf1;

            if sz != buf.len() {
                buf.resize(sz, 0);
            }
            let (res, buf2) = output_file
                .write_at(buf, block_device.blocks_to_size(pos))
                .await;
            let sz1 = res?;
            if sz1 != sz {
                return Err(eio!(
                    "block_device: failed to write data to disk image file, written less data than requested"
                ));
            }
            buf = buf2;

            // Generate Merkle tree leaf nodes.
            if let Some(generator) = generator.as_ref() {
                let mut page_idx = (block_device.blocks_to_size(pos) / block_size as u64) as u32;
                let mut offset = 0;
                while offset < buf.len() {
                    let digest = RafsDigest::from_buf(
                        &buf[offset..offset + block_size],
                        digest::Algorithm::Sha256,
                    );
                    let mut guard = generator.lock().unwrap();
                    guard.set_digest(1, page_idx, &digest.data)?;
                    offset += block_size;
                    page_idx += 1;
                }
            }

            pos += count;
            blocks -= count;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blob_cache::generate_blob_key;
    use nydus_api::BlobCacheEntry;
    use nydus_utils::digest::{DigestHasher, RafsDigest};
    use std::fs::{self, File};
    use std::io::{BufReader, Read};
    use std::path::PathBuf;
    use vmm_sys_util::tempdir::TempDir;

    #[test]
    fn test_block_device() {
        let tmp_dir = TempDir::new().unwrap();
        let entry = create_bootstrap_entry(&tmp_dir);

        let mgr = BlobCacheMgr::new();
        mgr.add_blob_entry(&entry).unwrap();
        let blob_id = generate_blob_key(&entry.domain_id, &entry.blob_id);
        assert!(mgr.get_config(&blob_id).is_some());

        // Check existence of data blob referenced by the bootstrap.
        let key = generate_blob_key(
            &entry.domain_id,
            "be7d77eeb719f70884758d1aa800ed0fb09d701aaec469964e9d54325f0d5fef",
        );
        assert!(mgr.get_config(&key).is_some());

        let mgr = Arc::new(mgr);
        // assert with wrong blob_id
        assert!(BlockDevice::new_with_cache_manager(String::from("blob_id"), mgr.clone()).is_err());
        let device = BlockDevice::new_with_cache_manager(blob_id, mgr).unwrap();
        assert_eq!(device.blocks(), 0x209);

        tokio_uring::start(async move {
            let buf = vec![0u8; 8192];
            let (res, buf) = device.async_read(u32::MAX, u32::MAX, buf).await;
            assert!(res.is_err());
            assert_eq!(buf.len(), 8192);
            let (res, _buf) = device.async_read(0, 1, vec![0u8]).await;
            assert!(res.is_err());

            let (res, buf) = device.async_read(0, 1, buf).await;
            assert_eq!(buf.len(), 8192);
            assert_eq!(res.unwrap(), 4096);
            assert_eq!(buf[0], 0);
            assert_eq!(buf[1023], 0);
            assert_eq!(buf[1024], 0xe2);
            assert_eq!(buf[1027], 0xe0);

            let (res, buf) = device.async_read(4, 2, buf).await;
            assert_eq!(res.unwrap(), 8192);
            assert_eq!(buf[4096], 0);
            assert_eq!(buf[5119], 0);
            assert_eq!(buf[5120], 0);
            assert_eq!(buf[5123], 0);
            assert_eq!(buf[5372], 0);
            assert_eq!(buf[8191], 0);

            let (res, buf) = device.async_read(0x200, 2, buf).await;
            assert_eq!(buf.len(), 8192);
            assert_eq!(res.unwrap(), 8192);

            let (res, buf) = device.async_read(0x208, 2, buf).await;
            assert_eq!(buf.len(), 8192);
            assert!(res.is_err());

            let (res, buf) = device.async_read(0x208, 1, buf).await;
            assert_eq!(buf.len(), 8192);
            assert_eq!(res.unwrap(), 4096);

            let (res, buf) = device.async_read(0x209, 1, buf).await;
            assert_eq!(buf.len(), 8192);
            assert!(res.is_err());
        });
    }

    fn create_bootstrap_entry(tmp_dir: &TempDir) -> BlobCacheEntry {
        let root_dir = &std::env::var("CARGO_MANIFEST_DIR").expect("$CARGO_MANIFEST_DIR");
        let mut source_path = PathBuf::from(root_dir);
        source_path.push("../tests/texture/blobs/be7d77eeb719f70884758d1aa800ed0fb09d701aaec469964e9d54325f0d5fef");
        let mut dest_path = tmp_dir.as_path().to_path_buf();
        dest_path.push("be7d77eeb719f70884758d1aa800ed0fb09d701aaec469964e9d54325f0d5fef");
        fs::copy(&source_path, &dest_path).unwrap();

        let mut source_path = PathBuf::from(root_dir);
        source_path.push("../tests/texture/bootstrap/rafs-v6-2.2.boot");
        let config = r#"
        {
            "type": "bootstrap",
            "id": "rafs-v6",
            "domain_id": "domain2",
            "config_v2": {
                "version": 2,
                "id": "factory1",
                "backend": {
                    "type": "localfs",
                    "localfs": {
                        "dir": "/tmp/nydus"
                    }
                },
                "cache": {
                    "type": "filecache",
                    "filecache": {
                        "work_dir": "/tmp/nydus"
                    }
                },
                "metadata_path": "RAFS_V5"
            }
        }"#;

        // config with non-existing path
        let entry: BlobCacheEntry = serde_json::from_str(config).unwrap();
        assert!(BlockDevice::new(entry).is_err());

        // config with correct path
        let content = config
            .replace("/tmp/nydus", tmp_dir.as_path().to_str().unwrap())
            .replace("RAFS_V5", &source_path.display().to_string());
        let mut entry: BlobCacheEntry = serde_json::from_str(&content).unwrap();
        assert!(entry.prepare_configuration_info());
        entry
    }

    fn create_block_device() -> BlockDevice {
        let tmp_dir = TempDir::new().unwrap();
        let entry = create_bootstrap_entry(&tmp_dir);

        let device = BlockDevice::new(entry);
        assert!(device.is_ok());
        let device = device.unwrap();
        assert_eq!(device.blocks(), 0x209);

        device
    }

    /// Like `create_block_device` but also returns TempDir to keep blob files alive
    /// during async operations (async_fetch accesses cache files by path).
    fn create_block_device_with_tmpdir() -> (BlockDevice, TempDir) {
        let tmp_dir = TempDir::new().unwrap();
        let entry = create_bootstrap_entry(&tmp_dir);

        let device = BlockDevice::new(entry).unwrap();
        assert_eq!(device.blocks(), 0x209);

        (device, tmp_dir)
    }

    #[test]
    fn test_block_size() {
        let mut device = create_block_device();

        assert!(!device.is_tarfs_mode);
        assert_eq!(device.block_size(), EROFS_BLOCK_SIZE_4096);
        assert_ne!(device.block_size(), EROFS_BLOCK_SIZE_512);

        device.is_tarfs_mode = true;
        assert_ne!(device.block_size(), EROFS_BLOCK_SIZE_4096);
        assert_eq!(device.block_size(), EROFS_BLOCK_SIZE_512);
    }

    #[test]
    fn test_size_to_blocks() {
        let mut device = create_block_device();

        assert!(!device.is_tarfs_mode);
        assert_eq!(device.size_to_blocks(0), 0);
        assert_eq!(device.size_to_blocks(4096), 1);
        assert_ne!(device.size_to_blocks(4096), 4096);
        assert_ne!(device.size_to_blocks(4096), 8);

        device.is_tarfs_mode = true;
        assert_eq!(device.size_to_blocks(0), 0);
        assert_eq!(device.size_to_blocks(512), 1);
        assert_ne!(device.size_to_blocks(512), 512);
        assert_ne!(device.size_to_blocks(4096), 1);
    }

    #[test]
    fn test_blocks_to_size() {
        let mut device = create_block_device();

        assert!(!device.is_tarfs_mode);
        assert_eq!(device.blocks_to_size(0), 0);
        assert_eq!(device.blocks_to_size(1), 4096);
        assert_ne!(device.blocks_to_size(4096), 4096);
        assert_ne!(device.blocks_to_size(8), 4096);

        device.is_tarfs_mode = true;
        assert_eq!(device.blocks_to_size(0), 0);
        assert_eq!(device.blocks_to_size(1), 512);
        assert_ne!(device.blocks_to_size(512), 512);
        assert_ne!(device.blocks_to_size(1), 4096);
    }

    fn sha256_digest<R: Read>(mut reader: R) -> Result<String> {
        let mut hasher = RafsDigest::hasher(digest::Algorithm::Sha256);
        let mut buffer = [0; 1024];

        loop {
            let count = reader.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            hasher.digest_update(&buffer[..count]);
        }

        Ok(hasher.digest_finalize().into())
    }

    fn test_export_arg_thread(thread: u32) -> Result<()> {
        let entry_tmp_dir = TempDir::new()?;
        let entry = create_bootstrap_entry(&entry_tmp_dir);

        let tmp_dir = TempDir::new().unwrap();
        let data_dir = Some(String::from(tmp_dir.as_path().to_str().unwrap()));

        assert!(BlockDevice::export(entry, None, data_dir, thread, true).is_ok());

        let mut disk_path = PathBuf::from(tmp_dir.as_path());
        disk_path.push("rafs-v6-2.2.boot.disk");
        let input = File::open(disk_path)?;
        let reader = BufReader::new(input);
        let sha256 = sha256_digest(reader)?;
        assert_eq!(
            sha256,
            String::from("5684c330c622350c12d633d0773201f862b9955375d806670e1aaf36ef038b31")
        );

        Ok(())
    }

    #[test]
    fn test_export() {
        assert!(test_export_arg_thread(1).is_ok());
        assert!(test_export_arg_thread(2).is_ok());
    }

    #[test]
    fn test_fetch_ranges_invalid() {
        let device = create_block_device();
        tokio_uring::start(async move {
            // Overflow check
            let res = device.fetch_ranges(u32::MAX, u32::MAX, false).await;
            assert!(res.is_err());
        });
    }

    #[test]
    fn test_fetch_ranges_out_of_range() {
        let device = create_block_device();
        tokio_uring::start(async move {
            // Past device end
            let res = device.fetch_ranges(0x20A, 1, false).await;
            assert!(res.is_err());
        });
    }

    #[test]
    fn test_fetch_ranges_meta_blob() {
        let device = create_block_device();
        tokio_uring::start(async move {
            // Block 0 is MetaBlob
            let ranges = device.fetch_ranges(0, 1, false).await.unwrap();
            assert!(!ranges.is_empty());
            let (fd, _offset, sz, _block_offset) = &ranges[0];
            assert!(*fd >= 0);
            assert_eq!(*sz, 4096);

            // Multiple MetaBlob blocks
            let ranges = device.fetch_ranges(0, 5, false).await.unwrap();
            assert!(!ranges.is_empty());
            let (fd, _offset, sz, _block_offset) = &ranges[0];
            assert!(*fd >= 0);
            assert_eq!(*sz, 5 * 4096);
        });
    }

    #[test]
    fn test_fetch_ranges_meta_blob_probe() {
        let device = create_block_device();
        tokio_uring::start(async move {
            // probe_only on MetaBlob should still return ranges (MetaBlob is always ready)
            let ranges = device.fetch_ranges(0, 1, true).await.unwrap();
            assert!(!ranges.is_empty());
            let (fd, _offset, sz, _block_offset) = &ranges[0];
            assert!(*fd >= 0);
            assert_eq!(*sz, 4096);
        });
    }

    #[test]
    fn test_fetch_ranges_data_blob() {
        let (device, _tmp_dir) = create_block_device_with_tmpdir();
        tokio_uring::start(async move {
            // Block 0x200 is DataBlob
            let ranges = device.fetch_ranges(0x200, 2, false).await.unwrap();
            assert!(!ranges.is_empty());
            let (fd, _offset, sz, _block_offset) = &ranges[0];
            assert!(*fd >= 0);
            assert_eq!(*sz, 2 * 4096);
        });
    }

    #[test]
    fn test_fetch_ranges_data_blob_probe() {
        let (device, _tmp_dir) = create_block_device_with_tmpdir();
        tokio_uring::start(async move {
            // probe_only on DataBlob exercises probe_blob_ranges
            let ranges = device.fetch_ranges(0x200, 2, true).await.unwrap();
            // May or may not have ready ranges depending on cache state,
            // but should not error
            for (fd, _offset, sz, _block_offset) in &ranges {
                assert!(*fd >= 0);
                assert!(*sz > 0);
            }
        });
    }

    #[test]
    fn test_fetch_ranges_mixed() {
        let (device, _tmp_dir) = create_block_device_with_tmpdir();
        tokio_uring::start(async move {
            // Span across MetaBlob + Hole: blocks 0-5+
            // MetaBlob is blocks 0-4, after that is Hole until DataBlob
            let ranges = device.fetch_ranges(0, 6, false).await.unwrap();
            // Should have at least MetaBlob range; Hole is skipped
            assert!(!ranges.is_empty());
        });
    }

    #[test]
    fn test_fetch_ranges_hole() {
        let device = create_block_device();
        tokio_uring::start(async move {
            // Block 5 is in the hole region between MetaBlob and DataBlob
            let ranges = device.fetch_ranges(5, 1, false).await.unwrap();
            // Holes produce no ranges
            assert!(ranges.is_empty());
        });
    }

    #[test]
    fn test_fetch_ranges_zero_blocks() {
        let device = create_block_device();
        tokio_uring::start(async move {
            let ranges = device.fetch_ranges(0, 0, false).await.unwrap();
            assert!(ranges.is_empty());
        });
    }

    #[test]
    fn test_fetch_ranges_meta_blob_offsets() {
        let device = create_block_device();
        tokio_uring::start(async move {
            // Fetch blocks 2..5 from MetaBlob (blocks 0-4)
            let ranges = device.fetch_ranges(2, 3, false).await.unwrap();
            assert_eq!(ranges.len(), 1);
            let (fd, offset, sz, block_offset) = &ranges[0];
            assert!(*fd >= 0);
            assert_eq!(*offset, 2 * 4096);
            assert_eq!(*sz, 3 * 4096);
            assert_eq!(*block_offset, 2 * 4096);
        });
    }

    #[test]
    fn test_fetch_ranges_data_blob_offsets() {
        let (device, _tmp_dir) = create_block_device_with_tmpdir();
        tokio_uring::start(async move {
            // Block 0x200 is the start of DataBlob region
            let ranges = device.fetch_ranges(0x200, 1, false).await.unwrap();
            assert_eq!(ranges.len(), 1);
            let (_fd, offset, sz, block_offset) = &ranges[0];
            assert_eq!(*sz, 4096);
            assert_eq!(*block_offset, 0x200u64 * 4096);
            // offset is relative to the DataBlob range start
            assert_eq!(*offset, 0);
        });
    }

    #[test]
    fn test_fetch_ranges_probe_after_fetch() {
        let (device, _tmp_dir) = create_block_device_with_tmpdir();
        tokio_uring::start(async move {
            // First fetch to populate cache (makes chunks ready)
            let ranges = device.fetch_ranges(0x200, 2, false).await.unwrap();
            assert!(!ranges.is_empty());

            // Now probe — chunks should be ready, exercising:
            // - (None, true) branch in probe_blob_ranges
            // - last-range closing logic
            let probe_ranges = device.fetch_ranges(0x200, 2, true).await.unwrap();
            assert!(!probe_ranges.is_empty());
            for (fd, _offset, sz, _block_offset) in &probe_ranges {
                assert!(*fd >= 0);
                assert!(*sz > 0);
            }
        });
    }

    #[test]
    fn test_fetch_ranges_probe_cold() {
        let (device, _tmp_dir) = create_block_device_with_tmpdir();
        tokio_uring::start(async move {
            // Probe without prior fetch — no chunks ready
            let ranges = device.fetch_ranges(0x200, 2, true).await.unwrap();
            // Empty or partial depending on cache state
            // This exercises the (None, false) -> _ => {} branch
            let _ = ranges;
        });
    }

    #[test]
    fn test_fetch_ranges_probe_mixed_ready() {
        let (device, _tmp_dir) = create_block_device_with_tmpdir();
        tokio_uring::start(async move {
            // Fetch only 1 block to make some chunks ready
            let _ = device.fetch_ranges(0x200, 1, false).await.unwrap();

            // Probe 2 blocks — first block's chunks ready, second not yet
            // Exercises (Some(start), false) transition in probe_blob_ranges
            let ranges = device.fetch_ranges(0x200, 2, true).await.unwrap();
            // Should have at least the ready range
            for (fd, _offset, sz, _block_offset) in &ranges {
                assert!(*fd >= 0);
                assert!(*sz > 0);
            }
        });
    }

    #[test]
    fn test_async_read_zero_buf() {
        let (device, _tmp_dir) = create_block_device_with_tmpdir();
        tokio_uring::start(async move {
            // Zero-length read triggers async_fetch(pos, 0) short-circuit
            let buf = vec![0u8; 0];
            let (res, _buf) = device.async_read(0x200, 0, buf).await;
            assert_eq!(res.unwrap(), 0);
        });
    }

    #[test]
    fn test_async_read_data_blob() {
        let (device, _tmp_dir) = create_block_device_with_tmpdir();
        tokio_uring::start(async move {
            // Read from DataBlob — exercises async_fetch normal path
            // and async_read Ok branch in blob_cache.rs
            let buf = vec![0u8; 4096];
            let (res, _buf) = device.async_read(0x200, 1, buf).await;
            assert_eq!(res.unwrap(), 4096);
        });
    }
}

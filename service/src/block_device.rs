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
use std::path::PathBuf;
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
    MetaBlob(Arc<MetaBlob>),
    DataBlob(Arc<DataBlob>),
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
    pub fn new(blob_id: String, cache_mgr: Arc<BlobCacheMgr>) -> Result<Self> {
        let mut ranges = IntervalTree::new();
        ranges.insert(Range::new(0, u32::MAX), None);

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
        let meta_blob = Arc::new(meta_blob);
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
            ranges.update(&range, BlockRange::DataBlob(Arc::new(data_blob)));
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

    /// Export a RAFS filesystem as a raw block disk image.
    pub fn export(
        blob_entry: BlobCacheEntry,
        output: Option<String>,
        localfs_dir: Option<String>,
        threads: u32,
        verity: bool,
    ) -> Result<()> {
        let cache_mgr = Arc::new(BlobCacheMgr::new());
        cache_mgr.add_blob_entry(&blob_entry).map_err(|e| {
            eother!(format!(
                "block_device: failed to add blob into CacheMgr, {}",
                e
            ))
        })?;
        let blob_id = generate_blob_key(&blob_entry.domain_id, &blob_entry.blob_id);
        let block_device = BlockDevice::new(blob_id.clone(), cache_mgr.clone()).map_err(|e| {
            eother!(format!(
                "block_device: failed to create block device object, {}",
                e
            ))
        })?;
        let block_device = Arc::new(block_device);
        let blocks = block_device.blocks();

        let path = match output {
            Some(v) => PathBuf::from(v),
            None => {
                let path = match cache_mgr.get_config(&blob_id) {
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
                let dir = localfs_dir
                    .ok_or_else(|| einval!("block_device: parameter `localfs_dir` is missing"))?;
                let path = PathBuf::from(dir);
                path.join(name.to_string() + ".disk")
            }
        };

        let output_file = OpenOptions::new()
            .create_new(true)
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
        let output_file = Arc::new(tokio_uring::fs::File::from_std(output_file));

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
                let mgr = cache_mgr.clone();
                let id = blob_id.clone();
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
                    let file = Arc::new(tokio_uring::fs::File::from_std(output_file));
                    let block_device = BlockDevice::new(id, mgr).map_err(|e| {
                        eother!(format!(
                            "block_device: failed to create block device object, {}",
                            e
                        ))
                    })?;
                    let device = Arc::new(block_device);

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
                .map(|v| format!("{:02x}", v))
                .collect();
            println!(
                "dm-verity options: --no-superblock --format=1 -s \"\" --hash=sha256 --data-block-size={} --hash-block-size=4096 --data-blocks {} --hash-offset {} {}",
                block_device.block_size(), blocks, verity_offset, root_digest
            );
        }

        Ok(())
    }

    async fn do_export(
        block_device: Arc<BlockDevice>,
        output_file: Arc<tokio_uring::fs::File>,
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
    use std::fs;
    use std::path::PathBuf;
    use vmm_sys_util::tempdir::TempDir;

    #[test]
    fn test_block_device() {
        let tmpdir = TempDir::new().unwrap();
        let root_dir = &std::env::var("CARGO_MANIFEST_DIR").expect("$CARGO_MANIFEST_DIR");
        let mut source_path = PathBuf::from(root_dir);
        source_path.push("../tests/texture/blobs/be7d77eeb719f70884758d1aa800ed0fb09d701aaec469964e9d54325f0d5fef");
        let mut dest_path = tmpdir.as_path().to_path_buf();
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
        let content = config
            .replace("/tmp/nydus", tmpdir.as_path().to_str().unwrap())
            .replace("RAFS_V5", &source_path.display().to_string());
        let mut entry: BlobCacheEntry = serde_json::from_str(&content).unwrap();
        assert!(entry.prepare_configuration_info());

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
        let device = BlockDevice::new(blob_id, mgr).unwrap();
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
}

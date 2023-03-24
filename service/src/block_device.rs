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

use std::cmp::min;
use std::io::Result;
use std::sync::Arc;

use dbs_allocator::{Constraint, IntervalTree, NodeState, Range};
use nydus_rafs::metadata::layout::v6::{
    EROFS_BLOCK_BITS_12, EROFS_BLOCK_BITS_9, EROFS_BLOCK_SIZE_4096, EROFS_BLOCK_SIZE_512,
};
use tokio_uring::buf::IoBufMut;

use crate::blob_cache::{BlobCacheMgr, BlobConfig, DataBlob, MetaBlob};

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
        ranges.update(&range, BlockRange::MetaBlob(meta_blob.clone()));

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
        let device = BlockDevice::new(blob_id.clone(), mgr).unwrap();
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

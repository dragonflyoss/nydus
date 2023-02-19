// Copyright (C) 2023 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0)

//! Represent a RAFSv6 image as a block device or a group of block devices.

use std::cmp::min;
use std::io::Result;
use std::sync::Arc;

use dbs_allocator::{Constraint, IntervalTree, NodeState, Range};
use nydus_rafs::metadata::layout::v6::EROFS_BLOCK_BITS;

use crate::blob_cache::{
    BlobCacheConfigDataBlob, BlobCacheConfigMetaBlob, BlobCacheMgr, BlobCacheObjectConfig,
};

enum BlockRange {
    Hole,
    MetaBlob(Arc<BlobCacheConfigMetaBlob>),
    DataBlob(Arc<BlobCacheConfigDataBlob>),
}

pub struct BlockDevice {
    blob_id: String,
    //blob_cache_mgr: Arc<BlobCacheMgr>,
    //meta_blob: Arc<BlobCacheConfigMetaBlob>,
    //data_blobs: Vec<Arc<BlobCacheConfigDataBlob>>,
    ranges: IntervalTree<BlockRange>,
}

impl BlockDevice {
    pub fn new(blob_id: String, blob_cache_mgr: Arc<BlobCacheMgr>) -> Result<Self> {
        let mut ranges = IntervalTree::new();
        //ranges.insert(Range::new(0, u32::MAX), None);

        /*
        let meta_blob = match blob_cache_mgr.get_config(&blob_id) {
            None => return Err(enoent!("block_device: can not find blob {} in blob cache manager", blob_id)),
            Some(BlobCacheObjectConfig::DataBlob(_v)) => return Err(einval!("block_device: blob {} is not a metadata blob", blob_id)),
            Some(BlobCacheObjectConfig::MetaBlob(v)) => v,
        };
        let constraint = Constraint::new(meta_blob.blocks()).min(0).max(meta_blob.blocks());
            let range = ranges.allocate(&constraint)?;
            ranges.update(&range, BlockRange::MetaBlob(meta_blob.clone()));

            let data_blobs = meta_blob.get_blobs();
            for blob in data_blobs.iter() {
                let blob_info = blob.blob_info();
                let blob_id = blob_info.blob_id();
                let extra_info = meta_blob.get_blob_extra_info(&blob_id).ok_or_else(||
                    enoent!("block_device: can not get extra information for blob {}", blob_id)
                )?;
                if extra_info.mapped_blkaddr == 0 {
                    return Err(einval!("block_device: mapped block address for blob {} is zero", blob_id));
                }
                let constraint = Constraint::new(blob.blocks()).min(extra_info.mapped_blkaddr).max(extra_info.mapped_blkaddr + blob.blocks());
                let range = ranges.allocate(&constraint)?;
                ranges.update(&range, BlockRange::DataBlob(blob.clone()));
            }
            */

        Ok(BlockDevice { blob_id, ranges })
    }

    /// Read block range [start, start + blocks) from the block device.
    pub async fn read(&self, mut start: u32, mut blocks: u32, buf: &mut [u8]) -> Result<()> {
        if start.checked_add(blocks).is_none()
            || (blocks as u64) << EROFS_BLOCK_BITS > buf.len() as u64
        {
            return Err(einval!("block_device: invalid parameters to read()"));
        }

        let mut pos = 0;
        while blocks > 0 {
            let (range, node) = match self.ranges.get_superset(&Range::new_point(start)) {
                Some(v) => v,
                None => {
                    return Err(eio!(format!(
                        "block_device: can not locate block 0x{:x} for meta blob {}",
                        start, self.blob_id
                    )))
                }
            };

            let count = min(range.len() as u32, blocks);
            let sz = (count as usize) << EROFS_BLOCK_BITS as usize;
            if let NodeState::Valued(r) = node {
                match r {
                    BlockRange::Hole => buf[pos..pos + sz].fill(0),
                    BlockRange::MetaBlob(_m) => unimplemented!(),
                    BlockRange::DataBlob(_d) => unimplemented!(),
                }
            } else {
                return Err(eio!(format!(
                    "block_device: block range 0x{:x}/0x{:x} of meta blob {} is unhandled",
                    start, blocks, self.blob_id,
                )));
            }

            start += count;
            blocks -= count;
            pos += sz;
        }

        Ok(())
    }
}

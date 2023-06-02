// Copyright 2020 Ant Group. All rights reserved.
// Copyright (C) 2020 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use nydus_storage::device::BlobChunkFlags;
use nydus_storage::RAFS_BATCH_SIZE_TO_GAP_SHIFT;

use super::cached_v5::CachedSuperBlockV5;
use super::direct_v5::DirectSuperBlockV5;
use super::layout::v5::{RafsV5PrefetchTable, RafsV5SuperBlock};
use super::*;

impl RafsSuper {
    pub(crate) fn try_load_v5(&mut self, r: &mut RafsIoReader) -> Result<bool> {
        let end = r.seek_to_end(0)?;
        r.seek_to_offset(0)?;
        let mut sb = RafsV5SuperBlock::new();
        r.read_exact(sb.as_mut())?;
        if !sb.is_rafs_v5() {
            return Ok(false);
        }
        sb.validate(end)?;

        self.meta.magic = sb.magic();
        self.meta.version = sb.version();
        self.meta.sb_size = sb.sb_size();
        self.meta.chunk_size = sb.block_size();
        self.meta.flags = RafsSuperFlags::from_bits(sb.flags())
            .ok_or_else(|| einval!(format!("invalid super flags 0x{:x}", sb.flags())))?;
        info!("RAFS v5 super block features: {}", self.meta.flags);

        self.meta.inodes_count = sb.inodes_count();
        self.meta.inode_table_entries = sb.inode_table_entries();
        self.meta.inode_table_offset = sb.inode_table_offset();
        self.meta.blob_table_offset = sb.blob_table_offset();
        self.meta.blob_table_size = sb.blob_table_size();
        self.meta.extended_blob_table_offset = sb.extended_blob_table_offset();
        self.meta.extended_blob_table_entries = sb.extended_blob_table_entries();
        self.meta.prefetch_table_entries = sb.prefetch_table_entries();
        self.meta.prefetch_table_offset = sb.prefetch_table_offset();

        match self.mode {
            RafsMode::Direct => {
                let mut inodes = DirectSuperBlockV5::new(&self.meta, self.validate_digest);
                inodes.load(r)?;
                self.superblock = Arc::new(inodes);
            }
            RafsMode::Cached => {
                let mut inodes = CachedSuperBlockV5::new(self.meta, self.validate_digest);
                inodes.load(r)?;
                self.superblock = Arc::new(inodes);
            }
        }

        Ok(true)
    }

    pub(crate) fn prefetch_data_v5<F>(
        &self,
        device: &BlobDevice,
        r: &mut RafsIoReader,
        root_ino: Inode,
        fetcher: F,
    ) -> RafsResult<bool>
    where
        F: Fn(&mut BlobIoVec, bool),
    {
        let hint_entries = self.meta.prefetch_table_entries as usize;
        if hint_entries == 0 {
            return Ok(false);
        }

        // Try to prefetch according to the list of files specified by the
        // builder's `--prefetch-policy fs` option.
        let mut prefetch_table = RafsV5PrefetchTable::new();
        prefetch_table
            .load_prefetch_table_from(r, self.meta.prefetch_table_offset, hint_entries)
            .map_err(|e| {
                RafsError::Prefetch(format!(
                    "Failed in loading hint prefetch table at offset {}. {:?}",
                    self.meta.prefetch_table_offset, e
                ))
            })?;

        let mut hardlinks: HashSet<u64> = HashSet::new();
        let mut state = BlobIoMerge::default();
        let mut found_root_inode = false;
        for ino in prefetch_table.inodes {
            // Inode number 0 is invalid, it was added because prefetch table has to be aligned.
            if ino == 0 {
                break;
            }
            if ino as Inode == root_ino {
                found_root_inode = true;
            }
            debug!("hint prefetch inode {}", ino);
            self.prefetch_data(device, ino as u64, &mut state, &mut hardlinks, &fetcher)
                .map_err(|e| RafsError::Prefetch(e.to_string()))?;
        }
        for (_id, mut desc) in state.drain() {
            fetcher(&mut desc, true);
        }

        Ok(found_root_inode)
    }

    pub(crate) fn skip_v5_superblock(&self, r: &mut RafsIoReader) -> Result<()> {
        let _ = RafsV5SuperBlock::read(r)?;

        Ok(())
    }

    fn merge_chunks_io(orig: &mut BlobIoVec, vec: BlobIoVec, max_gap: u64) {
        assert!(!orig.is_empty());
        if !vec.is_empty() {
            let last = orig.blob_io_desc(orig.len() - 1).unwrap().clone();
            let head = vec.blob_io_desc(0).unwrap();
            if last.is_continuous(head, max_gap) {
                // Safe to unwrap since d is not empty.
                orig.append(vec);
            }
        }
    }

    // TODO: Add a UT for me.
    // `window_base` is calculated by caller, which MUST be the chunk that does
    // not overlap user IO's chunk.
    // V5 rafs tries to amplify user IO by expanding more chunks to user IO and
    // expect that those chunks are likely to be continuous with user IO's chunks.
    pub(crate) fn amplify_io(
        &self,
        device: &BlobDevice,
        max_uncomp_size: u32,
        descs: &mut [BlobIoVec],
        inode: &Arc<dyn RafsInode>,
        window_base: u64,
        mut window_size: u64,
    ) -> Result<()> {
        let inode_size = inode.size();
        let last_desc = match descs.last_mut() {
            Some(d) if !d.is_empty() => d,
            _ => return Ok(()),
        };

        // Read left content of current file.
        if window_base < inode_size {
            let size = std::cmp::min(inode_size - window_base, window_size);
            let amplified_io_vec =
                inode.alloc_bio_vecs(device, window_base, size as usize, false)?;
            for vec in amplified_io_vec {
                if last_desc.has_same_blob(&vec) {
                    window_size = if window_size > vec.size() as u64 {
                        window_size - vec.size() as u64
                    } else {
                        0
                    };
                    Self::merge_chunks_io(
                        last_desc,
                        vec,
                        (max_uncomp_size as u64) >> RAFS_BATCH_SIZE_TO_GAP_SHIFT,
                    );
                }
            }
        }

        // Read more small files.
        let mut max_tries = 64;
        let mut next_ino = inode.ino();
        while window_size > 0 && max_tries > 0 {
            next_ino += 1;
            if let Ok(ni) = self.get_inode(next_ino, false) {
                if ni.is_reg() {
                    let next_size = ni.size();
                    let next_size = if next_size == 0 {
                        continue;
                    } else if next_size < window_size {
                        next_size
                    } else if window_size >= self.meta.chunk_size as u64 {
                        window_size / self.meta.chunk_size as u64 * self.meta.chunk_size as u64
                    } else {
                        break;
                    };

                    let amplified_io_vec =
                        ni.alloc_bio_vecs(device, 0, next_size as usize, false)?;
                    for vec in amplified_io_vec {
                        max_tries -= 1;
                        if last_desc.has_same_blob(&vec) {
                            window_size = if window_size > vec.size() as u64 {
                                window_size - vec.size() as u64
                            } else {
                                0
                            };
                            Self::merge_chunks_io(
                                last_desc,
                                vec,
                                (max_uncomp_size as u64) >> RAFS_BATCH_SIZE_TO_GAP_SHIFT,
                            );
                        }
                    }
                }
            } else {
                break;
            }
        }

        Ok(())
    }
}

/// Represents backend storage chunked IO address for V5 since V5 format has to
/// load below chunk address from rafs layer and pass it to storage layer.
pub struct V5IoChunk {
    // block hash
    pub block_id: Arc<RafsDigest>,
    // blob containing the block
    pub blob_index: u32,
    // chunk index in blob
    pub index: u32,
    // position of the block within the file
    // offset of the block within the blob
    pub compressed_offset: u64,
    pub uncompressed_offset: u64,
    // size of the block, compressed
    pub compressed_size: u32,
    pub uncompressed_size: u32,
    pub flags: BlobChunkFlags,
}

impl BlobChunkInfo for V5IoChunk {
    fn chunk_id(&self) -> &RafsDigest {
        &self.block_id
    }

    fn id(&self) -> u32 {
        self.index
    }

    fn is_compressed(&self) -> bool {
        self.flags.contains(BlobChunkFlags::COMPRESSED)
    }

    fn is_encrypted(&self) -> bool {
        false
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    impl_getter!(blob_index, blob_index, u32);
    impl_getter!(compressed_offset, compressed_offset, u64);
    impl_getter!(compressed_size, compressed_size, u32);
    impl_getter!(uncompressed_offset, uncompressed_offset, u64);
    impl_getter!(uncompressed_size, uncompressed_size, u32);
}

#[cfg(test)]
mod tests {
    // TODO: add unit test cases for RafsSuper::{try_load_v5, amplify_io}
}

// Copyright 2020 Ant Group. All rights reserved.
// Copyright (C) 2020 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use super::cached_v5::CachedSuperBlockV5;
use super::direct_v5::DirectSuperBlockV5;
use super::layout::v5::{RafsV5PrefetchTable, RafsV5SuperBlock};
use super::*;

impl RafsSuperMeta {
    /// V5: get compression algorithm to handle chunk data for the filesystem.
    pub fn get_compressor(&self) -> compress::Algorithm {
        if self.is_v5() {
            self.flags.into()
        } else {
            compress::Algorithm::None
        }
    }

    /// V5: get message digest algorithm to validate chunk data for the filesystem.
    pub fn get_digester(&self) -> digest::Algorithm {
        if self.is_v5() {
            self.flags.into()
        } else {
            digest::Algorithm::Blake3
        }
    }
}

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
            .ok_or_else(|| einval!(format!("invalid super flags {:x}", sb.flags())))?;
        info!("rafs superblock features: {}", self.meta.flags);

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

    pub(crate) fn store_v5(&self, w: &mut RafsIoWriter) -> Result<usize> {
        let mut sb = RafsV5SuperBlock::new();

        sb.set_magic(self.meta.magic);
        sb.set_version(self.meta.version);
        sb.set_sb_size(self.meta.sb_size);
        sb.set_block_size(self.meta.chunk_size);
        sb.set_flags(self.meta.flags.bits());

        sb.set_inodes_count(self.meta.inodes_count);
        sb.set_inode_table_entries(self.meta.inode_table_entries);
        sb.set_inode_table_offset(self.meta.inode_table_offset);
        sb.set_blob_table_offset(self.meta.blob_table_offset);
        sb.set_blob_table_size(self.meta.blob_table_size);
        sb.set_extended_blob_table_offset(self.meta.extended_blob_table_offset);
        sb.set_extended_blob_table_entries(self.meta.extended_blob_table_entries);
        sb.set_prefetch_table_offset(self.meta.prefetch_table_offset);
        sb.set_prefetch_table_entries(self.meta.prefetch_table_entries);

        w.write_all(sb.as_ref())?;
        let meta_size = w.seek_to_end()?;
        if meta_size > RAFS_MAX_METADATA_SIZE as u64 {
            return Err(einval!("metadata blob is too big"));
        }
        sb.validate(meta_size)?;
        trace!("written superblock: {}", &sb);

        Ok(meta_size as usize)
    }

    pub(crate) fn prefetch_data_v5<F>(&self, r: &mut RafsIoReader, fetcher: F) -> RafsResult<usize>
    where
        F: Fn(&mut BlobIoVec),
    {
        let hint_entries = self.meta.prefetch_table_entries as usize;
        if hint_entries == 0 {
            return Ok(0);
        }

        let mut prefetch_table = RafsV5PrefetchTable::new();
        let mut hardlinks: HashSet<u64> = HashSet::new();
        let mut head_desc = BlobIoVec::new();

        // Try to prefetch according to the list of files specified by the
        // builder's `--prefetch-policy fs` option.
        prefetch_table
            .load_prefetch_table_from(r, self.meta.prefetch_table_offset, hint_entries)
            .map_err(|e| {
                RafsError::Prefetch(format!(
                    "Failed in loading hint prefetch table at offset {}. {:?}",
                    self.meta.prefetch_table_offset, e
                ))
            })?;

        for ino in prefetch_table.inodes {
            // Inode number 0 is invalid, it was added because prefetch table has to be aligned.
            if ino == 0 {
                break;
            }
            debug!("hint prefetch inode {}", ino);
            self.prefetch_data(ino as u64, &mut head_desc, &mut hardlinks, &fetcher)
                .map_err(|e| RafsError::Prefetch(e.to_string()))?;
        }
        // The left chunks whose size is smaller than 4MB will be fetched here.
        fetcher(&mut head_desc);

        Ok(hint_entries)
    }

    pub(crate) fn skip_v5_superblock(&self, r: &mut RafsIoReader) -> Result<()> {
        let _ = RafsV5SuperBlock::read(r)?;

        Ok(())
    }

    // TODO: Add a UT for me.
    pub(crate) fn carry_more_until(
        &self,
        inode: &dyn RafsInode,
        bound: u64,
        tail_chunk: &dyn BlobChunkInfo,
        expected_size: u64,
    ) -> Result<Option<BlobIoVec>> {
        let mut left = expected_size;
        let inode_size = inode.size();
        let mut ra_desc = BlobIoVec::new();

        let extra_file_needed = if let Some(delta) = inode_size.checked_sub(bound) {
            let sz = std::cmp::min(delta, expected_size);
            let mut d = inode.alloc_bio_vecs(bound, sz as usize, false)?;

            // It is possible that read size is beyond file size, so chunks vector is zero length.
            if !d[0].bi_vec.is_empty() {
                let ck = d[0].bi_vec[0].chunkinfo.clone();
                // Might be smaller than uncompressed size. It is user part.
                let trimming_size = d[0].bi_vec[0].size;
                let trimming = tail_chunk.compress_offset() == ck.compress_offset();
                // Stolen chunk bigger than expected size will involve more backend IO, thus
                // to slow down current user IO.
                if let Some(cks) = Self::steal_chunks(&mut d[0], left as u32) {
                    if trimming {
                        ra_desc.bi_vec.extend_from_slice(&cks.bi_vec[1..]);
                        ra_desc.bi_size += cks.bi_size;
                        ra_desc.bi_size -= trimming_size;
                    } else {
                        ra_desc.bi_vec.append(&mut cks.bi_vec);
                        ra_desc.bi_size += cks.bi_size;
                    }
                }
                if delta >= expected_size {
                    false
                } else {
                    left -= delta;
                    true
                }
            } else {
                true
            }
        } else {
            true
        };

        if extra_file_needed {
            let mut next_ino = inode.ino() + 1;
            loop {
                let next_inode = self.get_inode(next_ino, false);
                if let Ok(ni) = next_inode {
                    if !ni.is_reg() {
                        next_ino = ni.ino() + 1;
                        continue;
                    }
                    let next_size = ni.size();
                    let sz = std::cmp::min(left, next_size);
                    let mut d = ni.alloc_bio_vecs(0, sz as usize, false)?;

                    // Stolen chunk bigger than expected size will involve more backend IO, thus
                    // to slow down current user IO.
                    if let Some(cks) = Self::steal_chunks(&mut d[0], sz as u32) {
                        ra_desc.bi_vec.append(&mut cks.bi_vec);
                        ra_desc.bi_size += cks.bi_size;
                    } else {
                        break;
                    }

                    // Even stolen chunks are truncated, still consume expected size.
                    left -= sz;
                    if left == 0 {
                        break;
                    }
                    next_ino = ni.ino() + 1;
                } else {
                    break;
                }
            }
        }

        if ra_desc.bi_size > 0 {
            assert!(!ra_desc.bi_vec.is_empty());
            Ok(Some(ra_desc))
        } else {
            Ok(None)
        }
    }

    fn steal_chunks(desc: &mut BlobIoVec, expected_size: u32) -> Option<&mut BlobIoVec> {
        enum State {
            All,
            None,
            Partial(usize),
        }

        let mut total = 0;
        let mut final_index = State::All;
        let len = desc.bi_vec.len();

        for (i, b) in desc.bi_vec.iter().enumerate() {
            let compressed_size = b.chunkinfo.compress_size();

            if compressed_size + total <= expected_size {
                total += compressed_size;
                continue;
            } else {
                if i != 0 {
                    final_index = State::Partial(i - 1);
                } else {
                    final_index = State::None;
                }
                break;
            }
        }

        match final_index {
            State::None => None,
            State::All => Some(desc),
            State::Partial(fi) => {
                for i in (fi..len).rev() {
                    desc.bi_size -= desc.bi_vec[i].chunkinfo.uncompress_size() as usize;
                    desc.bi_vec.remove(i as usize);
                }
                Some(desc)
            }
        }
    }
}

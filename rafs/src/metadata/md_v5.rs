// Copyright 2020 Ant Group. All rights reserved.
// Copyright (C) 2020 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use super::cached_v5::CachedSuperBlockV5;
use super::direct_v5::DirectSuperBlockV5;
use super::direct_v6::DirectSuperBlockV6;
use super::layout::v5::{RafsV5PrefetchTable, RafsV5SuperBlock};
use super::layout::v6::{RafsV6SuperBlock, RafsV6SuperBlockExt};
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
    pub(crate) fn try_load_v6(&mut self, r: &mut RafsIoReader) -> Result<bool> {
        let end = r.seek_to_end(0)?;
        r.seek_to_offset(0)?;
        let mut sb = RafsV6SuperBlock::new();
        sb.load(r)?;
        if !sb.is_rafs_v6() {
            return Ok(false);
        }
        sb.validate(end)?;

        self.meta.magic = sb.magic();

        let mut ext_sb = RafsV6SuperBlockExt::new();
        ext_sb.load(r)?;
        ext_sb.validate(end)?;

        // use RAFS_DEFAULT_CHUNK_SIZE for now
        self.meta.chunk_size = ext_sb.chunk_size();
        self.meta.flags = RafsSuperFlags::from_bits(ext_sb.flags())
            .ok_or_else(|| einval!(format!("invalid super flags {:x}", ext_sb.flags())))?;
        info!("rafs superblock features: {}", self.meta.flags);

        self.meta.blob_table_offset = ext_sb.blob_table_offset();
        self.meta.blob_table_size = ext_sb.blob_table_size();

        match self.mode {
            RafsMode::Direct => {
                let mut sb_v6 = DirectSuperBlockV6::new(&self.meta, self.validate_digest);
                sb_v6.load(r)?;
                self.superblock = Arc::new(sb_v6);
            }
            RafsMode::Cached => todo!(),
        }

        Ok(true)
    }

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
    pub(crate) fn amplify_io(
        &self,
        max_size: u32,
        descs: &mut Vec<BlobIoVec>,
        inode: &Arc<dyn RafsInode>,
        window_base: u64,
        mut window_size: u64,
    ) -> Result<()> {
        let inode_size = inode.size();

        // Read left content of current file.
        if window_base < inode_size {
            let size = inode_size - window_base;
            let sz = std::cmp::min(size, window_size);
            let mut d = inode.alloc_bio_vecs(window_base, sz as usize, false)?;
            debug_assert!(!d.is_empty() && !d[0].bi_vec.is_empty());
            descs.append(&mut d);
            window_size -= sz;
            if window_size == 0 {
                return Ok(());
            }
        }

        // Read more small files.
        let mut next_ino = inode.ino();
        while window_size > 0 {
            next_ino += 1;
            if let Ok(ni) = self.get_inode(next_ino, false) {
                if ni.is_reg() {
                    let next_size = ni.size();
                    if next_size > max_size as u64 {
                        break;
                    }

                    let sz = std::cmp::min(window_size, next_size);
                    let mut d = ni.alloc_bio_vecs(0, sz as usize, false)?;
                    debug_assert!(!d.is_empty() && !d[0].bi_vec.is_empty());
                    descs.append(&mut d);
                    window_size -= sz;
                }
            } else {
                break;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    // TODO: add unit test cases for RafsSuper::{try_load_v5, amplify_io}
}

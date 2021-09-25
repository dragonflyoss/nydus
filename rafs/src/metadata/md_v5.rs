// Copyright 2020 Ant Group. All rights reserved.
// Copyright (C) 2020 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use super::cached_v5::CachedSuperBlockV5;
use super::direct_v5::DirectSuperBlockV5;
use super::layout::v5::{RafsV5PrefetchTable, RafsV5SuperBlock, RafsV5SuperFlags};
use super::*;

impl RafsSuperMeta {
    /// V5: Check whether the superblock is for Rafs v4/v5 filesystems.
    pub fn is_v4_v5(&self) -> bool {
        self.version == RAFS_SUPER_VERSION_V4 || self.version == RAFS_SUPER_VERSION_V5
    }

    /// V5: get compression algorithm to handle chunk data for the filesystem.
    pub fn get_compressor(&self) -> compress::Algorithm {
        if self.is_v4_v5() {
            self.flags.into()
        } else {
            compress::Algorithm::None
        }
    }

    /// V5: get message digest algorithm to validate chunk data for the filesystem.
    pub fn get_digester(&self) -> digest::Algorithm {
        if self.is_v4_v5() {
            self.flags.into()
        } else {
            digest::Algorithm::Blake3
        }
    }
}

impl RafsSuper {
    pub(crate) fn load_v4v5(&mut self, r: &mut RafsIoReader, sb: &RafsV5SuperBlock) -> Result<()> {
        sb.validate()?;

        self.meta.magic = sb.magic();
        self.meta.version = sb.version();
        self.meta.sb_size = sb.sb_size();
        self.meta.block_size = sb.block_size();
        self.meta.flags = RafsV5SuperFlags::from_bits(sb.flags())
            .ok_or_else(|| einval!(format!("invalid super flags {:x}", sb.flags())))?;
        self.meta.prefetch_table_offset = sb.prefetch_table_offset();
        self.meta.prefetch_table_entries = sb.prefetch_table_entries();

        info!("rafs superblock features: {}", self.meta.flags);

        match self.meta.version {
            RAFS_SUPER_VERSION_V4 => {
                self.meta.inodes_count = u64::MAX;
            }
            RAFS_SUPER_VERSION_V5 => {
                self.meta.inodes_count = sb.inodes_count();
                self.meta.inode_table_entries = sb.inode_table_entries();
                self.meta.inode_table_offset = sb.inode_table_offset();
                self.meta.blob_table_offset = sb.blob_table_offset();
                self.meta.blob_table_size = sb.blob_table_size();
                self.meta.extended_blob_table_offset = sb.extended_blob_table_offset();
                self.meta.extended_blob_table_entries = sb.extended_blob_table_entries();
            }
            _ => return Err(ebadf!("invalid superblock version number")),
        }

        match sb.version() {
            RAFS_SUPER_VERSION_V4 => {
                // TODO: Support Rafs v4
                unimplemented!();
            }
            RAFS_SUPER_VERSION_V5 => match self.mode {
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
            },
            _ => return Err(einval!("invalid superblock version number")),
        }

        Ok(())
    }

    pub(crate) fn store_v4v5(&self, w: &mut RafsIoWriter) -> Result<usize> {
        let mut sb = RafsV5SuperBlock::new();

        sb.set_magic(self.meta.magic);
        sb.set_version(self.meta.version);
        sb.set_sb_size(self.meta.sb_size);
        sb.set_block_size(self.meta.block_size);
        sb.set_flags(self.meta.flags.bits());

        match self.meta.version {
            RAFS_SUPER_VERSION_V4 => {}
            RAFS_SUPER_VERSION_V5 => {
                sb.set_inodes_count(self.meta.inodes_count);
                sb.set_inode_table_entries(self.meta.inode_table_entries);
                sb.set_inode_table_offset(self.meta.inode_table_offset);
            }
            _ => return Err(einval!("invalid superblock version number")),
        }

        sb.validate()?;
        w.write_all(sb.as_ref())?;

        trace!("written superblock: {}", &sb);

        Ok(std::mem::size_of::<RafsV5SuperBlock>())
    }

    pub(crate) fn prefetch_data_v4v5<F>(&self, r: &mut RafsIoReader, fetcher: F) -> RafsResult<()>
    where
        F: Fn(&mut BlobIoVec),
    {
        let hint_entries = self.meta.prefetch_table_entries as usize;
        if hint_entries == 0 {
            return Err(RafsError::Prefetch(
                "Prefetch table is empty and no file was ever specified".to_string(),
            ));
        }

        let mut prefetch_table = RafsV5PrefetchTable::new();
        let mut hardlinks: HashSet<u64> = HashSet::new();
        let mut head_desc = BlobIoVec {
            bi_size: 0,
            bi_flags: 0,
            bi_vec: Vec::new(),
        };

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
            // Inode number 0 is invalid,
            // it was added because prefetch table has to be aligned.
            if ino == 0 {
                break;
            }
            debug!("hint prefetch inode {}", ino);
            self.prefetch_data(ino as u64, &mut head_desc, &mut hardlinks, &fetcher)
                .map_err(|e| RafsError::Prefetch(e.to_string()))?;
        }
        // The left chunks whose size is smaller than 4MB will be fetched here.
        fetcher(&mut head_desc);

        Ok(())
    }
}

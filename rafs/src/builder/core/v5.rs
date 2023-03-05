// Copyright 2020 Ant Group. All rights reserved.
// Copyright (C) 2021 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::{bail, Context, Result};
use nydus_utils::try_round_up_4k;

use super::node::Node;
use crate::builder::{BuildContext, Tree};
use crate::metadata::inode::InodeWrapper;
use crate::metadata::layout::v5::RafsV5InodeWrapper;
use crate::metadata::{RafsStore, RafsVersion};
use crate::RafsIoWrite;

// Filesystem may have different algorithms to calculate `i_size` for directory entries,
// which may break "repeatable build". To support repeatable build, instead of reuse the value
// provided by the source filesystem, we use our own algorithm to calculate `i_size` for directory
// entries for stable `i_size`.
//
// Rafs v6 already has its own algorithm to calculate `i_size` for directory entries, but we don't
// have directory entries for Rafs v5. So let's generate a pseudo `i_size` for Rafs v5 directory
// inode.
const RAFS_V5_VIRTUAL_ENTRY_SIZE: u64 = 8;

impl Node {
    /// Dump RAFS v5 inode metadata to meta blob.
    pub fn dump_bootstrap_v5(
        &self,
        ctx: &mut BuildContext,
        f_bootstrap: &mut dyn RafsIoWrite,
    ) -> Result<()> {
        debug!("[{}]\t{}", self.overlay, self);

        if let InodeWrapper::V5(raw_inode) = &self.inode {
            // Dump inode info
            let name = self.name();
            let inode = RafsV5InodeWrapper {
                name,
                symlink: self.info.symlink.as_deref(),
                inode: raw_inode,
            };
            inode
                .store(f_bootstrap)
                .context("failed to dump inode to bootstrap")?;

            // Dump inode xattr
            if !self.info.xattrs.is_empty() {
                self.info
                    .xattrs
                    .store_v5(f_bootstrap)
                    .context("failed to dump xattr to bootstrap")?;
                ctx.has_xattr = true;
            }

            // Dump chunk info
            if self.is_reg() && self.inode.child_count() as usize != self.chunks.len() {
                bail!("invalid chunk count {}: {}", self.chunks.len(), self);
            }
            for chunk in &self.chunks {
                chunk
                    .inner
                    .store(f_bootstrap)
                    .context("failed to dump chunk info to bootstrap")?;
                trace!("\t\tchunk: {} compressor {}", chunk, ctx.compressor,);
            }

            Ok(())
        } else {
            bail!("dump_bootstrap_v5() encounters non-v5-inode");
        }
    }

    // Filesystem may have different algorithms to calculate `i_size` for directory entries,
    // which may break "repeatable build". To support repeatable build, instead of reuse the value
    // provided by the source filesystem, we use our own algorithm to calculate `i_size` for
    // directory entries for stable `i_size`.
    //
    // Rafs v6 already has its own algorithm to calculate `i_size` for directory entries, but we
    // don't have directory entries for Rafs v5. So let's generate a pseudo `i_size` for Rafs v5
    // directory inode.
    pub fn v5_set_dir_size(&mut self, fs_version: RafsVersion, children: &[Tree]) {
        if !self.is_dir() || !fs_version.is_v5() {
            return;
        }

        let mut d_size = 0u64;
        for child in children.iter() {
            d_size += child.node.inode.name_size() as u64 + RAFS_V5_VIRTUAL_ENTRY_SIZE;
        }
        if d_size == 0 {
            self.inode.set_size(4096);
        } else {
            // Safe to unwrap() because we have u32 for child count.
            self.inode.set_size(try_round_up_4k(d_size).unwrap());
        }
        self.set_inode_blocks();
    }
}

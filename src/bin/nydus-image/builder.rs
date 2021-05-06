// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Bootstrap and blob file builder for RAFS format

use std::os::unix::ffi::OsStrExt;

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};

use crate::core::blob::{Blob, BlobStorage};
use crate::core::bootstrap::Bootstrap;
use crate::core::context::{BuildContext, SourceType};
use crate::tree::Tree;

use nydus_utils::digest::{self, RafsDigest};

pub struct Builder {}

impl Builder {
    #[allow(clippy::too_many_arguments)]
    pub fn new() -> Result<Self> {
        Ok(Self {})
    }

    fn digest_stargz_node(&mut self, ctx: &mut BuildContext) {
        // Set blob index and inode digest for upper nodes
        for node in &mut ctx.nodes {
            if node.overlay.lower_layer() {
                continue;
            }

            let mut inode_hasher = RafsDigest::hasher(digest::Algorithm::Sha256);

            let blob_index = ctx.blob_table.entries.len() as u32;
            for chunk in node.chunks.iter_mut() {
                (*chunk).blob_index = blob_index;
                inode_hasher.digest_update(chunk.block_id.as_ref());
            }

            let digest = if node.is_symlink() {
                RafsDigest::from_buf(
                    node.symlink.as_ref().unwrap().as_bytes(),
                    digest::Algorithm::Sha256,
                )
            } else {
                inode_hasher.digest_finalize()
            };
            node.inode.i_digest = digest;
        }
    }

    /// Build workflow, return (Vec<blob_id>, blob_size)
    pub fn build(
        &mut self,
        mut ctx: &mut BuildContext,
        bs: Option<BlobStorage>,
    ) -> Result<(Vec<String>, usize)> {
        let mut bootstrap = Bootstrap::new()?;

        let layered = ctx.f_parent_bootstrap.is_some();

        // Build tree from source
        let mut tree = match ctx.source_type {
            SourceType::Directory => {
                // Build node tree of upper layer from a filesystem directory
                Tree::from_filesystem(
                    &ctx.source_path,
                    ctx.explicit_uidgid,
                    layered,
                    &ctx.whiteout_spec,
                )
                .context("failed to build tree from filesystem")?
            }
            SourceType::StargzIndex => {
                // Build node tree of upper layer from a stargz index
                Tree::from_stargz_index(
                    &ctx.source_path,
                    &ctx.blob_id,
                    ctx.explicit_uidgid,
                    &ctx.whiteout_spec,
                )
                .context("failed to build tree from stargz index")?
            }
        };

        // Build bootstrap from source
        if ctx.f_parent_bootstrap.is_some() {
            bootstrap.build(&mut ctx, &mut tree);
            // Applay to parent bootstrap for layered build
            let mut tree = bootstrap.apply(&mut ctx)?;
            timing_tracer!({ bootstrap.build(&mut ctx, &mut tree) }, "build_bootstrap");
        } else {
            bootstrap.build(&mut ctx, &mut tree);
        }

        if let Some(bs) = bs {
            let mut blob = Blob::new(bs)?;
            // Dump blob file for directory source
            let (blob_hash, blob_size, blob_readahead_size) = blob.dump(&mut ctx)?;
            // Dump bootstrap file for directory source
            let (blob_ids, blob_size) =
                bootstrap.dump(&mut ctx, blob_hash, blob_size, blob_readahead_size)?;
            blob.flush(&ctx)?;
            return Ok((blob_ids, blob_size));
        }

        // Calculate stargz node digest
        self.digest_stargz_node(&mut ctx);

        // Dump bootstrap file for stargz source
        bootstrap.dump(&mut ctx, Sha256::new(), 0, 0)
    }
}

// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::os::unix::ffi::OsStrExt;

use anyhow::{Context, Result};
use nydus_utils::digest::{self, DigestHasher, RafsDigest};
use sha2::Digest;

use super::chunk_dict::ChunkDict;
use super::context::{BlobContext, BuildContext, SourceType};
use super::node::Node;

pub struct Blob {}

impl Blob {
    pub fn new() -> Self {
        Self {}
    }

    /// Dump blob file and generate chunks
    pub fn dump<T: ChunkDict>(
        &mut self,
        ctx: &BuildContext,
        blob_ctx: &mut BlobContext,
        blob_index: u32,
        nodes: &mut Vec<Node>,
        chunk_dict: &mut T,
    ) -> Result<()> {
        match ctx.source_type {
            SourceType::Directory => {
                let (inodes, prefetch_entries) = blob_ctx
                    .blob_layout
                    .layout_blob_simple(&ctx.prefetch, nodes)?;
                for (idx, inode) in inodes.iter().enumerate() {
                    let node = &mut nodes[*inode];
                    let size = node
                        .dump_blob(ctx, blob_ctx, blob_index, chunk_dict)
                        .context("failed to dump blob chunks")?;
                    if idx < prefetch_entries {
                        debug!("[{}]\treadahead {}", node.overlay, node);
                        blob_ctx.blob_readahead_size += size;
                    } else {
                        debug!("[{}]\t{}", node.overlay, node);
                    }
                }
            }
            SourceType::StargzIndex => {
                for node in nodes {
                    if node.overlay.is_lower_layer() {
                        continue;
                    } else if node.is_symlink() {
                        node.inode.set_digest(RafsDigest::from_buf(
                            node.symlink.as_ref().unwrap().as_bytes(),
                            digest::Algorithm::Sha256,
                        ));
                    } else {
                        // Set blob index and inode digest for upper nodes
                        let mut inode_hasher = RafsDigest::hasher(digest::Algorithm::Sha256);
                        for chunk in node.chunks.iter_mut() {
                            chunk.set_blob_index(blob_index);
                            inode_hasher.digest_update(chunk.id().as_ref());
                        }
                        node.inode.set_digest(inode_hasher.digest_finalize());
                    }
                }
            }
        }

        // Name blob id by blob hash if not specified.
        if blob_ctx.blob_id.is_empty() {
            blob_ctx.blob_id = format!("{:x}", blob_ctx.blob_hash.clone().finalize());
        }

        Ok(())
    }

    pub fn flush(self, blob_ctx: &mut BlobContext) -> Result<()> {
        let blob_id = if blob_ctx.compressed_blob_size > 0 {
            Some(blob_ctx.blob_id.as_str())
        } else {
            None
        };
        if let Some(writer) = blob_ctx.writer.take() {
            writer.release(blob_id)?;
        }

        Ok(())
    }
}

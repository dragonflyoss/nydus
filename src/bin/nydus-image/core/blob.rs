// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::os::unix::ffi::OsStrExt;

use anyhow::{Context, Result};
use nydus_utils::digest::{self, DigestHasher, RafsDigest};
use sha2::Digest;
use storage::compress;
use storage::meta::{BlobChunkInfoOndisk, BlobMetaHeaderOndisk};

use super::chunk_dict::ChunkDict;
use super::context::{BlobContext, BuildContext, SourceType};
use super::node::Node;

pub struct Blob {}

impl Blob {
    pub fn new() -> Self {
        Self {}
    }

    /// Dump blob file and generate chunks
    pub fn dump<'a, T: ChunkDict>(
        &mut self,
        ctx: &BuildContext,
        blob_ctx: &'a mut BlobContext,
        blob_index: u32,
        nodes: &mut Vec<Node>,
        chunk_dict: &mut T,
    ) -> Result<bool> {
        match ctx.source_type {
            SourceType::Directory | SourceType::Diff => {
                let (inodes, prefetch_entries) = blob_ctx
                    .blob_layout
                    .layout_blob_simple(&ctx.prefetch, nodes)?;
                for (idx, inode) in inodes.iter().enumerate() {
                    let node = &mut nodes[*inode];
                    let size = node
                        .dump_blob(ctx, blob_ctx, blob_index, chunk_dict)
                        .context("failed to dump blob chunks")?;
                    if idx < prefetch_entries {
                        blob_ctx.blob_readahead_size += size;
                    }
                }
                self.dump_meta_data(blob_ctx)?;
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
                            chunk.inner.set_blob_index(blob_index);
                            inode_hasher.digest_update(chunk.inner.id().as_ref());
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

        blob_ctx.set_blob_readahead_size(ctx);
        blob_ctx.flush()?;

        let blob_exists = blob_ctx.compressed_blob_size > 0;

        Ok(blob_exists)
    }

    pub(crate) fn dump_meta_data(&mut self, blob_ctx: &mut BlobContext) -> Result<()> {
        if !blob_ctx.blob_meta_info_enabled {
            return Ok(());
        }

        if let Some(writer) = &mut blob_ctx.writer {
            let pos = writer.get_pos()?;
            let data = unsafe {
                std::slice::from_raw_parts(
                    blob_ctx.blob_meta_info.as_ptr() as *const u8,
                    blob_ctx.blob_meta_info.len() * std::mem::size_of::<BlobChunkInfoOndisk>(),
                )
            };
            let (buf, compressed) = compress::compress(data, compress::Algorithm::Lz4Block)
                .with_context(|| "failed to compress blob chunk info array".to_string())?;
            let mut header = BlobMetaHeaderOndisk::default();

            if compressed {
                header.set_ci_compressor(compress::Algorithm::Lz4Block);
            } else {
                header.set_ci_compressor(compress::Algorithm::None);
            }
            header.set_ci_entries(blob_ctx.blob_meta_info.len() as u32);
            header.set_ci_compressed_offset(pos);
            header.set_ci_compressed_size(buf.len() as u64);
            header.set_ci_uncompressed_size(data.len() as u64);
            header.set_4k_aligned(true);

            blob_ctx.blob_meta_header = header;

            writer.write_all(&buf)?;
            writer.write_all(header.as_bytes())?;
            blob_ctx.blob_hash.update(&buf);
            blob_ctx.blob_hash.update(header.as_bytes());
        }

        Ok(())
    }
}

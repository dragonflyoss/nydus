// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::io::Write;

use anyhow::{Context, Result};
use nydus_rafs::metadata::RAFS_MAX_CHUNK_SIZE;
use nydus_storage::meta::{BlobChunkInfoOndisk, BlobMetaHeaderOndisk};
use nydus_utils::{compress, try_round_up_4k};
use sha2::Digest;

use super::context::{ArtifactWriter, BlobContext, BlobManager, BuildContext, ConversionType};
use super::layout::BlobLayout;
use super::node::Node;

pub struct Blob {}

impl Blob {
    pub fn new() -> Self {
        Self {}
    }

    /// Dump blob file and generate chunks
    pub fn dump(
        &mut self,
        ctx: &BuildContext,
        nodes: &mut [Node],
        blob_mgr: &mut BlobManager,
        blob_writer: &mut Option<ArtifactWriter>,
    ) -> Result<()> {
        if ctx.source_type == ConversionType::DirectoryToRafs {
            let (inodes, prefetch_entries) = BlobLayout::layout_blob_simple(&ctx.prefetch, nodes)?;
            let mut chunk_data_buf = vec![0u8; RAFS_MAX_CHUNK_SIZE as usize];
            for (idx, inode) in inodes.iter().enumerate() {
                let node = &mut nodes[*inode];
                let size = node
                    .dump_node_data(ctx, blob_mgr, blob_writer, &mut chunk_data_buf)
                    .context("failed to dump blob chunks")?;
                if idx < prefetch_entries {
                    if let Some((_, blob_ctx)) = blob_mgr.get_current_blob() {
                        blob_ctx.blob_prefetch_size += size;
                    }
                }
            }
            if let Some((_, blob_ctx)) = blob_mgr.get_current_blob() {
                Self::dump_meta_data(ctx, blob_ctx, blob_writer)?;
            }
        }

        // Name blob id by blob hash if not specified.
        if let Some((_, blob_ctx)) = blob_mgr.get_current_blob() {
            if blob_ctx.blob_id.is_empty() {
                blob_ctx.blob_id = format!("{:x}", blob_ctx.blob_hash.clone().finalize());
            }
            blob_ctx.set_blob_prefetch_size(ctx);
        }

        Ok(())
    }

    fn dump_meta_data_raw(
        pos: u64,
        blob_meta_info: &[BlobChunkInfoOndisk],
        compressor: compress::Algorithm,
    ) -> Result<(std::borrow::Cow<[u8]>, BlobMetaHeaderOndisk)> {
        let data = unsafe {
            std::slice::from_raw_parts(
                blob_meta_info.as_ptr() as *const u8,
                blob_meta_info.len() * std::mem::size_of::<BlobChunkInfoOndisk>(),
            )
        };
        let (buf, compressed) = compress::compress(data, compressor)
            .with_context(|| "failed to compress blob chunk info array".to_string())?;

        let mut header = BlobMetaHeaderOndisk::default();
        if compressed {
            header.set_ci_compressor(compressor);
        } else {
            header.set_ci_compressor(compress::Algorithm::None);
        }
        header.set_ci_entries(blob_meta_info.len() as u32);
        header.set_ci_compressed_offset(pos);
        header.set_ci_compressed_size(buf.len() as u64);
        header.set_ci_uncompressed_size(data.len() as u64);
        header.set_4k_aligned(true);

        Ok((buf, header))
    }

    pub(crate) fn dump_meta_data(
        ctx: &BuildContext,
        blob_ctx: &mut BlobContext,
        blob_writer: &mut Option<ArtifactWriter>,
    ) -> Result<()> {
        // Dump is only required if there is chunk in the blob or blob meta info enabled
        if !blob_ctx.blob_meta_info_enabled || blob_ctx.uncompressed_blob_size == 0 {
            return Ok(());
        }

        // Write blob metadata to the data blob itself.
        if let Some(writer) = blob_writer {
            let pos = writer.pos()?;
            let (data, header) = Self::dump_meta_data_raw(
                pos,
                &blob_ctx.blob_meta_info,
                compress::Algorithm::Lz4Block,
            )?;

            writer.write_all(&data)?;
            writer.write_all(header.as_bytes())?;

            blob_ctx.blob_meta_header = header;
            blob_ctx.blob_hash.update(&data);
            blob_ctx.blob_hash.update(header.as_bytes());
        } else if let Some(stor) = ctx.blob_meta_storage.clone() {
            // Dump blob meta to an independent local file, use uncompressed format.
            let mut writer = ArtifactWriter::new(stor, false)?;
            let (data, header) =
                Self::dump_meta_data_raw(0, &blob_ctx.blob_meta_info, compress::Algorithm::None)?;

            writer.write_all(&data)?;
            // For uncompressed blob meta, keeping 4k alignment to make compatible
            // with nydusd runtime, allowing runtime to use the blob meta in blob
            // cache directory directly.
            let aligned_len: usize = try_round_up_4k(data.len() as u64).unwrap();
            writer.write_all(&vec![0u8; aligned_len - data.len()])?;
            writer.write_all(header.as_bytes())?;

            blob_ctx.blob_meta_header = header;
        }

        Ok(())
    }
}

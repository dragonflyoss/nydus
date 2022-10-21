// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::io::Write;

use anyhow::{Context, Result};
use nydus_rafs::metadata::RAFS_MAX_CHUNK_SIZE;
use nydus_storage::meta::{BlobMetaChunkArray, BLOB_META_FEATURE_SEPARATE, BLOB_META_FEATURE_ZRAN};
use nydus_utils::{compress, try_round_up_4k};
use sha2::Digest;

use super::context::{
    ArtifactStorage, ArtifactWriter, BlobContext, BlobManager, BuildContext, ConversionType,
};
use super::layout::BlobLayout;
use super::node::Node;

pub struct Blob {}

impl Blob {
    /// Dump blob file and generate chunks
    pub fn dump(
        ctx: &BuildContext,
        nodes: &mut [Node],
        blob_mgr: &mut BlobManager,
        blob_writer: &mut Option<ArtifactWriter>,
    ) -> Result<()> {
        match ctx.conversion_type {
            ConversionType::DirectoryToRafs => {
                let (inodes, prefetch_entries) =
                    BlobLayout::layout_blob_simple(&ctx.prefetch, nodes)?;
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
            ConversionType::TarToRafs
            | ConversionType::TargzToRafs
            | ConversionType::EStargzToRafs => {
                if let Some((_, blob_ctx)) = blob_mgr.get_current_blob() {
                    Self::dump_meta_data(ctx, blob_ctx, blob_writer)?;
                }
            }
            ConversionType::TargzToRef | ConversionType::EStargzToRef => {
                assert!(blob_writer.is_none());
                if let Some((_, blob_ctx)) = blob_mgr.get_current_blob() {
                    if let Some(zran) = &ctx.blob_zran_generator {
                        let reader = zran.lock().unwrap().reader();
                        blob_ctx.blob_hash = reader.get_data_digest();
                        blob_ctx.compressed_blob_size = reader.get_data_size();
                    }
                    if blob_ctx.blob_id.is_empty() {
                        blob_ctx.blob_id = format!("{:x}", blob_ctx.blob_hash.clone().finalize());
                    }
                    Self::dump_meta_data(ctx, blob_ctx, blob_writer)?;
                }
            }
            ConversionType::TarToStargz
            | ConversionType::DirectoryToTargz
            | ConversionType::DirectoryToStargz
            | ConversionType::EStargzIndexToRef
            | ConversionType::TargzToStargz => {
                unimplemented!()
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
        ctx: &BuildContext,
        blob_ctx: &mut BlobContext,
        compressor: compress::Algorithm,
        writer: &mut ArtifactWriter,
    ) -> Result<()> {
        let mut pos = writer.pos()?;
        let blob_meta_info = &blob_ctx.blob_meta_info;
        let data = blob_meta_info.as_byte_slice();
        let (buf, compressed) = compress::compress(data, compressor)
            .with_context(|| "failed to compress blob chunk info array".to_string())?;

        //let mut header = BlobMetaHeaderOndisk::default();
        let header = &mut blob_ctx.blob_meta_header;
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
        match blob_meta_info {
            BlobMetaChunkArray::V1(_) => header.set_chunk_info_v2(false),
            BlobMetaChunkArray::V2(_) => header.set_chunk_info_v2(true),
        }

        writer.write_all(&buf)?;
        pos += buf.len() as u64;

        if ctx.blob_meta_features & BLOB_META_FEATURE_ZRAN != 0 {
            let zran = ctx.blob_zran_generator.as_ref().unwrap();
            let (count, zran_count) = zran.lock().unwrap().store(writer)?;
            pos += count as u64;
            header.set_ci_compressed_size(buf.len() as u64 + count as u64);
            header.set_ci_uncompressed_size(data.len() as u64 + count as u64);
            header.set_ci_zran_count(zran_count);
            header.set_ci_zran_offset(buf.len() as u64);
            header.set_ci_zran_size(count as u64);
            header.set_ci_zran(true);
        } else {
            header.set_ci_zran(false);
        }
        if ctx.blob_meta_features & BLOB_META_FEATURE_SEPARATE != 0 {
            // For uncompressed blob meta, keeping 4k alignment to make compatible
            // with nydusd runtime, allowing runtime to use the blob meta in blob
            // cache directory directly.
            let aligned_len: usize = try_round_up_4k(pos).unwrap();
            writer.write_all(&vec![0u8; aligned_len - pos as usize])?;
            header.set_ci_separate(true);
        } else {
            header.set_ci_separate(false);
            blob_ctx.blob_hash.update(&buf);
            blob_ctx.blob_hash.update(header.as_bytes());
        }

        writer.write_all(header.as_bytes())?;
        //blob_ctx.blob_meta_header = header;

        Ok(())
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
            Self::dump_meta_data_raw(ctx, blob_ctx, ctx.compressor, writer)?;
        } else if let Some(stor) = ctx.blob_meta_storage.clone() {
            // Dump blob meta to an independent local file, use uncompressed format.
            let mut writer = ArtifactWriter::new(stor.clone(), false)?;
            Self::dump_meta_data_raw(ctx, blob_ctx, compress::Algorithm::None, &mut writer)?;
            if let ArtifactStorage::FileDir(_d) = stor {
                let filename = format!("{}.blob.meta", blob_ctx.blob_id);
                writer.finalize(Some(filename))?;
            }
        }

        Ok(())
    }
}

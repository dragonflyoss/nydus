// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::borrow::Cow;

use anyhow::{Context, Result};
use nydus_rafs::metadata::layout::toc;
use nydus_rafs::metadata::RAFS_MAX_CHUNK_SIZE;
use nydus_storage::device::BlobFeatures;
use nydus_storage::meta::BlobMetaChunkArray;
use nydus_utils::digest::{DigestHasher, RafsDigest};
use nydus_utils::{compress, digest, try_round_up_4k};
use sha2::digest::Digest;

use super::context::{ArtifactWriter, BlobContext, BlobManager, BuildContext, ConversionType};
use super::feature::Feature;
use super::layout::BlobLayout;
use super::node::Node;

pub struct Blob {}

impl Blob {
    /// Dump blob file and generate chunks
    pub fn dump(
        ctx: &BuildContext,
        nodes: &mut [Node],
        blob_mgr: &mut BlobManager,
        blob_writer: &mut ArtifactWriter,
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
                Self::finalize_blob_data(ctx, blob_mgr, blob_writer)?;
            }
            ConversionType::TarToRafs
            | ConversionType::TargzToRafs
            | ConversionType::EStargzToRafs => {
                Self::finalize_blob_data(ctx, blob_mgr, blob_writer)?;
            }
            ConversionType::TargzToRef | ConversionType::EStargzToRef => {
                if let Some((_, blob_ctx)) = blob_mgr.get_current_blob() {
                    if let Some(zran) = &ctx.blob_zran_generator {
                        let reader = zran.lock().unwrap().reader();
                        blob_ctx.blob_hash = reader.get_data_digest();
                        blob_ctx.compressed_blob_size = reader.get_data_size();
                    }
                    if blob_ctx.blob_id.is_empty() {
                        blob_ctx.blob_id = format!("{:x}", blob_ctx.blob_hash.clone().finalize());
                    }
                }
                Self::finalize_blob_data(ctx, blob_mgr, blob_writer)?;
            }
            ConversionType::TarToStargz
            | ConversionType::DirectoryToTargz
            | ConversionType::DirectoryToStargz
            | ConversionType::EStargzIndexToRef
            | ConversionType::TargzToStargz => {
                unimplemented!()
            }
        }

        if let Some((_, blob_ctx)) = blob_mgr.get_current_blob() {
            blob_ctx.set_blob_prefetch_size(ctx);
        }

        Ok(())
    }

    fn finalize_blob_data(
        ctx: &BuildContext,
        blob_mgr: &mut BlobManager,
        blob_writer: &mut ArtifactWriter,
    ) -> Result<()> {
        if ctx.blob_inline_meta || ctx.features.is_enabled(Feature::BlobToc) {
            if let Some((_, blob_ctx)) = blob_mgr.get_current_blob() {
                blob_ctx.write_tar_header(
                    blob_writer,
                    toc::ENTRY_BLOB_RAW,
                    blob_ctx.compressed_blob_size,
                )?;
                if ctx.features.is_enabled(Feature::BlobToc) {
                    let blob_digest = RafsDigest {
                        data: blob_ctx.blob_hash.clone().finalize().into(),
                    };
                    blob_ctx.entry_list.add(
                        toc::ENTRY_BLOB_RAW,
                        compress::Algorithm::None,
                        blob_digest,
                        blob_ctx.compressed_offset,
                        blob_ctx.compressed_blob_size,
                        blob_ctx.uncompressed_blob_size,
                    )?;
                }
            }
        }

        Ok(())
    }

    pub(crate) fn dump_meta_data(
        ctx: &BuildContext,
        blob_ctx: &mut BlobContext,
        blob_writer: &mut ArtifactWriter,
    ) -> Result<()> {
        // Dump blob meta for v6 when it has chunks or bootstrap is to be inlined.
        if !blob_ctx.blob_meta_info_enabled || blob_ctx.uncompressed_blob_size == 0 {
            return Ok(());
        }

        // Prepare blob meta information data.
        let blob_meta_info = &blob_ctx.blob_meta_info;
        let mut ci_data = blob_meta_info.as_byte_slice();
        let mut zran_buf = Vec::new();
        let mut header = blob_ctx.blob_meta_header;
        if ctx.blob_features.contains(BlobFeatures::ZRAN) {
            let zran = ctx.blob_zran_generator.as_ref().unwrap();
            let (zran_data, zran_count) = zran.lock().unwrap().to_vec()?;
            header.set_ci_zran_count(zran_count);
            header.set_ci_zran_offset(ci_data.len() as u64);
            header.set_ci_zran_size(zran_data.len() as u64);
            header.set_ci_zran(true);
            zran_buf = [ci_data, &zran_data].concat();
            ci_data = &zran_buf;
        } else {
            header.set_ci_zran(false);
        };

        let mut compressor = if ctx.conversion_type.is_to_ref() {
            compress::Algorithm::Zstd
        } else {
            ctx.compressor
        };
        let (compressed_data, compressed) = compress::compress(ci_data, compressor)
            .with_context(|| "failed to compress blob chunk info array".to_string())?;
        if !compressed {
            compressor = compress::Algorithm::None;
        }
        let compressed_offset = blob_writer.pos()?;
        let compressed_size = compressed_data.len() as u64;
        let uncompressed_size = ci_data.len() as u64;

        header.set_ci_compressor(compressor);
        header.set_ci_entries(blob_meta_info.len() as u32);
        header.set_ci_compressed_offset(compressed_offset);
        header.set_ci_compressed_size(compressed_size as u64);
        header.set_ci_uncompressed_size(uncompressed_size as u64);
        header.set_4k_aligned(true);
        match blob_meta_info {
            BlobMetaChunkArray::V1(_) => header.set_chunk_info_v2(false),
            BlobMetaChunkArray::V2(_) => header.set_chunk_info_v2(true),
        }

        let header_size = header.as_bytes().len();
        blob_ctx.blob_meta_header = header;

        // Write blob meta data and header
        match compressed_data {
            Cow::Owned(v) => blob_ctx.write_data(blob_writer, &v)?,
            Cow::Borrowed(v) => {
                let buf = v.to_vec();
                blob_ctx.write_data(blob_writer, &buf)?;
            }
        }
        blob_ctx.write_data(blob_writer, header.as_bytes())?;

        // Write tar header for `blob.meta`.
        if ctx.blob_inline_meta || ctx.features.is_enabled(Feature::BlobToc) {
            blob_ctx.write_tar_header(
                blob_writer,
                toc::ENTRY_BLOB_META,
                compressed_size + header_size as u64,
            )?;
        }

        // Generate ToC entry for `blob.meta`.
        if ctx.features.is_enabled(Feature::BlobToc) {
            let mut hasher = RafsDigest::hasher(digest::Algorithm::Sha256);
            let ci_data = if ctx.blob_features.contains(BlobFeatures::ZRAN) {
                zran_buf.as_slice()
            } else {
                blob_ctx.blob_meta_info.as_byte_slice()
            };
            hasher.digest_update(ci_data);
            let aligned_uncompressed_size: u64 = try_round_up_4k(uncompressed_size).unwrap();
            let padding = &vec![0u8; (aligned_uncompressed_size - uncompressed_size) as usize];
            if !padding.is_empty() {
                hasher.digest_update(padding);
            }
            hasher.digest_update(header.as_bytes());
            blob_ctx.entry_list.add(
                toc::ENTRY_BLOB_META,
                compressor,
                // Ths digest is sha256(uncompressed data + 4k aligned padding + header data).
                hasher.digest_finalize(),
                compressed_offset,
                compressed_size + header_size as u64,
                aligned_uncompressed_size + header_size as u64,
            )?;
        }

        Ok(())
    }
}

// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::io::Write;

use anyhow::{Context, Result};
use nydus_utils::digest::RafsDigest;
use sha2::digest::Digest;

use nydus_rafs::metadata::layout::toc;
use nydus_rafs::metadata::RAFS_MAX_CHUNK_SIZE;
use nydus_storage::meta::{BlobMetaChunkArray, BLOB_META_FEATURE_ZRAN};
use nydus_utils::{compress, try_round_up_4k};

use super::context::{ArtifactWriter, BlobContext, BlobManager, BuildContext, ConversionType};
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
                    if let Some(blob_writer) = blob_writer {
                        blob_writer
                            .write_tar_header(toc::ENTRY_BLOB_RAW, blob_ctx.compressed_blob_size)?;
                        let blob_digest = RafsDigest {
                            data: blob_ctx.blob_hash.clone().finalize().into(),
                        };
                        blob_ctx.entry_list.add(
                            toc::ENTRY_BLOB_RAW,
                            blob_digest,
                            blob_ctx.compressed_offset,
                            blob_ctx.compressed_blob_size,
                        )?;
                        debug!(
                            "dump rafs blob {} {} {}",
                            toc::ENTRY_BLOB_RAW,
                            blob_ctx.compressed_offset,
                            blob_ctx.compressed_blob_size
                        );
                    }
                }
            }
            ConversionType::TarToRafs
            | ConversionType::TargzToRafs
            | ConversionType::EStargzToRafs => {}
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
            if blob_ctx.blob_id.is_empty() {
                // Name blob id by blob hash if not specified.
                blob_ctx.blob_id = format!("{:x}", blob_ctx.blob_hash.clone().finalize());
            }
            blob_ctx.set_blob_prefetch_size(ctx);
        }

        Ok(())
    }

    pub(crate) fn dump_meta_data(
        ctx: &BuildContext,
        blob_ctx: &mut BlobContext,
        blob_meta_writer: Option<&mut ArtifactWriter>,
    ) -> Result<()> {
        let blob_meta_writer = if let Some(blob_meta_writer) = blob_meta_writer {
            blob_meta_writer
        } else {
            return Ok(());
        };

        // Dump is only required if there is chunk in the blob or blob meta info enabled
        if !blob_ctx.blob_meta_info_enabled || blob_ctx.uncompressed_blob_size == 0 {
            return Ok(());
        }

        let blob_meta_data_offset = blob_meta_writer.pos()?;

        // Write blob metadata to the data blob itself.
        let compressor = if ctx.blob_meta_storage.is_some() {
            if ctx.conversion_type.to_ref() {
                // Forcibly use zstd for better compression ratio.
                compress::Algorithm::Zstd
            } else {
                // Dump blob meta to an independent local file, use uncompressed format.
                compress::Algorithm::None
            }
        } else {
            ctx.compressor
        };

        let mut offset = 0;
        let mut header = blob_ctx.blob_meta_header.clone();
        let blob_meta_info = &blob_ctx.blob_meta_info;
        let ci_data = blob_meta_info.as_byte_slice();
        let uncompressed_data = if ctx.blob_meta_features & BLOB_META_FEATURE_ZRAN != 0 {
            let zran = ctx.blob_zran_generator.as_ref().unwrap();
            let (zran_data, zran_count) = zran.lock().unwrap().to_vec()?;
            header.set_ci_zran_count(zran_count);
            header.set_ci_zran_offset(ci_data.len() as u64);
            header.set_ci_zran_size(zran_data.len() as u64);
            header.set_ci_zran(true);
            [ci_data, &zran_data].concat()
        } else {
            header.set_ci_zran(false);
            ci_data.to_vec()
        };

        let (compressed_data, compressed) = compress::compress(&uncompressed_data, compressor)
            .with_context(|| "failed to compress blob chunk info array".to_string())?;

        if compressed {
            header.set_ci_compressor(compressor);
        } else {
            header.set_ci_compressor(compress::Algorithm::None);
        }
        header.set_ci_entries(blob_meta_info.len() as u32);
        header.set_ci_compressed_offset(blob_meta_data_offset);
        header.set_ci_compressed_size(compressed_data.len() as u64);
        header.set_ci_uncompressed_size(uncompressed_data.len() as u64);

        header.set_4k_aligned(true);
        match blob_meta_info {
            BlobMetaChunkArray::V1(_) => header.set_chunk_info_v2(false),
            BlobMetaChunkArray::V2(_) => header.set_chunk_info_v2(true),
        }

        blob_meta_writer.write_all(&compressed_data)?;
        offset += compressed_data.len() as u64;

        if !compressed {
            // For uncompressed blob meta, keeping 4k alignment to make compatible
            // with nydusd runtime, allowing runtime to use the blob meta in blob
            // cache directory directly.
            let aligned_len: usize = try_round_up_4k(offset).unwrap();
            blob_meta_writer.write_all(&vec![0u8; aligned_len - offset as usize])?;
            header.set_ci_separate(true);
        } else {
            header.set_ci_separate(false);
            blob_ctx.blob_hash.update(&compressed_data);
            blob_ctx.blob_hash.update(header.as_bytes());
        }

        blob_ctx.blob_meta_header = header;

        let blob_meta_data_size = blob_meta_writer.pos()? - blob_meta_data_offset;
        debug!(
            "dump rafs blob {} data {} {} {}",
            toc::ENTRY_BLOB_META,
            compressor,
            blob_meta_data_offset,
            blob_meta_data_size
        );

        let blob_meta_header_offset = blob_meta_writer.pos()?;
        let blob_meta_header_size = header.as_bytes().len();
        blob_meta_writer.write_all(header.as_bytes())?;
        blob_meta_writer.write_tar_header(
            toc::ENTRY_BLOB_META,
            blob_meta_data_size + blob_meta_header_size as u64,
        )?;
        blob_ctx.entry_list.add(
            toc::ENTRY_BLOB_META,
            RafsDigest::default(),
            blob_meta_data_offset,
            blob_meta_data_size + blob_meta_header_size as u64,
        )?;
        debug!(
            "dump rafs blob {} header {} {}",
            toc::ENTRY_BLOB_META,
            blob_meta_header_offset,
            blob_meta_header_size
        );

        Ok(())
    }
}

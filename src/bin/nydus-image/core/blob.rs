// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::borrow::Cow;
use std::io::Write;
use std::slice;

use anyhow::{Context, Result};
use nydus_rafs::metadata::RAFS_MAX_CHUNK_SIZE;
use nydus_storage::device::BlobFeatures;
use nydus_storage::meta::{toc, BlobMetaChunkArray};
use nydus_utils::compress;
use nydus_utils::digest::{self, DigestHasher, RafsDigest};
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
            ConversionType::TarToRef
            | ConversionType::TargzToRef
            | ConversionType::EStargzToRef => {
                // Use `sha256(tarball)` as `blob_id` for ref-type conversions.
                if let Some((_, blob_ctx)) = blob_mgr.get_current_blob() {
                    if let Some(zran) = &ctx.blob_zran_generator {
                        let reader = zran.lock().unwrap().reader();
                        blob_ctx.compressed_blob_size = reader.get_data_size();
                        if blob_ctx.blob_id.is_empty() {
                            let hash = reader.get_data_digest();
                            blob_ctx.blob_id = format!("{:x}", hash.finalize());
                        }
                    } else if let Some(tar_reader) = &ctx.blob_tar_reader {
                        blob_ctx.compressed_blob_size = tar_reader.position();
                        if blob_ctx.blob_id.is_empty() {
                            let hash = tar_reader.get_hash_object();
                            blob_ctx.blob_id = format!("{:x}", hash.finalize());
                        }
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
        if !ctx.blob_features.contains(BlobFeatures::SEPARATE)
            && (ctx.blob_inline_meta || ctx.features.is_enabled(Feature::BlobToc))
        {
            if let Some((_, blob_ctx)) = blob_mgr.get_current_blob() {
                blob_ctx.write_tar_header(
                    blob_writer,
                    toc::TOC_ENTRY_BLOB_RAW,
                    blob_ctx.compressed_blob_size,
                )?;
                if ctx.features.is_enabled(Feature::BlobToc) {
                    let blob_digest = RafsDigest {
                        data: blob_ctx.blob_hash.clone().finalize().into(),
                    };
                    blob_ctx.entry_list.add(
                        toc::TOC_ENTRY_BLOB_RAW,
                        compress::Algorithm::None,
                        blob_digest,
                        blob_ctx.compressed_offset(),
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
        if let Some(ref zran) = ctx.blob_zran_generator {
            let (zran_data, zran_count) = zran.lock().unwrap().to_vec()?;
            header.set_ci_zran_count(zran_count);
            header.set_ci_zran_offset(ci_data.len() as u64);
            header.set_ci_zran_size(zran_data.len() as u64);
            header.set_ci_zran(true);
            header.set_separate_blob(true);
            zran_buf = [ci_data, &zran_data].concat();
            ci_data = &zran_buf;
        } else if ctx.blob_tar_reader.is_some() {
            header.set_separate_blob(true);
            header.set_ci_zran(false);
        } else {
            header.set_separate_blob(false);
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
        if ctx.features.is_enabled(Feature::BlobToc) && blob_ctx.chunk_count > 0 {
            header.set_inlined_chunk_digest(true);
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
                toc::TOC_ENTRY_BLOB_META,
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
            blob_ctx.entry_list.add(
                toc::TOC_ENTRY_BLOB_META,
                compressor,
                hasher.digest_finalize(),
                compressed_offset,
                compressed_size as u64,
                uncompressed_size as u64,
            )?;

            let mut hasher = RafsDigest::hasher(digest::Algorithm::Sha256);
            hasher.digest_update(header.as_bytes());
            blob_ctx.entry_list.add(
                toc::TOC_ENTRY_BLOB_META_HEADER,
                compress::Algorithm::None,
                hasher.digest_finalize(),
                compressed_offset + compressed_size,
                header_size as u64,
                header_size as u64,
            )?;

            let buf = unsafe {
                slice::from_raw_parts(
                    blob_ctx.blob_chunk_digest.as_ptr() as *const u8,
                    blob_ctx.blob_chunk_digest.len() * 32,
                )
            };
            assert!(!buf.is_empty());
            // The chunk digest array is almost incompressible, no need for compression.
            let digest = RafsDigest::from_buf(buf, digest::Algorithm::Sha256);
            let compressed_offset = blob_writer.pos()?;
            let size = buf.len() as u64;
            blob_writer.write_all(buf)?;
            blob_ctx.write_tar_header(blob_writer, toc::TOC_ENTRY_BLOB_DIGEST, size)?;
            blob_ctx.entry_list.add(
                toc::TOC_ENTRY_BLOB_DIGEST,
                compress::Algorithm::None,
                digest,
                compressed_offset,
                size,
                size,
            )?;
        }

        Ok(())
    }
}

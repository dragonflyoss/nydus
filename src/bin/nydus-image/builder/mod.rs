// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::io::Write;

use anyhow::{Context, Result};
use sha2::Digest;

use crate::core::bootstrap::Bootstrap;
use crate::core::context::{
    ArtifactWriter, BlobContext, BlobManager, BootstrapContext, BootstrapManager, BuildContext,
    BuildOutput,
};
use crate::core::feature::Feature;
use crate::core::tree::Tree;
use nydus_rafs::metadata::layout::toc;
use nydus_utils::digest::RafsDigest;
use nydus_utils::{compress, digest};

pub(crate) use self::directory::DirectoryBuilder;
pub(crate) use self::stargz::StargzBuilder;
pub(crate) use self::tarball::TarballBuilder;

mod directory;
mod stargz;
mod tarball;

/// Trait to generate a RAFS filesystem from the source.
pub(crate) trait Builder {
    fn build(
        &mut self,
        build_ctx: &mut BuildContext,
        bootstrap_mgr: &mut BootstrapManager,
        blob_mgr: &mut BlobManager,
    ) -> Result<BuildOutput>;
}

fn build_bootstrap(
    ctx: &mut BuildContext,
    bootstrap_mgr: &mut BootstrapManager,
    bootstrap_ctx: &mut BootstrapContext,
    blob_mgr: &mut BlobManager,
    mut tree: Tree,
) -> Result<Bootstrap> {
    let mut bootstrap = Bootstrap::new()?;
    // Merge with lower layer if there's one.
    if bootstrap_ctx.layered {
        let origin_bootstarp_offset = bootstrap_ctx.offset;
        // Disable prefetch and bootstrap.apply() will reset the prefetch enable/disable flag.
        ctx.prefetch.disable();
        bootstrap.build(ctx, bootstrap_ctx, &mut tree)?;
        tree = bootstrap.apply(ctx, bootstrap_ctx, bootstrap_mgr, blob_mgr, None)?;
        bootstrap_ctx.offset = origin_bootstarp_offset;
        bootstrap_ctx.layered = false;
    }

    // Convert the hierarchy tree into an array, stored in `bootstrap_ctx.nodes`.
    timing_tracer!(
        { bootstrap.build(ctx, bootstrap_ctx, &mut tree) },
        "build_bootstrap"
    )?;

    Ok(bootstrap)
}

fn dump_toc(
    ctx: &mut BuildContext,
    blob_ctx: &mut BlobContext,
    blob_writer: Option<&mut ArtifactWriter>,
) -> Result<()> {
    if let Some(blob_writer) = blob_writer {
        if ctx.blob_inline_meta && ctx.features.enable(Feature::BlobToc) {
            let data = blob_ctx.entry_list.as_bytes();
            let toc_size = data.len() as u64;
            blob_writer.write_all(data)?;
            let header = blob_writer.write_tar_header(toc::ENTRY_TOC, toc_size)?;
            blob_ctx.blob_hash.update(header.as_bytes());
        }
    }
    Ok(())
}

fn dump_bootstrap(
    ctx: &mut BuildContext,
    bootstrap_mgr: &mut BootstrapManager,
    bootstrap_ctx: &mut BootstrapContext,
    bootstrap: &mut Bootstrap,
    blob_mgr: &mut BlobManager,
    blob_writer: Option<&mut ArtifactWriter>,
) -> Result<()> {
    if let Some((_, blob_ctx)) = blob_mgr.get_current_blob() {
        if blob_ctx.blob_id.is_empty() {
            // Make sure blob id is updated according to blob hash if user not specified.
            blob_ctx.blob_id = format!("{:x}", blob_ctx.blob_hash.clone().finalize());
        }
    }

    // Dump bootstrap file
    let blob_table = blob_mgr.to_blob_table(ctx)?;
    bootstrap.dump(
        ctx,
        &mut bootstrap_mgr.bootstrap_storage,
        bootstrap_ctx,
        &blob_table,
    )?;

    if let Some(blob_writer) = blob_writer {
        if ctx.blob_inline_meta {
            let bootstrap_offset = blob_writer.pos()?;
            let uncompressed_bootstrap = bootstrap_ctx.writer.as_bytes()?;
            let uncompressed_digest =
                RafsDigest::from_buf(&uncompressed_bootstrap, digest::Algorithm::Sha256);
            let uncomprssed_size = uncompressed_bootstrap.len();

            let (bootstrap_data, compressor) = if ctx.features.enable(Feature::BlobToc) {
                let (compressed_data, compressed) =
                    compress::compress(&uncompressed_bootstrap, compress::Algorithm::Zstd)
                        .with_context(|| "failed to compress bootstrap".to_string())?;
                blob_writer.write_all(&compressed_data)?;
                let compressor = if compressed {
                    compress::Algorithm::Zstd
                } else {
                    compress::Algorithm::None
                };
                (compressed_data, compressor)
            } else {
                blob_writer.write_all(&uncompressed_bootstrap)?;
                (uncompressed_bootstrap, compress::Algorithm::None)
            };

            let compressed_size = bootstrap_data.len();
            let header =
                blob_writer.write_tar_header(toc::ENTRY_BOOTSTRAP, compressed_size as u64)?;
            if let Some((_, blob_ctx)) = blob_mgr.get_current_blob() {
                blob_ctx.blob_hash.update(bootstrap_data);
                blob_ctx.blob_hash.update(header.as_bytes());
                blob_ctx.entry_list.add(
                    toc::ENTRY_BOOTSTRAP,
                    compressor,
                    uncompressed_digest,
                    bootstrap_offset,
                    compressed_size as u64,
                    uncomprssed_size as u64,
                )?;
            }
        } else {
            let blob_id = blob_mgr
                .get_current_blob()
                .map(|(_, blob_ctx)| blob_ctx.blob_id().unwrap_or_default());
            blob_writer.finalize(blob_id)?;
        }
    }

    Ok(())
}

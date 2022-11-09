// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::io::Write;

use anyhow::Result;
use sha2::{Digest, Sha256};

use crate::core::bootstrap::Bootstrap;
use crate::core::context::{
    ArtifactWriter, BlobManager, BootstrapContext, BootstrapManager, BuildContext, BuildOutput,
};
use crate::core::tree::Tree;

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

const TAR_BLOB_NAME: &str = "image.blob";
const TAR_BOOTSTRAP_NAME: &str = "image.boot";

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

fn dump_bootstrap(
    ctx: &mut BuildContext,
    bootstrap_mgr: &mut BootstrapManager,
    bootstrap_ctx: &mut BootstrapContext,
    bootstrap: &mut Bootstrap,
    blob_mgr: &mut BlobManager,
    blob_writer: &mut Option<ArtifactWriter>,
) -> Result<()> {
    // Dump bootstrap file
    let blob_table = blob_mgr.to_blob_table(ctx)?;
    bootstrap.dump(
        ctx,
        &mut bootstrap_mgr.bootstrap_storage,
        bootstrap_ctx,
        &blob_table,
    )?;

    if let Some(blob_writer) = blob_writer.as_mut() {
        let mut blob_hash = blob_mgr
            .get_current_blob()
            .map(|(_, blob_ctx)| blob_ctx.blob_hash.clone())
            .unwrap_or_else(Sha256::new);
        if ctx.inline_bootstrap {
            if blob_mgr.get_current_blob().is_some() {
                let header = blob_writer.write_tar_header(TAR_BLOB_NAME, blob_writer.pos()?)?;
                blob_hash.update(header.as_bytes());
            };

            let reader = bootstrap_ctx.writer.as_reader()?;
            let mut size = 0;
            let mut buf = vec![0u8; 16384];
            loop {
                let sz = reader.read(&mut buf)?;
                if sz == 0 {
                    break;
                }
                blob_writer.write_all(&buf[..sz])?;
                blob_hash.update(&buf[..sz]);
                size += sz;
            }

            let header = blob_writer.write_tar_header(TAR_BOOTSTRAP_NAME, size as u64)?;
            blob_hash.update(header.as_bytes());

            if ctx.blob_id.is_empty() {
                ctx.blob_id = format!("{:x}", blob_hash.finalize());
            }
            blob_writer.finalize(Some(ctx.blob_id.clone()))?;
        } else {
            let blob_id = blob_mgr
                .get_current_blob()
                .map(|(_, blob_ctx)| blob_ctx.blob_id().unwrap_or_default());
            blob_writer.finalize(blob_id)?;
        }
    }

    Ok(())
}

// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::fs::DirEntry;
use std::io::Write;

use anyhow::{Context, Result};
use sha2::Digest;

use crate::builder::Builder;
use crate::core::blob::Blob;
use crate::core::bootstrap::Bootstrap;
use crate::core::context::{
    ArtifactWriter, BlobManager, BootstrapContext, BootstrapManager, BuildContext, BuildOutput,
};
use crate::core::node::{Node, Overlay};
use crate::core::tree::Tree;

const TAR_BLOB_NAME: &str = "image.blob";
const TAR_BOOTSTRAP_NAME: &str = "image.boot";

struct FilesystemTreeBuilder {}

impl FilesystemTreeBuilder {
    fn new() -> Self {
        Self {}
    }

    /// Walk directory to build node tree by DFS
    fn load_children(
        &self,
        ctx: &mut BuildContext,
        bootstrap_ctx: &mut BootstrapContext,
        parent: &mut Node,
        layer_idx: u16,
    ) -> Result<Vec<Tree>> {
        let mut result = Vec::new();
        if !parent.is_dir() {
            return Ok(result);
        }

        let children = fs::read_dir(parent.path())
            .with_context(|| format!("failed to read dir {:?}", parent.path()))?;
        let children = children.collect::<Result<Vec<DirEntry>, std::io::Error>>()?;

        event_tracer!("load_from_directory", +children.len());
        for child in children {
            let path = child.path();
            let mut child = Node::new(
                ctx.fs_version,
                ctx.source_path.clone(),
                path.clone(),
                Overlay::UpperAddition,
                ctx.chunk_size,
                parent.explicit_uidgid,
                true,
            )
            .with_context(|| format!("failed to create node {:?}", path))?;
            child.layer_idx = layer_idx;

            // as per OCI spec, whiteout file should not be present within final image
            // or filesystem, only existed in layers.
            if !bootstrap_ctx.layered
                && child.whiteout_type(ctx.whiteout_spec).is_some()
                && !child.is_overlayfs_opaque(ctx.whiteout_spec)
            {
                continue;
            }

            let mut child = Tree::new(child);
            child.children = self.load_children(ctx, bootstrap_ctx, &mut child.node, layer_idx)?;
            child.node.v5_set_dir_size(ctx.fs_version, &child.children);
            result.push(child);
        }

        Ok(result)
    }
}

pub(crate) struct DirectoryBuilder {}

impl DirectoryBuilder {
    pub fn new() -> Self {
        Self {}
    }

    /// Build node tree from a filesystem directory
    fn build_tree(
        &mut self,
        ctx: &mut BuildContext,
        bootstrap_ctx: &mut BootstrapContext,
        layer_idx: u16,
    ) -> Result<Tree> {
        let node = Node::new(
            ctx.fs_version,
            ctx.source_path.clone(),
            ctx.source_path.clone(),
            Overlay::UpperAddition,
            ctx.chunk_size,
            ctx.explicit_uidgid,
            true,
        )?;
        let mut tree = Tree::new(node);
        let tree_builder = FilesystemTreeBuilder::new();

        tree.children = timing_tracer!(
            { tree_builder.load_children(ctx, bootstrap_ctx, &mut tree.node, layer_idx) },
            "load_from_directory"
        )?;
        tree.node.v5_set_dir_size(ctx.fs_version, &tree.children);

        Ok(tree)
    }
}

impl Builder for DirectoryBuilder {
    fn build(
        &mut self,
        ctx: &mut BuildContext,
        bootstrap_mgr: &mut BootstrapManager,
        blob_mgr: &mut BlobManager,
    ) -> Result<BuildOutput> {
        let mut bootstrap_ctx = bootstrap_mgr.create_ctx(ctx.inline_bootstrap)?;
        let layer_idx = if bootstrap_ctx.layered { 1u16 } else { 0u16 };
        let mut bootstrap = Bootstrap::new()?;

        // Scan source directory to build upper layer tree.
        let mut tree = self.build_tree(ctx, &mut bootstrap_ctx, layer_idx)?;

        // Merge with lower layer if there's one.
        if bootstrap_ctx.layered {
            let origin_bootstarp_offset = bootstrap_ctx.offset;
            // Disable prefetch and bootstrap.apply() will reset the prefetch enable/disable flag.
            ctx.prefetch.disable();
            bootstrap.build(ctx, &mut bootstrap_ctx, &mut tree)?;
            tree = bootstrap.apply(ctx, &mut bootstrap_ctx, bootstrap_mgr, blob_mgr, None)?;
            bootstrap_ctx.offset = origin_bootstarp_offset;
            bootstrap_ctx.layered = false;
        }

        // Convert the hierarchy tree into an array, stored in `bootstrap_ctx.nodes`.
        timing_tracer!(
            { bootstrap.build(ctx, &mut bootstrap_ctx, &mut tree) },
            "build_bootstrap"
        )?;

        let mut blob_writer = if let Some(blob_stor) = ctx.blob_storage.clone() {
            Some(ArtifactWriter::new(blob_stor, ctx.inline_bootstrap)?)
        } else {
            return Err(anyhow!(
                "the target blob path should always be valid for directory builder"
            ));
        };

        if ctx.inline_bootstrap {
            let (_, _) = blob_mgr.get_or_create_current_blob(ctx)?;
        }

        // Dump blob file
        timing_tracer!(
            { Blob::dump(ctx, &mut bootstrap_ctx.nodes, blob_mgr, &mut blob_writer) },
            "dump_blob"
        )?;

        // Dump bootstrap file
        let blob_table = blob_mgr.to_blob_table(ctx)?;
        bootstrap.dump(
            ctx,
            &mut bootstrap_mgr.bootstrap_storage,
            &mut bootstrap_ctx,
            &blob_table,
        )?;

        if let Some((_, blob_ctx)) = blob_mgr.get_current_blob() {
            // Safe to unwrap because we have ensure blob_writer is valid above.
            let blob_writer = blob_writer.as_mut().unwrap();
            if ctx.inline_bootstrap {
                let header = blob_writer.write_tar_header(TAR_BLOB_NAME, blob_writer.pos()?)?;
                blob_ctx.blob_hash.update(header.as_bytes());

                let reader = bootstrap_ctx.writer.as_reader()?;
                let mut size = 0;
                let mut buf = vec![0u8; 16384];
                loop {
                    let sz = reader.read(&mut buf)?;
                    if sz == 0 {
                        break;
                    }
                    blob_writer.write_all(&buf[..sz])?;
                    blob_ctx.blob_hash.update(&buf[..sz]);
                    size += sz;
                }

                let header = blob_writer.write_tar_header(TAR_BOOTSTRAP_NAME, size as u64)?;
                blob_ctx.blob_hash.update(header.as_bytes());

                if ctx.blob_id.is_empty() {
                    ctx.blob_id = format!("{:x}", blob_ctx.blob_hash.clone().finalize());
                }
                blob_writer.finalize(Some(ctx.blob_id.clone()))?;
            } else {
                blob_writer.finalize(blob_ctx.blob_id())?;
            }
        }

        BuildOutput::new(blob_mgr, &bootstrap_mgr.bootstrap_storage)
    }
}

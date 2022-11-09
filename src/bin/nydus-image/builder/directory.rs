// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::fs::DirEntry;

use anyhow::{Context, Result};

use crate::builder::{build_bootstrap, dump_bootstrap, Builder};
use crate::core::blob::Blob;
use crate::core::context::{
    ArtifactWriter, BlobManager, BootstrapContext, BootstrapManager, BuildContext, BuildOutput,
};
use crate::core::node::{Node, Overlay};
use crate::core::tree::Tree;

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
        let mut blob_writer = if let Some(blob_stor) = ctx.blob_storage.clone() {
            Some(ArtifactWriter::new(blob_stor, ctx.inline_bootstrap)?)
        } else {
            return Err(anyhow!(
                "the target blob path should always be valid for directory builder"
            ));
        };

        // Scan source directory to build upper layer tree.
        let tree = timing_tracer!(
            { self.build_tree(ctx, &mut bootstrap_ctx, layer_idx) },
            "build_tree"
        )?;
        let mut bootstrap = timing_tracer!(
            { build_bootstrap(ctx, bootstrap_mgr, &mut bootstrap_ctx, blob_mgr, tree) },
            "build_bootstrap"
        )?;

        // Dump blob file
        timing_tracer!(
            { Blob::dump(ctx, &mut bootstrap_ctx.nodes, blob_mgr, &mut blob_writer,) },
            "dump_blob"
        )?;

        let mut origin_blob_meta_writer = if let Some(stor) = &ctx.blob_meta_storage {
            Some(ArtifactWriter::new(stor.clone(), ctx.inline_bootstrap)?)
        } else {
            None
        };
        let blob_meta_writer = origin_blob_meta_writer.as_mut().or(blob_writer.as_mut());
        if let Some((_, blob_ctx)) = blob_mgr.get_current_blob() {
            Blob::dump_meta_data(ctx, blob_ctx, blob_meta_writer)?;
        }

        // Dump blob meta to blob file
        timing_tracer!(
            {
                dump_bootstrap(
                    ctx,
                    bootstrap_mgr,
                    &mut bootstrap_ctx,
                    &mut bootstrap,
                    blob_mgr,
                    blob_writer.as_mut(),
                )
            },
            "dump_bootstrap"
        )?;

        BuildOutput::new(blob_mgr, &bootstrap_mgr.bootstrap_storage)
    }
}

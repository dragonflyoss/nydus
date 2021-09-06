// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result};

use std::fs;
use std::fs::DirEntry;

use crate::builder::Builder;
use crate::core::blob::Blob;
use crate::core::bootstrap::Bootstrap;
use crate::core::context::{BlobContext, BlobManager, BootstrapContext, BuildContext};
use crate::core::node::*;
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
    ) -> Result<Vec<Tree>> {
        let mut result = Vec::new();

        if !parent.is_dir() {
            return Ok(result);
        }

        let layered = bootstrap_ctx.f_parent_bootstrap.is_some();
        let children = fs::read_dir(&parent.path)
            .with_context(|| format!("failed to read dir {:?}", parent.path))?;
        let children = children.collect::<Result<Vec<DirEntry>, std::io::Error>>()?;

        event_tracer!("load_from_directory", +children.len());

        for child in children {
            let path = child.path();

            let child = Node::new(
                ctx.source_path.clone(),
                path.clone(),
                Overlay::UpperAddition,
                parent.explicit_uidgid,
            )
            .with_context(|| format!("failed to create node {:?}", path))?;

            // as per OCI spec, whiteout file should not be present within final image
            // or filesystem, only existed in layers.
            if child.whiteout_type(ctx.whiteout_spec).is_some()
                && !child.is_overlayfs_opaque(ctx.whiteout_spec)
                && !layered
            {
                continue;
            }

            let mut child = Tree::new(child);
            child.children = self.load_children(ctx, bootstrap_ctx, &mut child.node)?;
            result.push(child);
        }

        Ok(result)
    }
}

pub struct DirectoryBuilder {}

impl DirectoryBuilder {
    pub fn new() -> Self {
        Self {}
    }

    /// Build node tree from a filesystem directory
    fn build_tree_from_fs(
        &mut self,
        ctx: &mut BuildContext,
        bootstrap_ctx: &mut BootstrapContext,
    ) -> Result<Tree> {
        let tree_builder = FilesystemTreeBuilder::new();

        let node = Node::new(
            ctx.source_path.clone(),
            ctx.source_path.clone(),
            Overlay::UpperAddition,
            ctx.explicit_uidgid,
        )?;
        let mut tree = Tree::new(node);

        tree.children = timing_tracer!(
            { tree_builder.load_children(ctx, bootstrap_ctx, &mut tree.node) },
            "load_from_directory"
        )?;

        Ok(tree)
    }
}

impl Builder for DirectoryBuilder {
    fn build(
        &mut self,
        ctx: &mut BuildContext,
        bootstrap_ctx: &mut BootstrapContext,
        blob_mgr: &mut BlobManager,
    ) -> Result<(Vec<String>, u64)> {
        let mut blob = Blob::new();
        let mut bootstrap = Bootstrap::new()?;

        // Build tree from source
        let mut tree = self.build_tree_from_fs(ctx, bootstrap_ctx)?;

        // Build bootstrap from source
        if bootstrap_ctx.f_parent_bootstrap.is_some() {
            bootstrap.build(ctx, bootstrap_ctx, &mut tree);
            // Apply to parent bootstrap for layered build
            let mut tree = bootstrap.apply(ctx, bootstrap_ctx, blob_mgr, None)?;
            timing_tracer!(
                { bootstrap.build(ctx, bootstrap_ctx, &mut tree) },
                "build_bootstrap"
            );
        } else {
            bootstrap.build(ctx, bootstrap_ctx, &mut tree);
        }

        // Dump blob file
        let mut blob_ctx = BlobContext::new(ctx.blob_id.clone(), ctx.blob_storage.clone())?;
        let blob_index = blob_mgr.alloc_index()?;
        timing_tracer!(
            { blob.dump(ctx, &mut blob_ctx, blob_index, &mut bootstrap_ctx.nodes) },
            "dump_blob"
        )?;
        blob.flush(&mut blob_ctx)?;

        // Add new blob to blob table
        if blob_ctx.compressed_blob_size > 0 {
            blob_mgr.add(blob_ctx);
        }

        // Dump bootstrap file
        bootstrap.dump_rafsv5(ctx, bootstrap_ctx, blob_mgr)
    }
}

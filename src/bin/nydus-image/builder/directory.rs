// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::fs::DirEntry;

use anyhow::{Context, Result};

use crate::builder::Builder;
use crate::core::blob::Blob;
use crate::core::bootstrap::Bootstrap;
use crate::core::context::{BlobContext, BlobManager, BootstrapContext, BuildContext, RafsVersion};
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
    ) -> Result<Vec<Tree>> {
        let mut result = Vec::new();
        if !parent.is_dir() {
            return Ok(result);
        }

        let layered = bootstrap_ctx.f_parent_bootstrap.is_some();
        let children = fs::read_dir(parent.path())
            .with_context(|| format!("failed to read dir {:?}", parent.path()))?;
        let children = children.collect::<Result<Vec<DirEntry>, std::io::Error>>()?;

        event_tracer!("load_from_directory", +children.len());
        for child in children {
            let path = child.path();
            let child = Node::new(
                ctx.fs_version,
                ctx.source_path.clone(),
                path.clone(),
                Overlay::UpperAddition,
                ctx.chunk_size,
                parent.explicit_uidgid,
            )
            .with_context(|| format!("failed to create node {:?}", path))?;

            // as per OCI spec, whiteout file should not be present within final image
            // or filesystem, only existed in layers.
            if !layered
                && child.whiteout_type(ctx.whiteout_spec).is_some()
                && !child.is_overlayfs_opaque(ctx.whiteout_spec)
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

pub(crate) struct DirectoryBuilder {}

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
        let node = Node::new(
            ctx.fs_version,
            ctx.source_path.clone(),
            ctx.source_path.clone(),
            Overlay::UpperAddition,
            ctx.chunk_size,
            ctx.explicit_uidgid,
        )?;
        let mut tree = Tree::new(node);
        let tree_builder = FilesystemTreeBuilder::new();

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
        // Scan source directory to build upper layer tree.
        let mut tree = self.build_tree_from_fs(ctx, bootstrap_ctx)?;
        let mut bootstrap = Bootstrap::new()?;
        if bootstrap_ctx.f_parent_bootstrap.is_some() {
            // Merge with lower layer if there's one, do not prepare `prefetch` list during merging.
            ctx.prefetch.disable();
            bootstrap.build(ctx, bootstrap_ctx, &mut tree);
            tree = bootstrap.apply(ctx, bootstrap_ctx, blob_mgr, None)?;
        }
        // Convert the hierarchy tree into an array, stored in `bootstrap_ctx.nodes`.
        timing_tracer!(
            { bootstrap.build(ctx, bootstrap_ctx, &mut tree) },
            "build_bootstrap"
        );

        // Dump blob file
        let mut blob_ctx = BlobContext::new(ctx.blob_id.clone(), ctx.blob_storage.clone())?;
        if let Some(dict) = blob_mgr.get_chunk_dict() {
            blob_ctx.set_chunk_dict(dict);
            blob_mgr.extend_blob_table_from_chunk_dict();
        }
        blob_ctx.set_chunk_size(ctx.chunk_size);
        blob_ctx.set_meta_info_enabled(true);

        let blob_index = blob_mgr.alloc_index()?;
        let mut blob = Blob::new();
        timing_tracer!(
            {
                blob.dump(
                    ctx,
                    &mut blob_ctx,
                    blob_index,
                    &mut bootstrap_ctx.nodes,
                    &mut blob_mgr.chunk_dict_cache,
                )
            },
            "dump_blob"
        )?;
        blob.flush(&mut blob_ctx)?;

        // Add new blob to blob table
        if blob_ctx.compressed_blob_size > 0 {
            blob_mgr.add(blob_ctx);
        }

        // Dump bootstrap file
        match ctx.fs_version {
            RafsVersion::V5 => bootstrap.dump_rafsv5(ctx, bootstrap_ctx, blob_mgr),
            RafsVersion::V6 => bootstrap.dump_rafsv6(ctx, bootstrap_ctx, blob_mgr),
        }
    }
}

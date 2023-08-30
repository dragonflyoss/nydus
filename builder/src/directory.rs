// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::fs::DirEntry;

use anyhow::{Context, Result};
use nydus_utils::{event_tracer, lazy_drop, root_tracer, timing_tracer};

use crate::core::context::{Artifact, NoopArtifactWriter};

use super::core::blob::Blob;
use super::core::context::{
    ArtifactWriter, BlobManager, BootstrapContext, BootstrapManager, BuildContext, BuildOutput,
};
use super::core::node::Node;
use super::{build_bootstrap, dump_bootstrap, finalize_blob, Builder, Overlay, Tree, TreeNode};

struct FilesystemTreeBuilder {}

impl FilesystemTreeBuilder {
    fn new() -> Self {
        Self {}
    }

    #[allow(clippy::only_used_in_recursion)]
    /// Walk directory to build node tree by DFS
    fn load_children(
        &self,
        ctx: &mut BuildContext,
        bootstrap_ctx: &mut BootstrapContext,
        parent: &TreeNode,
        layer_idx: u16,
    ) -> Result<Vec<Tree>> {
        let mut result = Vec::new();
        let parent = parent.lock().unwrap();
        if !parent.is_dir() {
            return Ok(result);
        }

        let children = fs::read_dir(parent.path())
            .with_context(|| format!("failed to read dir {:?}", parent.path()))?;
        let children = children.collect::<Result<Vec<DirEntry>, std::io::Error>>()?;

        event_tracer!("load_from_directory", +children.len());
        for child in children {
            let path = child.path();
            let mut child = Node::from_fs_object(
                ctx.fs_version,
                ctx.source_path.clone(),
                path.clone(),
                Overlay::UpperAddition,
                ctx.chunk_size,
                parent.info.explicit_uidgid,
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
            child.children = self.load_children(ctx, bootstrap_ctx, &child.node, layer_idx)?;
            child
                .lock_node()
                .v5_set_dir_size(ctx.fs_version, &child.children);
            result.push(child);
        }

        result.sort_unstable_by(|a, b| a.name().cmp(b.name()));

        Ok(result)
    }
}

#[derive(Default)]
pub struct DirectoryBuilder {}

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
        let node = Node::from_fs_object(
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
            { tree_builder.load_children(ctx, bootstrap_ctx, &tree.node, layer_idx) },
            "load_from_directory"
        )?;
        tree.lock_node()
            .v5_set_dir_size(ctx.fs_version, &tree.children);

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
        let mut bootstrap_ctx = bootstrap_mgr.create_ctx()?;
        let layer_idx = u16::from(bootstrap_ctx.layered);
        let mut blob_writer: Box<dyn Artifact> = if let Some(blob_stor) = ctx.blob_storage.clone() {
            Box::new(ArtifactWriter::new(blob_stor)?)
        } else {
            Box::<NoopArtifactWriter>::default()
        };

        // Scan source directory to build upper layer tree.
        let tree = timing_tracer!(
            { self.build_tree(ctx, &mut bootstrap_ctx, layer_idx) },
            "build_tree"
        )?;

        // Build bootstrap
        let mut bootstrap = timing_tracer!(
            { build_bootstrap(ctx, bootstrap_mgr, &mut bootstrap_ctx, blob_mgr, tree) },
            "build_bootstrap"
        )?;

        // Dump blob file
        timing_tracer!(
            { Blob::dump(ctx, &bootstrap.tree, blob_mgr, blob_writer.as_mut(),) },
            "dump_blob"
        )?;

        // Dump blob meta information
        if let Some((_, blob_ctx)) = blob_mgr.get_current_blob() {
            Blob::dump_meta_data(ctx, blob_ctx, blob_writer.as_mut())?;
        }

        // Dump RAFS meta/bootstrap and finalize the data blob.
        if ctx.blob_inline_meta {
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
            finalize_blob(ctx, blob_mgr, blob_writer.as_mut())?;
        } else {
            finalize_blob(ctx, blob_mgr, blob_writer.as_mut())?;
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
        }

        lazy_drop(bootstrap_ctx);

        BuildOutput::new(blob_mgr, &bootstrap_mgr.bootstrap_storage)
    }
}

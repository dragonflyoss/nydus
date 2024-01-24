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
    ArtifactWriter, BlobManager, BootstrapManager, BuildContext, BuildOutput,
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
        parent: &TreeNode,
        layer_idx: u16,
    ) -> Result<(Vec<Tree>, Vec<Tree>)> {
        let mut trees = Vec::new();
        let mut external_trees = Vec::new();
        let parent = parent.borrow();
        if !parent.is_dir() {
            return Ok((trees.clone(), external_trees));
        }

        let children = fs::read_dir(parent.path())
            .with_context(|| format!("failed to read dir {:?}", parent.path()))?;
        let children = children.collect::<Result<Vec<DirEntry>, std::io::Error>>()?;

        event_tracer!("load_from_directory", +children.len());
        for child in children {
            let path = child.path();
            let target = Node::generate_target(&path, &ctx.source_path);
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
            if layer_idx == 0
                && child.whiteout_type(ctx.whiteout_spec).is_some()
                && !child.is_overlayfs_opaque(ctx.whiteout_spec)
            {
                continue;
            }

            let (mut child, mut external_child) = (Tree::new(child.clone()), Tree::new(child));

            let external = ctx.attributes.get(&target).is_some();
            if external {
                info!("ignore external file data: {:?}", path);
            }

            let (child_children, external_children) =
                self.load_children(ctx, &child.node, layer_idx)?;

            child.children = child_children;
            external_child.children = external_children;
            child
                .borrow_mut_node()
                .v5_set_dir_size(ctx.fs_version, &child.children);
            external_child
                .borrow_mut_node()
                .v5_set_dir_size(ctx.fs_version, &external_child.children);

            if external {
                external_trees.push(external_child);
            } else {
                trees.push(child.clone());
                for (path, _) in &ctx.attributes {
                    if path.starts_with(&target) {
                        external_trees.push(external_child);
                        break;
                    }
                }
            };
        }

        trees.sort_unstable_by(|a, b| a.name().cmp(b.name()));
        external_trees.sort_unstable_by(|a, b| a.name().cmp(b.name()));

        Ok((trees, external_trees))
    }
}

#[derive(Default)]
pub struct DirectoryBuilder {}

impl DirectoryBuilder {
    pub fn new() -> Self {
        Self {}
    }

    /// Build node tree from a filesystem directory
    fn build_tree(&mut self, ctx: &mut BuildContext, layer_idx: u16) -> Result<(Tree, Tree)> {
        let node = Node::from_fs_object(
            ctx.fs_version,
            ctx.source_path.clone(),
            ctx.source_path.clone(),
            Overlay::UpperAddition,
            ctx.chunk_size,
            ctx.explicit_uidgid,
            true,
        )?;
        let mut tree = Tree::new(node.clone());
        let mut external_tree = Tree::new(node);
        let tree_builder = FilesystemTreeBuilder::new();

        let (tree_children, external_tree_children) = timing_tracer!(
            { tree_builder.load_children(ctx, &tree.node, layer_idx) },
            "load_from_directory"
        )?;
        tree.children = tree_children;
        external_tree.children = external_tree_children;
        tree.borrow_mut_node()
            .v5_set_dir_size(ctx.fs_version, &tree.children);
        external_tree
            .borrow_mut_node()
            .v5_set_dir_size(ctx.fs_version, &external_tree.children);

        Ok((tree, external_tree))
    }
}

impl Builder for DirectoryBuilder {
    fn build(
        &mut self,
        ctx: &mut BuildContext,
        bootstrap_mgr: &mut BootstrapManager,
        blob_mgr: &mut BlobManager,
    ) -> Result<BuildOutput> {
        let layer_idx = u16::from(bootstrap_mgr.f_parent_path.is_some());

        // Scan source directory to build upper layer tree.
        let (tree, _external_tree) =
            timing_tracer!({ self.build_tree(ctx, layer_idx) }, "build_tree")?;

        // Build bootstrap
        let mut bootstrap_ctx = bootstrap_mgr.create_ctx()?;
        let mut bootstrap = timing_tracer!(
            { build_bootstrap(ctx, bootstrap_mgr, &mut bootstrap_ctx, blob_mgr, tree) },
            "build_bootstrap"
        )?;

        // Dump blob file
        let mut blob_writer: Box<dyn Artifact> = if let Some(blob_stor) = ctx.blob_storage.clone() {
            Box::new(ArtifactWriter::new(blob_stor)?)
        } else {
            Box::<NoopArtifactWriter>::default()
        };
        timing_tracer!(
            { Blob::dump(ctx, blob_mgr, blob_writer.as_mut()) },
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

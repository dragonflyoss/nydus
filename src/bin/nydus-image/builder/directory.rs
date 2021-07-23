// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result};

use std::fs;
use std::fs::DirEntry;

use crate::builder::Builder;
use crate::core::blob::{Blob, BlobStorage};
use crate::core::bootstrap::Bootstrap;
use crate::core::context::BuildContext;
use crate::core::node::*;
use crate::core::tree::Tree;

struct FilesystemTreeBuilder {}

impl FilesystemTreeBuilder {
    fn new() -> Self {
        Self {}
    }

    /// Walk directory to build node tree by DFS
    fn load_children(&self, mut ctx: &mut BuildContext, parent: &mut Node) -> Result<Vec<Tree>> {
        let mut result = Vec::new();

        if !parent.is_dir() {
            return Ok(result);
        }

        let layered = ctx.f_parent_bootstrap.is_some();
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
            if child.whiteout_type(&ctx.whiteout_spec).is_some()
                && !child.is_overlayfs_opaque(&ctx.whiteout_spec)
                && !layered
            {
                continue;
            }

            let mut child = Tree::new(child);
            child.children = self.load_children(&mut ctx, &mut child.node)?;
            result.push(child);
        }

        Ok(result)
    }
}

pub struct DirectoryBuilder {
    blob_stor: BlobStorage,
}

impl DirectoryBuilder {
    pub fn new(blob_stor: BlobStorage) -> Self {
        Self { blob_stor }
    }

    /// Build node tree from a filesystem directory
    fn build_tree_from_fs(&mut self, mut ctx: &mut BuildContext) -> Result<Tree> {
        let tree_builder = FilesystemTreeBuilder::new();

        let node = Node::new(
            ctx.source_path.clone(),
            ctx.source_path.clone(),
            Overlay::UpperAddition,
            ctx.explicit_uidgid,
        )?;
        let mut tree = Tree::new(node);

        tree.children = timing_tracer!(
            { tree_builder.load_children(&mut ctx, &mut tree.node) },
            "load_from_directory"
        )?;

        Ok(tree)
    }
}

impl Builder for DirectoryBuilder {
    fn build(&mut self, mut ctx: &mut BuildContext) -> Result<(Vec<String>, usize)> {
        let mut blob = Blob::new(self.blob_stor.clone())?;
        let mut bootstrap = Bootstrap::new()?;

        // Build tree from source
        let mut tree = self.build_tree_from_fs(&mut ctx)?;

        // Build bootstrap from source
        if ctx.f_parent_bootstrap.is_some() {
            bootstrap.build(&mut ctx, &mut tree);
            // Apply to parent bootstrap for layered build
            let mut tree = bootstrap.apply(&mut ctx)?;
            timing_tracer!({ bootstrap.build(&mut ctx, &mut tree) }, "build_bootstrap");
        } else {
            bootstrap.build(&mut ctx, &mut tree);
        }

        // Dump blob file
        let (blob_hash, blob_size, blob_readahead_size, blob_cache_size, compressed_blob_size) =
            timing_tracer!({ blob.dump(&mut ctx) }, "dump_blob")?;

        // Dump bootstrap file
        let (blob_ids, blob_size) = bootstrap.dump(
            &mut ctx,
            blob_hash,
            blob_size,
            blob_readahead_size,
            blob_cache_size,
            compressed_blob_size,
        )?;
        blob.flush(&ctx)?;

        Ok((blob_ids, blob_size))
    }
}

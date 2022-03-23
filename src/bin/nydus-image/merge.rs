// Copyright (C) 2022 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use anyhow::Result;

use rafs::metadata::layout::RAFS_ROOT_INODE;
use rafs::metadata::{RafsInode, RafsMode, RafsSuper};

use crate::core::bootstrap::Bootstrap;
use crate::core::chunk_dict::HashChunkDict;
use crate::core::context::ArtifactStorage;
use crate::core::context::{BlobContext, BlobManager, BootstrapContext, BuildContext};
use crate::core::node::{ChunkSource, Overlay, WhiteoutSpec};
use crate::core::tree::{MetadataTreeBuilder, Tree};

pub struct Merger {}

impl Merger {
    pub fn merge(
        ctx: &mut BuildContext,
        sources: Vec<PathBuf>,
        target: PathBuf,
        chunk_dict: Option<PathBuf>,
    ) -> Result<()> {
        if sources.is_empty() {
            bail!("please provide at least one source bootstrap");
        }

        let mut dict = HashChunkDict::default();

        let mut tree: Option<Tree> = None;
        let mut blob_mgr = BlobManager::new();
        let mut chunk_dict_blobs = HashSet::new();

        for source in sources {
            let rs = RafsSuper::load_from_metadata(&source, RafsMode::Direct, true)?;
            let blobs = rs.superblock.get_blob_infos();

            if let Some(path) = &chunk_dict {
                let rs = RafsSuper::load_from_metadata(&path, RafsMode::Direct, true)?;
                for blob in rs.superblock.get_blob_infos() {
                    chunk_dict_blobs.insert(blob.blob_id().to_string());
                }
            }

            let blob_id = source.file_name().unwrap().to_str().unwrap();

            let mut blob_idx_map = Vec::new();
            let mut parent_blob_added = false;
            for blob in &blobs {
                let mut blob_ctx = BlobContext::from(blob, ChunkSource::Parent);
                if chunk_dict_blobs.get(blob.blob_id()).is_none() {
                    if parent_blob_added {
                        bail!("invalid bootstrap, seems have multiple non-chunk-dict blobs in this bootstrap");
                    }
                    blob_ctx.blob_id = blob_id.to_owned();
                    parent_blob_added = true;
                }
                blob_idx_map.push(blob_mgr.len() as u32);
                blob_mgr.add(blob_ctx);
            }

            if let Some(tree) = &mut tree {
                let mut nodes = Vec::new();
                rs.walk_inodes(RAFS_ROOT_INODE, None, &mut |inode: &dyn RafsInode,
                                                            path: &Path|
                 -> Result<()> {
                    let mut node = MetadataTreeBuilder::parse_node(&rs, inode, path.to_path_buf())?;
                    for chunk in &mut node.chunks {
                        let origin_blob_index = chunk.inner.blob_index() as usize;
                        chunk.inner.set_blob_index(blob_idx_map[origin_blob_index]);
                    }
                    node.overlay = Overlay::UpperAddition;
                    match node.whiteout_type(WhiteoutSpec::Oci) {
                        Some(_) => {
                            nodes.insert(0, node.clone());
                        }
                        _ => {
                            nodes.push(node.clone());
                        }
                    }
                    Ok(())
                })?;
                for node in &nodes {
                    tree.apply(node, true, WhiteoutSpec::Oci)?;
                }
            } else {
                tree = Some(Tree::from_bootstrap(&rs, &mut dict)?);
            }
        }

        // Safe to unwrap because source bootstrap is at least one.
        let mut tree = tree.unwrap();
        let mut bootstrap = Bootstrap::new()?;
        let storage = ArtifactStorage::SingleFile(target.clone());
        let mut bootstrap_ctx = BootstrapContext::new(storage, false)?;
        bootstrap.build(ctx, &mut bootstrap_ctx, &mut tree)?;
        let blob_table = blob_mgr.to_blob_table(&ctx)?;
        bootstrap.dump(ctx, &mut bootstrap_ctx, &blob_table)?;

        Ok(())
    }
}

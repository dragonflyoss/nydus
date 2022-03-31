// Copyright (C) 2022 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashSet;
use std::convert::TryFrom;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use rafs::metadata::layout::RAFS_ROOT_INODE;
use rafs::metadata::{RafsInode, RafsMode, RafsSuper};

use crate::core::bootstrap::Bootstrap;
use crate::core::chunk_dict::HashChunkDict;
use crate::core::context::ArtifactStorage;
use crate::core::context::{BlobContext, BlobManager, BootstrapContext, BuildContext};
use crate::core::node::{ChunkSource, Overlay, WhiteoutSpec};
use crate::core::tree::{MetadataTreeBuilder, Tree};

/// Merger merge multiple bootstraps (generally come from nydus tar blob of
/// intermediate image layer) into one bootstrap (uses as final image layer).
pub struct Merger {}

impl Merger {
    /// Merge assumes the bootstrap name as the hash of whole tar blob.
    fn get_blob_hash(bootstrap_path: &Path) -> Result<String> {
        let blob_hash = bootstrap_path
            .file_name()
            .ok_or_else(|| anyhow!("get file name"))?
            .to_str()
            .ok_or_else(|| anyhow!("convert to string"))?;
        Ok(blob_hash.to_string())
    }

    pub fn merge(
        ctx: &mut BuildContext,
        sources: Vec<PathBuf>,
        target: PathBuf,
        chunk_dict: Option<PathBuf>,
    ) -> Result<()> {
        if sources.is_empty() {
            bail!("please provide at least one source bootstrap path");
        }

        let mut tree: Option<Tree> = None;
        let mut blob_mgr = BlobManager::new();

        for (layer_idx, bootstrap_path) in sources.iter().enumerate() {
            // Get the blobs come from chunk dict bootstrap.
            let mut chunk_dict_blobs = HashSet::new();
            if let Some(chunk_dict_path) = &chunk_dict {
                let rs = RafsSuper::load_from_metadata(&chunk_dict_path, RafsMode::Direct, true)?;
                for blob in rs.superblock.get_blob_infos() {
                    chunk_dict_blobs.insert(blob.blob_id().to_string());
                }
            }

            let rs = RafsSuper::load_from_metadata(&bootstrap_path, RafsMode::Direct, true)?;
            let parent_blobs = rs.superblock.get_blob_infos();
            let blob_hash = Self::get_blob_hash(bootstrap_path)?;
            let mut blob_idx_map = Vec::new();
            let mut parent_blob_added = false;

            for blob in &parent_blobs {
                let mut blob_ctx = BlobContext::from(blob, ChunkSource::Parent);
                if chunk_dict_blobs.get(blob.blob_id()).is_none() {
                    // Only up to one blob from the parent bootstrap, the other blobs should be
                    // from the chunk dict image.
                    if parent_blob_added {
                        bail!("invalid bootstrap, seems have multiple non-chunk-dict blobs in this bootstrap");
                    }
                    // The blob id (blob sha256 hash) in parent bootstrap is invalid for nydusd
                    // runtime, should change it to the hash of whole tar blob.
                    blob_ctx.blob_id = blob_hash.to_owned();
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
                        // Set the blob index of chunk to real index in blob table of final bootstrap.
                        chunk.inner.set_blob_index(blob_idx_map[origin_blob_index]);
                    }
                    // Set node's layer index to distinguish same inode number (from bootstrap)
                    // between different layers.
                    node.layer_idx = u16::try_from(layer_idx).context(format!(
                        "too many layers {}, limited to {}",
                        layer_idx,
                        u16::MAX
                    ))?;
                    node.overlay = Overlay::UpperAddition;
                    match node.whiteout_type(WhiteoutSpec::Oci) {
                        Some(_) => {
                            // Insert removal operations at the head, so they will be handled first when
                            // applying to lower layer.
                            nodes.insert(0, node);
                        }
                        _ => {
                            nodes.push(node);
                        }
                    }
                    Ok(())
                })?;
                for node in &nodes {
                    tree.apply(node, true, WhiteoutSpec::Oci)?;
                }
            } else {
                let mut dict = HashChunkDict::default();
                tree = Some(Tree::from_bootstrap(&rs, &mut dict)?);
            }
        }

        // Safe to unwrap because there is at least one source bootstrap.
        let mut tree = tree.unwrap();
        let mut bootstrap = Bootstrap::new()?;
        let storage = ArtifactStorage::SingleFile(target);
        let mut bootstrap_ctx = BootstrapContext::new(storage, false)?;
        bootstrap.build(ctx, &mut bootstrap_ctx, &mut tree)?;
        let blob_table = blob_mgr.to_blob_table(&ctx)?;
        bootstrap.dump(ctx, &mut bootstrap_ctx, &blob_table)?;

        Ok(())
    }
}

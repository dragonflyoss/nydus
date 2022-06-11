// Copyright (C) 2022 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashSet;
use std::convert::TryFrom;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use nydus_utils::compress;
use nydus_utils::digest::{self};
use rafs::metadata::{RafsInode, RafsMode, RafsSuper, RafsSuperMeta};

use crate::core::bootstrap::Bootstrap;
use crate::core::chunk_dict::HashChunkDict;
use crate::core::context::{ArtifactStorage, RafsVersion};
use crate::core::context::{BlobContext, BlobManager, BootstrapContext, BuildContext};
use crate::core::node::{ChunkSource, Overlay, WhiteoutSpec};
use crate::core::tree::{MetadataTreeBuilder, Tree};

#[derive(Clone, Debug, Eq, PartialEq)]
struct Flags {
    explicit_uidgid: bool,
    compressor: compress::Algorithm,
    digester: digest::Algorithm,
}

impl Flags {
    fn from_meta(meta: &RafsSuperMeta) -> Self {
        Self {
            explicit_uidgid: meta.explicit_uidgid(),
            compressor: meta.get_compressor(),
            digester: meta.get_digester(),
        }
    }

    fn set_to_ctx(&self, ctx: &mut BuildContext) {
        ctx.explicit_uidgid = self.explicit_uidgid;
        ctx.compressor = self.compressor;
        ctx.digester = self.digester;
    }
}

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
        let mut flags: Option<Flags> = None;

        // Get the blobs come from chunk dict bootstrap.
        let mut chunk_dict_blobs = HashSet::new();
        if let Some(chunk_dict_path) = &chunk_dict {
            let rs = RafsSuper::load_from_metadata(chunk_dict_path, RafsMode::Direct, true)
                .context(format!("load chunk dict bootstrap {:?}", chunk_dict_path))?;
            for blob in rs.superblock.get_blob_infos() {
                chunk_dict_blobs.insert(blob.blob_id().to_string());
            }
        }
        let mut fs_version = None;
        for (layer_idx, bootstrap_path) in sources.iter().enumerate() {
            let rs = RafsSuper::load_from_metadata(bootstrap_path, RafsMode::Direct, true)
                .context(format!("load bootstrap {:?}", bootstrap_path))?;

            match fs_version {
                Some(version) => {
                    if version != rs.meta.version {
                        bail!(
                            "inconsistent fs version between layers, expected version {}",
                            version
                        );
                    }
                }
                None => fs_version = Some(rs.meta.version),
            }
            let current_flags = Flags::from_meta(&rs.meta);
            if let Some(flags) = &flags {
                if flags != &current_flags {
                    bail!(
                        "inconsistent flags between bootstraps, current bootstrap {:?}, flags {:?}, expected flags {:?}",
                        bootstrap_path,
                        current_flags,
                        flags,
                    );
                }
            } else {
                // Keep final bootstrap following superblock flags of source bootstraps.
                current_flags.set_to_ctx(ctx);
                flags = Some(current_flags);
            }

            let parent_blobs = rs.superblock.get_blob_infos();
            let blob_hash = Self::get_blob_hash(bootstrap_path)?;
            let mut blob_idx_map = Vec::new();
            let mut parent_blob_added = false;

            for blob in &parent_blobs {
                let mut blob_ctx = BlobContext::from(ctx, blob, ChunkSource::Parent);
                if chunk_dict_blobs.get(blob.blob_id()).is_none() {
                    // It is assumed that the `nydus-image create` at each layer and `nydus-image merge` commands
                    // use the same chunk dict bootstrap. So the parent bootstrap includes multiple blobs, but
                    // only at most one new blob, the other blobs should be from the chunk dict image.
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
                rs.walk_dir(
                    rs.superblock.root_ino(),
                    None,
                    &mut |inode: &dyn RafsInode, path: &Path| -> Result<()> {
                        let mut node =
                            MetadataTreeBuilder::parse_node(&rs, inode, path.to_path_buf())
                                .context(format!(
                                    "parse node from bootstrap {:?}",
                                    bootstrap_path
                                ))?;
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
                                // Insert whiteouts at the head, so they will be handled first when
                                // applying to lower layer.
                                nodes.insert(0, node);
                            }
                            _ => {
                                nodes.push(node);
                            }
                        }
                        Ok(())
                    },
                )?;
                for node in &nodes {
                    tree.apply(node, true, WhiteoutSpec::Oci)?;
                }
            } else {
                let mut dict = HashChunkDict::default();
                tree = Some(Tree::from_bootstrap(&rs, &mut dict)?);
            }
        }

        // Safe to unwrap because a valid version must exist
        ctx.fs_version = RafsVersion::try_from(fs_version.unwrap())?;
        // Safe to unwrap because there is at least one source bootstrap.
        let mut tree = tree.unwrap();
        let mut bootstrap = Bootstrap::new()?;
        let storage = ArtifactStorage::SingleFile(target.clone());
        let mut bootstrap_ctx = BootstrapContext::new(Some(storage), false, false)?;
        bootstrap.build(ctx, &mut bootstrap_ctx, &mut tree)?;
        let blob_table = blob_mgr.to_blob_table(ctx)?;
        bootstrap
            .dump(ctx, &mut bootstrap_ctx, &blob_table)
            .context(format!("dump bootstrap to {:?}", target))?;

        Ok(())
    }
}

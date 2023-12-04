// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Builder to create RAFS filesystems from directories and tarballs.

#[macro_use]
extern crate log;

use crate::core::context::Artifact;
use std::ffi::OsString;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use nydus_rafs::metadata::inode::InodeWrapper;
use nydus_rafs::metadata::layout::RafsXAttrs;
use nydus_rafs::metadata::{Inode, RafsVersion};
use nydus_storage::meta::toc;
use nydus_utils::digest::{DigestHasher, RafsDigest};
use nydus_utils::{compress, digest, root_tracer, timing_tracer};
use sha2::Digest;

use self::core::node::{Node, NodeInfo};

pub use self::compact::BlobCompactor;
pub use self::core::bootstrap::Bootstrap;
pub use self::core::chunk_dict::{parse_chunk_dict_arg, ChunkDict, HashChunkDict};
pub use self::core::context::{
    ArtifactStorage, ArtifactWriter, BlobCacheGenerator, BlobContext, BlobManager,
    BootstrapContext, BootstrapManager, BuildContext, BuildOutput, ConversionType,
};
pub use self::core::feature::{Feature, Features};
pub use self::core::node::{ChunkSource, NodeChunk};
pub use self::core::overlay::{Overlay, WhiteoutSpec};
pub use self::core::prefetch::{Prefetch, PrefetchPolicy};
pub use self::core::tree::{MetadataTreeBuilder, Tree, TreeNode};
pub use self::directory::DirectoryBuilder;
pub use self::merge::Merger;
pub use self::stargz::StargzBuilder;
pub use self::tarball::TarballBuilder;

mod compact;
pub mod core;
mod directory;
mod merge;
mod stargz;
mod tarball;

/// Trait to generate a RAFS filesystem from the source.
pub trait Builder {
    fn build(
        &mut self,
        build_ctx: &mut BuildContext,
        bootstrap_mgr: &mut BootstrapManager,
        blob_mgr: &mut BlobManager,
    ) -> Result<BuildOutput>;
}

fn build_bootstrap(
    ctx: &mut BuildContext,
    bootstrap_mgr: &mut BootstrapManager,
    bootstrap_ctx: &mut BootstrapContext,
    blob_mgr: &mut BlobManager,
    mut tree: Tree,
) -> Result<Bootstrap> {
    // For multi-layer build, merge the upper layer and lower layer with overlay whiteout applied.
    if bootstrap_ctx.layered {
        let mut parent = Bootstrap::load_parent_bootstrap(ctx, bootstrap_mgr, blob_mgr)?;
        timing_tracer!({ parent.merge_overaly(ctx, tree) }, "merge_bootstrap")?;
        tree = parent;
    }

    let mut bootstrap = Bootstrap::new(tree)?;
    timing_tracer!({ bootstrap.build(ctx, bootstrap_ctx) }, "build_bootstrap")?;

    Ok(bootstrap)
}

fn dump_bootstrap(
    ctx: &mut BuildContext,
    bootstrap_mgr: &mut BootstrapManager,
    bootstrap_ctx: &mut BootstrapContext,
    bootstrap: &mut Bootstrap,
    blob_mgr: &mut BlobManager,
    blob_writer: &mut dyn Artifact,
) -> Result<()> {
    // Make sure blob id is updated according to blob hash if not specified by user.
    if let Some((_, blob_ctx)) = blob_mgr.get_current_blob() {
        if blob_ctx.blob_id.is_empty() {
            // `Blob::dump()` should have set `blob_ctx.blob_id` to referenced OCI tarball for
            // ref-type conversion.
            assert!(!ctx.conversion_type.is_to_ref());
            if ctx.blob_inline_meta {
                // Set special blob id for blob with inlined meta.
                blob_ctx.blob_id = "x".repeat(64);
            } else {
                blob_ctx.blob_id = format!("{:x}", blob_ctx.blob_hash.clone().finalize());
            }
        }
        if !ctx.conversion_type.is_to_ref() {
            blob_ctx.compressed_blob_size = blob_writer.pos()?;
        }
    }

    // Dump bootstrap file
    let blob_table = blob_mgr.to_blob_table(ctx)?;
    let storage = &mut bootstrap_mgr.bootstrap_storage;
    bootstrap.dump(ctx, storage, bootstrap_ctx, &blob_table)?;

    // Dump RAFS meta to data blob if inline meta is enabled.
    if ctx.blob_inline_meta {
        assert_ne!(ctx.conversion_type, ConversionType::TarToTarfs);
        // Ensure the blob object is created in case of no chunks generated for the blob.
        let (_, blob_ctx) = blob_mgr
            .get_or_create_current_blob(ctx)
            .map_err(|_e| anyhow!("failed to get current blob object"))?;
        let bootstrap_offset = blob_writer.pos()?;
        let uncompressed_bootstrap = bootstrap_ctx.writer.as_bytes()?;
        let uncompressed_size = uncompressed_bootstrap.len();
        let uncompressed_digest =
            RafsDigest::from_buf(&uncompressed_bootstrap, digest::Algorithm::Sha256);

        // Output uncompressed data for backward compatibility and compressed data for new format.
        let (bootstrap_data, compressor) = if ctx.features.is_enabled(Feature::BlobToc) {
            let mut compressor = compress::Algorithm::Zstd;
            let (compressed_data, compressed) =
                compress::compress(&uncompressed_bootstrap, compressor)
                    .with_context(|| "failed to compress bootstrap".to_string())?;
            blob_ctx.write_data(blob_writer, &compressed_data)?;
            if !compressed {
                compressor = compress::Algorithm::None;
            }
            (compressed_data, compressor)
        } else {
            blob_ctx.write_data(blob_writer, &uncompressed_bootstrap)?;
            (uncompressed_bootstrap, compress::Algorithm::None)
        };

        let compressed_size = bootstrap_data.len();
        blob_ctx.write_tar_header(
            blob_writer,
            toc::TOC_ENTRY_BOOTSTRAP,
            compressed_size as u64,
        )?;

        if ctx.features.is_enabled(Feature::BlobToc) {
            blob_ctx.entry_list.add(
                toc::TOC_ENTRY_BOOTSTRAP,
                compressor,
                uncompressed_digest,
                bootstrap_offset,
                compressed_size as u64,
                uncompressed_size as u64,
            )?;
        }
    }

    Ok(())
}

fn dump_toc(
    ctx: &mut BuildContext,
    blob_ctx: &mut BlobContext,
    blob_writer: &mut dyn Artifact,
) -> Result<()> {
    if ctx.features.is_enabled(Feature::BlobToc) {
        assert_ne!(ctx.conversion_type, ConversionType::TarToTarfs);
        let mut hasher = RafsDigest::hasher(digest::Algorithm::Sha256);
        let data = blob_ctx.entry_list.as_bytes().to_vec();
        let toc_size = data.len() as u64;
        blob_ctx.write_data(blob_writer, &data)?;
        hasher.digest_update(&data);
        let header = blob_ctx.write_tar_header(blob_writer, toc::TOC_ENTRY_BLOB_TOC, toc_size)?;
        hasher.digest_update(header.as_bytes());
        blob_ctx.blob_toc_digest = hasher.digest_finalize().data;
        blob_ctx.blob_toc_size = toc_size as u32 + header.as_bytes().len() as u32;
    }
    Ok(())
}

fn finalize_blob(
    ctx: &mut BuildContext,
    blob_mgr: &mut BlobManager,
    blob_writer: &mut dyn Artifact,
) -> Result<()> {
    if let Some((_, blob_ctx)) = blob_mgr.get_current_blob() {
        let is_tarfs = ctx.conversion_type == ConversionType::TarToTarfs;

        if !is_tarfs {
            dump_toc(ctx, blob_ctx, blob_writer)?;
        }
        if !ctx.conversion_type.is_to_ref() {
            blob_ctx.compressed_blob_size = blob_writer.pos()?;
        }
        if ctx.blob_inline_meta && blob_ctx.blob_id == "x".repeat(64) {
            blob_ctx.blob_id = String::new();
        }

        let hash = blob_ctx.blob_hash.clone().finalize();
        let blob_meta_id = if ctx.blob_id.is_empty() {
            format!("{:x}", hash)
        } else {
            assert!(!ctx.conversion_type.is_to_ref() || is_tarfs);
            ctx.blob_id.clone()
        };

        if ctx.conversion_type.is_to_ref() {
            if blob_ctx.blob_id.is_empty() {
                // Use `sha256(tarball)` as `blob_id`. A tarball without files will fall through
                // this path because `Blob::dump()` hasn't generated `blob_ctx.blob_id`.
                if let Some(zran) = &ctx.blob_zran_generator {
                    let reader = zran.lock().unwrap().reader();
                    blob_ctx.compressed_blob_size = reader.get_data_size();
                    if blob_ctx.blob_id.is_empty() {
                        let hash = reader.get_data_digest();
                        blob_ctx.blob_id = format!("{:x}", hash.finalize());
                    }
                } else if let Some(tar_reader) = &ctx.blob_tar_reader {
                    blob_ctx.compressed_blob_size = tar_reader.position();
                    if blob_ctx.blob_id.is_empty() {
                        let hash = tar_reader.get_hash_object();
                        blob_ctx.blob_id = format!("{:x}", hash.finalize());
                    }
                }
            }
            // Tarfs mode only has tar stream and meta blob, there's no data blob.
            if !ctx.blob_inline_meta && !is_tarfs {
                blob_ctx.blob_meta_digest = hash.into();
                blob_ctx.blob_meta_size = blob_writer.pos()?;
            }
        } else if blob_ctx.blob_id.is_empty() {
            // `blob_ctx.blob_id` should be RAFS blob id.
            blob_ctx.blob_id = blob_meta_id.clone();
        }

        // Tarfs mode directly use the tar file as RAFS data blob, so no need to generate the data
        // blob file.
        if !is_tarfs {
            blob_writer.finalize(Some(blob_meta_id))?;
        }

        if let Some(blob_cache) = ctx.blob_cache_generator.as_ref() {
            blob_cache.finalize(&blob_ctx.blob_id)?;
        }
    }

    Ok(())
}

/// Helper for TarballBuilder/StargzBuilder to build the filesystem tree.
pub struct TarBuilder {
    pub explicit_uidgid: bool,
    pub layer_idx: u16,
    pub version: RafsVersion,
    next_ino: Inode,
}

impl TarBuilder {
    /// Create a new instance of [TarBuilder].
    pub fn new(explicit_uidgid: bool, layer_idx: u16, version: RafsVersion) -> Self {
        TarBuilder {
            explicit_uidgid,
            layer_idx,
            next_ino: 0,
            version,
        }
    }

    /// Allocate an inode number.
    pub fn next_ino(&mut self) -> Inode {
        self.next_ino += 1;
        self.next_ino
    }

    /// Insert a node into the tree, creating any missing intermediate directories.
    pub fn insert_into_tree(&mut self, tree: &mut Tree, node: Node) -> Result<()> {
        let target_paths = node.target_vec();
        let target_paths_len = target_paths.len();

        if target_paths_len == 1 {
            // Handle root node modification
            assert_eq!(node.path(), Path::new("/"));
            tree.set_node(node);
        } else {
            let mut tmp_tree = tree;
            for idx in 1..target_paths.len() {
                match tmp_tree.get_child_idx(target_paths[idx].as_bytes()) {
                    Some(i) => {
                        if idx == target_paths_len - 1 {
                            tmp_tree.children[i].set_node(node);
                            break;
                        } else {
                            tmp_tree = &mut tmp_tree.children[i];
                        }
                    }
                    None => {
                        if idx == target_paths_len - 1 {
                            tmp_tree.insert_child(Tree::new(node));
                            break;
                        } else {
                            let node = self.create_directory(&target_paths[..=idx])?;
                            tmp_tree.insert_child(Tree::new(node));
                            let last_idx = tmp_tree.children.len() - 1;
                            tmp_tree = &mut tmp_tree.children[last_idx];
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Create a new node for a directory.
    pub fn create_directory(&mut self, target_paths: &[OsString]) -> Result<Node> {
        let ino = self.next_ino();
        let name = &target_paths[target_paths.len() - 1];
        let mut inode = InodeWrapper::new(self.version);
        inode.set_ino(ino);
        inode.set_mode(0o755 | libc::S_IFDIR as u32);
        inode.set_nlink(2);
        inode.set_name_size(name.len());
        inode.set_rdev(u32::MAX);

        let source = PathBuf::from("/");
        let target_vec = target_paths.to_vec();
        let mut target = PathBuf::new();
        for name in target_paths.iter() {
            target = target.join(name);
        }
        let info = NodeInfo {
            explicit_uidgid: self.explicit_uidgid,
            src_ino: ino,
            src_dev: u64::MAX,
            rdev: u64::MAX,
            path: target.clone(),
            source,
            target,
            target_vec,
            symlink: None,
            xattrs: RafsXAttrs::new(),
            v6_force_extended_inode: false,
        };

        Ok(Node::new(inode, info, self.layer_idx))
    }

    /// Check whether the path is a eStargz special file.
    pub fn is_stargz_special_files(&self, path: &Path) -> bool {
        path == Path::new("/stargz.index.json")
            || path == Path::new("/.prefetch.landmark")
            || path == Path::new("/.no.prefetch.landmark")
    }
}

#[cfg(test)]
mod tests {
    use vmm_sys_util::tempdir::TempDir;

    use super::*;

    #[test]
    fn test_tar_builder_is_stargz_special_files() {
        let builder = TarBuilder::new(true, 0, RafsVersion::V6);

        let path = Path::new("/stargz.index.json");
        assert!(builder.is_stargz_special_files(&path));
        let path = Path::new("/.prefetch.landmark");
        assert!(builder.is_stargz_special_files(&path));
        let path = Path::new("/.no.prefetch.landmark");
        assert!(builder.is_stargz_special_files(&path));

        let path = Path::new("/no.prefetch.landmark");
        assert!(!builder.is_stargz_special_files(&path));
        let path = Path::new("/prefetch.landmark");
        assert!(!builder.is_stargz_special_files(&path));
        let path = Path::new("/tar.index.json");
        assert!(!builder.is_stargz_special_files(&path));
    }

    #[test]
    fn test_tar_builder_create_directory() {
        let tmp_dir = TempDir::new().unwrap();
        let target_paths = [OsString::from(tmp_dir.as_path())];
        let mut builder = TarBuilder::new(true, 0, RafsVersion::V6);

        let node = builder.create_directory(&target_paths);
        assert!(node.is_ok());
        let node = node.unwrap();
        println!("Node: {}", node);
        assert_eq!(node.file_type(), "dir");
        assert_eq!(node.target(), tmp_dir.as_path());

        assert_eq!(builder.next_ino, 1);
        assert_eq!(builder.next_ino(), 2);
    }
}

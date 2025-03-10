// Copyright (C) 2023 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Generate Chunkdict RAFS bootstrap.
//! -------------------------------------------------------------------------------------------------
//! Bug 1: Inconsistent Chunk Size Leading to Blob Size Less Than 4K(v6_block_size)
//! Description: The size of chunks is not consistent, which results in the possibility that a blob,
//! composed of a group of these chunks, may be less than 4K(v6_block_size) in size.
//! This inconsistency leads to a failure in passing the size check.
//! -------------------------------------------------------------------------------------------------
//! Bug 2: Incorrect Chunk Number Calculation Due to Premature Check Logic
//! Description: The current logic for calculating the chunk number is based on the formula size/chunk size.
//! However, this approach is flawed as it precedes the actual check which accounts for chunk statistics.
//! Consequently, this leads to inaccurate counting of chunk numbers.

use super::core::node::{ChunkSource, NodeInfo};
use super::{BlobManager, Bootstrap, BootstrapManager, BuildContext, BuildOutput, Tree};
use crate::core::node::Node;
use crate::NodeChunk;
use crate::OsString;
use anyhow::{Ok, Result};
use nydus_rafs::metadata::chunk::ChunkWrapper;
use nydus_rafs::metadata::inode::InodeWrapper;
use nydus_rafs::metadata::layout::RafsXAttrs;
use nydus_storage::meta::BlobChunkInfoV1Ondisk;
use nydus_utils::compress::Algorithm;
use nydus_utils::digest::RafsDigest;

use std::mem::size_of;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ChunkdictChunkInfo {
    pub image_reference: String,
    pub version: String,
    pub chunk_blob_id: String,
    pub chunk_digest: String,
    pub chunk_compressed_size: u32,
    pub chunk_uncompressed_size: u32,
    pub chunk_compressed_offset: u64,
    pub chunk_uncompressed_offset: u64,
}

pub struct ChunkdictBlobInfo {
    pub blob_id: String,
    pub blob_compressed_size: u64,
    pub blob_uncompressed_size: u64,
    pub blob_compressor: String,
    pub blob_meta_ci_compressed_size: u64,
    pub blob_meta_ci_uncompressed_size: u64,
    pub blob_meta_ci_offset: u64,
}

/// Struct to generate chunkdict RAFS bootstrap.
pub struct Generator {}

impl Generator {
    // Generate chunkdict RAFS bootstrap.
    pub fn generate(
        ctx: &mut BuildContext,
        bootstrap_mgr: &mut BootstrapManager,
        blob_mgr: &mut BlobManager,
        chunkdict_chunks_origin: Vec<ChunkdictChunkInfo>,
        chunkdict_blobs: Vec<ChunkdictBlobInfo>,
    ) -> Result<BuildOutput> {
        // Validate and remove chunks whose belonged blob sizes are smaller than a block.
        let mut chunkdict_chunks = chunkdict_chunks_origin.to_vec();
        Self::validate_and_remove_chunks(ctx, &mut chunkdict_chunks);
        // Build root tree.
        let mut tree = Self::build_root_tree(ctx)?;

        // Build child tree.
        let child = Self::build_child_tree(ctx, blob_mgr, &chunkdict_chunks, &chunkdict_blobs)?;
        let result = vec![child];
        tree.children = result;

        Self::validate_tree(&tree)?;

        // Build bootstrap.
        let mut bootstrap_ctx = bootstrap_mgr.create_ctx()?;
        let mut bootstrap = Bootstrap::new(tree)?;
        bootstrap.build(ctx, &mut bootstrap_ctx)?;

        let blob_table = blob_mgr.to_blob_table(ctx)?;
        let storage = &mut bootstrap_mgr.bootstrap_storage;
        bootstrap.dump(ctx, storage, &mut bootstrap_ctx, &blob_table)?;

        BuildOutput::new(blob_mgr, &bootstrap_mgr.bootstrap_storage)
    }

    /// Validate tree.
    fn validate_tree(tree: &Tree) -> Result<()> {
        let pre = &mut |t: &Tree| -> Result<()> {
            let node = t.borrow_mut_node();
            debug!("chunkdict tree: ");
            debug!("inode: {}", node);
            for chunk in &node.chunks {
                debug!("\t chunk: {}", chunk);
            }
            Ok(())
        };
        tree.walk_dfs_pre(pre)?;
        debug!("chunkdict tree is valid.");
        Ok(())
    }

    /// Validates and removes chunks with a total uncompressed size smaller than the block size limit.
    fn validate_and_remove_chunks(ctx: &mut BuildContext, chunkdict: &mut Vec<ChunkdictChunkInfo>) {
        let mut chunk_sizes = std::collections::HashMap::new();

        // Accumulate the uncompressed size for each chunk_blob_id.
        for chunk in chunkdict.iter() {
            *chunk_sizes.entry(chunk.chunk_blob_id.clone()).or_insert(0) +=
                chunk.chunk_uncompressed_size as u64;
        }
        // Find all chunk_blob_ids with a total uncompressed size > v6_block_size.
        let small_chunks: Vec<String> = chunk_sizes
            .into_iter()
            .filter(|&(_, size)| size < ctx.v6_block_size())
            .inspect(|(id, _)| {
                eprintln!(
                    "Warning: Blob with id '{}' is smaller than {} bytes.",
                    id,
                    ctx.v6_block_size()
                )
            })
            .map(|(id, _)| id)
            .collect();

        // Retain only chunks with chunk_blob_id that has a total uncompressed size > v6_block_size.
        chunkdict.retain(|chunk| !small_chunks.contains(&chunk.chunk_blob_id));
    }

    /// Build the root tree.
    pub fn build_root_tree(ctx: &mut BuildContext) -> Result<Tree> {
        let mut inode = InodeWrapper::new(ctx.fs_version);
        inode.set_ino(1);
        inode.set_uid(1000);
        inode.set_gid(1000);
        inode.set_projid(0);
        inode.set_mode(0o660 | libc::S_IFDIR as u32);
        inode.set_nlink(3);
        inode.set_name_size("/".len());
        inode.set_rdev(0);
        inode.set_blocks(256);
        let node_info = NodeInfo {
            explicit_uidgid: true,
            src_dev: 0,
            src_ino: 0,
            rdev: 0,
            source: PathBuf::from("/"),
            path: PathBuf::from("/"),
            target: PathBuf::from("/"),
            target_vec: vec![OsString::from("/")],
            symlink: None,
            xattrs: RafsXAttrs::default(),
            v6_force_extended_inode: true,
        };
        let root_node = Node::new(inode, node_info, 0);
        let tree = Tree::new(root_node);
        Ok(tree)
    }

    /// Build the child tree.
    fn build_child_tree(
        ctx: &mut BuildContext,
        blob_mgr: &mut BlobManager,
        chunkdict_chunks: &[ChunkdictChunkInfo],
        chunkdict_blobs: &[ChunkdictBlobInfo],
    ) -> Result<Tree> {
        let mut inode = InodeWrapper::new(ctx.fs_version);
        inode.set_ino(2);
        inode.set_uid(0);
        inode.set_gid(0);
        inode.set_projid(0);
        inode.set_mode(0o660 | libc::S_IFREG as u32);
        inode.set_nlink(1);
        inode.set_name_size("chunkdict".len());
        inode.set_rdev(0);
        inode.set_blocks(256);
        let node_info = NodeInfo {
            explicit_uidgid: true,
            src_dev: 0,
            src_ino: 1,
            rdev: 0,
            source: PathBuf::from("/"),
            path: PathBuf::from("/chunkdict"),
            target: PathBuf::from("/chunkdict"),
            target_vec: vec![OsString::from("/"), OsString::from("/chunkdict")],
            symlink: None,
            xattrs: RafsXAttrs::new(),
            v6_force_extended_inode: true,
        };
        let mut node = Node::new(inode, node_info, 0);

        // Insert chunks.
        Self::insert_chunks(ctx, blob_mgr, &mut node, chunkdict_chunks, chunkdict_blobs)?;
        let node_size: u64 = node
            .chunks
            .iter()
            .map(|chunk| chunk.inner.uncompressed_size() as u64)
            .sum();
        node.inode.set_size(node_size);

        // Update child count.
        node.inode.set_child_count(node.chunks.len() as u32);
        let child = Tree::new(node);
        child
            .borrow_mut_node()
            .v5_set_dir_size(ctx.fs_version, &child.children);
        Ok(child)
    }

    /// Insert chunks.
    fn insert_chunks(
        ctx: &mut BuildContext,
        blob_mgr: &mut BlobManager,
        node: &mut Node,
        chunkdict_chunks: &[ChunkdictChunkInfo],
        chunkdict_blobs: &[ChunkdictBlobInfo],
    ) -> Result<()> {
        for (index, chunk_info) in chunkdict_chunks.iter().enumerate() {
            let chunk_size: u32 = chunk_info.chunk_compressed_size;
            let file_offset = index as u64 * chunk_size as u64;
            let mut chunk = ChunkWrapper::new(ctx.fs_version);

            // Update blob context.
            let (blob_index, blob_ctx) =
                blob_mgr.get_or_cerate_blob_for_chunkdict(ctx, &chunk_info.chunk_blob_id)?;
            let chunk_uncompressed_size = chunk_info.chunk_uncompressed_size;
            let pre_d_offset = blob_ctx.current_uncompressed_offset;
            blob_ctx.uncompressed_blob_size = pre_d_offset + chunk_uncompressed_size as u64;
            blob_ctx.current_uncompressed_offset += chunk_uncompressed_size as u64;

            blob_ctx.blob_meta_header.set_ci_uncompressed_size(
                blob_ctx.blob_meta_header.ci_uncompressed_size()
                    + size_of::<BlobChunkInfoV1Ondisk>() as u64,
            );
            blob_ctx.blob_meta_header.set_ci_compressed_size(
                blob_ctx.blob_meta_header.ci_uncompressed_size()
                    + size_of::<BlobChunkInfoV1Ondisk>() as u64,
            );
            let chunkdict_blob_info = chunkdict_blobs
                .iter()
                .find(|blob| blob.blob_id == chunk_info.chunk_blob_id)
                .unwrap();
            blob_ctx.blob_compressor =
                Algorithm::from_str(chunkdict_blob_info.blob_compressor.as_str())?;
            blob_ctx
                .blob_meta_header
                .set_ci_uncompressed_size(chunkdict_blob_info.blob_meta_ci_uncompressed_size);
            blob_ctx
                .blob_meta_header
                .set_ci_compressed_size(chunkdict_blob_info.blob_meta_ci_compressed_size);
            blob_ctx
                .blob_meta_header
                .set_ci_compressed_offset(chunkdict_blob_info.blob_meta_ci_offset);
            blob_ctx.blob_meta_header.set_ci_compressor(Algorithm::Zstd);

            // Update chunk context.
            let chunk_index = blob_ctx.alloc_chunk_index()?;
            chunk.set_blob_index(blob_index);
            chunk.set_index(chunk_index);
            chunk.set_file_offset(file_offset);
            chunk.set_compressed_size(chunk_info.chunk_compressed_size);
            chunk.set_compressed_offset(chunk_info.chunk_compressed_offset);
            chunk.set_uncompressed_size(chunk_info.chunk_uncompressed_size);
            chunk.set_uncompressed_offset(chunk_info.chunk_uncompressed_offset);
            chunk.set_id(RafsDigest::from_string(&chunk_info.chunk_digest));
            // TODO: set crc32 of chunk.

            node.chunks.push(NodeChunk {
                source: ChunkSource::Build,
                inner: Arc::new(chunk.clone()),
            });
        }
        Ok(())
    }
}

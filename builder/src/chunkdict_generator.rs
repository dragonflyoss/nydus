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
use crate::core::blob::Blob;
use crate::core::node::Node;
use crate::core::prefetch;
use crate::TreeNode;
use crate::{ArtifactWriter, BlobContext, NodeChunk};
use anyhow::{Ok, Result};
use nydus_rafs::metadata::chunk::ChunkWrapper;
use nydus_rafs::metadata::inode::InodeWrapper;
use nydus_rafs::metadata::layout::v6::RafsV6BlobTable;
use nydus_rafs::metadata::layout::{RafsBlobTable, RafsXAttrs};
use nydus_storage::device::{BlobFeatures, BlobInfo};
use nydus_storage::meta::BatchContextGenerator;
use nydus_storage::meta::BlobChunkInfoV1Ondisk;
use nydus_utils::compress;
use nydus_utils::compress::Algorithm;
use nydus_utils::digest::RafsDigest;
use sha2::digest::Update;

use crate::finalize_blob;
use crate::Artifact;
use core::panic;
use std::borrow::BorrowMut;
use std::ffi::OsString;
use std::fs::File;
use std::io::{Read, Seek, Write};
use std::mem::size_of;
use std::ops::Add;
use std::ops::{Rem, Sub};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::u32;

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

// TODO(daiyongxuan): implement Read Trait for BlobNodeReader
#[derive(Debug)]
#[allow(dead_code)]
pub struct BlobNodeReader {
    blob: Arc<File>,
    start: u64,
    end: u64,
    position: u64,
}

impl BlobNodeReader {
    pub fn new(blob: Arc<File>, start: u64, end: u64) -> Result<Self> {
        let mut reader = BlobNodeReader {
            blob,
            start,
            end,
            position: start,
        };
        reader.blob.seek(std::io::SeekFrom::Start(start))?;
        Ok(reader)
    }
}

impl Read for BlobNodeReader {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, std::io::Error> {
        // EOF
        if self.position > self.end {
            return std::io::Result::Ok(0);
        }
        let max_read = (self.end - self.position) as usize;
        let to_read = std::cmp::min(buf.len(), max_read);
        let bytes_read = self.blob.read(&mut buf[..to_read])?;
        self.position += bytes_read as u64;
        std::io::Result::Ok(bytes_read)
    }
}

/// Struct to generate chunkdict RAFS bootstrap.
pub struct Generator {}

#[allow(dead_code)]
struct BlobIdAndCompressor {
    pub blob_id: String,
    pub compressor: compress::Algorithm,
}

struct PrefetchBlobState {
    blob_info: BlobInfo,
    blob_ctx: BlobContext,
    blob_writer: Box<dyn Artifact>,
    chunk_count: u32,
    blob_offset: u64,
    meta_uncompressed_size: u64,
    chunk_index: u32,
}

impl PrefetchBlobState {
    fn new(ctx: &BuildContext, blob_layer_num: u32, blobs_dir_path: &PathBuf) -> Result<Self> {
        let blob_info = BlobInfo::new(
            blob_layer_num,
            String::from("Prefetch-blob"),
            0,
            0,
            ctx.chunk_size,
            u32::MAX,
            BlobFeatures::ALIGNED
                | BlobFeatures::INLINED_CHUNK_DIGEST
                | BlobFeatures::HAS_TAR_HEADER
                | BlobFeatures::HAS_TOC
                | BlobFeatures::CAP_TAR_TOC,
        );
        let mut blob_ctx = BlobContext::from(ctx, &blob_info, ChunkSource::Build)?;
        blob_ctx.chunk_count = 0;
        blob_ctx.blob_meta_info_enabled = true;
        let blob_writer = ArtifactWriter::new(crate::ArtifactStorage::SingleFile(
            blobs_dir_path.join("Prefetch-blob"),
        ))
        .map(|writer| Box::new(writer) as Box<dyn Artifact>)?;
        Ok(Self {
            blob_info,
            blob_ctx,
            blob_writer,
            chunk_count: 0,
            blob_offset: 0,
            meta_uncompressed_size: 0,
            chunk_index: 0,
        })
    }
}

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

    /// Generate a new bootstrap for prefetch.
    pub fn generate_prefetch(
        tree: &mut Tree,
        ctx: &mut BuildContext,
        bootstrap_mgr: &mut BootstrapManager,
        blobtable: &mut RafsV6BlobTable,
        blobs_dir_path: PathBuf,
        prefetch_nodes: Vec<TreeNode>,
    ) -> Result<()> {
        // let mut prefetch_state =
        //     PrefetchBlobState::new(ctx, blobtable.entries.len() as u32, &blobs_dir_path);
        // let mut batch = BatchContextGenerator::new(4096).unwrap();
        // unimplemented!();
        // create a new blob for prefetch layer
        let blob_layer_num = blobtable.entries.len();
        // TODO: Add Appropriate BlobFeatures
        let mut prefetch_blob_info = BlobInfo::new(
            blob_layer_num as u32,
            String::from("Prefetch-blob"),
            0,
            0,
            ctx.chunk_size,
            // If chunkcount is zero, it will add a feature
            u32::MAX,
            BlobFeatures::ALIGNED
                | BlobFeatures::INLINED_CHUNK_DIGEST
                | BlobFeatures::HAS_TAR_HEADER
                | BlobFeatures::HAS_TOC
                | BlobFeatures::CAP_TAR_TOC,
        );

        // for every node in prefetch list, change the offset and blob id

        let mut blobs_id_and_compressor: Vec<BlobIdAndCompressor> = Vec::new();
        for blob in &blobtable.entries {
            blobs_id_and_compressor.push(BlobIdAndCompressor {
                blob_id: blob.blob_id(),
                compressor: blob.compressor(),
            });
        }

        let prefetch_blob_index = prefetch_blob_info.blob_index();
        let mut chunk_count = 0;
        // For every chunk, need to align to 4k
        let mut prefetch_blob_offset = 0;
        let mut meta_uncompressed_size = 0;
        let mut chunk_index_in_prefetch = 0;

        // Create a new blob for prefetch layer
        let mut prefetch_blob_ctx =
            BlobContext::from(ctx, &prefetch_blob_info, ChunkSource::Build).unwrap();
        prefetch_blob_ctx.chunk_count = 0;
        let encrypted = prefetch_blob_ctx.blob_compressor != compress::Algorithm::None;
        let mut batch = BatchContextGenerator::new(4096).unwrap();
        prefetch_blob_ctx.blob_meta_info_enabled = true;
        debug!(
            "Prefetch blob ctx meta len: {}",
            prefetch_blob_ctx.blob_meta_info.len()
        );
        let blob_writer = ArtifactWriter::new(crate::ArtifactStorage::SingleFile(
            blobs_dir_path.clone().join("Prefetch-blob"),
        ))
        .expect("Failed to create ArtifactWriter");

        let mut blob_writer: Box<dyn Artifact> = Box::new(blob_writer);
        for node in &prefetch_nodes {
            let child = tree.get_node_mut(&node.borrow().path()).unwrap();
            let mut child  = child.node.as_ref().borrow_mut();
            let index = child.chunks.first().unwrap().inner.blob_index();
            let blob_id = blobs_id_and_compressor
                .get(index as usize)
                .unwrap()
                .blob_id
                .clone();
            let blob_file = blobs_dir_path.clone().join(blob_id);
            let blob_file = Arc::new(File::open(blob_file).unwrap());
            child.layer_idx = prefetch_blob_index as u16;
            for chunk in &mut child.chunks {
                // TODO(daiyongxuan): Dump Blob Dirrectly.
                // Use BlobReader::read
                chunk_count += 1;
                let inner = Arc::make_mut(&mut chunk.inner);
                let mut reader = BlobNodeReader::new(
                    Arc::clone(&blob_file),
                    inner.compressed_offset(),
                    inner.compressed_offset() + inner.compressed_size() as u64,
                )
                .unwrap();
                let buf = &mut vec![0u8; inner.compressed_size() as usize];
                reader.read_exact(buf).unwrap();
                blob_writer.write_all(buf).unwrap();

                let info = batch
                    .generate_chunk_info(
                        prefetch_blob_ctx.current_compressed_offset,
                        prefetch_blob_ctx.current_uncompressed_offset,
                        inner.uncompressed_size() as u32,
                        encrypted,
                    )
                    .unwrap();
                debug!(
                    "Prefetch blob ctx meta len: {}",
                    prefetch_blob_ctx.blob_meta_info.len()
                );

                inner.set_blob_index(prefetch_blob_index);
                inner.set_index(chunk_index_in_prefetch);
                chunk_index_in_prefetch += 1;
                inner.set_compressed_offset(prefetch_blob_offset);
                inner.set_uncompressed_offset(prefetch_blob_offset);
                let aligned_d_size: u64 =
                    nydus_utils::try_round_up_4k(inner.uncompressed_size()).unwrap();
                prefetch_blob_ctx.uncompressed_blob_size += aligned_d_size;
                prefetch_blob_ctx.current_compressed_offset += inner.compressed_size() as u64;
                prefetch_blob_ctx.compressed_blob_size += inner.compressed_size() as u64;
                prefetch_blob_ctx.blob_hash.update(&buf);
                debug!(
                    "Prefetch blob ctx meta len: {}",
                    prefetch_blob_ctx.blob_meta_info.len()
                );

                prefetch_blob_ctx
                    .add_chunk_meta_info(inner, Some(info))
                    .unwrap();
                prefetch_blob_ctx.chunk_count += 1;
                prefetch_blob_offset += inner.uncompressed_size() as u64;
                meta_uncompressed_size += inner.uncompressed_size() as u64;
                prefetch_blob_offset = Self::align_to_4k(prefetch_blob_offset);
                // set meta ci data
                prefetch_blob_info.set_meta_ci_uncompressed_size(
                    (prefetch_blob_info.meta_ci_uncompressed_size()
                        + size_of::<BlobChunkInfoV1Ondisk>() as u64) as usize,
                );
                prefetch_blob_info.set_meta_ci_compressed_size(
                    (prefetch_blob_info.meta_ci_compressed_size()
                        + size_of::<BlobChunkInfoV1Ondisk>() as u64) as usize,
                );
            }
        }
        // align prefetch blob size to 4096
        prefetch_blob_info.set_meta_ci_offset(0x200 + meta_uncompressed_size as usize);
        prefetch_blob_info.set_chunk_count(chunk_count as usize);
        prefetch_blob_info.set_compressed_size(prefetch_blob_offset as usize);
        prefetch_blob_info.set_uncompressed_size(prefetch_blob_offset as usize);
        prefetch_blob_info.set_compressor(Algorithm::Zstd);

        let mut blob_table_withprefetch = RafsV6BlobTable::new();
        for blob in blobtable.entries.iter() {
            blob_table_withprefetch.entries.push(blob.clone());
        }
        blob_table_withprefetch
            .entries
            .push(prefetch_blob_info.clone().into());

        // Build Prefetch Blob
        let mut prefetch_build_ctx = BuildContext {
            blob_id: String::from("Prefetch-blob"),
            // To Avoid Compress Twice.
            compressor: compress::Algorithm::Zstd,
            prefetch: ctx.prefetch.clone(),
            blob_inline_meta: true,
            ..Default::default()
        };

        let mut prefetch_blob_mgr = BlobManager::new(nydus_utils::digest::Algorithm::Blake3);

        prefetch_blob_mgr.add_blob(prefetch_blob_ctx);
        prefetch_blob_mgr.set_current_blob_index(0);
        if let Some((_, blob_ctx)) = prefetch_blob_mgr.get_current_blob() {
            blob_ctx.set_meta_info_enabled(true);
        }

        Blob::finalize_blob_data(
            &prefetch_build_ctx,
            &mut prefetch_blob_mgr,
            blob_writer.as_mut(),
        )
        .unwrap();

        if let Some((_, blob_ctx)) = prefetch_blob_mgr.get_current_blob() {
            blob_ctx.set_meta_info_enabled(true);
            Blob::dump_meta_data(&prefetch_build_ctx, blob_ctx, blob_writer.as_mut()).unwrap();
        } else {
            panic!();
        }
        // replace the prefetch build ctx blod id to empty
        // to generate blob id
        prefetch_build_ctx.blob_id = String::from("");
        prefetch_blob_mgr.get_current_blob().unwrap().1.blob_id = String::from("");
        finalize_blob(
            &mut prefetch_build_ctx,
            &mut prefetch_blob_mgr,
            blob_writer.as_mut(),
        )?;
        debug!("prefetch blob id: {}", prefetch_build_ctx.blob_id);
        // Build bootstrap
        let mut bootstrap_ctx = bootstrap_mgr.create_ctx().unwrap();

        let mut bootstrap = Bootstrap::new(tree.clone()).unwrap();

        bootstrap.build(ctx, &mut bootstrap_ctx).unwrap();

        // The prefetch blob id generated, Rewrite
        let updated_entries: Vec<Arc<BlobInfo>> = blob_table_withprefetch
            .entries
            .iter()
            .map(|blobinfo| {
                if blobinfo.blob_id() == "Prefetch-blob" {
                    let mut prefetch_blob_info = (**blobinfo).clone();
                    prefetch_blob_info.set_blob_id(prefetch_build_ctx.blob_id.clone());
                    Arc::new(prefetch_blob_info)
                } else {
                    Arc::clone(blobinfo)
                }
            })
            .collect();
        blob_table_withprefetch.entries = updated_entries;
        // Dump Bootstrap
        let storage = &mut bootstrap_mgr.bootstrap_storage;
        let blob_table_withprefetch = RafsBlobTable::V6(blob_table_withprefetch);
        bootstrap.dump(ctx, storage, &mut bootstrap_ctx, &blob_table_withprefetch)?;
        Ok(())
    }

    fn process_prefetch_node(
        tree: &mut Tree,
        node: &TreeNode,
        prefetch_state: &mut PrefetchBlobState,
        batch: &BatchContextGenerator,
        blobtable: &RafsV6BlobTable,
        blobs_dir_path: &PathBuf,
    ) {
        let node = tree.get_node(&node.borrow().path()).unwrap();
        // let mut node = node.node.borrow_mut();
    }

    fn align_to_4k<T>(offset: T) -> T
    where
        T: Sub<Output = T> + Add<Output = T> + Rem<Output = T> + PartialEq + TryFrom<u64> + Copy,
        <T as TryFrom<u64>>::Error: std::fmt::Debug,
    {
        let alignment = T::try_from(4096).unwrap();
        let remainder = offset % alignment;
        if remainder == T::try_from(0).unwrap() {
            offset
        } else {
            offset + (alignment - remainder)
        }
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

            node.chunks.push(NodeChunk {
                source: ChunkSource::Build,
                inner: Arc::new(chunk.clone()),
            });
        }
        Ok(())
    }
}

// Read the blob, get the chunk, fix dump node chunk function, Blob::dump generate a blob

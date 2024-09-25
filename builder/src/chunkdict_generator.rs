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
use crate::{ArtifactWriter, BlobContext, NodeChunk};
use anyhow::{Ok, Result};
use nydus_api::BackendConfigV2;
use nydus_rafs::metadata::chunk::ChunkWrapper;
use nydus_rafs::metadata::inode::InodeWrapper;
use nydus_rafs::metadata::layout::v6::RafsV6BlobTable;
use nydus_rafs::metadata::layout::{RafsBlobTable, RafsXAttrs};
use nydus_storage::device::{BlobFeatures, BlobInfo};
use nydus_storage::factory::BlobFactory;
use nydus_storage::meta::BlobChunkInfoV1Ondisk;
use nydus_utils::compress;
use nydus_utils::compress::Algorithm;
use nydus_utils::digest::RafsDigest;
use tempfile::TempDir;

use crate::finalize_blob;
use crate::Artifact;
use core::panic;
use std::ffi::OsString;
use std::fs::File;
use std::io::Write;
use std::mem::size_of;
use std::ops::Add;
use std::ops::{Rem, Sub};
use std::path::PathBuf;
use std::rc::Rc;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::u32;
use zstd::decode_all;

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

struct BlobIdAndCompressor {
    pub blob_id: String,
    pub compressor: compress::Algorithm,
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
        blobs_dir_path: PathBuf
    ) -> Result<()> {
        let (prefetch_nodes, _) = ctx.prefetch.get_file_nodes();
        for node in prefetch_nodes {
            let node = node.lock().unwrap();
            match node.inode {
                InodeWrapper::Ref(_) => {
                    debug!("Node Wrapper: Reference")
                }
                _ => {
                    debug!("Not Reference")
                }
            }
        }

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
        let (file_nodes_prefetch, _) = ctx.prefetch.get_file_nodes();

        let mut backend_config = BackendConfigV2 {
            backend_type: String::from("localfs"),
            localdisk: None,
            localfs: Some(nydus_api::LocalFsConfig {
                dir: blobs_dir_path.display().to_string(),
                alt_dirs: Vec::new(),
                ..Default::default()
            }),
            oss: None,
            s3: None,
            registry: None,
            http_proxy: None,
        };

        // Revert files
        let mut blobs_id_and_compressor: Vec<BlobIdAndCompressor> = Vec::new();
        for blob in &blobtable.entries {
            blobs_id_and_compressor.push(BlobIdAndCompressor {
                blob_id: blob.blob_id(),
                compressor: blob.compressor(),
            });
        }

        let tmp_dir = TempDir::new().unwrap();
        let tmp_path = tmp_dir.into_path();
        debug!("temp path: {}", tmp_path.display());

        Self::revert_files(
            blobs_id_and_compressor,
            file_nodes_prefetch.clone(),
            &mut backend_config,
            tmp_path.clone(),
        );

        let prefetch_blob_index = prefetch_blob_info.blob_index();
        let mut chunk_count = 0;
        // For every chunk, need to align to 4k
        let mut prefetch_blob_offset = 0;
        let mut meta_uncompressed_size = 0;
        let mut chunk_index_in_prefetch = 0;
        for node in &file_nodes_prefetch {
            let child = tree.get_node(&node.lock().unwrap().path()).unwrap();
            let mut child = child.node.lock().unwrap();
            child.layer_idx = prefetch_blob_index as u16;
            for chunk in &mut child.chunks {
                chunk_count += 1;
                let inner = Arc::make_mut(&mut chunk.inner);
                inner.set_blob_index(prefetch_blob_index);
                inner.set_index(chunk_index_in_prefetch);
                chunk_index_in_prefetch += 1;
                inner.set_compressed_offset(prefetch_blob_offset);
                inner.set_uncompressed_offset(prefetch_blob_offset);
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
        prefetch_blob_info.set_chunk_count(chunk_count);
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
            compressor: ctx.compressor,
            prefetch: ctx.prefetch.clone(),
            ..Default::default()
        };

        let mut prefetch_blob_mgr = BlobManager::new(nydus_utils::digest::Algorithm::Blake3);
        // prefetch_blob_mgr.set_current_blob_index(0);
        let mut prefetch_blob_ctx =
            BlobContext::from(&prefetch_build_ctx, &prefetch_blob_info, ChunkSource::Build)
                .unwrap();
        prefetch_blob_ctx.blob_meta_info_enabled = true;
        prefetch_blob_mgr.add_blob(prefetch_blob_ctx);

        let mut blob_writer: Box<dyn Artifact> = Box::new(
            Box::new(ArtifactWriter::new(crate::ArtifactStorage::SingleFile(
                PathBuf::from("./prefetch_blob"),
            )))
            .unwrap(),
        );
        Blob::dump(
            &prefetch_build_ctx,
            &mut prefetch_blob_mgr,
            &mut *blob_writer,
            Some(tmp_path),
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
                if blobinfo.blob_id() == String::from("Prefetch-blob") {
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

    /// Revert files from the blob
    fn revert_files(
        blob_ids: Vec<BlobIdAndCompressor>,
        nodes: Vec<Rc<Mutex<Node>>>,
        backend: &mut BackendConfigV2,
        workdir: PathBuf,
    ) {
        debug!("BackEnd: {:?}", backend);
        for node in nodes {
            let node = node.lock().unwrap();
            let blob_id = node.chunks.get(0).unwrap().inner.blob_index();
            let blob_id = blob_ids.get(blob_id as usize).unwrap().blob_id.clone();
            // backend.localfs.unwrap().blob_file = 
            let mut node_backend = backend.clone();
            let blob_dir = backend.localfs.as_ref().unwrap().dir.clone();
            let mut blob_file = PathBuf::from(blob_dir);
            blob_file.push(blob_id);
            if let Some(localfs_config) = &mut node_backend.localfs {
                localfs_config.blob_file = blob_file.display().to_string();
            }
            
            let blob_mgr = BlobFactory::new_backend(&node_backend, "Fix-Prefetch-Blob-ID").unwrap();

            debug!("Node Path: {}", node.path().display());
            let mut path = PathBuf::from(&workdir);
            path.push(node.path().strip_prefix("/").unwrap());
            let mut file = File::create(path).unwrap();
            for chunk in &node.chunks {
                let inner = &chunk.inner;
                // Read From Blob
                let blob_index = inner.blob_index();
                debug!("blob index: {}", blob_index);
                let BlobIdAndCompressor {
                    blob_id,
                    compressor,
                } = blob_ids.get(blob_index as usize).unwrap();

                let reader = blob_mgr.get_reader(blob_id.as_ref()).unwrap();
                debug!("blob id: {}", blob_id);
                let compressed_size = inner.compressed_size();
                debug!("compressed size as u8: {}", compressed_size as u8);
                let mut buf: Vec<u8> = vec![0; compressed_size as usize];
                debug!("buf len: {}", buf.len());
                let compressed_offset = inner.compressed_offset();
                debug!("compressed {}/{}", compressed_size, compressed_offset);
                let size = reader.read(&mut buf, compressed_offset).unwrap();
                debug!("size: {}", size);
                debug!("buf len: {}", buf.len());
                match compressor {
                    Algorithm::Zstd => {
                        let revert = Self::decompress_zstd(&buf).unwrap();
                        debug!("Revert size: {}", revert.len());
                        file.write_all(&revert).unwrap();
                    }
                    _ => unimplemented!(),
                }
            }
        }
    }

    fn decompress_zstd(compressed: &[u8]) -> Result<Vec<u8>> {
        Ok(decode_all(compressed)?)
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
            let node = t.lock_node();
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
            .lock_node()
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

#[cfg(test)]
mod test {
    use std::env;

    use nydus_rafs::fs::Rafs;

    use crate::{core::prefetch, Features, Prefetch};

    use super::*;

    #[test]
    fn test_backend() {
        println!("current dir: {}", env::current_dir().unwrap().display());
        let backend_config = BackendConfigV2 {
            backend_type: String::from("localfs"),
            localdisk: None,
            localfs: Some(nydus_api::LocalFsConfig {
                blob_file: String::from("/root/nydusTestImage/test-image/blobs/f22c9758339fcf8fe77a4ca0b4deba2ededad9904bdf8e520df2c0277e666070"),
                dir: String::from("/root/nydusTestImage/test-image/blobs/"),
                alt_dirs: Vec::new(),
            }),
            oss: None,
            s3: None,
            registry: None,
            http_proxy: None,
        };

        let blob_mgr = BlobFactory::new_backend(&backend_config, "Fix-Prefetch-Blob-ID").unwrap();
        let reader = blob_mgr
            .get_reader("f22c9758339fcf8fe77a4ca0b4deba2ededad9904bdf8e520df2c0277e666070")
            .unwrap();
        println!("Reader Done");
        let mut buf2: Vec<u8> = vec![0; 19];
        let size = reader.read(&mut buf2, 19).unwrap();
        println!("size: {}", size);
        println!("buf len: {}", buf2.len());

        let revert = Generator::decompress_zstd(&buf2).unwrap();
        println!("len: {}", revert.len());

        let mut buf: Vec<u8> = vec![0; 19];
        let size = reader.read(&mut buf, 0).unwrap();
        println!("size: {}", size);

        let revert = Generator::decompress_zstd(&buf).unwrap();
        println!("len: {}", revert.len());
    }
}

// Read the blob, get the chunk, fix dump node chunk function, Blob::dump generate a blob

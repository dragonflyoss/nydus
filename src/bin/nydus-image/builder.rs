// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Bootstrap and blob file builder for RAFS format

use std::ffi::{CString, OsString};
use std::fs::{remove_file, File, OpenOptions};
use std::io::{BufWriter, Write};
use std::mem::size_of;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::AsRawFd;
use std::path::PathBuf;

use anyhow::{Context, Result};
use sha2::digest::Digest;
use sha2::Sha256;

use rafs::metadata::layout::*;
use rafs::metadata::{RafsMode, RafsStore, RafsSuper};
use vmm_sys_util::tempfile::TempFile;

use nydus_utils::digest::{self, RafsDigest};

use crate::core::context::{BuildContext, SourceType, BUF_WRITER_CAPACITY};
use crate::core::prefetch::PrefetchPolicy;
use crate::node::*;
use crate::stargz;
use crate::tree::Tree;

pub struct BlobBufferWriter {
    parent_dir: Option<File>,
    file: BufWriter<File>,
    blob_stor: BlobStorage,
    // Keep this because tmp file will be removed automatically when it is dropped.
    // But we will rename/link the tmp file before it is removed.
    _tmp_file: Option<TempFile>,
}

#[derive(Debug)]
pub enum BlobStorage {
    // Won't rename user's specification
    SingleFile(PathBuf),
    // Will rename it from tmp file as user didn't specify a
    BlobsDir(PathBuf),
}

impl BlobBufferWriter {
    pub fn new(blob_stor: BlobStorage) -> Result<Self> {
        match blob_stor {
            BlobStorage::SingleFile(ref p) => {
                let b = BufWriter::with_capacity(
                    BUF_WRITER_CAPACITY,
                    OpenOptions::new()
                        .write(true)
                        .create(true)
                        .truncate(true)
                        .open(p)?,
                );
                Ok(Self {
                    file: b,
                    parent_dir: None,
                    blob_stor,
                    _tmp_file: None,
                })
            }
            BlobStorage::BlobsDir(ref p) => {
                // Better we can use open(2) O_TMPFILE, but for compatibility sake, we delay this job.
                // TODO: Blob dir existence?
                let tmp = TempFile::new_in(&p)?;
                Ok(Self {
                    file: BufWriter::with_capacity(
                        BUF_WRITER_CAPACITY,
                        // Safe to unwrap because it should not be a bad fd.
                        tmp.as_file().try_clone().unwrap(),
                    ),
                    parent_dir: Some(File::open(p)?),
                    blob_stor,
                    _tmp_file: Some(tmp),
                })
            }
        }
    }

    pub fn write_all(&mut self, buf: &[u8]) -> Result<()> {
        self.file.write_all(buf).map_err(|e| anyhow!(e))
    }

    fn release(self, new_name: Option<&str>) -> Result<()> {
        let mut f = self.file.into_inner()?;
        f.flush()?;

        if let Some(name) = new_name {
            if let BlobStorage::BlobsDir(_s) = &self.blob_stor {
                let empty = CString::default();
                // Safe because this doesn't modify any memory and we check the return value.
                // Being used fd never be closed before.
                let res = unsafe {
                    libc::linkat(
                        f.as_raw_fd(),
                        empty.as_ptr(),
                        // Safe because it is using BlobsDir storage.
                        self.parent_dir.unwrap().as_raw_fd(),
                        CString::new(name)?.as_ptr(),
                        libc::AT_EMPTY_PATH,
                    )
                };

                if res < 0 {
                    bail!(
                        "Rename blob to {} failed. error: {:?} ",
                        &name,
                        last_error!()
                    );
                }
            }
        } else if let BlobStorage::SingleFile(s) = &self.blob_stor {
            // `new_name` is None means no blob is really built, perhaps due to dedup.
            // We don't want to puzzle user, so delete it from here.
            // In the future, FIFO could be leveraged, don't remove it then.
            remove_file(s)?;
        }

        Ok(())
    }
}

pub struct Builder {
    blob_size: usize,
}

impl Builder {
    #[allow(clippy::too_many_arguments)]
    pub fn new() -> Result<Self> {
        Ok(Self { blob_size: 0 })
    }

    /// Traverse node tree, set inode index, ino, child_index and
    /// child_count etc according to RAFS format, then store to nodes collection.
    fn build_rafs(&mut self, ctx: &mut BuildContext, tree: &mut Tree, nodes: &mut Vec<Node>) {
        // FIX: Insert parent inode to inode map to keep correct inodes count in superblock.
        let inode_map = if tree.node.overlay.lower_layer() {
            &mut ctx.lower_inode_map
        } else {
            &mut ctx.upper_inode_map
        };
        inode_map.insert((tree.node.real_ino, tree.node.dev), vec![tree.node.index]);

        let index = nodes.len() as u64;
        let parent = &mut nodes[tree.node.index as usize - 1];

        if parent.is_dir() {
            parent.inode.i_child_index = index as u32 + 1;
            parent.inode.i_child_count = tree.children.len() as u32;
        }

        let parent_ino = parent.inode.i_ino;

        // Cache dir tree for BFS walk
        let mut dirs: Vec<&mut Tree> = Vec::new();

        // Sort children list by name,
        // so that we can improve performance in fs read_dir using binary search.
        tree.children
            .sort_by_key(|child| child.node.name().to_os_string());

        for child in tree.children.iter_mut() {
            let index = nodes.len() as u64 + 1;
            child.node.index = index;
            child.node.inode.i_parent = parent_ino;

            // Hardlink handle, all hardlink nodes' ino, nlink should be the same,
            // because the real_ino may be conflicted between different layers,
            // so we need to find hardlink node index list in the layer where the node is located.
            let inode_map = if child.node.overlay.lower_layer() {
                &mut ctx.lower_inode_map
            } else {
                &mut ctx.upper_inode_map
            };
            if let Some(indexes) = inode_map.get_mut(&(child.node.real_ino, child.node.dev)) {
                indexes.push(index);
                let first_index = indexes.first().unwrap();
                let nlink = indexes.len() as u32;
                child.node.inode.i_ino = *first_index;
                child.node.inode.i_nlink = nlink;
                // Update nlink for previous hardlink inodes
                for idx in indexes {
                    if index == *idx {
                        continue;
                    }
                    nodes[*idx as usize - 1].inode.i_nlink = nlink;
                }
            } else {
                child.node.inode.i_ino = index;
                child.node.inode.i_nlink = 1;
                // Store inode real ino
                inode_map.insert(
                    (child.node.real_ino, child.node.dev),
                    vec![child.node.index],
                );
            }

            // Store node for bootstrap & blob dump.
            // Put the whiteout file of upper layer in the front of node list for layered build,
            // so that it can be applied to the node tree of lower layer first than other files of upper layer.
            match (
                &ctx.f_parent_bootstrap,
                child.node.whiteout_type(&ctx.whiteout_spec),
            ) {
                (Some(_), Some(whiteout_type)) => {
                    // For the overlayfs opaque, we need to remove the lower node that has the same name
                    // first, then apply upper node to the node tree of lower layer.
                    nodes.insert(0, child.node.clone());
                    if whiteout_type == WhiteoutType::OverlayFSOpaque {
                        child
                            .node
                            .remove_xattr(&OsString::from(OVERLAYFS_WHITEOUT_OPAQUE));
                        nodes.push(child.node.clone());
                    }
                }
                (None, Some(whiteout_type)) => {
                    // Remove overlayfs opaque xattr for single layer build
                    if whiteout_type == WhiteoutType::OverlayFSOpaque {
                        child
                            .node
                            .remove_xattr(&OsString::from(OVERLAYFS_WHITEOUT_OPAQUE));
                    }
                    nodes.push(child.node.clone());
                }
                _ => {
                    nodes.push(child.node.clone());
                }
            }

            ctx.prefetch.insert_if_need(&child.node);

            if child.node.is_dir() {
                dirs.push(child);
            }
        }

        // According to filesystem semantics, a parent dir should have nlink equal to
        // 2 plus the number of its child directory. And in case of layered build,
        // updating parent directory's nlink here is reliable since builder re-constructs
        // the entire tree and intends to layout all inodes into a plain array fetching
        // from the previously applied tree.
        if tree.node.is_dir() {
            let parent_dir = &mut nodes[tree.node.index as usize - 1];
            parent_dir.inode.i_nlink = (2 + dirs.len()) as u32;
        }

        for dir in dirs {
            self.build_rafs(ctx, dir, nodes);
        }
    }

    fn build_rafs_wrap(&mut self, mut ctx: &mut BuildContext, mut tree: &mut Tree) {
        let index = RAFS_ROOT_INODE;
        tree.node.index = index;
        tree.node.inode.i_ino = index;

        // Filesystem walking skips root inode within subsequent while loop, however, we allow
        // user to pass the source root as prefetch hint. Check it here.
        ctx.prefetch.insert_if_need(&tree.node);

        let mut nodes = vec![tree.node.clone()];
        self.build_rafs(&mut ctx, &mut tree, &mut nodes);
        ctx.nodes = nodes;
    }

    /// Apply new node (upper layer from filesystem directory) to
    /// bootstrap node tree (lower layer from bootstrap file)
    pub fn apply_to_bootstrap(&mut self, mut ctx: &mut BuildContext) -> Result<()> {
        let mut rs = RafsSuper {
            mode: RafsMode::Direct,
            digest_validate: true,
            ..Default::default()
        };

        rs.load(ctx.f_parent_bootstrap.as_mut().unwrap())
            .context("failed to load superblock from bootstrap")?;

        let lower_compressor = rs.meta.get_compressor();
        if ctx.compressor != lower_compressor {
            bail!(
                "inconsistent compressor with the lower layer, current {}, lower: {}.",
                ctx.compressor,
                lower_compressor
            );
        }

        // Reuse lower layer blob table,
        // we need to append the blob entry of upper layer to the table
        ctx.blob_table = rs.inodes.get_blob_table().as_ref().clone();

        // Build node tree of lower layer from a bootstrap file, drop by to add
        // chunks of lower node to chunk_cache for chunk deduplication on next.
        let mut tree = Tree::from_bootstrap(&rs, Some(&mut ctx.chunk_cache))
            .context("failed to build tree from bootstrap")?;

        // Apply new node (upper layer) to node tree (lower layer)
        timing_tracer!(
            {
                for node in &ctx.nodes {
                    tree.apply(&node, true, &ctx.whiteout_spec)
                        .context("failed to apply tree")?;
                }
                Ok(true)
            },
            "apply_tree",
            Result<bool>
        )?;

        ctx.lower_inode_map.clear();
        ctx.upper_inode_map.clear();

        timing_tracer!({ self.build_rafs_wrap(&mut ctx, &mut tree) }, "build_rafs");

        Ok(())
    }

    /// Build node tree of upper layer from a filesystem directory
    pub fn build_from_filesystem(
        &mut self,
        mut ctx: &mut BuildContext,
        layered: bool,
    ) -> Result<()> {
        let mut tree = Tree::from_filesystem(
            &ctx.source_path,
            ctx.explicit_uidgid,
            layered,
            &ctx.whiteout_spec,
        )
        .context("failed to build tree from filesystem")?;

        self.build_rafs_wrap(&mut ctx, &mut tree);

        Ok(())
    }

    /// Build node tree of upper layer from a stargz index
    pub fn build_from_stargz_index(&mut self, mut ctx: &mut BuildContext) -> Result<()> {
        let mut tree = Tree::from_stargz_index(
            &ctx.source_path,
            &ctx.blob_id,
            ctx.explicit_uidgid,
            &ctx.whiteout_spec,
        )
        .context("failed to build tree from stargz index")?;

        self.build_rafs_wrap(&mut ctx, &mut tree);

        Ok(())
    }

    /// Dump blob file and generate chunks
    fn dump_blob(
        &mut self,
        ctx: &mut BuildContext,
        mut writer: Option<&mut BlobBufferWriter>,
    ) -> Result<(Sha256, usize, usize)> {
        // NOTE: Don't try to sort readahead files by their sizes,  thus to keep files
        // belonging to the same directory arranged in adjacent in blob file. Together with
        // BFS style collecting descendants inodes, it will have a higher merging possibility.
        let readahead_files = ctx.prefetch.get_file_indexs();

        let blob_index = ctx.blob_table.entries.len() as u32;

        let mut blob_readahead_size = 0usize;
        let mut blob_size = 0usize;
        let mut compress_offset = 0u64;
        let mut decompress_offset = 0u64;
        let mut blob_hash = Sha256::new();

        match ctx.source_type {
            SourceType::Directory => {
                // Dump readahead nodes
                for index in &readahead_files {
                    let node = ctx.nodes.get_mut(**index as usize - 1).unwrap();
                    debug!("[{}]\treadahead {}", node.overlay, node);
                    if node.overlay == Overlay::UpperAddition
                        || node.overlay == Overlay::UpperModification
                    {
                        blob_readahead_size += node
                            .dump_blob(
                                // Safe to unwrap because `Directory source` must have blob
                                &mut writer.as_mut().unwrap(),
                                &mut blob_hash,
                                &mut compress_offset,
                                &mut decompress_offset,
                                &mut ctx.chunk_cache,
                                ctx.compressor,
                                ctx.digester,
                                blob_index,
                                // TODO: Introduce build context to enclose the sparse states?
                                ctx.aligned_chunk,
                            )
                            .context("failed to dump readahead blob chunks")?;
                    }
                }

                blob_size += blob_readahead_size;

                // Dump other nodes
                for node in &mut ctx.nodes {
                    if ctx.prefetch.contains(node) {
                        continue;
                    }
                    // Ignore lower layer node when dump blob
                    debug!("[{}]\t{}", node.overlay, node);
                    if !node.is_dir()
                        && (node.overlay == Overlay::UpperAddition
                            || node.overlay == Overlay::UpperModification)
                    {
                        // Safe to unwrap because `Directory source` must have blob
                        blob_size += node
                            .dump_blob(
                                // Safe to unwrap because `Directory source` must have blob
                                &mut writer.as_mut().unwrap(),
                                &mut blob_hash,
                                &mut compress_offset,
                                &mut decompress_offset,
                                &mut ctx.chunk_cache,
                                ctx.compressor,
                                ctx.digester,
                                blob_index,
                                ctx.aligned_chunk,
                            )
                            .context("failed to dump remaining blob chunks")?;
                    }
                }
            }
            SourceType::StargzIndex => {
                // Set blob index and inode digest for upper nodes
                for node in &mut ctx.nodes {
                    if node.overlay.lower_layer() {
                        continue;
                    }

                    let mut inode_hasher = RafsDigest::hasher(digest::Algorithm::Sha256);

                    for chunk in node.chunks.iter_mut() {
                        (*chunk).blob_index = blob_index;
                        inode_hasher.digest_update(chunk.block_id.as_ref());
                    }

                    if node.is_symlink() {
                        node.inode.i_digest = RafsDigest::from_buf(
                            node.symlink.as_ref().unwrap().as_bytes(),
                            digest::Algorithm::Sha256,
                        );
                    } else {
                        node.inode.i_digest = inode_hasher.digest_finalize();
                    }
                }
            }
        }

        Ok((blob_hash, blob_size, blob_readahead_size))
    }

    /// Dump bootstrap and blob file, return (Vec<blob_id>, blob_size)
    fn dump_to_file(
        &mut self,
        mut ctx: &mut BuildContext,
        mut writer: Option<BlobBufferWriter>,
    ) -> Result<(Vec<String>, usize)> {
        let (blob_hash, blob_size, mut blob_readahead_size) =
            timing_tracer!({ self.dump_blob(&mut ctx, writer.as_mut()) }, "dump_blob")?;

        // Set blob hash as blob id if not specified.
        if ctx.blob_id.is_empty() {
            ctx.blob_id = format!("{:x}", blob_hash.finalize());
        }
        if blob_size > 0 || (ctx.source_type == SourceType::StargzIndex && !ctx.blob_id.is_empty())
        {
            if ctx.prefetch.policy != PrefetchPolicy::Blob {
                blob_readahead_size = 0;
            }
            ctx.blob_table
                .add(ctx.blob_id.clone(), 0, blob_readahead_size as u32);
        }

        // Set inode digest, use reverse iteration order to reduce repeated digest calculations.
        for idx in (0..ctx.nodes.len()).rev() {
            let node = ctx.nodes[idx].clone();
            ctx.nodes[idx].inode.i_digest = self.digest_node(&mut ctx, node);
        }

        // Set inode table
        let super_block_size = size_of::<OndiskSuperBlock>();
        let inode_table_entries = ctx.nodes.len() as u32;
        let mut inode_table = OndiskInodeTable::new(inode_table_entries as usize);
        let inode_table_size = inode_table.size();

        // Set prefetch table
        let (prefetch_table_size, prefetch_table_entries) =
            if let Some(prefetch_table) = ctx.prefetch.get_prefetch_table() {
                (prefetch_table.size(), prefetch_table.len() as u32)
            } else {
                (0, 0u32)
            };

        // Set blob table, use sha256 string (length 64) as blob id if not specified
        let blob_table_size = ctx.blob_table.size();
        let prefetch_table_offset = super_block_size + inode_table_size;
        let blob_table_offset = (prefetch_table_offset + prefetch_table_size) as u64;

        // Set super block
        let mut super_block = OndiskSuperBlock::new();
        let inodes_count = (ctx.lower_inode_map.len() + ctx.upper_inode_map.len()) as u64;
        super_block.set_inodes_count(inodes_count);
        super_block.set_inode_table_offset(super_block_size as u64);
        super_block.set_inode_table_entries(inode_table_entries);
        super_block.set_blob_table_offset(blob_table_offset);
        super_block.set_blob_table_size(blob_table_size as u32);
        super_block.set_prefetch_table_offset(prefetch_table_offset as u64);
        super_block.set_compressor(ctx.compressor);
        super_block.set_digester(ctx.digester);
        if ctx.explicit_uidgid {
            super_block.set_explicit_uidgid();
        }
        if ctx.source_type == SourceType::StargzIndex {
            super_block.set_block_size(stargz::DEFAULT_BLOCK_SIZE);
        }
        super_block.set_prefetch_table_entries(prefetch_table_entries);

        let mut inode_offset =
            (super_block_size + inode_table_size + prefetch_table_size + blob_table_size) as u32;

        let mut has_xattr = false;
        for node in &mut ctx.nodes {
            inode_table.set(node.index, inode_offset)?;
            // Add inode size
            inode_offset += node.inode.size() as u32;
            if node.inode.has_xattr() {
                has_xattr = true;
                if !node.xattrs.is_empty() {
                    inode_offset += (size_of::<OndiskXAttrs>() + node.xattrs.aligned_size()) as u32;
                }
            }
            // Add chunks size
            if node.is_reg() {
                inode_offset +=
                    (node.inode.i_child_count as usize * size_of::<OndiskChunkInfo>()) as u32;
            }
        }
        if has_xattr {
            super_block.set_has_xattr();
        }

        // Dump bootstrap
        super_block
            .store(&mut ctx.f_bootstrap)
            .context("failed to store superblock")?;
        inode_table
            .store(&mut ctx.f_bootstrap)
            .context("failed to store inode table")?;
        if let Some(mut prefetch_table) = ctx.prefetch.get_prefetch_table() {
            prefetch_table.store(&mut ctx.f_bootstrap)?;
        }
        ctx.blob_table
            .store(&mut ctx.f_bootstrap)
            .context("failed to store blob table")?;

        timing_tracer!(
            {
                for node in &mut ctx.nodes {
                    if ctx.source_type == SourceType::StargzIndex {
                        debug!("[{}]\t{}", node.overlay, node);
                        if log::max_level() >= log::LevelFilter::Debug {
                            for chunk in node.chunks.iter_mut() {
                                trace!("\t\tbuilding chunk: {}", chunk);
                            }
                        }
                    }
                    node.dump_bootstrap(&mut ctx.f_bootstrap)
                        .context("failed to dump bootstrap")?;
                }

                Ok(())
            },
            "dump_bootstrap",
            Result<()>
        )?;

        let blob_ids: Vec<String> = ctx
            .blob_table
            .entries
            .iter()
            .map(|entry| entry.blob_id.clone())
            .collect();

        self.blob_size = blob_size;

        // Flush remaining data in BufWriter to file
        ctx.f_bootstrap.flush()?;

        let blob_id = if self.blob_size > 0 {
            Some(ctx.blob_id.as_str())
        } else {
            None
        };
        if let Some(writer) = writer {
            writer.release(blob_id)?;
        }

        Ok((blob_ids, blob_size))
    }

    /// Calculate inode digest
    fn digest_node(&self, ctx: &mut BuildContext, node: Node) -> RafsDigest {
        // We have set digest for non-directory inode in the previous dump_blob workflow, so just return digest here.
        if !node.is_dir() {
            return node.inode.i_digest;
        }

        let child_index = node.inode.i_child_index;
        let child_count = node.inode.i_child_count;
        let mut inode_hasher = RafsDigest::hasher(ctx.digester);

        for idx in child_index..child_index + child_count {
            let child = &ctx.nodes[(idx - 1) as usize];
            inode_hasher.digest_update(child.inode.i_digest.as_ref());
        }

        inode_hasher.digest_finalize()
    }

    /// Build workflow, return (Vec<blob_id>, blob_size)
    pub fn build(
        &mut self,
        mut ctx: &mut BuildContext,
        writer: Option<BlobBufferWriter>,
    ) -> Result<(Vec<String>, usize)> {
        let layered = ctx.f_parent_bootstrap.is_some();
        match ctx.source_type {
            SourceType::Directory => {
                self.build_from_filesystem(&mut ctx, layered)?;
            }
            SourceType::StargzIndex => {
                self.build_from_stargz_index(&mut ctx)?;
            }
        }
        if layered {
            // For layered build
            self.apply_to_bootstrap(&mut ctx)?;
        }
        // Dump blob and bootstrap file
        let (blob_ids, blob_size) = self.dump_to_file(&mut ctx, writer)?;

        Ok((blob_ids, blob_size))
    }
}

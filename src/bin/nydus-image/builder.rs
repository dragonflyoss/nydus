// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Bootstrap and blob file builder for RAFS format

use std::collections::{BTreeMap, HashMap};
use std::ffi::OsString;
use std::fs::OpenOptions;
use std::io::BufWriter;
use std::mem::size_of;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use anyhow::{anyhow, bail, Context, Error, Result};
use sha2::digest::Digest;
use sha2::Sha256;

use rafs::metadata::layout::*;
use rafs::metadata::{Inode, RafsMode, RafsStore, RafsSuper};
use rafs::storage::compress;
use rafs::{RafsIoRead, RafsIoWrite};

use nydus_utils::digest::{self, RafsDigest};

use crate::stargz;
use crate::trace::*;
use crate::{root_tracer, timing_tracer};

use crate::node::*;
use crate::tree::Tree;

// TODO: select BufWriter capacity by performance testing.
const BUF_WRITER_CAPACITY: usize = 2 << 17;

pub struct Builder {
    /// Source type: Directory | StargzIndex
    source_type: SourceType,
    /// Source path, for different source type:
    /// Directory: should be a directory path
    /// StargzIndex: should be a stargz index json file path
    source_path: PathBuf,
    /// Blob id (user specified or sha256(blob)).
    blob_id: String,
    /// Blob file writer.
    f_blob: Option<Box<dyn RafsIoWrite>>,
    /// Bootstrap file writer.
    f_bootstrap: Box<dyn RafsIoWrite>,
    /// Parent bootstrap file reader.
    f_parent_bootstrap: Option<Box<dyn RafsIoRead>>,
    /// Blob chunk compress flag.
    compressor: compress::Algorithm,
    /// Inode and chunk digest algorithm flag.
    digester: digest::Algorithm,
    /// Save host uid gid in each inode.
    explicit_uidgid: bool,
    /// whiteout spec: overlayfs or oci
    whiteout_spec: WhiteoutSpec,
    /// Cache node index for hardlinks, HashMap<Inode, Vec<index>>.
    lower_inode_map: HashMap<(Inode, u64), Vec<u64>>,
    upper_inode_map: HashMap<(Inode, u64), Vec<u64>>,
    /// Store all chunk digest for chunk deduplicate during build.
    chunk_cache: HashMap<RafsDigest, OndiskChunkInfo>,
    /// Store all blob id entry during build.
    blob_table: OndiskBlobTable,
    /// Readahead file list, use BTreeMap to keep stable iteration order, HashMap<path, Option<index>>.
    /// Files from this collection are all regular files and will be persisted to blob following a certain scheme.
    readahead_files: BTreeMap<PathBuf, Option<u64>>,
    /// Specify files or directories which need to prefetch. Their inode indexes will
    /// be persist to prefetch table. They could be directory's or regular file's index
    hint_readahead_files: BTreeMap<PathBuf, Option<u64>>,
    prefetch_policy: PrefetchPolicy,
    /// Store all nodes during build, node index of root starting from 1,
    /// so the collection index equal to (node.index - 1).
    nodes: Vec<Node>,
    /// When filling local blobcache file, chunks are arranged as per the
    /// `decompress_offset` within chunk info. Therefore, provide a new flag
    /// to image tool thus to align chunks in blob with 4k size.
    aligned_chunk: bool,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum PrefetchPolicy {
    None,
    /// Readahead will be issued from Fs layer, which leverages inode/chunkinfo to prefetch data
    /// from blob no mather where it resides(OSS/Localfs). Basically, it is willing to cache the
    /// data into blobcache(if exists). It's more nimble. With this policy applied, image builder
    /// currently puts readahead files' data into a continuous region within blob which behaves very
    /// similar to `Blob` policy.
    Fs,
    /// Readahead will be issued directly from backend/blob layer
    Blob,
}

impl FromStr for PrefetchPolicy {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        match s {
            "none" => Ok(Self::None),
            "fs" => Ok(Self::Fs),
            "blob" => Ok(Self::Blob),
            _ => Err(anyhow!("invalid prefetch policy")),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum SourceType {
    Directory,
    StargzIndex,
}

impl FromStr for SourceType {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        match s {
            "directory" => Ok(Self::Directory),
            "stargz_index" => Ok(Self::StargzIndex),
            _ => Err(anyhow!("invalid source type")),
        }
    }
}

impl Builder {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        source_type: SourceType,
        source_path: &Path,
        blob_path: Option<&Path>,
        bootstrap_path: &Path,
        parent_bootstrap_path: &Path,
        blob_id: String,
        compressor: compress::Algorithm,
        digester: digest::Algorithm,
        hint_readahead_files: BTreeMap<PathBuf, Option<u64>>,
        prefetch_policy: PrefetchPolicy,
        explicit_uidgid: bool,
        whiteout_spec: WhiteoutSpec,
        aligned_chunk: bool,
    ) -> Result<Builder> {
        let f_blob = if let Some(blob_path) = blob_path {
            Some(Box::new(BufWriter::with_capacity(
                BUF_WRITER_CAPACITY,
                OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .open(blob_path)
                    .with_context(|| format!("failed to create blob file {:?}", blob_path))?,
            )) as Box<dyn RafsIoWrite>)
        } else {
            None
        };

        let f_bootstrap = Box::new(BufWriter::with_capacity(
            BUF_WRITER_CAPACITY,
            OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(bootstrap_path)
                .with_context(|| format!("failed to create bootstrap file {:?}", bootstrap_path))?,
        ));

        let f_parent_bootstrap: Option<Box<dyn RafsIoRead>> =
            if parent_bootstrap_path != Path::new("") {
                Some(Box::new(
                    OpenOptions::new()
                        .read(true)
                        .write(false)
                        .open(parent_bootstrap_path)
                        .with_context(|| {
                            format!(
                                "failed to open parent bootstrap file {:?}",
                                parent_bootstrap_path
                            )
                        })?,
                ))
            } else {
                None
            };

        Ok(Builder {
            source_type,
            source_path: PathBuf::from(source_path),
            blob_id,
            f_blob,
            f_bootstrap,
            f_parent_bootstrap,
            compressor,
            digester,
            explicit_uidgid,
            whiteout_spec,
            lower_inode_map: HashMap::new(),
            upper_inode_map: HashMap::new(),
            chunk_cache: HashMap::new(),
            blob_table: OndiskBlobTable::new(),
            readahead_files: BTreeMap::new(),
            hint_readahead_files,
            prefetch_policy,
            nodes: Vec::new(),
            aligned_chunk,
        })
    }

    /// Gain file or directory inode indexes which will be put into prefetch table.
    fn need_prefetch(&mut self, node: &Node) -> bool {
        let path = &node.rootfs();
        let index = node.inode.i_ino;

        if self.prefetch_policy == PrefetchPolicy::None || node.inode.i_size == 0 {
            return false;
        }

        for f in self.hint_readahead_files.keys() {
            // As path is canonicalized, it should be reliable.
            if path.as_os_str() == f.as_os_str() {
                if self.prefetch_policy == PrefetchPolicy::Fs {
                    if let Some(i) = self.hint_readahead_files.get_mut(path) {
                        *i = Some(index);
                    }
                }
                return true;
            } else if path.starts_with(f) {
                // Users can specify hinted parent directory with its child files hinted as well.
                // Only put the parent directory into ondisk prefetch table since a hinted directory's
                // all child files will be prefetched after mount.
                if self.hint_readahead_files.get(path).is_some() {
                    self.hint_readahead_files.remove(path);
                }
                return true;
            }
        }

        false
    }

    /// Traverse node tree, set inode index, ino, child_index and
    /// child_count etc according to RAFS format, then store to nodes collection.
    fn build_rafs(&mut self, tree: &mut Tree, nodes: &mut Vec<Node>) {
        // FIX: Insert parent inode to inode map to keep correct inodes count in superblock.
        let inode_map = if tree.node.overlay.lower_layer() {
            &mut self.lower_inode_map
        } else {
            &mut self.upper_inode_map
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
                &mut self.lower_inode_map
            } else {
                &mut self.upper_inode_map
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
                &self.f_parent_bootstrap,
                child.node.whiteout_type(&self.whiteout_spec),
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

            if self.need_prefetch(&child.node) {
                self.readahead_files
                    .insert(child.node.rootfs(), Some(child.node.index));
            }

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
            self.build_rafs(dir, nodes);
        }
    }

    fn build_rafs_wrap(&mut self, mut tree: &mut Tree) {
        let index = RAFS_ROOT_INODE;
        tree.node.index = index;
        tree.node.inode.i_ino = index;

        // Filesystem walking skips root inode within subsequent while loop, however, we allow
        // user to pass the source root as prefetch hint. Check it here.
        let root_path = Path::new("/").to_path_buf();
        if self.need_prefetch(&tree.node) {
            self.readahead_files.insert(root_path, Some(index));
        }

        let mut nodes = vec![tree.node.clone()];
        self.build_rafs(&mut tree, &mut nodes);
        self.nodes = nodes;
    }

    /// Apply new node (upper layer from filesystem directory) to
    /// bootstrap node tree (lower layer from bootstrap file)
    pub fn apply_to_bootstrap(&mut self) -> Result<()> {
        let mut rs = RafsSuper {
            mode: RafsMode::Direct,
            digest_validate: true,
            ..Default::default()
        };

        rs.load(self.f_parent_bootstrap.as_mut().unwrap())
            .context("failed to load superblock from bootstrap")?;

        let lower_compressor = rs.meta.get_compressor();
        if self.compressor != lower_compressor {
            bail!(
                "inconsistent compressor with the lower layer, current {}, lower: {}.",
                self.compressor,
                lower_compressor
            );
        }

        // Reuse lower layer blob table,
        // we need to append the blob entry of upper layer to the table
        self.blob_table = rs.inodes.get_blob_table().as_ref().clone();

        // Build node tree of lower layer from a bootstrap file, drop by to add
        // chunks of lower node to chunk_cache for chunk deduplication on next.
        let mut tree = Tree::from_bootstrap(&rs, Some(&mut self.chunk_cache))
            .context("failed to build tree from bootstrap")?;

        // Apply new node (upper layer) to node tree (lower layer)
        timing_tracer!(
            {
                for node in &self.nodes {
                    tree.apply(&node, true, &self.whiteout_spec)
                        .context("failed to apply tree")?;
                }
                Ok(true)
            },
            "apply layers",
            Result<bool>
        )?;

        self.lower_inode_map.clear();
        self.upper_inode_map.clear();
        self.readahead_files.clear();

        timing_tracer!({ self.build_rafs_wrap(&mut tree) }, "build rafs");

        Ok(())
    }

    /// Build node tree of upper layer from a filesystem directory
    pub fn build_from_filesystem(&mut self, layered: bool) -> Result<()> {
        let mut tree = Tree::from_filesystem(
            &self.source_path,
            self.explicit_uidgid,
            layered,
            &self.whiteout_spec,
        )
        .context("failed to build tree from filesystem")?;

        self.build_rafs_wrap(&mut tree);

        Ok(())
    }

    /// Build node tree of upper layer from a stargz index
    pub fn build_from_stargz_index(&mut self) -> Result<()> {
        let mut tree = Tree::from_stargz_index(
            &self.source_path,
            &self.blob_id,
            self.explicit_uidgid,
            &self.whiteout_spec,
        )
        .context("failed to build tree from stargz index")?;

        self.build_rafs_wrap(&mut tree);

        Ok(())
    }

    /// Dump blob file and generate chunks
    fn dump_blob(&mut self) -> Result<(Sha256, usize, usize)> {
        // NOTE: Don't try to sort readahead files by their sizes,  thus to keep files
        // belonging to the same directory arranged in adjacent in blob file. Together with
        // BFS style collecting descendants inodes, it will have a higher merging possibility.
        let readahead_files = self
            .readahead_files
            .values()
            .filter_map(|index| index.as_ref())
            .collect::<Vec<&u64>>();

        let blob_index = self.blob_table.entries.len() as u32;

        let mut blob_readahead_size = 0usize;
        let mut blob_size = 0usize;
        let mut compress_offset = 0u64;
        let mut decompress_offset = 0u64;
        let mut blob_hash = Sha256::new();

        match self.source_type {
            SourceType::Directory => {
                // Dump readahead nodes
                for index in &readahead_files {
                    let node = self.nodes.get_mut(**index as usize - 1).unwrap();
                    debug!("[{}]\treadahead {}", node.overlay, node);
                    if node.overlay == Overlay::UpperAddition
                        || node.overlay == Overlay::UpperModification
                    {
                        blob_readahead_size += node
                            .dump_blob(
                                self.f_blob.as_mut(),
                                &mut blob_hash,
                                &mut compress_offset,
                                &mut decompress_offset,
                                &mut self.chunk_cache,
                                self.compressor,
                                self.digester,
                                blob_index,
                                // TODO: Introduce build context to enclose the sparse states?
                                self.aligned_chunk,
                            )
                            .context("failed to dump readahead blob chunks")?;
                    }
                }

                blob_size += blob_readahead_size;

                // Dump other nodes
                for node in &mut self.nodes {
                    if self.readahead_files.get(&node.rootfs()).is_some() {
                        continue;
                    }
                    // Ignore lower layer node when dump blob
                    debug!("[{}]\t{}", node.overlay, node);
                    if !node.is_dir()
                        && (node.overlay == Overlay::UpperAddition
                            || node.overlay == Overlay::UpperModification)
                    {
                        blob_size += node
                            .dump_blob(
                                self.f_blob.as_mut(),
                                &mut blob_hash,
                                &mut compress_offset,
                                &mut decompress_offset,
                                &mut self.chunk_cache,
                                self.compressor,
                                self.digester,
                                blob_index,
                                self.aligned_chunk,
                            )
                            .context("failed to dump remaining blob chunks")?;
                    }
                }
            }
            SourceType::StargzIndex => {
                // Set blob index and inode digest for upper nodes
                for node in &mut self.nodes {
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
    fn dump_to_file(&mut self) -> Result<(Vec<String>, usize)> {
        let (blob_hash, blob_size, mut blob_readahead_size) = timing_tracer!(
            { self.dump_blob() },
            "write all nodes to blob including hashing"
        )?;

        // Set blob hash as blob id if not specified.
        if self.blob_id.is_empty() {
            self.blob_id = format!("{:x}", blob_hash.finalize());
        }
        if blob_size > 0
            || (self.source_type == SourceType::StargzIndex && !self.blob_id.is_empty())
        {
            if self.prefetch_policy != PrefetchPolicy::Blob {
                blob_readahead_size = 0;
            }
            self.blob_table
                .add(self.blob_id.clone(), 0, blob_readahead_size as u32);
        }

        // Set inode digest, use reverse iteration order to reduce repeated digest calculations.
        for idx in (0..self.nodes.len()).rev() {
            self.nodes[idx].inode.i_digest = self.digest_node(&self.nodes[idx]);
        }

        // Set inode table
        let super_block_size = size_of::<OndiskSuperBlock>();
        let inode_table_entries = self.nodes.len() as u32;
        let mut inode_table = OndiskInodeTable::new(inode_table_entries as usize);
        let inode_table_size = inode_table.size();

        // Set prefetch table
        let mut prefetch_table = PrefetchTable::new();
        let mut prefetch_table_size = 0;
        let prefetch_table_entries = if self.prefetch_policy == PrefetchPolicy::Fs {
            for i in self
                .hint_readahead_files
                .iter()
                .filter_map(|(_, v)| v.as_ref())
            {
                prefetch_table.add_entry(*i as u32);
            }
            prefetch_table_size = prefetch_table.size();
            prefetch_table.len() as u32
        } else {
            0u32
        };

        // Set blob table, use sha256 string (length 64) as blob id if not specified
        let blob_table_size = self.blob_table.size();
        let prefetch_table_offset = super_block_size + inode_table_size;
        let blob_table_offset = (prefetch_table_offset + prefetch_table_size) as u64;

        // Set super block
        let mut super_block = OndiskSuperBlock::new();
        let inodes_count = (self.lower_inode_map.len() + self.upper_inode_map.len()) as u64;
        super_block.set_inodes_count(inodes_count);
        super_block.set_inode_table_offset(super_block_size as u64);
        super_block.set_inode_table_entries(inode_table_entries);
        super_block.set_blob_table_offset(blob_table_offset);
        super_block.set_blob_table_size(blob_table_size as u32);
        super_block.set_prefetch_table_offset(prefetch_table_offset as u64);
        super_block.set_compressor(self.compressor);
        super_block.set_digester(self.digester);
        if self.explicit_uidgid {
            super_block.set_explicit_uidgid();
        }
        if self.source_type == SourceType::StargzIndex {
            super_block.set_block_size(stargz::DEFAULT_BLOCK_SIZE);
        }
        super_block.set_prefetch_table_entries(prefetch_table_entries);

        let mut inode_offset =
            (super_block_size + inode_table_size + prefetch_table_size + blob_table_size) as u32;

        let mut has_xattr = false;
        for node in &mut self.nodes {
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
            .store(&mut self.f_bootstrap)
            .context("failed to store superblock")?;
        inode_table
            .store(&mut self.f_bootstrap)
            .context("failed to store inode table")?;
        if self.prefetch_policy == PrefetchPolicy::Fs {
            prefetch_table.store(&mut self.f_bootstrap)?;
        }
        self.blob_table
            .store(&mut self.f_bootstrap)
            .context("failed to store blob table")?;

        timing_tracer!(
            {
                for node in &mut self.nodes {
                    if self.source_type == SourceType::StargzIndex {
                        debug!("[{}]\t{}", node.overlay, node);
                        if log::max_level() >= log::LevelFilter::Debug {
                            for chunk in node.chunks.iter_mut() {
                                trace!("\t\tbuilding chunk: {}", chunk);
                            }
                        }
                    }
                    node.dump_bootstrap(&mut self.f_bootstrap)
                        .context("failed to dump bootstrap")?;
                }

                Ok(())
            },
            "write all nodes to bootstrap",
            Result<()>
        )?;

        let blob_ids: Vec<String> = self
            .blob_table
            .entries
            .iter()
            .map(|entry| entry.blob_id.clone())
            .collect();

        // Flush remaining data in BufWriter to file
        self.f_bootstrap.flush()?;
        if let Some(f_blob) = self.f_blob.as_mut() {
            f_blob.flush()?;
        }

        Ok((blob_ids, blob_size))
    }

    /// Calculate inode digest
    fn digest_node(&self, node: &Node) -> RafsDigest {
        // We have set digest for non-directory inode in the previous dump_blob workflow, so just return digest here.
        if !node.is_dir() {
            return node.inode.i_digest;
        }

        let child_index = node.inode.i_child_index;
        let child_count = node.inode.i_child_count;
        let mut inode_hasher = RafsDigest::hasher(self.digester);

        for idx in child_index..child_index + child_count {
            let child = &self.nodes[(idx - 1) as usize];
            inode_hasher.digest_update(child.inode.i_digest.as_ref());
        }

        inode_hasher.digest_finalize()
    }

    /// Build workflow, return (Vec<blob_id>, blob_size)
    pub fn build(&mut self) -> Result<(Vec<String>, usize)> {
        match self.source_type {
            SourceType::Directory => {
                self.build_from_filesystem(self.f_parent_bootstrap.is_some())?;
            }
            SourceType::StargzIndex => {
                self.build_from_stargz_index()?;
            }
        }
        if self.f_parent_bootstrap.is_some() {
            // For layered build
            self.apply_to_bootstrap()?;
        }
        // Dump blob and bootstrap file
        let (blob_ids, blob_size) =
            timing_tracer!({ self.dump_to_file() }, "dump bootstrap and blob")?;

        Ok((blob_ids, blob_size))
    }
}

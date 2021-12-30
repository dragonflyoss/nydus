// Copyright 2021 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Diff build is a new multi-layers image build workflow that allows
//! multiple directory paths to be passed into the builder at once as
//! arguments, e.g.

//! ```
//! nydus-image create ... --source-type diff \
//! /path/to/snapshot.1 /path/to/snapshot.2 ...  /path/to/snapshot.N
//! ```
//!
//! or
//!
//! nydus-image create ... --source-type diff --diff-overlay-hint \
//! /path/to/snapshot.1 /path/to/snapshot.2 ...  /path/to/snapshot.N \
//! /path/to/upper.1 /path/to/upper.2 ... /path/to/upper.N
//! ```

//! Where snapshot directories are the committed snapshots of an image
//! in containerd, sorted by layer, each snapshot is the merge (overlayed)
//! dir of all lower snapshots below it. And where upper directories (only
//! need be specified when --diff-overlay-hint option is enabled) are
//! the upper directories of each snapshot for overlayfs, they are used
//! to tell diff build to find added or modified files in each layer
//! faster. The diff build workflow is divided into two phases:

//! Phase 1: walk snapshot.n and snapshot.n+1, compare the differences
//! in regular files between the dirs, dump the chunk of file data added
//! or modified in snapshot.n+1 to a blob, which is the nydus blob of
//! snapshot.n+1, when --diff-overlay-hint option (only for overlayfs)
//! is enabled, added or modified files can be found faster from the
//! upper.n+1 directory, thus speeding up the blob dumping. In this way,
//! iteratively build each layer of dir in sequence.
//
//! Phase 2: walk the last snapshot directory, dumping the file metadata
//! to a bootstrap file, which is the nydus bootstrap of the entire image.

//! The advantage of diff build is that it can build the blob of each
//! layer concurrently in phase 1, which greatly improves the speed of
//! building multi-layers image and eliminates the need to consider the
//! processing of whiteouts in upper layer.

//! Diff build with build cache:

//! In buildkit scenario, nydus-image need to dump blobs and bootstraps for
//! every layer, the last bootstrap file of layer will be used as final metadata
//! of a Nydus image, and other bootstraps of lower layer will be used as
//! cache files in buildkit to speed up image build on next.

//! A common usage like this:

//! The first build needs to dump all blobs and bootstraps:

//! nydus-image create \
//!   --source-type diff \
//!   --diff-bootstrap-dir /path/to/bootstrap-dir \
//!   --blob-dir /path/to/blob-dir \
//!   --output-json /path/to/output.json \
//!   /path/to/snapshot-0 \
//!   /path/to/snapshot-1

//! The output JSON file is like this:

//! {
//!   ...
//!   "blobs": [
//!     "blob-0",
//!     "blob-1"
//!   ],
//!   "bootstraps": [
//!     "bootstrap-0",
//!     "bootstrap-1"
//!   ]
//!   ...
//! }

//! The second build uses bootstrap-1 in the first build as parent and skip layer 0, layer 1,
//! and only need to dump blobs and bootstraps for layer 2, layer 3:

//! nydus-image create \
//!   --source-type diff \
//!   --diff-bootstrap-dir /path/to/bootstrap-dir \
//!   --diff-skip-layer 1 \
//!   --parent-bootstrap /path/to/bootstrap-dir/bootstrap-1 \
//!   --blob-dir /path/to/blob-dir \
//!   --output-json /path/to/output.json \
//!   /path/to/snapshot-0 \
//!   /path/to/snapshot-1 \
//!   /path/to/snapshot-2 \
//!   /path/to/snapshot-3

//! The output JSON file is like this:

//! {
//!   ...
//!   "blobs": [
//!     "blob-2",
//!     "blob-3"
//!   ],
//!   "bootstraps": [
//!     "bootstrap-2",
//!     "bootstrap-3"
//!   ]
//!   ...
//! }

use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Arc, RwLock};
use std::thread;

use anyhow::{anyhow, Context, Result};

use crate::builder::Builder;
use crate::core::blob::Blob;
use crate::core::bootstrap::Bootstrap;
use crate::core::chunk_dict::{ChunkDict, HashChunkDict};
use crate::core::context::{
    ArtifactStorage, BlobContext, BlobManager, BootstrapContext, BootstrapManager, BuildContext,
    BuildOutput, RafsVersion,
};
use crate::core::node::{ChunkWrapper, Node, Overlay};
use crate::core::tree::Tree;
use nydus_utils::digest::RafsDigest;
use rafs::metadata::layout::RAFS_ROOT_INODE;
use rafs::metadata::{Inode, RafsInode, RafsMode, RafsSuper};

#[derive(Clone)]
struct CachedNode {
    chunks: Vec<ChunkWrapper>,
    digest: RafsDigest,
}

type CachedNodes = Arc<RwLock<HashMap<PathBuf, Vec<Option<CachedNode>>>>>;

/// Compare two files to see if they are the same, file 1 should be from
/// lower snapshot and file 2 should be from upper snapshot.
fn same_file(f1: &Node, f2: &Node) -> bool {
    if f1.src_dev == f2.src_dev && f1.src_ino == f2.src_ino {
        return true;
    }
    if !(f1.inode.mode() == f2.inode.mode()
        && f1.inode.uid() == f2.inode.uid()
        && f1.inode.gid() == f2.inode.gid()
        && f1.rdev == f2.rdev)
    {
        return false;
    }
    let cap_name = OsStr::new("security.capability");
    if f1.xattrs.get(&cap_name) != f2.xattrs.get(&cap_name) {
        return false;
    }
    if !f1.is_dir() {
        if f1.inode.size() != f2.inode.size() {
            return false;
        }
        if f1.ctime != f2.ctime {
            return false;
        }
        if f1.ctime == 0 && f2.ctime == 0 {
            if f1.is_symlink() {
                return f1.symlink == f2.symlink;
            }
            if f1.inode.size() == 0 {
                return true;
            }
            // TODO: compare file content.
            unimplemented!("compare file content");
        } else if f1.ctime != f2.ctime {
            return false;
        }
    }
    true
}

/// Build nodes vec from a filesystem diff, which use the upper snapshot
/// as the upper_root path and lower snapshot as the lower_root path,
/// compare the differences between two snapshots, the added and modified
/// files will be put to nodes vec.
fn walk_diff(
    ctx: &BuildContext,
    lower_root: Option<PathBuf>,
    upper_root: PathBuf,
    upper_path: PathBuf,
) -> Result<Vec<Node>> {
    let children = fs::read_dir(&*upper_path)
        .with_context(|| format!("failed to read dir {:?}", upper_path))?;
    let mut children = children
        .map(|entry| entry.map(|e| e.path()))
        .collect::<Result<Vec<_>, std::io::Error>>()
        .with_context(|| format!("failed to traverse directory entries for {:?}", upper_path))?;
    children.sort();

    let mut nodes = Vec::new();
    for child_path in children {
        let is_dir = std::fs::symlink_metadata(&child_path)
            .with_context(|| format!("failed to get metadata for {:?}", child_path))?
            .is_dir();
        if is_dir {
            let mut dir_nodes = walk_diff(
                ctx,
                lower_root.clone(),
                upper_root.clone(),
                child_path.clone(),
            )?;
            nodes.append(&mut dir_nodes);
            continue;
        }
        let mut child_node = Node::new(
            ctx.fs_version,
            upper_root.clone(),
            child_path.clone(),
            Overlay::UpperAddition,
            ctx.chunk_size,
            ctx.explicit_uidgid,
        )
        .with_context(|| format!("failed to create node from {:?}", child_path))?;

        if let Some(lower_root) = &lower_root {
            let lower_path = lower_root.join(child_path.strip_prefix(&upper_root)?);
            if lower_path.exists() {
                let lower_node = Node::new(
                    ctx.fs_version,
                    lower_root.clone(),
                    lower_path,
                    Overlay::Lower,
                    ctx.chunk_size,
                    ctx.explicit_uidgid,
                )?;
                if same_file(&lower_node, &child_node) {
                    child_node.overlay = Overlay::Lower;
                } else {
                    child_node.overlay = Overlay::UpperModification;
                    nodes.push(child_node);
                }
            } else {
                nodes.push(child_node);
            }
        } else {
            nodes.push(child_node);
        }
    }

    Ok(nodes)
}

// Walk a directory to export all files as nodes vec.
fn walk_all(ctx: &BuildContext, dir_root: PathBuf, dir_path: PathBuf) -> Result<Vec<Node>> {
    let children =
        fs::read_dir(&*dir_path).with_context(|| format!("failed to read dir {:?}", dir_path))?;
    let mut children = children
        .map(|entry| entry.map(|e| e.path()))
        .collect::<Result<Vec<_>, std::io::Error>>()
        .with_context(|| format!("failed to traverse directory entries {:?}", dir_path))?;
    children.sort();

    let mut nodes = Vec::new();
    for child_path in children {
        let is_dir = std::fs::symlink_metadata(&child_path)
            .with_context(|| format!("failed to get metadata for {:?}", child_path))?
            .is_dir();
        if is_dir {
            let mut dir_nodes = walk_all(ctx, dir_root.clone(), child_path.clone())?;
            nodes.append(&mut dir_nodes);
            continue;
        }

        let child_node = Node::new(
            ctx.fs_version,
            dir_root.clone(),
            child_path.clone(),
            Overlay::UpperAddition,
            ctx.chunk_size,
            ctx.explicit_uidgid,
        )
        .with_context(|| format!("failed to create node from {:?}", child_path))?;

        nodes.push(child_node);
    }

    Ok(nodes)
}

// Dump blob for addition and modification files from upper nodes.
fn dump_blob(
    ctx: Arc<BuildContext>,
    snapshot_idx: u32,
    blob_id: String,
    blob_storage: Option<ArtifactStorage>,
    cached_nodes: CachedNodes,
    blob_nodes: &mut Vec<Node>,
    chunk_dict: Arc<dyn ChunkDict>,
) -> Result<Option<BlobContext>> {
    let mut blob_ctx = BlobContext::new(blob_id, blob_storage)?;
    blob_ctx.set_chunk_dict(chunk_dict);
    blob_ctx.set_chunk_size(ctx.chunk_size);
    blob_ctx.set_meta_info_enabled(true);

    // Since all layers are built concurrently, it is not possible to deduplicate
    // chunk between layers while ensuring reproducible build, so we only do
    // deduplication within layers here, and use chunk dict to deduplicate most
    // of chunks shared between layers.
    let mut chunk_cache = HashChunkDict::default();

    let mut blob = Blob::new();
    let blob_ctx = if blob.dump(
        ctx.as_ref(),
        &mut blob_ctx,
        snapshot_idx,
        blob_nodes,
        &mut chunk_cache,
    )? {
        Some(blob_ctx)
    } else {
        None
    };

    // Put the regular files from upper snapshot into CachedNodes, to make the
    // final bootstrap of image refer to the modified files in upper snapshot,
    // not the files in lower snapshot.
    for node in blob_nodes {
        if node.is_dir() {
            continue;
        }
        let mut cached_nodes = cached_nodes.write().unwrap();
        let capacity = (snapshot_idx + 1) as usize;
        if let Some(caches) = cached_nodes.get_mut(node.target()) {
            if capacity > caches.len() {
                caches.resize(capacity, None);
            }
            caches[snapshot_idx as usize] = Some(CachedNode {
                chunks: node.chunks.clone(),
                digest: *node.inode.digest(),
            });
        } else {
            let mut caches: Vec<Option<CachedNode>> = vec![None; capacity];
            caches[snapshot_idx as usize] = Some(CachedNode {
                chunks: node.chunks.clone(),
                digest: *node.inode.digest(),
            });
            cached_nodes.insert(node.target().clone(), caches);
        }
    }

    Ok(blob_ctx)
}

pub struct DiffBuilder {
    /// The source_path and extra_paths compose up all the paths required
    /// by a diff build workflow, the paths have two formats, user can
    /// specify format type by `--diff-overlay-hint` option:
    ///
    /// Format 1 (without --diff-overlay-hint):
    ///
    /// This format only have snapshot paths (snapshot in containerd), it
    /// provides wide compatibility for any snapshotter in containerd, but
    /// it need to compare the difference (added or modified files) between
    /// lower (snapshot.n) and upper (snapshot.n+1) layer, therefore the
    /// build performance will be affected.
    ///
    /// vec![
    ///     /path/to/snapshot.1, // merge(/path/to/upper.1)
    ///     /path/to/snapshot.2, // merge(/path/to/upper.1, /path/to/upper.2)
    ///     /path/to/snapshot.3, // merge(/path/to/upper.1, /path/to/upper.2, /path/to/upper.3)
    /// ]
    ///
    /// Format 2 (with --diff-overlay-hint)
    ///
    /// This format adds upper paths, which provides a hint to build to find
    /// files added or modified in the each snapshot faster, and without doing
    /// inter-snapshot comparisons to improve the speed of the entire build,
    /// but it's only available for overlayfs snapshotter in containerd.
    ///
    /// vec![
    ///     /path/to/snapshot.1, // merge(/path/to/upper.1)
    ///     /path/to/snapshot.2, // merge(/path/to/upper.1, /path/to/upper.2)
    ///     /path/to/snapshot.3, // merge(/path/to/upper.1, /path/to/upper.2, /path/to/upper.3)
    ///
    ///     /path/to/upper.1,
    ///     /path/to/upper.2,
    ///     /path/to/upper.3,
    /// ]
    extra_paths: Vec<PathBuf>,
    /// Enable to speed up building (see the detail comments above).
    diff_hint: bool,
    /// Arc<RwLock<HashMap<PathBuf, Vec<Option<CachedNode>>>>>
    /// PathBuf used as file rootfs path, Vec index used as snapshot index.
    ///
    /// We need to find the chunks of a regular file in any snapshot layer
    /// by specifying a file path.
    ///
    /// Use this to make the final bootstrap of image refer to the chunks of
    /// modified files in upper snapshot, not the chunks in lower snapshot.
    cached_nodes: CachedNodes,
    /// The index of snapshot to skip and start building from there for
    /// speeding up diff build.
    skip_snapshot_idx: Option<u32>,
}

impl DiffBuilder {
    pub fn new(
        extra_paths: Vec<PathBuf>,
        diff_hint: bool,
        skip_snapshot_idx: Option<&str>,
    ) -> Result<Self> {
        let skip_snapshot_idx = if let Some(idx) = skip_snapshot_idx {
            Some(
                u32::from_str(idx)
                    .context(format!("invalid layer index {:?}", skip_snapshot_idx))?,
            )
        } else {
            None
        };
        Ok(Self {
            skip_snapshot_idx,
            extra_paths,
            diff_hint,
            cached_nodes: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    fn cache_chunks(&mut self, inode: &dyn RafsInode, path: &Path) -> Result<()> {
        let chunk_count = inode.get_chunk_count();
        let mut chunks = Vec::with_capacity(chunk_count as usize);
        let mut blob_index = 0;
        for i in 0..chunk_count {
            let cki = inode.get_chunk_info(i)?;
            chunks.push(ChunkWrapper::from_chunk_info(&cki));
            blob_index = cki.blob_index();
        }

        // This logic uses CachedNodes to make the final bootstrap of image refer
        // to the modified files in upper snapshot, not the files in lower snapshot,
        // so here we should fill None for the lower snapshot that does not contain
        // the file.
        let mut cached = vec![None::<CachedNode>; blob_index as usize];
        cached.push(Some(CachedNode {
            chunks,
            digest: inode.get_digest(),
        }));
        let mut cached_nodes = self.cached_nodes.write().unwrap();
        cached_nodes.insert(path.to_path_buf(), cached);

        Ok(())
    }

    fn load_chunks(&mut self, rs: &RafsSuper, ino: Inode, parent: Option<&PathBuf>) -> Result<()> {
        let inode = rs.get_inode(ino, false)?;
        if !inode.is_dir() {
            return Ok(());
        }

        let parent_path = if let Some(parent) = parent {
            parent.join(inode.name())
        } else {
            PathBuf::from("/")
        };

        let child_count = inode.get_child_count();
        for idx in 0..child_count {
            let child = inode.get_child_by_index(idx)?;
            let child_ino = child.ino();
            if child.is_dir() {
                self.load_chunks(&rs, child_ino, Some(&parent_path))?;
            } else {
                let child_path = parent_path.join(child.name());
                self.cache_chunks(child.as_ref(), &child_path)?;
            }
        }

        Ok(())
    }

    fn load_parent_chunks(
        &mut self,
        bootstrap_mgr: &mut BootstrapManager,
        blob_mgr: &mut BlobManager,
    ) -> Result<()> {
        if let Some(r) = bootstrap_mgr.f_parent_bootstrap.as_mut() {
            let mut rs = RafsSuper {
                mode: RafsMode::Cached,
                validate_digest: false,
                ..Default::default()
            };
            rs.load(r)
                .context("failed to load superblock from bootstrap")?;
            // Load blobs from the blob table of parent bootstrap.
            blob_mgr.from_blob_table(rs.superblock.get_blob_infos());
            self.load_chunks(&rs, RAFS_ROOT_INODE, None)?;
        };

        Ok(())
    }

    fn build_tree(
        &mut self,
        ctx: &mut BuildContext,
        blob_mgr: &BlobManager,
        snapshot_idx: u32,
        snapshot_path: PathBuf,
    ) -> Result<Tree> {
        let root = Node::new(
            ctx.fs_version,
            snapshot_path.clone(),
            snapshot_path.clone(),
            Overlay::UpperAddition,
            ctx.chunk_size,
            ctx.explicit_uidgid,
        )?;
        let mut tree = Tree::new(root);
        tree.children = self.build_tree_from_children(
            ctx,
            blob_mgr,
            snapshot_idx,
            snapshot_path.clone(),
            snapshot_path,
        )?;
        Ok(tree)
    }

    fn build_tree_from_children(
        &mut self,
        ctx: &mut BuildContext,
        blob_mgr: &BlobManager,
        snapshot_idx: u32,
        snapshot_root: PathBuf,
        snapshot_path: PathBuf,
    ) -> Result<Vec<Tree>> {
        let children = fs::read_dir(&*snapshot_path)
            .with_context(|| format!("failed to read dir {:?}", snapshot_path))?;
        let mut children = children
            .map(|entry| entry.map(|e| e.path()))
            .collect::<Result<Vec<_>, std::io::Error>>()
            .with_context(|| format!("failed to traverse directory entries {:?}", snapshot_path))?;
        children.sort();

        let mut trees = Vec::new();

        for child_path in children {
            let mut child_node = Node::new(
                ctx.fs_version,
                snapshot_root.clone(),
                child_path.clone(),
                Overlay::UpperAddition,
                ctx.chunk_size,
                ctx.explicit_uidgid,
            )
            .with_context(|| format!("failed to create node from {:?}", child_path))?;

            let is_dir = child_node.is_dir();

            if !is_dir {
                // This logic uses CachedNodes to make the final bootstrap of image refer
                // to the modified files in upper snapshot, not the files in lower snapshot.
                if let Some(caches) = self.cached_nodes.read().unwrap().get(child_node.target()) {
                    if let Some(Some(cached)) = caches.last() {
                        child_node.inode.set_child_count(cached.chunks.len() as u32);
                        child_node.chunks = cached.chunks.clone();
                        child_node.inode.set_digest(cached.digest);
                        if !child_node.chunks.is_empty() {
                            let target_snapshot_idx = caches.len() - 1;
                            let blob_index = blob_mgr
                                .get_blob_idx_by_layer_idx(target_snapshot_idx as u32)
                                .ok_or_else(|| {
                                    anyhow!(
                                        "failed to get blob index for file {:?}, snapshot index {}",
                                        child_path,
                                        target_snapshot_idx
                                    )
                                })?;
                            for chunk in &mut child_node.chunks {
                                chunk.set_blob_index(blob_index);
                            }
                        }
                    }
                }
            }

            let mut child = Tree::new(child_node);
            if is_dir {
                child.children = self.build_tree_from_children(
                    ctx,
                    blob_mgr,
                    snapshot_idx,
                    snapshot_root.clone(),
                    child_path,
                )?;
            }

            trees.push(child);
        }

        Ok(trees)
    }

    fn build_bootstrap(
        &mut self,
        ctx: &mut BuildContext,
        bootstrap_ctx: &mut BootstrapContext,
        blob_mgr: &mut BlobManager,
        snapshot_idx: u32,
        snapshot_path: PathBuf,
    ) -> Result<()> {
        // Build tree from filesystem diff
        let mut tree = self.build_tree(ctx, blob_mgr, snapshot_idx, snapshot_path)?;

        // Build bootstrap from tree
        let mut bootstrap = Bootstrap::new()?;
        bootstrap.build(ctx, bootstrap_ctx, &mut tree)?;

        // Dump bootstrap file
        match ctx.fs_version {
            RafsVersion::V5 => {
                let blob_table = blob_mgr.to_blob_table_v5(ctx, Some(snapshot_idx as usize))?;
                bootstrap.dump_rafsv5(ctx, bootstrap_ctx, &blob_table)?
            }
            RafsVersion::V6 => {
                let blob_table = blob_mgr.to_blob_table_v6(ctx, Some(snapshot_idx as usize))?;
                bootstrap.dump_rafsv6(ctx, bootstrap_ctx, &blob_table)?
            }
        }

        Ok(())
    }

    fn build_with_hint(
        &mut self,
        ctx: &mut BuildContext,
        bootstrap_mgr: &mut BootstrapManager,
        blob_mgr: &mut BlobManager,
    ) -> Result<BuildOutput> {
        let mut paths = vec![ctx.source_path.clone()];
        paths.append(&mut self.extra_paths);

        if paths.len() < 2 {
            bail!("the number of paths should be equal or greater than 2");
        }

        if paths.len() & 1 != 0 {
            bail!(
                "the number of paths should be even, for example: {}",
                "/path/to/snapshot.1 /path/to/snapshot.2 /path/to/upper.1 /path/to/upper.2"
            );
        }

        let mut workers = Vec::new();
        let base = paths.len() / 2;

        // Skip specified snapshot layers.
        let skip = self.skip_snapshot_idx.map(|idx| idx + 1).unwrap_or(0) as usize;
        // Add None blob context for snapshots which have empty blobs.
        for _ in blob_mgr.len()..skip {
            blob_mgr.add(None);
        }

        // Dump blobs concurrently for every snapshot layer.
        for idx in skip..base {
            let blob_id = ctx.blob_id.clone();
            let blob_storage = ctx.blob_storage.clone();
            let ctx = Arc::new(ctx.clone());
            let cached_nodes = self.cached_nodes.clone();
            let hint_path_idx = idx + base;
            let hint_path = paths[hint_path_idx].clone();
            let chunk_dict = blob_mgr.get_chunk_dict().clone();
            let worker = thread::spawn(move || -> Result<Option<BlobContext>> {
                info!("[{}] diff building with hint {:?}", idx, hint_path);

                let snapshot_idx = idx as u32;
                let mut blob_nodes = walk_all(ctx.as_ref(), hint_path.clone(), hint_path)?;

                let blob_ctx = dump_blob(
                    ctx,
                    snapshot_idx,
                    blob_id,
                    blob_storage,
                    cached_nodes,
                    &mut blob_nodes,
                    chunk_dict,
                )?;

                Ok(blob_ctx)
            });
            workers.push(worker);
        }

        // Wait dump worker finish, then add blob context to blob manager.
        for worker in workers {
            let blob_ctx = worker.join().expect("panic on diff build")?;
            blob_mgr.add(blob_ctx);
        }

        // Dump bootstraps for every snapshot layer.
        for (idx, _) in paths.iter().enumerate().take(base).skip(skip) {
            let mut bootstrap_ctx = bootstrap_mgr.create_ctx()?;
            bootstrap_ctx.name = format!("bootstrap-{}", idx);
            self.build_bootstrap(
                ctx,
                &mut bootstrap_ctx,
                blob_mgr,
                idx as u32,
                paths[idx].clone(),
            )?;
            bootstrap_mgr.add(bootstrap_ctx);
        }

        BuildOutput::new(&blob_mgr, &bootstrap_mgr)
    }

    fn build_with_diff(
        &mut self,
        ctx: &mut BuildContext,
        bootstrap_mgr: &mut BootstrapManager,
        blob_mgr: &mut BlobManager,
    ) -> Result<BuildOutput> {
        let mut paths = vec![None, Some(ctx.source_path.clone())];
        let mut extra_paths: Vec<_> = self.extra_paths.iter().map(|p| Some(p.clone())).collect();
        paths.append(&mut extra_paths);

        let mut workers = Vec::new();
        let base = paths.len() - 1;

        for idx in 0..base {
            let blob_id = ctx.blob_id.clone();
            let blob_storage = ctx.blob_storage.clone();
            let ctx = Arc::new(ctx.clone());
            let cached_nodes = self.cached_nodes.clone();
            let (lower, upper) = (paths[idx].clone(), paths[idx + 1].clone());
            let chunk_dict = blob_mgr.get_chunk_dict().clone();
            let worker = thread::spawn(move || -> Result<Option<BlobContext>> {
                info!("[{}] diff building {:?} -> {:?}", idx, lower, upper);

                let snapshot_idx = idx as u32;

                // Safe to unwrap because upper path must be exists.
                let upper = upper.as_ref().unwrap().clone();
                let mut blob_nodes = walk_diff(ctx.as_ref(), lower.clone(), upper.clone(), upper)?;

                let blob_ctx = dump_blob(
                    ctx,
                    snapshot_idx,
                    blob_id,
                    blob_storage,
                    cached_nodes,
                    &mut blob_nodes,
                    chunk_dict,
                )?;

                Ok(blob_ctx)
            });
            workers.push(worker);
        }

        for (snapshot_idx, worker) in workers.into_iter().enumerate() {
            let blob_ctx = worker.join().expect("panic on diff build")?;
            blob_mgr.add(blob_ctx);
            let mut bootstrap_ctx = bootstrap_mgr.create_ctx()?;
            let snapshot_path = paths[snapshot_idx + 1].clone().unwrap();
            self.build_bootstrap(
                ctx,
                &mut bootstrap_ctx,
                blob_mgr,
                snapshot_idx as u32,
                snapshot_path,
            )?;
        }

        BuildOutput::new(&blob_mgr, &bootstrap_mgr)
    }
}

impl Builder for DiffBuilder {
    fn build(
        &mut self,
        ctx: &mut BuildContext,
        bootstrap_mgr: &mut BootstrapManager,
        blob_mgr: &mut BlobManager,
    ) -> Result<BuildOutput> {
        self.load_parent_chunks(bootstrap_mgr, blob_mgr)
            .context("failed to load chunks from bootstrap")?;
        if self.diff_hint {
            self.build_with_hint(ctx, bootstrap_mgr, blob_mgr)
        } else {
            self.build_with_diff(ctx, bootstrap_mgr, blob_mgr)
        }
    }
}

#[cfg(test)]
pub mod tests {
    use std::fs::{self, File};
    use std::io::Write;
    use std::os::unix::fs as unix_fs;
    use std::path::Path;

    use nix::sys::stat::{dev_t, makedev, mknod, Mode, SFlag};
    use vmm_sys_util::tempdir::TempDir;

    use super::*;
    use nydus_utils::exec;
    use storage::RAFS_DEFAULT_CHUNK_SIZE;

    fn create_dir(path: &Path) {
        fs::create_dir_all(path).unwrap();
    }

    fn create_file(path: &Path, data: &[u8]) {
        File::create(path).unwrap().write_all(data).unwrap();
    }

    fn create_symlink(src: &Path, dst: &Path) {
        unix_fs::symlink(src, dst).unwrap();
    }

    fn create_hardlink(src: &Path, dst: &Path) {
        fs::hard_link(src, dst).unwrap();
    }

    fn create_whiteout_file(path: &Path) {
        let dev: dev_t = makedev(0, 0);
        mknod(
            path.to_str().unwrap(),
            SFlag::S_IFCHR,
            Mode::S_IRUSR | Mode::S_IWUSR,
            dev,
        )
        .expect("mknod failed");
    }

    fn create_opaque_dir(path: &Path) {
        create_dir(path);
        set_xattr(path, "trusted.overlay.opaque", b"y");
    }

    fn set_xattr(path: &Path, key: &str, value: &[u8]) {
        xattr::set(path, key, value).unwrap();
    }

    struct Mounter {
        mountpoint: PathBuf,
    }

    impl Mounter {
        fn new(lower_dir: PathBuf, upper_dir: PathBuf, merge_dir: PathBuf) -> Self {
            exec(
                &format!(
                    "mount -t overlay -o lowerdir={:?}:{:?} overlay {:?}",
                    upper_dir, lower_dir, merge_dir,
                ),
                true,
            )
            .unwrap();
            Mounter {
                mountpoint: merge_dir,
            }
        }
    }

    impl Drop for Mounter {
        fn drop(&mut self) {
            exec(&format!("umount {:?}", self.mountpoint), true).unwrap();
        }
    }

    #[test]
    fn test_walk_diff() {
        let tmp_dir_prefix =
            std::env::var("TEST_WORKDIR_PREFIX").expect("Please specify `TEST_WORKDIR_PREFIX` env");

        // Create lower layer
        let tmp_dir = TempDir::new_with_prefix(format!("{}/", tmp_dir_prefix)).unwrap();
        let lower_dir = tmp_dir.as_path().to_path_buf();
        create_file(&lower_dir.join("test-1"), b"test-1");
        create_symlink(&lower_dir.join("test-1"), &lower_dir.join("test-1-symlink"));
        create_hardlink(
            &lower_dir.join("test-1"),
            &lower_dir.join("test-1-hardlink"),
        );
        create_dir(&lower_dir.join("dir-1"));
        create_file(&lower_dir.join("dir-1/test-1"), b"dir-1/test-1");
        create_file(&lower_dir.join("dir-1/test-2"), b"dir-1/test-2");
        create_dir(&lower_dir.join("dir-2"));
        create_file(&lower_dir.join("dir-2/test-1"), b"dir-2/test-1");
        create_file(&lower_dir.join("dir-2/test-2"), b"dir-2/test-2");
        create_dir(&lower_dir.join("dir-3"));
        create_file(&lower_dir.join("dir-3/test-1"), b"dir-3/test-1");
        create_file(&lower_dir.join("dir-3/test-2"), b"dir-3/test-2");
        create_dir(&lower_dir.join("dir-5"));
        create_file(&lower_dir.join("dir-5/test-1"), b"dir-5/test-1");
        create_file(&lower_dir.join("dir-5/test-2"), b"dir-5/test-2");
        create_file(&lower_dir.join("test-2"), b"test-2");

        // Create upper layer
        let tmp_dir = TempDir::new_with_prefix("./").unwrap();
        let upper_dir = tmp_dir.as_path().to_path_buf();
        create_whiteout_file(&upper_dir.join("test-2"));
        create_opaque_dir(&upper_dir.join("dir-2"));
        create_file(&upper_dir.join("dir-2/test-1"), b"dir-2/test-1-new");
        create_file(&upper_dir.join("dir-2/test-2"), b"dir-2/test-2-new");
        create_file(&upper_dir.join("dir-2/test-3"), b"dir-2/test-3-new");
        create_whiteout_file(&upper_dir.join("dir-3"));
        create_file(&upper_dir.join("test-3"), b"test-3");
        create_dir(&upper_dir.join("dir-4"));
        create_file(&upper_dir.join("dir-4/test-1"), b"dir-4/test-1");
        create_file(&upper_dir.join("dir-4/test-2"), b"dir-4/test-2");
        create_file(&upper_dir.join("test-1"), b"test-1-modified");

        // Mount using overlayfs
        let tmp_dir = TempDir::new_with_prefix(format!("{}/", tmp_dir_prefix)).unwrap();
        let merge_dir = tmp_dir.as_path().to_path_buf();
        let _mounter = Mounter::new(lower_dir.clone(), upper_dir, merge_dir.clone());

        println!(
            "lower dir:\n {}",
            exec(&format!("tree -a {:?}", lower_dir), true).unwrap()
        );
        println!(
            "merge dir:\n{}",
            exec(&format!("tree -a {:?}", merge_dir), true).unwrap()
        );

        // Diff build lower layer
        let expected = vec![
            (Overlay::UpperAddition, PathBuf::from("/dir-1/test-1")),
            (Overlay::UpperAddition, PathBuf::from("/dir-1/test-2")),
            (Overlay::UpperAddition, PathBuf::from("/dir-2/test-1")),
            (Overlay::UpperAddition, PathBuf::from("/dir-2/test-2")),
            (Overlay::UpperAddition, PathBuf::from("/dir-3/test-1")),
            (Overlay::UpperAddition, PathBuf::from("/dir-3/test-2")),
            (Overlay::UpperAddition, PathBuf::from("/dir-5/test-1")),
            (Overlay::UpperAddition, PathBuf::from("/dir-5/test-2")),
            (Overlay::UpperAddition, PathBuf::from("/test-1")),
            (Overlay::UpperAddition, PathBuf::from("/test-1-hardlink")),
            (Overlay::UpperAddition, PathBuf::from("/test-1-symlink")),
            (Overlay::UpperAddition, PathBuf::from("/test-2")),
        ];
        let ctx = BuildContext {
            chunk_size: RAFS_DEFAULT_CHUNK_SIZE as u32,
            ..Default::default()
        };
        let nodes = walk_diff(&ctx, None, lower_dir.clone(), lower_dir.clone()).unwrap();
        for (i, node) in nodes.into_iter().enumerate() {
            println!("lower node: {:?} {:?}", node.overlay, node.target());
            assert_eq!(expected[i], (node.overlay.clone(), node.target().clone()));
        }

        // Diff build upper layer
        let expected = vec![
            (Overlay::UpperModification, PathBuf::from("/dir-2/test-1")),
            (Overlay::UpperModification, PathBuf::from("/dir-2/test-2")),
            (Overlay::UpperAddition, PathBuf::from("/dir-2/test-3")),
            (Overlay::UpperAddition, PathBuf::from("/dir-4/test-1")),
            (Overlay::UpperAddition, PathBuf::from("/dir-4/test-2")),
            (Overlay::UpperModification, PathBuf::from("/test-1")),
            (Overlay::UpperAddition, PathBuf::from("/test-3")),
        ];
        let nodes = walk_diff(
            &ctx,
            Some(lower_dir.clone()),
            merge_dir.clone(),
            merge_dir.clone(),
        )
        .unwrap();
        for (i, node) in nodes.into_iter().enumerate() {
            println!("merged node: {:?} {:?}", node.overlay, node.target());
            assert_eq!(expected[i], (node.overlay.clone(), node.target().clone()));
        }
        println!("{:?} {:?}", lower_dir, merge_dir);
    }
}

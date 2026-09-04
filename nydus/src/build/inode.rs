use crate::build::blob_chunk::BlobWriter;
use nydus_error::{Context, Error, Result};
use nydus_format::erofs::{
    erofs_chunk_format, erofs_compact_i_format, erofs_extended_i_format, erofs_xattr_ibody_size,
    erofs_xattr_icount, erofs_xattr_name_split, mode_to_erofs_file_type,
    needs_erofs_extended_inode, ErofsChunkAddr, ErofsChunkIndex, ErofsInodeCompact,
    ErofsInodeExtended, XattrEntry, EROFS_BLKSZBITS, EROFS_BLOCK_SIZE, EROFS_CHUNK_INDEX_SIZE,
    EROFS_FT_DIR, EROFS_INODE_CHUNK_BASED, EROFS_INODE_COMPACT_SIZE, EROFS_INODE_EXTENDED_SIZE,
    EROFS_INODE_FLAT_INLINE, EROFS_INODE_FLAT_PLAIN, EROFS_XATTR_ENTRY_HEADER_SIZE,
    EROFS_XATTR_IBODY_HEADER_SIZE, EROFS_XATTR_INDEX_TRUSTED, NYDUS_XATTR_SUFFIX_PREFETCH_BLOBS,
};
use nydus_format::utils::align_up_usize;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Write;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// In-memory inode representation.
pub struct InodeInfo {
    /// File mode (type and permissions).
    pub mode: u16,

    /// User ID.
    pub uid: u32,

    /// Group ID.
    pub gid: u32,

    /// File size in bytes.
    pub size: u64,

    /// Modification time seconds since epoch.
    pub mtime: u64,

    /// Modification time nanosecond part.
    pub mtime_nsec: u32,

    /// Number of hard links.
    pub nlink: u32,

    /// Inode number (for hardlink tracking).
    pub ino: u32,

    /// Assigned EROFS inode number (nid) and metadata offset in the final image.
    pub nid: u64,

    /// Metadata offset in the final image (set during layout).
    pub meta_offset: usize,

    /// True if this inode needs extended (64-byte) format.
    pub is_extended: bool,

    /// File-type-specific data.
    pub data: InodeData,

    /// Inline xattr entries, in EROFS ibody order.
    pub xattrs: Vec<XattrEntry>,
}

/// File-type-specific data for an inode.
pub enum InodeData {
    /// Regular file: chunk indexes for chunk-based layout.
    RegularFile {
        /// List of chunk indexes (EROFS_CHUNK_INDEX_SIZE bytes each) for the file's data chunks.
        chunk_index_entries: Vec<ErofsChunkAddr>,

        /// Number of bits for the chunk size (e.g. 12 for 4KB chunks).
        chunk_size_bits: u32,
    },

    /// Directory: sorted children.
    Directory {
        // List of child entries (name, file type, inode index in the inodes vector).
        children: Vec<ChildRef>,

        /// Starting block address of the directory data (set during layout).
        startblk: u64,

        /// Size of the directory data in bytes (set during layout).
        data_size: usize,

        /// NID of the parent directory (set during layout, 0 for root).
        parent_nid: u64,
    },

    /// Symbolic link: target path.
    ///
    /// A target normally rides inline behind the inode header, but PATH_MAX is
    /// 4096 and an inode header plus its xattrs plus a target that long cannot
    /// fit in one 4096-byte block. Such a symlink falls back to a data block of
    /// its own, exactly like a directory, so `startblk` is set during layout
    /// and left at 0 for the inline case.
    Symlink { target: Vec<u8>, startblk: u64 },

    /// Character/block device.
    Device { rdev: u32 },

    /// FIFO or socket (no data).
    FifoOrSocket,
}

/// A directory entry referencing a child inode.
pub struct ChildRef {
    /// Entry name, as the raw bytes the kernel reported.
    pub name: Vec<u8>,

    /// File type.
    pub file_type: u8,

    /// Index of the child inode in the inodes vector.
    pub inode_index: usize,
}

/// Calculate the size of an inode's metadata (header + xattr ibody + chunk indexes) for the final
/// image.
pub(crate) fn erofs_inode_size(inode: &InodeInfo) -> usize {
    let inode_isize = if inode.is_extended {
        EROFS_INODE_EXTENDED_SIZE
    } else {
        EROFS_INODE_COMPACT_SIZE
    };

    let xattr_isize = erofs_xattr_ibody_size(&inode.xattrs);
    match &inode.data {
        InodeData::RegularFile {
            chunk_index_entries,
            ..
        } => {
            if chunk_index_entries.is_empty() {
                inode_isize + xattr_isize
            } else {
                align_up_usize(inode_isize + xattr_isize, EROFS_CHUNK_INDEX_SIZE)
                    .expect("alignment overflowed")
                    + chunk_index_entries.len() * EROFS_CHUNK_INDEX_SIZE
            }
        }
        InodeData::Directory { .. } => inode_isize + xattr_isize,
        InodeData::Symlink { target, .. } => {
            if symlink_is_inline(inode) {
                inode_isize + xattr_isize + target.len()
            } else {
                inode_isize + xattr_isize
            }
        }
        InodeData::Device { .. } | InodeData::FifoOrSocket => inode_isize + xattr_isize,
    }
}

/// Whether a symlink target still fits behind its own inode header within a
/// single block. The header and its xattrs are already accounted for by
/// `header_size`.
fn symlink_fits_inline(header_size: usize, target_len: usize) -> bool {
    header_size + target_len <= EROFS_BLOCK_SIZE as usize
}

/// Whether a symlink stores its target inline rather than in a data block.
///
/// A target that needs its own block forces the extended layout: a compact
/// inode's `i_nb` field carries the link count, leaving nowhere to put the
/// block address' high bits, whereas the extended layout has a separate
/// `i_nlink`.
pub(crate) fn symlink_is_inline(inode: &InodeInfo) -> bool {
    match &inode.data {
        InodeData::Symlink { target, .. } => symlink_fits_inline(
            EROFS_INODE_COMPACT_SIZE + erofs_xattr_ibody_size(&inode.xattrs),
            target.len(),
        ),
        _ => false,
    }
}

/// Set the root directory's trusted.nydus.prefetch_blobs xattr to a comma-separated list of
/// unique non-zero blob indexes.
pub fn set_root_prefetch_blobs_xattr(inode: &mut InodeInfo, blob_indexes: &[u16]) -> Result<()> {
    let mut prefetch_blob_indexes = Vec::new();
    for blob_index in blob_indexes.iter().copied() {
        if blob_index != 0 && !prefetch_blob_indexes.contains(&blob_index) {
            prefetch_blob_indexes.push(blob_index);
        }
    }

    if prefetch_blob_indexes.is_empty() {
        return Ok(());
    }

    let value = prefetch_blob_indexes
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(",");
    if value.len() > u16::MAX as usize {
        return Err(Error::InvalidParameter(
            "root prefetch xattr value exceeds EROFS xattr value size limit".to_string(),
        ));
    }

    inode.xattrs.retain(|entry| {
        !(entry.name_index == EROFS_XATTR_INDEX_TRUSTED
            && entry.suffix.as_slice() == NYDUS_XATTR_SUFFIX_PREFETCH_BLOBS)
    });

    inode.xattrs.push(XattrEntry {
        name_index: EROFS_XATTR_INDEX_TRUSTED,
        suffix: NYDUS_XATTR_SUFFIX_PREFETCH_BLOBS.to_vec(),
        value: value.into_bytes(),
    });

    Ok(())
}

/// Build the in-memory inode tree from a source directory.
///
/// Walks `source` recursively and returns one [`InodeInfo`] per filesystem
/// object as a flat list in DFS pre-order (root at index 0); directories
/// reference children by index into this list.
///
/// File contents are streamed into `blob_writer` in `chunk_size` chunks
/// (must be a power of two). Hardlinks share a single inode entry, and
/// children are visited in sorted name order for deterministic output.
/// Layout fields (`nid`, `meta_offset`, etc.) are left 0 for a later pass.
pub fn build_tree<W: Write>(
    source: &Path,
    blob_writer: &mut BlobWriter<W>,
    chunk_size: u32,
    excludes: &HashSet<PathBuf>,
) -> Result<Vec<InodeInfo>> {
    let mut ctx = FsBuildContext {
        blob_writer,
        chunk_size,
        excludes,
    };
    let mut inodes = flatten_tree(FsTreeNode::new(source.to_path_buf())?, &mut ctx)?;

    // The root directory is created by whatever staged the layer, so its mtime
    // is the moment of the build rather than anything about the content. Left
    // alone it makes the bootstrap, and with it the layer digest, differ
    // between two builds of the same source. nydus v2 drops it for the same
    // reason.
    if let Some(root) = inodes.first_mut() {
        root.mtime = 0;
        root.mtime_nsec = 0;
    }

    Ok(inodes)
}

/// Inode attributes gathered once per node by a [`TreeNode`] implementation.
pub(crate) struct NodeAttrs {
    pub mode: u16,
    pub uid: u32,
    pub gid: u32,
    /// Content size; only used for regular files (the flattener derives the
    /// size of every other inode kind itself).
    pub size: u64,
    pub mtime: u64,
    pub mtime_nsec: u32,
    /// Source link count; only used for non-directories (a directory's link
    /// count is recomputed from the tree being flattened).
    pub nlink: u32,
    /// Inline xattr entries: (prefix_index, name_suffix, value), sorted.
    pub xattrs: Vec<XattrEntry>,
}

/// A directory's children as (name, node) pairs, sorted by name.
pub(crate) type NamedChildren<N> = Vec<(Vec<u8>, N)>;

/// A node of a source tree that [`flatten_tree`] can turn into [`InodeInfo`]s.
///
/// Implemented by the host-filesystem walker below and by the in-memory merge
/// tree in [`crate::build::merge`], so building a directory and merging layers
/// share a single flattening pass and cannot drift apart. `C` is the traversal
/// state threaded through the walk (e.g. the blob writer receiving file
/// contents).
pub(crate) trait TreeNode<C>: Sized {
    /// Identifies a hardlink group across the whole tree, e.g. host
    /// `(dev, ino)`.
    type LinkKey: Copy + Eq + std::hash::Hash;

    /// Common inode attributes. Takes `&mut self` so owned fields (xattrs)
    /// can be moved out instead of cloned; called exactly once per node.
    /// Fallible because lazily-expanded sources read them from disk.
    fn attrs(&mut self) -> Result<NodeAttrs>;

    /// Hardlink-group key; `Some` only for non-directories that may share
    /// their inode with other links. Fallible for lazily-expanded sources.
    fn link_key(&mut self) -> Result<Option<Self::LinkKey>>;

    /// `Some(children)` sorted by name when the node is a directory, `None`
    /// otherwise. Owned children are moved out so each subtree can be freed
    /// as soon as it has been flattened.
    fn children(&mut self, ctx: &mut C) -> Result<Option<NamedChildren<Self>>>;

    /// Type-specific data for a non-directory node; called exactly once per
    /// inode (regular-file contents are chunked into the blob here).
    fn leaf_data(&mut self, ctx: &mut C) -> Result<InodeData>;
}

/// Flatten a source tree into one [`InodeInfo`] per filesystem object, as a
/// flat list in DFS pre-order; directories reference children by index into
/// this list.
///
/// The returned list is never empty: the root's inode is always at index 0.
/// Nodes sharing a [`TreeNode::link_key`] are deduplicated into a single
/// entry. A directory's `nlink` (`2 + subdirectory count`) and its
/// compact/extended format are computed from the tree being flattened rather
/// than taken from source metadata, keeping the output independent of how the
/// source filesystem reports directories. Layout fields (`nid`, `meta_offset`,
/// etc.) are left 0 for a later pass.
pub(crate) fn flatten_tree<C, N: TreeNode<C>>(root: N, ctx: &mut C) -> Result<Vec<InodeInfo>> {
    let mut inodes = Vec::new();
    let mut ino_counter = 0u32;
    let mut hardlink_map = HashMap::new();
    flatten_tree_node(root, ctx, &mut inodes, &mut ino_counter, &mut hardlink_map)?;
    Ok(inodes)
}

/// Recursively flatten `node` and its descendants, appending to `inodes` in
/// DFS pre-order and returning the index of `node`'s inode (the existing
/// index when `node` is a later link of an already-flattened hardlink group).
/// Nodes are consumed: each subtree is dropped right after flattening, so the
/// source tree and the inode table are never both fully resident.
fn flatten_tree_node<C, N: TreeNode<C>>(
    mut node: N,
    ctx: &mut C,
    inodes: &mut Vec<InodeInfo>,
    ino_counter: &mut u32,
    hardlink_map: &mut HashMap<N::LinkKey, usize>,
) -> Result<usize> {
    let link_key = node.link_key()?;
    if let Some(key) = link_key {
        if let Some(existing_index) = hardlink_map.get(&key) {
            return Ok(*existing_index);
        }
    }

    let attrs = node.attrs()?;
    *ino_counter += 1;
    let ino = *ino_counter;
    let inode_index = inodes.len();

    if let Some(children) = node.children(ctx)? {
        // Push the directory before its children to keep DFS pre-order; the
        // fields that depend on the children are patched below.
        inodes.push(InodeInfo {
            mode: attrs.mode,
            uid: attrs.uid,
            gid: attrs.gid,
            size: 0,
            mtime: attrs.mtime,
            mtime_nsec: attrs.mtime_nsec,
            nlink: 0,
            ino,
            nid: 0,
            meta_offset: 0,
            is_extended: false,
            data: InodeData::Directory {
                children: Vec::new(),
                startblk: 0,
                data_size: 0,
                parent_nid: 0,
            },
            xattrs: attrs.xattrs,
        });

        let mut child_entries = Vec::with_capacity(children.len());
        let mut subdir_count = 0u32;
        for (name, child) in children {
            let child_index = flatten_tree_node(child, ctx, inodes, ino_counter, hardlink_map)?;
            let file_type = mode_to_erofs_file_type(inodes[child_index].mode);
            if file_type == EROFS_FT_DIR {
                subdir_count += 1;
            }
            child_entries.push(ChildRef {
                name,
                file_type,
                inode_index: child_index,
            });
        }

        // A directory's link count is `.`, its entry in the parent, and one
        // `..` per subdirectory. Deriving it (and the format decision) from
        // the flattened tree instead of source metadata keeps the bootstrap
        // identical however the source filesystem counts directory links.
        let nlink = 2 + subdir_count;
        inodes[inode_index].nlink = nlink;
        inodes[inode_index].is_extended =
            needs_erofs_extended_inode(0, attrs.uid, attrs.gid, nlink as u64);
        if let InodeData::Directory {
            children: ref mut dir_children,
            ..
        } = inodes[inode_index].data
        {
            *dir_children = child_entries;
        }
    } else {
        let data = node.leaf_data(ctx)?;
        let size = match &data {
            InodeData::RegularFile { .. } => attrs.size,
            InodeData::Symlink { target, .. } => target.len() as u64,
            InodeData::Device { .. } | InodeData::FifoOrSocket => 0,
            InodeData::Directory { .. } => {
                unreachable!("leaf_data is only called for non-directories")
            }
        };
        let nlink = attrs.nlink.max(1);
        inodes.push(InodeInfo {
            mode: attrs.mode,
            uid: attrs.uid,
            gid: attrs.gid,
            size,
            mtime: attrs.mtime,
            mtime_nsec: attrs.mtime_nsec,
            nlink,
            ino,
            nid: 0,
            meta_offset: 0,
            is_extended: needs_erofs_extended_inode(size, attrs.uid, attrs.gid, nlink as u64),
            data,
            xattrs: attrs.xattrs,
        });
    }

    if let Some(key) = link_key {
        hardlink_map.insert(key, inode_index);
    }

    Ok(inode_index)
}

/// Traversal state for the host-filesystem walk: the blob writer receiving
/// file contents, the file chunk size, and the exclusion set.
struct FsBuildContext<'a, W> {
    blob_writer: &'a mut BlobWriter<W>,
    chunk_size: u32,
    excludes: &'a HashSet<PathBuf>,
}

/// A host filesystem object: its path plus the (symlink-aware) metadata,
/// stat'ed once when the node is created.
struct FsTreeNode {
    path: PathBuf,
    meta: fs::Metadata,
}

impl FsTreeNode {
    fn new(path: PathBuf) -> Result<Self> {
        let meta = fs::symlink_metadata(&path)
            .with_context(|| format!("failed to stat source entry: {}", path.display()))?;
        Ok(Self { path, meta })
    }
}

impl<'a, W: Write> TreeNode<FsBuildContext<'a, W>> for FsTreeNode {
    type LinkKey = (u64, u64);

    fn attrs(&mut self) -> Result<NodeAttrs> {
        Ok(NodeAttrs {
            mode: self.meta.mode() as u16,
            uid: self.meta.uid(),
            gid: self.meta.gid(),
            size: self.meta.size(),
            mtime: self.meta.mtime() as u64,
            mtime_nsec: self.meta.mtime_nsec() as u32,
            nlink: self.meta.nlink() as u32,
            xattrs: read_xattrs_from_path(&self.path),
        })
    }

    fn link_key(&mut self) -> Result<Option<(u64, u64)>> {
        Ok((!self.meta.file_type().is_dir() && self.meta.nlink() > 1)
            .then(|| (self.meta.dev(), self.meta.ino())))
    }

    fn children(&mut self, ctx: &mut FsBuildContext<'a, W>) -> Result<Option<NamedChildren<Self>>> {
        if !self.meta.file_type().is_dir() {
            return Ok(None);
        }

        let entries = fs::read_dir(&self.path)
            .with_context(|| format!("failed to read directory: {}", self.path.display()))?
            .collect::<std::io::Result<Vec<_>>>()
            .with_context(|| format!("failed to read directory entry: {}", self.path.display()))?;

        let mut children = Vec::with_capacity(entries.len());
        for entry in entries {
            let child_path = entry.path();

            // Skip entries whose absolute path is in the exclude set.
            if ctx.excludes.contains(&child_path) {
                continue;
            }

            children.push((entry.file_name().into_vec(), FsTreeNode::new(child_path)?));
        }
        children.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(Some(children))
    }

    fn leaf_data(&mut self, ctx: &mut FsBuildContext<'a, W>) -> Result<InodeData> {
        let ft = self.meta.file_type();
        if ft.is_file() {
            let chunk_index_entries = ctx
                .blob_writer
                .write_file_chunks(&self.path, self.meta.size())?;
            Ok(InodeData::RegularFile {
                chunk_index_entries,
                chunk_size_bits: ctx.chunk_size.trailing_zeros(),
            })
        } else if ft.is_symlink() {
            let target = fs::read_link(&self.path)
                .with_context(|| format!("failed to read symlink: {}", self.path.display()))?
                .into_os_string()
                .into_vec();
            Ok(InodeData::Symlink {
                target,
                startblk: 0,
            })
        } else {
            let file_type = self.meta.mode() & libc::S_IFMT;
            if file_type == libc::S_IFCHR || file_type == libc::S_IFBLK {
                Ok(InodeData::Device {
                    rdev: self.meta.rdev() as u32,
                })
            } else {
                Ok(InodeData::FifoOrSocket)
            }
        }
    }
}

/// Serialize an inode (header, xattrs, chunk indexes and inline tail) to bytes.
pub(crate) fn serialize_inode(inode: &InodeInfo, epoch: u64) -> Vec<u8> {
    let blkszbits = EROFS_BLKSZBITS as u32;
    let inode_size = erofs_inode_size(inode);
    let mut buf = vec![0u8; inode_size];

    let xattr_size = erofs_xattr_ibody_size(&inode.xattrs);
    let i_xattr_icount = erofs_xattr_icount(xattr_size);

    match &inode.data {
        InodeData::RegularFile {
            chunk_index_entries,
            chunk_size_bits,
        } => {
            let datalayout = EROFS_INODE_CHUNK_BASED;
            let cf = erofs_chunk_format(*chunk_size_bits, blkszbits);
            let i_u = cf as u32;

            if inode.is_extended {
                let i_format = erofs_extended_i_format(datalayout);
                let hdr = ErofsInodeExtended::new(
                    i_format,
                    inode.mode,
                    0,
                    inode.size,
                    i_u,
                    inode.ino,
                    inode.uid,
                    inode.gid,
                    inode.mtime,
                    inode.mtime_nsec,
                    inode.nlink,
                );
                buf[..EROFS_INODE_EXTENDED_SIZE].copy_from_slice(hdr.as_bytes());
                write_erofs_xattr_ibody(&mut buf, EROFS_INODE_EXTENDED_SIZE, &inode.xattrs);
            } else {
                let i_format = erofs_compact_i_format(datalayout);
                let i_mtime = inode.mtime.wrapping_sub(epoch) as u32;
                let hdr = ErofsInodeCompact::new(
                    i_format,
                    inode.mode,
                    1,
                    inode.size as u32,
                    i_mtime,
                    i_u,
                    inode.ino,
                    inode.uid as u16,
                    inode.gid as u16,
                );
                buf[..EROFS_INODE_COMPACT_SIZE].copy_from_slice(hdr.as_bytes());
                write_erofs_xattr_ibody(&mut buf, EROFS_INODE_COMPACT_SIZE, &inode.xattrs);
            }

            let base = if inode.is_extended {
                EROFS_INODE_EXTENDED_SIZE
            } else {
                EROFS_INODE_COMPACT_SIZE
            };
            let extent_offset = align_up_usize(base + xattr_size, EROFS_CHUNK_INDEX_SIZE)
                .expect("alignment overflowed");
            for (i, entry) in chunk_index_entries.iter().enumerate() {
                let index = ErofsChunkIndex::new(entry.blkaddr, entry.device_id);
                let off = extent_offset + i * EROFS_CHUNK_INDEX_SIZE;
                buf[off..off + EROFS_CHUNK_INDEX_SIZE].copy_from_slice(index.as_bytes());
            }
        }
        InodeData::Directory { startblk, .. } => {
            let datalayout = EROFS_INODE_FLAT_PLAIN;
            let startblk_lo = *startblk as u32;
            let startblk_hi = (*startblk >> 32) as u16;

            if inode.is_extended {
                let i_format = erofs_extended_i_format(datalayout);
                let hdr = ErofsInodeExtended::new(
                    i_format,
                    inode.mode,
                    startblk_hi,
                    inode.size,
                    startblk_lo,
                    inode.ino,
                    inode.uid,
                    inode.gid,
                    inode.mtime,
                    inode.mtime_nsec,
                    inode.nlink,
                );
                buf[..EROFS_INODE_EXTENDED_SIZE].copy_from_slice(hdr.as_bytes());
                write_erofs_xattr_ibody(&mut buf, EROFS_INODE_EXTENDED_SIZE, &inode.xattrs);
            } else {
                let i_format = erofs_compact_i_format(datalayout);
                let i_mtime = inode.mtime.wrapping_sub(epoch) as u32;
                let hdr = ErofsInodeCompact::new(
                    i_format,
                    inode.mode,
                    startblk_hi,
                    inode.size as u32,
                    i_mtime,
                    startblk_lo,
                    inode.ino,
                    inode.uid as u16,
                    inode.gid as u16,
                );
                buf[..EROFS_INODE_COMPACT_SIZE].copy_from_slice(hdr.as_bytes());
                write_erofs_xattr_ibody(&mut buf, EROFS_INODE_COMPACT_SIZE, &inode.xattrs);
            }
        }
        InodeData::Symlink { target, startblk } => {
            let inline = symlink_is_inline(inode);
            let datalayout = if inline {
                EROFS_INODE_FLAT_INLINE
            } else {
                EROFS_INODE_FLAT_PLAIN
            };
            let inline_off = if inode.is_extended {
                EROFS_INODE_EXTENDED_SIZE + xattr_size
            } else {
                EROFS_INODE_COMPACT_SIZE + xattr_size
            };
            let startblk_lo = if inline { 0 } else { *startblk as u32 };

            if inode.is_extended {
                let i_format = erofs_extended_i_format(datalayout);
                let hdr = ErofsInodeExtended::new(
                    i_format,
                    inode.mode,
                    0,
                    inode.size,
                    startblk_lo,
                    inode.ino,
                    inode.uid,
                    inode.gid,
                    inode.mtime,
                    inode.mtime_nsec,
                    inode.nlink,
                );
                buf[..EROFS_INODE_EXTENDED_SIZE].copy_from_slice(hdr.as_bytes());
                write_erofs_xattr_ibody(&mut buf, EROFS_INODE_EXTENDED_SIZE, &inode.xattrs);
            } else {
                let i_format = erofs_compact_i_format(datalayout);
                let i_mtime = inode.mtime.wrapping_sub(epoch) as u32;
                let hdr = ErofsInodeCompact::new(
                    i_format,
                    inode.mode,
                    1,
                    inode.size as u32,
                    i_mtime,
                    startblk_lo,
                    inode.ino,
                    inode.uid as u16,
                    inode.gid as u16,
                );
                buf[..EROFS_INODE_COMPACT_SIZE].copy_from_slice(hdr.as_bytes());
                write_erofs_xattr_ibody(&mut buf, EROFS_INODE_COMPACT_SIZE, &inode.xattrs);
            }
            if inline {
                buf[inline_off..inline_off + target.len()].copy_from_slice(target);
            }
        }
        InodeData::Device { rdev } => {
            let datalayout = EROFS_INODE_FLAT_PLAIN;

            if inode.is_extended {
                let i_format = erofs_extended_i_format(datalayout);
                let hdr = ErofsInodeExtended::new(
                    i_format,
                    inode.mode,
                    0,
                    0,
                    *rdev,
                    inode.ino,
                    inode.uid,
                    inode.gid,
                    inode.mtime,
                    inode.mtime_nsec,
                    inode.nlink,
                );
                buf[..EROFS_INODE_EXTENDED_SIZE].copy_from_slice(hdr.as_bytes());
                write_erofs_xattr_ibody(&mut buf, EROFS_INODE_EXTENDED_SIZE, &inode.xattrs);
            } else {
                let i_format = erofs_compact_i_format(datalayout);
                let i_mtime = inode.mtime.wrapping_sub(epoch) as u32;
                let hdr = ErofsInodeCompact::new(
                    i_format,
                    inode.mode,
                    1,
                    0,
                    i_mtime,
                    *rdev,
                    inode.ino,
                    inode.uid as u16,
                    inode.gid as u16,
                );
                buf[..EROFS_INODE_COMPACT_SIZE].copy_from_slice(hdr.as_bytes());
                write_erofs_xattr_ibody(&mut buf, EROFS_INODE_COMPACT_SIZE, &inode.xattrs);
            }
        }
        InodeData::FifoOrSocket => {
            let datalayout = EROFS_INODE_FLAT_PLAIN;

            if inode.is_extended {
                let i_format = erofs_extended_i_format(datalayout);
                let hdr = ErofsInodeExtended::new(
                    i_format,
                    inode.mode,
                    0,
                    0,
                    0,
                    inode.ino,
                    inode.uid,
                    inode.gid,
                    inode.mtime,
                    inode.mtime_nsec,
                    inode.nlink,
                );
                buf[..EROFS_INODE_EXTENDED_SIZE].copy_from_slice(hdr.as_bytes());
                write_erofs_xattr_ibody(&mut buf, EROFS_INODE_EXTENDED_SIZE, &inode.xattrs);
            } else {
                let i_format = erofs_compact_i_format(datalayout);
                let i_mtime = inode.mtime.wrapping_sub(epoch) as u32;
                let hdr = ErofsInodeCompact::new(
                    i_format,
                    inode.mode,
                    1,
                    0,
                    i_mtime,
                    0,
                    inode.ino,
                    inode.uid as u16,
                    inode.gid as u16,
                );
                buf[..EROFS_INODE_COMPACT_SIZE].copy_from_slice(hdr.as_bytes());
                write_erofs_xattr_ibody(&mut buf, EROFS_INODE_COMPACT_SIZE, &inode.xattrs);
            }
        }
    }

    // Set i_xattr_icount in the inode header (bytes 2-3 for both compact and extended)
    if i_xattr_icount > 0 {
        buf[2..4].copy_from_slice(&i_xattr_icount.to_le_bytes());
    }

    buf
}

/// Write the EROFS xattr inline body (ibody) into `buf` at `offset`.
///
/// Layout: an all-zero `erofs_xattr_ibody_header` (meaning no shared
/// xattrs), followed by one 4-byte-aligned entry per element of `xattrs`
/// (`(name_index, name_suffix, value)`).
///
/// Returns the ibody size in bytes, or 0 when `xattrs` is empty.
/// Panics if the ibody does not fit in `buf` at `offset`.
fn write_erofs_xattr_ibody(buf: &mut [u8], offset: usize, xattrs: &[XattrEntry]) -> usize {
    if xattrs.is_empty() {
        return 0;
    }

    // Carve out the whole ibody region up front: bounds are checked exactly
    // once and fail fast; every write below stays inside this region.
    let ibody_size = erofs_xattr_ibody_size(xattrs);
    let ibody = &mut buf[offset..offset + ibody_size];

    // Entries start right after the header; `entry_start` stays 4-byte aligned.
    let mut entry_start = EROFS_XATTR_IBODY_HEADER_SIZE;
    for entry in xattrs {
        let (name_index, name_suffix, value) = (&entry.name_index, &entry.suffix, &entry.value);
        // EROFS XATTR Entry: e_name_len(u8) + e_name_index(u8) +
        // e_value_size(u16 LE), followed by the name suffix and the value.
        let name_start = entry_start + EROFS_XATTR_ENTRY_HEADER_SIZE;
        let value_start = name_start + name_suffix.len();

        // Write the entry header and body.
        ibody[entry_start] = name_suffix.len() as u8;
        ibody[entry_start + 1] = *name_index;
        ibody[entry_start + 2..name_start].copy_from_slice(&(value.len() as u16).to_le_bytes());
        ibody[name_start..value_start].copy_from_slice(name_suffix);
        ibody[value_start..][..value.len()].copy_from_slice(value);

        // Next entry begins at the next 4-byte boundary; padding is already zero.
        entry_start = align_up_usize(value_start + value.len(), 4).expect("alignment overflowed");
    }

    ibody_size
}

/// Read xattrs from a filesystem path, returning (prefix_index, suffix_bytes, value) triples.
fn read_xattrs_from_path(path: &Path) -> Vec<XattrEntry> {
    use std::os::unix::ffi::OsStrExt;
    let Ok(names) = xattr::list(path) else {
        return Vec::new();
    };

    let mut xattrs: Vec<XattrEntry> = names
        .filter_map(|name| {
            let (prefix_index, suffix) = erofs_xattr_name_split(name.as_bytes())?;
            let value = xattr::get(path, &name).ok().flatten().unwrap_or_default();
            Some(XattrEntry {
                name_index: prefix_index,
                suffix: suffix.to_vec(),
                value,
            })
        })
        .collect();
    // listxattr returns attributes in whatever order the source filesystem
    // stored them, which is the order they were set in. Sorting keeps the
    // bootstrap identical for two trees that differ only in that order.
    xattrs.sort_by(|a, b| (a.name_index, &a.suffix).cmp(&(b.name_index, &b.suffix)));
    xattrs
}

#[cfg(test)]
mod tests {
    use super::*;
    use nydus_format::erofs::EROFS_XATTR_INDEX_USER;

    fn root_inode_with_xattrs(xattrs: Vec<XattrEntry>) -> InodeInfo {
        InodeInfo {
            mode: 0o040755,
            uid: 0,
            gid: 0,
            size: 0,
            mtime: 0,
            mtime_nsec: 0,
            nlink: 2,
            ino: 1,
            nid: 0,
            meta_offset: 0,
            is_extended: false,
            data: InodeData::Directory {
                children: Vec::new(),
                startblk: 0,
                data_size: 0,
                parent_nid: 0,
            },
            xattrs,
        }
    }

    #[test]
    fn set_root_prefetch_blobs_xattr_replaces_and_deduplicates_value() {
        let mut inode = root_inode_with_xattrs(vec![
            XattrEntry {
                name_index: EROFS_XATTR_INDEX_TRUSTED,
                suffix: NYDUS_XATTR_SUFFIX_PREFETCH_BLOBS.to_vec(),
                value: b"old".to_vec(),
            },
            XattrEntry {
                name_index: EROFS_XATTR_INDEX_USER,
                suffix: b"keep".to_vec(),
                value: b"value".to_vec(),
            },
        ]);

        set_root_prefetch_blobs_xattr(&mut inode, &[2, 5, 2, 0, 1]).unwrap();

        let prefetch_xattrs = inode
            .xattrs
            .iter()
            .filter(|entry| {
                entry.name_index == EROFS_XATTR_INDEX_TRUSTED
                    && entry.suffix.as_slice() == NYDUS_XATTR_SUFFIX_PREFETCH_BLOBS
            })
            .collect::<Vec<_>>();
        assert_eq!(prefetch_xattrs.len(), 1);
        assert_eq!(prefetch_xattrs[0].value, b"2,5,1");
        assert!(inode.xattrs.iter().any(|entry| {
            entry.name_index == EROFS_XATTR_INDEX_USER
                && entry.suffix.as_slice() == b"keep"
                && entry.value.as_slice() == b"value"
        }));
    }
}

// Copyright 2020 Alibaba cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Generate a RAFS filesystem bootstrap from an stargz layer, reusing the stargz layer as data blob.

use std::cell::RefCell;
use std::collections::HashMap;
use std::ffi::OsString;
use std::fs::File;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use anyhow::{anyhow, bail, Context, Error, Result};
use base64::Engine;
use serde::{Deserialize, Serialize};

use nydus_rafs::metadata::chunk::ChunkWrapper;
use nydus_rafs::metadata::inode::InodeWrapper;
use nydus_rafs::metadata::layout::v5::{RafsV5ChunkInfo, RafsV5Inode, RafsV5InodeFlags};
use nydus_rafs::metadata::layout::RafsXAttrs;
use nydus_rafs::metadata::{Inode, RafsVersion};
use nydus_storage::device::BlobChunkFlags;
use nydus_storage::{RAFS_MAX_CHUNKS_PER_BLOB, RAFS_MAX_CHUNK_SIZE};
use nydus_utils::compact::makedev;
use nydus_utils::compress::compute_compressed_gzip_size;
use nydus_utils::digest::{self, Algorithm, DigestHasher, RafsDigest};
use nydus_utils::{compress, try_round_up_4k, ByteSize};

use crate::builder::{build_bootstrap, Builder};
use crate::core::blob::Blob;
use crate::core::context::{
    ArtifactWriter, BlobContext, BlobManager, BootstrapContext, BootstrapManager, BuildContext,
    BuildOutput,
};
use crate::core::node::{ChunkSource, Node, NodeChunk, Overlay};
use crate::core::tree::Tree;

type RcTocEntry = Rc<RefCell<TocEntry>>;

#[derive(Deserialize, Serialize, Debug, Clone, Default)]
struct TocEntry {
    /// Name is the tar entry's name. It is the complete path
    /// stored in the tar file, not just the base name.
    pub name: PathBuf,

    /// Type is one of "dir", "reg", "symlink", "hardlink", "char",
    /// "block", "fifo", or "chunk".
    /// The "chunk" type is used for regular file data chunks past the first
    /// TOCEntry; the 2nd chunk and on have only Type ("chunk"), Offset,
    /// ChunkOffset, and ChunkSize populated.
    #[serde(rename = "type")]
    pub toc_type: String,

    /// Size, for regular files, is the logical size of the file.
    #[serde(default)]
    pub size: u64,

    // // ModTime3339 is the modification time of the tar entry. Empty
    // // means zero or unknown. Otherwise it's in UTC RFC3339
    // // format. Use the ModTime method to access the time.Time value.
    // #[serde(default, alias = "modtime")]
    // mod_time_3339: String,
    // #[serde(skip)]
    // mod_time: Time,
    /// LinkName, for symlinks and hardlinks, is the link target.
    #[serde(default, rename = "linkName")]
    pub link_name: PathBuf,

    /// Mode is the permission and mode bits.
    #[serde(default)]
    pub mode: u32,

    /// Uid is the user ID of the owner.
    #[serde(default)]
    pub uid: u32,

    /// Gid is the group ID of the owner.
    #[serde(default)]
    pub gid: u32,

    /// Uname is the username of the owner.
    ///
    /// In the serialized JSON, this field may only be present for
    /// the first entry with the same Uid.
    #[serde(default, rename = "userName")]
    pub uname: String,

    /// Gname is the group name of the owner.
    ///
    /// In the serialized JSON, this field may only be present for
    /// the first entry with the same Gid.
    #[serde(default, rename = "groupName")]
    pub gname: String,

    /// Offset, for regular files, provides the offset in the
    /// stargz file to the file's data bytes. See ChunkOffset and
    /// ChunkSize.
    #[serde(default)]
    pub offset: u64,

    /// the Offset of the next entry with a non-zero Offset
    #[allow(unused)]
    #[serde(skip)]
    pub next_offset: u64,

    // DevMajor is the major device number for "char" and "block" types.
    #[serde(default, rename = "devMajor")]
    pub dev_major: u64,

    // DevMinor is the major device number for "char" and "block" types.
    #[serde(default, rename = "devMinor")]
    pub dev_minor: u64,

    // NumLink is the number of entry names pointing to this entry.
    // Zero means one name references this entry.
    #[serde(skip)]
    pub num_link: u32,

    // Xattrs are the extended attribute for the entry.
    #[serde(default)]
    pub xattrs: HashMap<String, String>,

    // Digest stores the OCI checksum for regular files payload.
    // It has the form "sha256:abcdef01234....".
    #[serde(default)]
    pub digest: String,

    // ChunkOffset is non-zero if this is a chunk of a large,
    // regular file. If so, the Offset is where the gzip header of
    // ChunkSize bytes at ChunkOffset in Name begin.
    //
    // In serialized form, a "chunkSize" JSON field of zero means
    // that the chunk goes to the end of the file. After reading
    // from the stargz TOC, though, the ChunkSize is initialized
    // to a non-zero file for when Type is either "reg" or
    // "chunk".
    #[serde(default, rename = "chunkOffset")]
    pub chunk_offset: u64,
    #[serde(default, rename = "chunkSize")]
    pub chunk_size: u64,

    #[allow(unused)]
    #[serde(skip)]
    pub children: Vec<RcTocEntry>,

    #[allow(unused)]
    #[serde(skip)]
    pub inode: u64,
}

impl TocEntry {
    /// Check whether the `TocEntry` is a directory.
    pub fn is_dir(&self) -> bool {
        self.toc_type.as_str() == "dir"
    }

    /// Check whether the `TocEntry` is a regular file.
    pub fn is_reg(&self) -> bool {
        self.toc_type.as_str() == "reg"
    }

    /// Check whether the `TocEntry` is a symlink.
    pub fn is_symlink(&self) -> bool {
        self.toc_type.as_str() == "symlink"
    }

    /// Check whether the `TocEntry` is a hardlink.
    pub fn is_hardlink(&self) -> bool {
        self.toc_type.as_str() == "hardlink"
    }

    /// Check whether the `TocEntry` is a file data chunk.
    pub fn is_chunk(&self) -> bool {
        self.toc_type.as_str() == "chunk"
    }

    /// Check whether the `TocEntry` is a block device.
    pub fn is_blockdev(&self) -> bool {
        self.toc_type.as_str() == "block"
    }

    /// Check whether the `TocEntry` is a char device.
    pub fn is_chardev(&self) -> bool {
        self.toc_type.as_str() == "char"
    }

    /// Check whether the `TocEntry` is a FIFO.
    pub fn is_fifo(&self) -> bool {
        self.toc_type.as_str() == "fifo"
    }

    /// Check whether the `TocEntry` is a special entry.
    pub fn is_special(&self) -> bool {
        self.is_blockdev() || self.is_chardev() || self.is_fifo()
    }

    /// Check whether the `TocEntry` has associated extended attributes.
    pub fn has_xattr(&self) -> bool {
        !self.xattrs.is_empty()
    }

    /// Get access permission and file mode of the `TocEntry`.
    pub fn mode(&self) -> u32 {
        let mut mode = 0;
        if self.is_dir() {
            mode |= libc::S_IFDIR;
        } else if self.is_reg() || self.is_hardlink() {
            mode |= libc::S_IFREG;
        } else if self.is_symlink() {
            mode |= libc::S_IFLNK;
        } else if self.is_blockdev() {
            mode |= libc::S_IFBLK;
        } else if self.is_chardev() {
            mode |= libc::S_IFCHR;
        } else if self.is_fifo() {
            mode |= libc::S_IFIFO;
        }

        self.mode | mode as u32
    }

    /// Get real device id associated with the `TocEntry`.
    pub fn rdev(&self) -> u32 {
        if self.is_special() {
            makedev(self.dev_major, self.dev_minor) as u32
        } else {
            u32::MAX
        }
    }

    /// Get file name of the `TocEntry` from the assoicated path.
    ///
    /// For example: `` to `/`, `/` to `/`, `a/b` to `b`, `a/b/` to `b`
    pub fn name(&self) -> Result<PathBuf> {
        let path = self.path()?;
        let root_path = PathBuf::from("/");
        if path == root_path {
            return Ok(root_path);
        }
        let name = path
            .file_name()
            .ok_or_else(|| anyhow!("invalid entry name"))?;
        Ok(PathBuf::from(name))
    }

    /// Get absolute path for the `TocEntry`.
    ///
    /// For example: `` to `/`, `a/b` to `/a/b`, `a/b/` to `/a/b`
    pub fn path(&self) -> Result<PathBuf> {
        let root_path = PathBuf::from("/");
        let empty_path = Path::new("");
        if self.name == empty_path || self.name == root_path {
            Ok(root_path)
        } else {
            let path = root_path.join(&self.name);
            if path.file_name().is_none() {
                Err(anyhow!("invalid entry name"))
            } else {
                Ok(path)
            }
        }
    }

    // Convert link path of hardlink entry to rootfs absolute path
    // For example: `a/b` to `/a/b`
    pub fn hardlink_link_path(&self) -> PathBuf {
        PathBuf::from("/").join(&self.link_name)
    }

    pub fn symlink_link_path(&self) -> PathBuf {
        self.link_name.clone()
    }

    pub fn is_supported(&self) -> bool {
        self.is_dir() || self.is_reg() || self.is_symlink() || self.is_hardlink() || self.is_chunk()
    }

    // TODO: think about chunk deduplicate
    pub fn block_id(&self, blob_id: &str) -> Result<RafsDigest> {
        if !self.is_reg() && !self.is_chunk() {
            bail!("only support chunk or reg entry");
        }
        let data = serde_json::to_string(self).context("block id calculation failed")?;

        Ok(RafsDigest::from_buf(
            (data + blob_id).as_bytes(),
            Algorithm::Sha256,
        ))
    }

    pub fn new_dir(path: PathBuf) -> Self {
        TocEntry {
            name: path,
            toc_type: String::from("dir"),
            mode: 0o755,
            num_link: 2,
            ..Default::default()
        }
    }
}

#[derive(Deserialize, Debug, Clone, Default)]
struct TocIndex {
    pub version: u32,
    pub entries: Vec<TocEntry>,
}

impl TocIndex {
    fn load(path: &Path) -> Result<TocIndex> {
        let index_file = File::open(path)
            .with_context(|| format!("failed to open stargz index file {:?}", path))?;
        let mut toc_index: TocIndex = serde_json::from_reader(index_file)
            .with_context(|| format!("invalid stargz index file {:?}", path))?;

        if toc_index.version != 1 {
            return Err(Error::msg(format!(
                "unsupported index version {}",
                toc_index.version
            )));
        }

        // Append root directory entry if not exists.
        if !toc_index.entries.is_empty() && toc_index.entries[0].name()? != PathBuf::from("/") {
            let root_entry = TocEntry {
                toc_type: String::from("dir"),
                ..Default::default()
            };
            toc_index.entries.insert(0, root_entry);
        }

        Ok(toc_index)
    }
}

struct StargzTreeBuilder {
    path_inode_map: HashMap<PathBuf, Inode>,
}

impl StargzTreeBuilder {
    fn new() -> Self {
        Self {
            path_inode_map: HashMap::new(),
        }
    }

    fn build(&mut self, ctx: &mut BuildContext, layer_idx: u16) -> Result<Tree> {
        let toc_index = TocIndex::load(&ctx.source_path)?;
        if toc_index.version != 1 {
            bail!("stargz version {} is unsupported", toc_index.version);
        } else if toc_index.entries.is_empty() {
            bail!("stargz TOC array is empty");
        }

        // Map hardlink path to linked path: HashMap<<hardlink_path>, <linked_path>>
        let mut hardlink_map: HashMap<PathBuf, PathBuf> = HashMap::new();
        // Map regular file path to chunks: HashMap<<file_path>, <(file_size, chunks)>>
        let mut file_chunk_map: HashMap<PathBuf, (u64, Vec<NodeChunk>)> = HashMap::new();
        let mut nodes = Vec::new();
        let mut tree: Option<Tree> = None;
        let mut last_reg_entry: Option<&TocEntry> = None;
        let mut uncompress_offset = 0;

        for entry in toc_index.entries.iter() {
            // Only support directory, symlink, hardlink, regular file and file chunk
            if !entry.is_supported() {
                continue;
            }

            let path = entry.path()?;
            let uncompress_size = Self::get_content_size(ctx, entry, &mut last_reg_entry)?;
            if (entry.is_reg() || entry.is_chunk()) && uncompress_size != 0 {
                let block_id = entry.block_id(&ctx.blob_id)?;
                // blob_index and compressed_size will be fixed later
                let v5_chunk_info = ChunkWrapper::V5(RafsV5ChunkInfo {
                    block_id,
                    blob_index: 0,
                    flags: BlobChunkFlags::COMPRESSED,
                    compressed_size: 0,
                    uncompressed_size: uncompress_size as u32,
                    compressed_offset: entry.offset as u64,
                    uncompressed_offset: uncompress_offset,
                    file_offset: entry.chunk_offset as u64,
                    index: 0,
                    reserved: 0,
                });
                let chunk = NodeChunk {
                    source: ChunkSource::Build,
                    inner: match ctx.fs_version {
                        RafsVersion::V5 => v5_chunk_info,
                        RafsVersion::V6 => v5_chunk_info,
                    },
                };

                if let Some((size, chunks)) = file_chunk_map.get_mut(&path) {
                    chunks.push(chunk);
                    if entry.is_reg() {
                        *size = entry.size;
                    }
                } else if entry.is_reg() {
                    file_chunk_map.insert(path.clone(), (entry.size, vec![chunk]));
                } else {
                    bail!("stargz file chunk lacks of corresponding head regular file entry");
                }

                let aligned_chunk_size = if ctx.aligned_chunk {
                    // Safe to unwrap because `chunk_size` is much less than u32::MAX.
                    try_round_up_4k(uncompress_size).unwrap()
                } else {
                    uncompress_size
                };
                uncompress_offset += aligned_chunk_size;
            }

            if entry.is_chunk() {
                continue;
            } else if entry.is_hardlink() {
                hardlink_map.insert(path.clone(), entry.hardlink_link_path());
            }

            let mut lost_dirs = Vec::new();
            self.make_lost_dirs(entry, &mut lost_dirs)?;
            for dir in &lost_dirs {
                let node = self.parse_node(dir, ctx.explicit_uidgid, ctx.fs_version, layer_idx)?;
                nodes.push(node);
            }
            let node = self.parse_node(entry, ctx.explicit_uidgid, ctx.fs_version, layer_idx)?;
            if path == Path::new("/") {
                tree = Some(Tree::new(node.clone()));
            }
            nodes.push(node);
        }

        let mut tree = tree.ok_or_else(|| anyhow!("stargz index has no root TOC entry"))?;
        for node in &mut nodes {
            let node_path = node.path();
            let path = hardlink_map.get(node_path).unwrap_or(node_path);
            if let Some((size, ref mut chunks)) = file_chunk_map.get_mut(path) {
                Self::sort_and_validate_chunks(chunks, *size)?;
                node.inode.set_size(*size);
                node.inode.set_child_count(chunks.len() as u32);
                node.chunks = chunks.to_vec();
            }
            tree.apply(node, false, ctx.whiteout_spec)?;
        }

        Ok(tree)
    }

    /// Get content size of a regular file or file chunk entry.
    fn get_content_size<'a>(
        ctx: &mut BuildContext,
        entry: &'a TocEntry,
        last_reg_entry: &mut Option<&'a TocEntry>,
    ) -> Result<u64> {
        if entry.chunk_offset % ctx.chunk_size as u64 != 0 {
            bail!(
                "stargz chunk offset (0x{:x}) is not aligned to 0x{:x}",
                entry.chunk_offset,
                ctx.chunk_size
            );
        }

        if entry.is_reg() {
            // Regular file without chunk
            if entry.chunk_offset == 0 && entry.chunk_size == 0 {
                Ok(entry.size)
            } else if entry.chunk_size != ctx.chunk_size as u64 {
                bail!("stargz first chunk size is not 0x{:x}", ctx.chunk_size);
            } else {
                *last_reg_entry = Some(entry);
                Ok(entry.chunk_size)
            }
        } else if entry.is_chunk() {
            if entry.chunk_size == 0 {
                // Figure out content size for the last chunk entry of regular file
                if let Some(reg_entry) = last_reg_entry {
                    let size = reg_entry.size - entry.chunk_offset;
                    *last_reg_entry = None;
                    Ok(size)
                } else {
                    bail!("stargz tailer chunk lacks of corresponding head chunk");
                }
            } else if entry.chunk_size != ctx.chunk_size as u64 {
                bail!("stargz chunk size is not 0x{:x}", ctx.chunk_size);
            } else {
                Ok(entry.chunk_size)
            }
        } else {
            Ok(0)
        }
    }

    // Create middle directory nodes which is not in entry list,
    // for example `/a/b/c`, we need to create `/a`, `/a/b` nodes first.
    fn make_lost_dirs(&mut self, entry: &TocEntry, dirs: &mut Vec<TocEntry>) -> Result<()> {
        if let Some(parent_path) = entry.path()?.parent() {
            if !self.path_inode_map.contains_key(parent_path) {
                let dir_entry = TocEntry::new_dir(parent_path.to_path_buf());
                self.make_lost_dirs(&dir_entry, dirs)?;
                dirs.push(dir_entry);
            }
        }

        Ok(())
    }

    fn sort_and_validate_chunks(chunks: &mut [NodeChunk], size: u64) -> Result<()> {
        if chunks.len() > RAFS_MAX_CHUNKS_PER_BLOB as usize {
            bail!("stargz file has two many chunks");
        }

        chunks.sort_unstable_by_key(|v| v.inner.file_offset());

        for idx in 0..chunks.len() - 1 {
            let next = chunks[idx]
                .inner
                .file_offset()
                .checked_add(chunks[idx].inner.uncompressed_size() as u64);
            if next.is_none() || next.unwrap() != chunks[idx + 1].inner.file_offset() {
                bail!("stargz has gaps between chunks");
            }
        }

        let last = &chunks[chunks.len() - 1];
        if last.inner.file_offset() + last.inner.uncompressed_size() as u64 != size {
            bail!("stargz file size and sum of chunk size doesn't match");
        }

        Ok(())
    }

    /// Parse stargz toc entry to Node in builder
    fn parse_node(
        &mut self,
        entry: &TocEntry,
        explicit_uidgid: bool,
        version: RafsVersion,
        layer_idx: u16,
    ) -> Result<Node> {
        let entry_path = entry.path()?;
        let mut file_size = entry.size;
        let mut flags = match version {
            RafsVersion::V5 => RafsV5InodeFlags::default(),
            RafsVersion::V6 => RafsV5InodeFlags::default(),
        };

        // Parse symlink
        let (symlink, symlink_size) = if entry.is_symlink() {
            let symlink_link_path = entry.symlink_link_path();
            let symlink_size = symlink_link_path.byte_size() as u16;
            file_size = symlink_size.into();
            flags |= RafsV5InodeFlags::SYMLINK;
            (Some(symlink_link_path.as_os_str().to_owned()), symlink_size)
        } else {
            (None, 0)
        };

        // Parse xattrs
        let mut xattrs = RafsXAttrs::new();
        if entry.has_xattr() {
            for (name, value) in entry.xattrs.iter() {
                flags |= RafsV5InodeFlags::XATTR;
                let value = base64::engine::general_purpose::STANDARD
                    .decode(value)
                    .with_context(|| {
                        format!(
                            "parse xattr name {:?} of file {:?} failed",
                            entry_path, name
                        )
                    })?;
                xattrs.add(OsString::from(name), value)?;
            }
        }

        // Handle hardlink ino
        let mut ino = (self.path_inode_map.len() + 1) as Inode;
        if entry.is_hardlink() {
            flags |= RafsV5InodeFlags::HARDLINK;
            if let Some(_ino) = self.path_inode_map.get(&entry.hardlink_link_path()) {
                ino = *_ino;
            } else {
                self.path_inode_map.insert(entry.path()?, ino);
            }
        } else {
            self.path_inode_map.insert(entry.path()?, ino);
        }

        // Get file name size
        let name_size = entry.name()?.as_os_str().byte_size() as u16;
        let uid = if explicit_uidgid { entry.uid } else { 0 };
        let gid = if explicit_uidgid { entry.gid } else { 0 };

        // Parse inode info
        let v5_inode = RafsV5Inode {
            i_digest: RafsDigest::default(),
            i_parent: 0,
            i_ino: ino,
            i_projid: 0,
            i_uid: uid,
            i_gid: gid,
            i_mode: entry.mode(),
            i_size: file_size,
            i_nlink: entry.num_link,
            i_blocks: 0,
            i_flags: flags,
            i_child_index: 0,
            i_child_count: 0,
            i_name_size: name_size,
            i_symlink_size: symlink_size,
            i_rdev: entry.rdev(),
            // TODO: add mtime from entry.ModTime()
            i_mtime: 0,
            i_mtime_nsec: 0,
            i_reserved: [0; 8],
        };
        let inode = match version {
            RafsVersion::V5 => InodeWrapper::V5(v5_inode),
            RafsVersion::V6 => InodeWrapper::V6(v5_inode),
        };

        let path = entry.path()?;
        let source = PathBuf::from("/");
        let target = Node::generate_target(&path, &source);
        let target_vec = Node::generate_target_vec(&target);

        Ok(Node {
            index: 0,
            src_ino: ino,
            src_dev: u64::MAX,
            rdev: entry.rdev() as u64,
            overlay: Overlay::UpperAddition,
            explicit_uidgid,
            source,
            target,
            path,
            target_vec,
            inode,
            chunks: Vec::new(),
            symlink,
            xattrs,
            layer_idx,
            ctime: 0,
            v6_offset: 0,
            v6_dirents: Vec::<(u64, OsString, u32)>::new(),
            v6_datalayout: 0,
            v6_compact_inode: false,
            v6_force_extended_inode: false,
            v6_dirents_offset: 0,
        })
    }
}

pub(crate) struct StargzBuilder {
    blob_size: u64,
}

impl StargzBuilder {
    pub fn new(blob_size: u64) -> Self {
        Self { blob_size }
    }

    fn generate_nodes(
        &mut self,
        ctx: &mut BuildContext,
        bootstrap_ctx: &mut BootstrapContext,
        blob_ctx: &mut BlobContext,
        blob_mgr: &mut BlobManager,
    ) -> Result<()> {
        if ctx.fs_version == RafsVersion::V6 {
            /*
            let mut header = BlobMetaHeaderOndisk::default();
            header.set_4k_aligned(true);
            header.set_ci_separate(ctx.blob_meta_features & BLOB_META_FEATURE_SEPARATE != 0);
            header.set_chunk_info_v2(ctx.blob_meta_features & BLOB_META_FEATURE_CHUNK_INFO_V2 != 0);
            header.set_ci_zran(ctx.blob_meta_features & BLOB_META_FEATURE_ZRAN != 0);
            blob_ctx.blob_meta_header = header;
             */
            blob_ctx.set_meta_info_enabled(true);
        } else {
            blob_ctx.set_meta_info_enabled(false);
        }
        blob_ctx.set_chunk_size(ctx.chunk_size);

        // Ensure that the chunks in the blob meta are sorted by uncompressed_offset
        // and ordered by chunk index so that they can be found quickly at runtime
        // with a binary search.
        let mut blob_chunks = Vec::new();
        for node in &bootstrap_ctx.nodes {
            if node.overlay.is_lower_layer() || node.inode.has_hardlink() {
                continue;
            }
            for chunk in node.chunks.iter() {
                blob_chunks.push(chunk.clone());
            }
        }
        blob_chunks.sort_unstable_by(|a, b| {
            a.inner
                .uncompressed_offset()
                .cmp(&b.inner.uncompressed_offset())
        });

        // Compute compressed_size for chunks.
        let chunk_count = blob_chunks.len();
        for idx in 0..chunk_count {
            let curr = blob_chunks[idx].inner.compressed_offset();
            let next = if idx == chunk_count - 1 {
                self.blob_size
            } else {
                blob_chunks[idx + 1].inner.compressed_offset()
            };
            if curr >= next {
                bail!("stargz compressed offset is out of order");
            } else if next - curr > RAFS_MAX_CHUNK_SIZE {
                bail!("stargz compressed size is too big");
            }
            let uncomp_size = blob_chunks[idx].inner.uncompressed_size() as usize;
            let max_size = (next - curr) as usize;
            let max_gzip_size = compute_compressed_gzip_size(uncomp_size, max_size);
            if max_gzip_size < max_size {
                trace!(
                    "shrink max gzip size from {} to {}",
                    max_size,
                    max_gzip_size
                );
            }
            blob_chunks[idx]
                .inner
                .set_compressed_size(max_gzip_size as u32);
        }

        let mut chunk_map = HashMap::new();
        for chunk in &mut blob_chunks {
            if !chunk_map.contains_key(chunk.inner.id()) {
                let chunk_index = blob_ctx.alloc_chunk_index()?;
                chunk.inner.set_index(chunk_index);
                blob_ctx.add_chunk_meta_info(&chunk.inner, None)?;
                chunk_map.insert(*chunk.inner.id(), chunk_index);
            } else {
                bail!("stargz unexpected duplicated data chunk");
            }
        }

        let blob_index = blob_mgr.alloc_index()?;
        let mut uncompressed_blob_size = 0u64;
        let mut compressed_blob_size = 0u64;
        for node in &mut bootstrap_ctx.nodes {
            if node.overlay.is_lower_layer() {
                continue;
            }

            let mut inode_hasher = if ctx.fs_version == RafsVersion::V5 {
                Some(RafsDigest::hasher(digest::Algorithm::Sha256))
            } else {
                None
            };

            for chunk in node.chunks.iter_mut() {
                // All chunks should exist in the map, we have just added them.
                let chunk_index = *chunk_map.get(chunk.inner.id()).unwrap();
                let prepared = &blob_chunks[chunk_index as usize];
                let file_offset = chunk.inner.file_offset();
                chunk.inner.copy_from(&prepared.inner);
                chunk.inner.set_file_offset(file_offset);
                chunk.inner.set_blob_index(blob_index);

                // This method is used here to calculate uncompressed_blob_size to
                // be compatible with the possible 4k alignment requirement of
                // uncompressed_offset (RAFS v6).
                uncompressed_blob_size = std::cmp::max(
                    chunk.inner.uncompressed_offset() + chunk.inner.uncompressed_size() as u64,
                    uncompressed_blob_size,
                );
                compressed_blob_size = std::cmp::max(
                    compressed_blob_size,
                    chunk.inner.compressed_offset() + chunk.inner.compressed_size() as u64,
                );
                if let Some(h) = inode_hasher.as_mut() {
                    h.digest_update(chunk.inner.id().as_ref());
                }
            }

            if let Some(h) = inode_hasher {
                let digest = if node.is_symlink() {
                    RafsDigest::from_buf(
                        node.symlink.as_ref().unwrap().as_bytes(),
                        digest::Algorithm::Sha256,
                    )
                } else {
                    h.digest_finalize()
                };
                node.inode.set_digest(digest);
            }
        }

        blob_ctx.uncompressed_blob_size = uncompressed_blob_size;
        blob_ctx.compressed_blob_size = compressed_blob_size;

        Ok(())
    }

    fn build_tree(&mut self, ctx: &mut BuildContext, layer_idx: u16) -> Result<Tree> {
        StargzTreeBuilder::new()
            .build(ctx, layer_idx)
            .context("failed to build tree from stargz index")
    }
}

impl Builder for StargzBuilder {
    fn build(
        &mut self,
        ctx: &mut BuildContext,
        bootstrap_mgr: &mut BootstrapManager,
        blob_mgr: &mut BlobManager,
    ) -> Result<BuildOutput> {
        let mut bootstrap_ctx = bootstrap_mgr.create_ctx(ctx.blob_inline_meta)?;
        let layer_idx = u16::from(bootstrap_ctx.layered);
        let mut blob_writer = if let Some(blob_stor) = ctx.blob_storage.clone() {
            Some(ArtifactWriter::new(blob_stor, ctx.blob_inline_meta)?)
        } else {
            return Err(anyhow!("missing configuration for target path"));
        };

        // Build filesystem tree from the stargz TOC.
        let tree = timing_tracer!({ self.build_tree(ctx, layer_idx) }, "build_tree")?;
        let mut bootstrap =
            build_bootstrap(ctx, bootstrap_mgr, &mut bootstrap_ctx, blob_mgr, tree)?;

        // Generate node chunks and digest
        let mut blob_ctx = BlobContext::new(
            ctx.blob_id.clone(),
            0,
            ctx.blob_features,
            compress::Algorithm::GZip,
            digest::Algorithm::Sha256,
        );
        self.generate_nodes(ctx, &mut bootstrap_ctx, &mut blob_ctx, blob_mgr)?;

        // Dump blob meta
        Blob::dump_meta_data(ctx, &mut blob_ctx, blob_writer.as_mut().unwrap())?;
        if blob_ctx.uncompressed_blob_size > 0 {
            blob_mgr.add(blob_ctx);
        }

        // Dump bootstrap file
        let blob_table = blob_mgr.to_blob_table(ctx)?;
        bootstrap.dump(
            ctx,
            &mut bootstrap_mgr.bootstrap_storage,
            &mut bootstrap_ctx,
            &blob_table,
        )?;

        BuildOutput::new(blob_mgr, &bootstrap_mgr.bootstrap_storage)
    }
}

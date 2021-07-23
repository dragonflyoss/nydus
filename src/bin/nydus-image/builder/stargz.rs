// Copyright 2020 Alibaba cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0
//
// Stargz support.

use anyhow::{anyhow, bail, Context, Result};

use nix::sys::stat::makedev;
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::collections::HashMap;
use std::fs::File;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::rc::Rc;
use std::str::FromStr;

use sha2::{Digest, Sha256};

use nydus_utils::digest::{self, Algorithm, RafsDigest};
use nydus_utils::ByteSize;
use rafs::metadata::layout::*;
use rafs::metadata::{Inode, RafsChunkFlags};

use crate::builder::Builder;
use crate::core::bootstrap::Bootstrap;
use crate::core::context::BuildContext;
use crate::core::node::*;
use crate::core::tree::Tree;

type RcTocEntry = Rc<RefCell<TocEntry>>;

#[derive(Deserialize, Serialize, Debug, Clone, Default)]
pub struct TocEntry {
    // Name is the tar entry's name. It is the complete path
    // stored in the tar file, not just the base name.
    pub name: PathBuf,

    // Type is one of "dir", "reg", "symlink", "hardlink", "char",
    // "block", "fifo", or "chunk".
    // The "chunk" type is used for regular file data chunks past the first
    // TOCEntry; the 2nd chunk and on have only Type ("chunk"), Offset,
    // ChunkOffset, and ChunkSize populated.
    #[serde(rename = "type")]
    pub toc_type: String,

    // Size, for regular files, is the logical size of the file.
    #[serde(default)]
    pub size: u64,

    // // ModTime3339 is the modification time of the tar entry. Empty
    // // means zero or unknown. Otherwise it's in UTC RFC3339
    // // format. Use the ModTime method to access the time.Time value.
    // #[serde(default, alias = "modtime")]
    // mod_time_3339: String,
    // #[serde(skip)]
    // mod_time: Time,

    // LinkName, for symlinks and hardlinks, is the link target.
    #[serde(default, rename = "linkName")]
    pub link_name: PathBuf,

    // Mode is the permission and mode bits.
    #[serde(default)]
    pub mode: u32,

    // Uid is the user ID of the owner.
    #[serde(default)]
    pub uid: u32,

    // Gid is the group ID of the owner.
    #[serde(default)]
    pub gid: u32,

    // Uname is the username of the owner.
    //
    // In the serialized JSON, this field may only be present for
    // the first entry with the same Uid.
    #[serde(default, rename = "userName")]
    pub uname: String,

    // Gname is the group name of the owner.
    //
    // In the serialized JSON, this field may only be present for
    // the first entry with the same Gid.
    #[serde(default, rename = "groupName")]
    pub gname: String,

    // Offset, for regular files, provides the offset in the
    // stargz file to the file's data bytes. See ChunkOffset and
    // ChunkSize.
    #[serde(default)]
    pub offset: u64,

    // the Offset of the next entry with a non-zero Offset
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

    #[serde(skip)]
    pub children: Vec<RcTocEntry>,

    #[serde(skip)]
    pub inode: u64,
}

impl TocEntry {
    pub fn is_dir(&self) -> bool {
        self.toc_type.as_str() == "dir"
    }

    pub fn is_reg(&self) -> bool {
        self.toc_type.as_str() == "reg"
    }

    pub fn is_symlink(&self) -> bool {
        self.toc_type.as_str() == "symlink"
    }

    pub fn is_hardlink(&self) -> bool {
        self.toc_type.as_str() == "hardlink"
    }

    pub fn is_chunk(&self) -> bool {
        self.toc_type.as_str() == "chunk"
    }

    pub fn has_xattr(&self) -> bool {
        !self.xattrs.is_empty()
    }

    pub fn is_blockdev(&self) -> bool {
        self.toc_type.as_str() == "block"
    }

    pub fn is_chardev(&self) -> bool {
        self.toc_type.as_str() == "char"
    }

    pub fn is_fifo(&self) -> bool {
        self.toc_type.as_str() == "fifo"
    }

    pub fn is_special(&self) -> bool {
        self.is_blockdev() || self.is_chardev() || self.is_fifo()
    }

    pub fn mode(&self) -> u32 {
        let mut mode = self.mode;

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

        mode
    }

    pub fn rdev(&self) -> u32 {
        if self.is_special() {
            makedev(self.dev_major, self.dev_minor) as u32
        } else {
            u32::MAX
        }
    }

    // Convert entry name to file name
    // For example: `` to `/`, `/` to `/`, `a/b` to `b`, `a/b/` to `b`
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

    // Convert entry name to rootfs absolute path
    // For example: `` to `/`, `a/b` to `/a/b`, `a/b/` to `/a/b`
    pub fn path(&self) -> Result<PathBuf> {
        let root_path = PathBuf::from("/");
        let empty_path = PathBuf::from("");
        if self.name == empty_path || self.name == root_path {
            return Ok(root_path);
        }
        let path = PathBuf::from("/").join(&self.name);
        Ok(path
            .parent()
            .ok_or_else(|| anyhow!("invalid entry path"))?
            .join(
                path.file_name()
                    .ok_or_else(|| anyhow!("invalid entry name"))?,
            ))
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
pub struct TocIndex {
    pub version: u32,
    pub entries: Vec<TocEntry>,
}

fn parse_index(path: &PathBuf) -> Result<TocIndex> {
    let index_file =
        File::open(path).with_context(|| format!("failed to open stargz index file {:?}", path))?;
    let toc_index: TocIndex = serde_json::from_reader(index_file)
        .with_context(|| format!("invalid stargz index file {:?}", path))?;
    if toc_index.version != 1 {
        bail!("unsupported index version {}", toc_index.version);
    }
    Ok(toc_index)
}

struct StargzIndexTreeBuilder {
    path_inode_map: HashMap<PathBuf, Inode>,
}

impl StargzIndexTreeBuilder {
    fn new() -> Self {
        Self {
            path_inode_map: HashMap::new(),
        }
    }

    // Create middle directory nodes which is not in entry list,
    // for example `/a/b/c`, we need to create `/a`, `/a/b` nodes first.
    fn make_lost_dirs(&mut self, entry: &TocEntry, dirs: &mut Vec<TocEntry>) -> Result<()> {
        if let Some(parent_path) = entry.path()?.parent() {
            let parent_path = parent_path.to_path_buf();
            if self.path_inode_map.get(&parent_path).is_none() {
                let dir_entry = TocEntry::new_dir(parent_path);
                self.make_lost_dirs(&dir_entry, dirs)?;
                dirs.push(dir_entry);
            }
        }
        Ok(())
    }

    fn build(&mut self, ctx: &BuildContext) -> Result<Tree> {
        // Parse stargz TOC index from a file
        let toc_index = parse_index(&ctx.source_path)?;

        if toc_index.entries.is_empty() {
            bail!("the stargz index has no toc entry");
        }

        let mut tree: Option<Tree> = None;

        // Map hardlink path to linked path: HashMap<<hardlink_path>, <linked_path>>
        let mut hardlink_map: HashMap<PathBuf, PathBuf> = HashMap::new();

        // Map regular file path to chunks: HashMap<<file_path>, <(file_size, chunks)>>
        let mut file_chunk_map: HashMap<PathBuf, (u64, Vec<OndiskChunkInfo>)> = HashMap::new();
        let mut nodes = Vec::new();

        let mut last_reg_entry: Option<&TocEntry> = None;
        for entry in toc_index.entries.iter() {
            if !entry.is_supported() {
                continue;
            }

            // Figure out decompress_size for the last chunk entry of regular file
            let mut decompress_size = entry.chunk_size;
            if entry.is_chunk() && entry.chunk_size == 0 {
                if let Some(reg_entry) = last_reg_entry {
                    decompress_size = reg_entry.size - entry.chunk_offset;
                }
            }
            // Figure out decompress_size for regular file entry
            if entry.chunk_size == 0 && entry.size != 0 {
                decompress_size = entry.size;
            }

            if (entry.is_reg() || entry.is_chunk()) && decompress_size != 0 {
                let block_id = entry.block_id(&ctx.blob_id)?;
                let chunk = OndiskChunkInfo {
                    block_id,
                    // Will be set later
                    blob_index: 0,
                    flags: RafsChunkFlags::COMPRESSED,
                    // No available data on entry
                    compress_size: 0,
                    decompress_size: decompress_size as u32,
                    compress_offset: entry.offset as u64,
                    // No available data on entry
                    decompress_offset: 0,
                    file_offset: entry.chunk_offset as u64,
                    index: 0,
                    reserved: 0,
                };
                if let Some((size, chunks)) = file_chunk_map.get_mut(&entry.path()?) {
                    chunks.push(chunk);
                    if entry.is_reg() {
                        *size = entry.size;
                    }
                } else {
                    let size = if entry.is_reg() { entry.size } else { 0 };
                    file_chunk_map.insert(entry.path()?, (size, vec![chunk]));
                }
            }
            if entry.is_reg() {
                last_reg_entry = Some(&entry);
            }
            if entry.is_chunk() {
                continue;
            }

            let mut lost_dirs = Vec::new();
            self.make_lost_dirs(&entry, &mut lost_dirs)?;
            for dir in &lost_dirs {
                let node = self.parse_node(dir, ctx.explicit_uidgid)?;
                nodes.push(node);
            }

            if entry.is_hardlink() {
                hardlink_map.insert(entry.path()?, entry.hardlink_link_path());
            }

            let node = self.parse_node(entry, ctx.explicit_uidgid)?;
            if entry.path()? == PathBuf::from("/") {
                tree = Some(Tree::new(node.clone()));
            }
            nodes.push(node);
        }

        // Set chunks and i_size to nodes
        for node in &mut nodes {
            let link_path = hardlink_map.get(&node.path).unwrap_or(&node.path);
            if let Some((size, chunks)) = file_chunk_map.get(link_path) {
                node.chunks = chunks.clone();
                node.inode.i_child_count = node.chunks.len() as u32;
                node.inode.i_size = *size;
            }
            if let Some(tree) = &mut tree {
                tree.apply(node, false, &ctx.whiteout_spec)?;
            }
        }

        tree.ok_or_else(|| anyhow!("the stargz index has no root toc entry"))
    }

    /// Parse stargz toc entry to Node in builder
    fn parse_node(&mut self, entry: &TocEntry, explicit_uidgid: bool) -> Result<Node> {
        let chunks = Vec::new();
        let entry_path = entry.path()?;
        let symlink_link_path = entry.symlink_link_path();

        let mut flags = RafsInodeFlags::default();

        // Parse symlink
        let mut file_size = entry.size;
        let mut symlink_size = 0;
        let symlink = if entry.is_symlink() {
            flags |= RafsInodeFlags::SYMLINK;
            symlink_size = symlink_link_path.byte_size() as u16;
            file_size = symlink_size.into();
            Some(symlink_link_path.as_os_str().to_owned())
        } else {
            None
        };

        // Parse xattrs
        let mut xattrs = XAttrs::new();
        if entry.has_xattr() {
            for (name, value) in entry.xattrs.iter() {
                flags |= RafsInodeFlags::XATTR;
                let value = base64::decode(value).with_context(|| {
                    format!(
                        "parse xattr name {:?} of file {:?} failed",
                        entry_path, name,
                    )
                })?;
                xattrs.add(name.into(), value);
            }
        }

        // Handle hardlink ino
        let mut ino = (self.path_inode_map.len() + 1) as Inode;
        if entry.is_hardlink() {
            flags |= RafsInodeFlags::HARDLINK;
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
        let inode = OndiskInode {
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
            i_reserved: [0; 20],
        };

        Ok(Node {
            index: 0,
            real_ino: ino,
            dev: u64::MAX,
            rdev: inode.i_rdev as u64,
            overlay: Overlay::UpperAddition,
            explicit_uidgid,
            source: PathBuf::from_str("/").unwrap(),
            path: entry.path()?,
            inode,
            chunks,
            symlink,
            xattrs,
        })
    }
}

pub struct StargzBuilder {}

impl StargzBuilder {
    pub fn new() -> Self {
        Self {}
    }

    fn calculate_nodes(&mut self, ctx: &mut BuildContext) -> Result<(u64, u64)> {
        let mut blob_cache_size = 0u64;
        let mut compressed_blob_size = 0u64;

        // Set blob index and inode digest for upper nodes
        for node in &mut ctx.nodes {
            if node.overlay.lower_layer() {
                continue;
            }

            let mut inode_hasher = RafsDigest::hasher(digest::Algorithm::Sha256);

            let blob_index = ctx.blob_table.entries.len() as u32;
            for chunk in node.chunks.iter_mut() {
                blob_cache_size += chunk.decompress_size as u64;
                compressed_blob_size += chunk.compress_size as u64;
                let chunk_index = ctx.chunk_count_map.alloc_index(blob_index)?;
                (*chunk).index = chunk_index;
                (*chunk).blob_index = blob_index;
                inode_hasher.digest_update(chunk.block_id.as_ref());
            }

            let digest = if node.is_symlink() {
                RafsDigest::from_buf(
                    node.symlink.as_ref().unwrap().as_bytes(),
                    digest::Algorithm::Sha256,
                )
            } else {
                inode_hasher.digest_finalize()
            };
            node.inode.i_digest = digest;
        }

        Ok((blob_cache_size, compressed_blob_size))
    }

    fn build_tree_from_index(&mut self, ctx: &mut BuildContext) -> Result<Tree> {
        let mut tree_builder = StargzIndexTreeBuilder::new();
        tree_builder
            .build(&ctx)
            .context("failed to build tree from stargz index")
    }
}

impl Builder for StargzBuilder {
    fn build(&mut self, mut ctx: &mut BuildContext) -> Result<(Vec<String>, usize)> {
        let mut bootstrap = Bootstrap::new()?;

        // Build tree from source
        let mut tree = self.build_tree_from_index(&mut ctx)?;

        // Build bootstrap from source
        if ctx.f_parent_bootstrap.is_some() {
            bootstrap.build(&mut ctx, &mut tree);
            // Apply to parent bootstrap for layered build
            let mut tree = bootstrap.apply(&mut ctx)?;
            timing_tracer!({ bootstrap.build(&mut ctx, &mut tree) }, "build_bootstrap");
        } else {
            bootstrap.build(&mut ctx, &mut tree);
        }

        // Calculate node chunks and digest
        let (blob_cache_size, compressed_blob_size) = self.calculate_nodes(&mut ctx)?;

        // Dump bootstrap file
        bootstrap.dump(
            &mut ctx,
            Sha256::new(),
            0,
            0,
            blob_cache_size,
            compressed_blob_size,
        )
    }
}

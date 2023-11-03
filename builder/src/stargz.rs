// Copyright 2020 Alibaba cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Generate a RAFS filesystem bootstrap from an stargz layer, reusing the stargz layer as data blob.

use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{Seek, SeekFrom};
use std::ops::Deref;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{anyhow, bail, Context, Error, Result};
use base64::Engine;
use nix::NixPath;
use nydus_rafs::metadata::chunk::ChunkWrapper;
use nydus_rafs::metadata::inode::{InodeWrapper, RafsInodeFlags, RafsV6Inode};
use nydus_rafs::metadata::layout::v5::RafsV5ChunkInfo;
use nydus_rafs::metadata::layout::RafsXAttrs;
use nydus_rafs::metadata::RafsVersion;
use nydus_storage::device::BlobChunkFlags;
use nydus_storage::{RAFS_MAX_CHUNKS_PER_BLOB, RAFS_MAX_CHUNK_SIZE};
use nydus_utils::compact::makedev;
use nydus_utils::compress::{self, compute_compressed_gzip_size};
use nydus_utils::digest::{self, DigestData, RafsDigest};
use nydus_utils::{lazy_drop, root_tracer, timing_tracer, try_round_up_4k, ByteSize};
use serde::{Deserialize, Serialize};

use crate::core::context::{Artifact, NoopArtifactWriter};

use super::core::blob::Blob;
use super::core::context::{
    ArtifactWriter, BlobManager, BootstrapManager, BuildContext, BuildOutput,
};
use super::core::node::{ChunkSource, Node, NodeChunk, NodeInfo};
use super::{
    build_bootstrap, dump_bootstrap, finalize_blob, Bootstrap, Builder, TarBuilder, Tree, TreeNode,
};

#[derive(Deserialize, Serialize, Debug, Clone, Default)]
struct TocEntry {
    /// This REQUIRED property contains the name of the tar entry.
    ///
    /// This MUST be the complete path stored in the tar file.
    pub name: PathBuf,

    /// This REQUIRED property contains the type of tar entry.
    ///
    /// This MUST be either of the following.
    /// - dir: directory
    /// - reg: regular file
    /// - symlink: symbolic link
    /// - hardlink: hard link
    /// - char: character device
    /// - block: block device
    /// - fifo: fifo
    /// - chunk: a chunk of regular file data As described in the above section,
    /// a regular file can be divided into several chunks. TOCEntry MUST be created for each chunk.
    /// TOCEntry of the first chunk of that file MUST be typed as reg. TOCEntry of each chunk after
    /// 2nd MUST be typed as chunk. chunk TOCEntry MUST set offset, chunkOffset and chunkSize
    /// properties.
    #[serde(rename = "type")]
    pub toc_type: String,

    /// This OPTIONAL property contains the uncompressed size of the regular file.
    ///
    /// Non-empty reg file MUST set this property.
    #[serde(default)]
    pub size: u64,

    // This OPTIONAL property contains the modification time of the tar entry.
    //
    // Empty means zero or unknown. Otherwise, the value is in UTC RFC3339 format.
    // // ModTime3339 is the modification time of the tar entry. Empty
    // // means zero or unknown. Otherwise it's in UTC RFC3339
    // // format. Use the ModTime method to access the time.Time value.
    // #[serde(default, alias = "modtime")]
    // mod_time_3339: String,
    // #[serde(skip)]
    // mod_time: Time,
    /// This OPTIONAL property contains the link target.
    ///
    /// Symlink and hardlink MUST set this property.
    #[serde(default, rename = "linkName")]
    pub link_name: PathBuf,

    /// This REQUIRED property contains the permission and mode bits.
    #[serde(default)]
    pub mode: u32,

    /// This REQUIRED property contains the user ID of the owner of this file.
    #[serde(default)]
    pub uid: u32,

    /// This REQUIRED property contains the group ID of the owner of this file.
    #[serde(default)]
    pub gid: u32,

    /// This OPTIONAL property contains the username of the owner.
    ///
    /// In the serialized JSON, this field may only be present for
    /// the first entry with the same Uid.
    #[serde(default, rename = "userName")]
    pub uname: String,

    /// This OPTIONAL property contains the groupname of the owner.
    ///
    /// In the serialized JSON, this field may only be present for
    /// the first entry with the same Gid.
    #[serde(default, rename = "groupName")]
    pub gname: String,

    /// This OPTIONAL property contains the major device number of device files.
    ///
    /// char and block files MUST set this property.
    #[serde(default, rename = "devMajor")]
    pub dev_major: u64,

    /// This OPTIONAL property contains the minor device number of device files.
    ///
    /// char and block files MUST set this property.
    #[serde(default, rename = "devMinor")]
    pub dev_minor: u64,

    /// This OPTIONAL property contains the extended attribute for the tar entry.
    #[serde(default)]
    pub xattrs: HashMap<String, String>,

    /// This OPTIONAL property contains the digest of the regular file contents.
    ///
    /// It has the form "sha256:abcdef01234....".
    #[serde(default)]
    pub digest: String,

    /// This OPTIONAL property contains the offset of the gzip header of the regular file or chunk
    /// in the blob.
    ///
    /// TOCEntries of non-empty reg and chunk MUST set this property.
    #[serde(default)]
    pub offset: u64,

    /// This OPTIONAL property contains the offset of this chunk in the decompressed regular file
    /// payload. TOCEntries of chunk type MUST set this property.
    ///
    /// ChunkOffset is non-zero if this is a chunk of a large, regular file.
    /// If so, the Offset is where the gzip header of ChunkSize bytes at ChunkOffset in Name begin.
    ///
    /// In serialized form, a "chunkSize" JSON field of zero means that the chunk goes to the end
    /// of the file. After reading from the stargz TOC, though, the ChunkSize is initialized to
    /// a non-zero file for when Type is either "reg" or "chunk".
    #[serde(default, rename = "chunkOffset")]
    pub chunk_offset: u64,

    /// This OPTIONAL property contains the decompressed size of this chunk.
    ///
    /// The last chunk in a reg file or reg file that isn't chunked MUST set this property to zero.
    /// Other reg and chunk MUST set this property.
    #[serde(default, rename = "chunkSize")]
    pub chunk_size: u64,

    /// This OPTIONAL property contains a digest of this chunk.
    ///
    /// TOCEntries of non-empty reg and chunk MUST set this property. This MAY be used for verifying
    /// the data of the chunk.
    #[serde(default, rename = "chunkDigest")]
    pub chunk_digest: String,

    /// This OPTIONAL property indicates the uncompressed offset of the "reg" or "chunk" entry
    /// payload in a stream starts from offset field.
    ///
    /// `innerOffset` enables to put multiple "reg" or "chunk" payloads in one gzip stream starts
    /// from offset.
    #[serde(default, rename = "innerOffset")]
    pub inner_offset: u64,
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

    pub fn is_supported(&self) -> bool {
        self.is_dir() || self.is_reg() || self.is_symlink() || self.is_hardlink() || self.is_chunk()
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

        self.mode & !libc::S_IFMT as u32 | mode as u32
    }

    /// Get real device id associated with the `TocEntry`.
    pub fn rdev(&self) -> u32 {
        if self.is_special() {
            makedev(self.dev_major, self.dev_minor) as u32
        } else {
            u32::MAX
        }
    }

    /// Get content size of the entry.
    pub fn size(&self) -> u64 {
        if self.is_reg() {
            self.size
        } else {
            0
        }
    }

    /// Get file name of the `TocEntry` from the associated path.
    ///
    /// For example: `` to `/`, `/` to `/`, `a/b` to `b`, `a/b/` to `b`
    pub fn name(&self) -> Result<&OsStr> {
        let name = if self.name == Path::new("/") {
            OsStr::new("/")
        } else {
            self.name
                .file_name()
                .ok_or_else(|| anyhow!("stargz: invalid entry name {}", self.name.display()))?
        };
        Ok(name)
    }

    /// Get absolute path for the `TocEntry`.
    ///
    /// For example: `` to `/`, `a/b` to `/a/b`, `a/b/` to `/a/b`
    pub fn path(&self) -> &Path {
        &self.name
    }

    /// Convert link path of hardlink entry to rootfs absolute path
    ///
    /// For example: `a/b` to `/a/b`
    pub fn hardlink_link_path(&self) -> &Path {
        assert!(self.is_hardlink());
        &self.link_name
    }

    /// Get target of symlink.
    pub fn symlink_link_path(&self) -> &Path {
        assert!(self.is_symlink());
        &self.link_name
    }

    pub fn block_id(&self) -> Result<RafsDigest> {
        if self.chunk_digest.len() != 71 || !self.chunk_digest.starts_with("sha256:") {
            bail!("stargz: invalid chunk digest {}", self.chunk_digest);
        }
        match hex::decode(&self.chunk_digest[7..]) {
            Err(_e) => bail!("stargz: invalid chunk digest {}", self.chunk_digest),
            Ok(v) => {
                let mut data = DigestData::default();
                data.copy_from_slice(&v[..32]);
                Ok(RafsDigest { data })
            }
        }
    }

    fn normalize(&mut self) -> Result<()> {
        if self.name.is_empty() {
            bail!("stargz: invalid TocEntry with empty name");
        }
        self.name = PathBuf::from("/").join(&self.name);

        if !self.is_supported() && !self.is_special() {
            bail!("stargz: invalid type {} for TocEntry", self.toc_type);
        }

        if (self.is_symlink() || self.is_hardlink()) && self.link_name.is_empty() {
            bail!("stargz: empty link target");
        }
        if self.is_hardlink() {
            self.link_name = PathBuf::from("/").join(&self.link_name);
        }

        if (self.is_reg() || self.is_chunk())
            && (self.digest.is_empty() || self.chunk_digest.is_empty())
        {
            bail!("stargz: missing digest or chunk digest");
        }

        if self.is_chunk() && self.chunk_offset == 0 {
            bail!("stargz: chunk offset is zero");
        }

        Ok(())
    }
}

#[derive(Deserialize, Debug, Clone, Default)]
struct TocIndex {
    pub version: u32,
    pub entries: Vec<TocEntry>,
}

impl TocIndex {
    fn load(path: &Path, offset: u64) -> Result<TocIndex> {
        let mut index_file = File::open(path)
            .with_context(|| format!("stargz: failed to open index file {:?}", path))?;
        let pos = index_file
            .seek(SeekFrom::Start(offset))
            .context("stargz: failed to seek to start of TOC")?;
        if pos != offset {
            bail!("stargz: failed to seek file position to start of TOC");
        }
        let mut toc_index: TocIndex = serde_json::from_reader(index_file).with_context(|| {
            format!(
                "stargz: failed to deserialize stargz TOC index file {:?}",
                path
            )
        })?;

        if toc_index.version != 1 {
            return Err(Error::msg(format!(
                "stargz: unsupported index version {}",
                toc_index.version
            )));
        }

        for entry in toc_index.entries.iter_mut() {
            entry.normalize()?;
        }

        Ok(toc_index)
    }
}

/// Build RAFS filesystems from eStargz images.
pub struct StargzBuilder {
    blob_size: u64,
    builder: TarBuilder,
    file_chunk_map: HashMap<PathBuf, (u64, Vec<NodeChunk>)>,
    hardlink_map: HashMap<PathBuf, TreeNode>,
    uncompressed_offset: u64,
}

impl StargzBuilder {
    /// Create a new instance of [StargzBuilder].
    pub fn new(blob_size: u64, ctx: &BuildContext) -> Self {
        Self {
            blob_size,
            builder: TarBuilder::new(ctx.explicit_uidgid, 0, ctx.fs_version),
            file_chunk_map: HashMap::new(),
            hardlink_map: HashMap::new(),
            uncompressed_offset: 0,
        }
    }

    fn build_tree(&mut self, ctx: &mut BuildContext, layer_idx: u16) -> Result<Tree> {
        let toc_index = TocIndex::load(&ctx.source_path, 0)?;
        if toc_index.version != 1 {
            bail!("stargz: TOC version {} is unsupported", toc_index.version);
        } else if toc_index.entries.is_empty() {
            bail!("stargz: TOC array is empty");
        }

        self.builder.layer_idx = layer_idx;
        let root = self.builder.create_directory(&[OsString::from("/")])?;
        let mut tree = Tree::new(root);

        // Map regular file path to chunks: HashMap<<file_path>, <(file_size, chunks)>>
        let mut last_reg_entry: Option<&TocEntry> = None;
        for entry in toc_index.entries.iter() {
            let path = entry.path();

            // TODO: support chardev/blockdev/fifo
            if !entry.is_supported() {
                warn!(
                    "stargz: unsupported {} with type {}",
                    path.display(),
                    entry.toc_type
                );
                continue;
            } else if self.builder.is_stargz_special_files(path) {
                // skip estargz special files.
                continue;
            }

            // Build RAFS chunk info from eStargz regular file or chunk data record.
            let uncompress_size = Self::get_content_size(ctx, entry, &mut last_reg_entry)?;
            if (entry.is_reg() || entry.is_chunk()) && uncompress_size != 0 {
                let block_id = entry
                    .block_id()
                    .context("stargz: failed to get chunk digest")?;
                // blob_index, index and compressed_size will be fixed later
                let chunk_info = ChunkWrapper::V6(RafsV5ChunkInfo {
                    block_id,
                    blob_index: 0,
                    flags: BlobChunkFlags::COMPRESSED,
                    compressed_size: 0,
                    uncompressed_size: uncompress_size as u32,
                    compressed_offset: entry.offset as u64,
                    uncompressed_offset: self.uncompressed_offset,
                    file_offset: entry.chunk_offset as u64,
                    index: 0,
                    reserved: 0,
                });
                let chunk = NodeChunk {
                    source: ChunkSource::Build,
                    inner: Arc::new(chunk_info),
                };

                if let Some((size, chunks)) = self.file_chunk_map.get_mut(path) {
                    chunks.push(chunk);
                    if entry.is_reg() {
                        *size = entry.size;
                    }
                } else if entry.is_reg() {
                    self.file_chunk_map
                        .insert(path.to_path_buf(), (entry.size, vec![chunk]));
                } else {
                    bail!("stargz: file chunk lacks of corresponding head regular file entry");
                }

                let aligned_chunk_size = if ctx.aligned_chunk {
                    // Safe to unwrap because `chunk_size` is much less than u32::MAX.
                    try_round_up_4k(uncompress_size).unwrap()
                } else {
                    uncompress_size
                };
                self.uncompressed_offset += aligned_chunk_size;
            }

            if !entry.is_chunk() && !self.builder.is_stargz_special_files(path) {
                self.parse_entry(&mut tree, entry, path)?;
            }
        }

        for (size, ref mut chunks) in self.file_chunk_map.values_mut() {
            Self::sort_and_validate_chunks(chunks, *size)?;
        }

        Ok(tree)
    }

    /// Get content size of a regular file or file chunk entry.
    fn get_content_size<'a>(
        ctx: &mut BuildContext,
        entry: &'a TocEntry,
        last_reg_entry: &mut Option<&'a TocEntry>,
    ) -> Result<u64> {
        if entry.is_reg() {
            // Regular file without chunk
            if entry.chunk_offset == 0 && entry.chunk_size == 0 {
                Ok(entry.size)
            } else if entry.chunk_offset % ctx.chunk_size as u64 != 0 {
                bail!(
                    "stargz: chunk offset (0x{:x}) is not aligned to 0x{:x}",
                    entry.chunk_offset,
                    ctx.chunk_size
                );
            } else if entry.chunk_size != ctx.chunk_size as u64 {
                bail!("stargz: first chunk size is not 0x{:x}", ctx.chunk_size);
            } else {
                *last_reg_entry = Some(entry);
                Ok(entry.chunk_size)
            }
        } else if entry.is_chunk() {
            if entry.chunk_offset % ctx.chunk_size as u64 != 0 {
                bail!(
                    "stargz: chunk offset (0x{:x}) is not aligned to 0x{:x}",
                    entry.chunk_offset,
                    ctx.chunk_size
                );
            } else if entry.chunk_size == 0 {
                // Figure out content size for the last chunk entry of regular file
                if let Some(reg_entry) = last_reg_entry {
                    let size = reg_entry.size - entry.chunk_offset;
                    if size > ctx.chunk_size as u64 {
                        bail!(
                            "stargz: size of last chunk 0x{:x} is bigger than chunk size 0x {:x}",
                            size,
                            ctx.chunk_size
                        );
                    }
                    *last_reg_entry = None;
                    Ok(size)
                } else {
                    bail!("stargz: tailer chunk lacks of corresponding head chunk");
                }
            } else if entry.chunk_size != ctx.chunk_size as u64 {
                bail!(
                    "stargz: chunk size 0x{:x} is not 0x{:x}",
                    entry.chunk_size,
                    ctx.chunk_size
                );
            } else {
                Ok(entry.chunk_size)
            }
        } else {
            Ok(0)
        }
    }

    fn parse_entry(&mut self, tree: &mut Tree, entry: &TocEntry, path: &Path) -> Result<()> {
        let name_size = entry.name()?.byte_size() as u16;
        let uid = if self.builder.explicit_uidgid {
            entry.uid
        } else {
            0
        };
        let gid = if self.builder.explicit_uidgid {
            entry.gid
        } else {
            0
        };
        let mut file_size = entry.size();
        let mut flags = RafsInodeFlags::default();

        // Parse symlink
        let (symlink, symlink_size) = if entry.is_symlink() {
            let symlink_link_path = entry.symlink_link_path();
            let symlink_size = symlink_link_path.as_os_str().byte_size() as u16;
            file_size = symlink_size.into();
            flags |= RafsInodeFlags::SYMLINK;
            (Some(symlink_link_path.as_os_str().to_owned()), symlink_size)
        } else {
            (None, 0)
        };

        // Handle hardlink ino
        let ino = if entry.is_hardlink() {
            let link_path = entry.hardlink_link_path();
            let link_path = link_path.components().as_path();
            let targets = Node::generate_target_vec(link_path);
            assert!(!targets.is_empty());
            let mut tmp_tree: &Tree = tree;
            for name in &targets[1..] {
                match tmp_tree.get_child_idx(name.as_bytes()) {
                    Some(idx) => tmp_tree = &tmp_tree.children[idx],
                    None => {
                        bail!(
                            "stargz: unknown target {} for hardlink {}",
                            link_path.display(),
                            path.display(),
                        );
                    }
                }
            }

            let mut tmp_node = tmp_tree.lock_node();
            if !tmp_node.is_reg() {
                bail!(
                    "stargz: target {} for hardlink {} is not a regular file",
                    link_path.display(),
                    path.display()
                );
            }
            self.hardlink_map
                .insert(path.to_path_buf(), tmp_tree.node.clone());
            flags |= RafsInodeFlags::HARDLINK;
            tmp_node.inode.set_has_hardlink(true);
            tmp_node.inode.ino()
        } else {
            self.builder.next_ino()
        };

        // Parse xattrs
        let mut xattrs = RafsXAttrs::new();
        if entry.has_xattr() {
            for (name, value) in entry.xattrs.iter() {
                flags |= RafsInodeFlags::XATTR;
                let value = base64::engine::general_purpose::STANDARD
                    .decode(value)
                    .with_context(|| {
                        format!(
                            "stargz: failed to parse xattr {:?} for entry {:?}",
                            path, name
                        )
                    })?;
                xattrs.add(OsString::from(name), value)?;
            }
        }

        let mut inode = InodeWrapper::V6(RafsV6Inode {
            i_ino: ino,
            i_projid: 0,
            i_uid: uid,
            i_gid: gid,
            i_mode: entry.mode(),
            i_size: file_size,
            i_nlink: 1,
            i_blocks: 0,
            i_flags: flags,
            i_child_count: 0,
            i_name_size: name_size,
            i_symlink_size: symlink_size,
            i_rdev: entry.rdev(),
            // TODO: add mtime from entry.ModTime()
            i_mtime: 0,
            i_mtime_nsec: 0,
        });
        inode.set_has_xattr(!xattrs.is_empty());

        let source = PathBuf::from("/");
        let target = Node::generate_target(&path, &source);
        let target_vec = Node::generate_target_vec(&target);
        let info = NodeInfo {
            explicit_uidgid: self.builder.explicit_uidgid,
            src_ino: ino,
            src_dev: u64::MAX,
            rdev: entry.rdev() as u64,
            source,
            target,
            path: path.to_path_buf(),
            target_vec,
            symlink,
            xattrs,
            v6_force_extended_inode: false,
        };
        let node = Node::new(inode, info, self.builder.layer_idx);

        self.builder.insert_into_tree(tree, node)
    }

    fn sort_and_validate_chunks(chunks: &mut [NodeChunk], size: u64) -> Result<()> {
        if chunks.len() > RAFS_MAX_CHUNKS_PER_BLOB as usize {
            bail!("stargz: file has two many chunks");
        }

        if chunks.len() > 1 {
            chunks.sort_unstable_by_key(|v| v.inner.file_offset());
            for idx in 0..chunks.len() - 2 {
                let curr = &chunks[idx].inner;
                let pos = curr
                    .file_offset()
                    .checked_add(curr.uncompressed_size() as u64);
                match pos {
                    Some(pos) => {
                        if pos != chunks[idx + 1].inner.file_offset() {
                            bail!("stargz: unexpected holes between data chunks");
                        }
                    }
                    None => {
                        bail!(
                            "stargz: invalid chunk offset 0x{:x} or size 0x{:x}",
                            curr.file_offset(),
                            curr.uncompressed_size()
                        )
                    }
                }
            }
        }

        if !chunks.is_empty() {
            let last = &chunks[chunks.len() - 1];
            if last.inner.file_offset() + last.inner.uncompressed_size() as u64 != size {
                bail!("stargz: file size and sum of chunk size doesn't match");
            }
        } else if size != 0 {
            bail!("stargz: file size and sum of chunk size doesn't match");
        }

        Ok(())
    }

    fn fix_chunk_info(&mut self, ctx: &mut BuildContext, blob_mgr: &mut BlobManager) -> Result<()> {
        /*
        let mut header = BlobMetaHeaderOndisk::default();
        header.set_4k_aligned(true);
        header.set_ci_separate(ctx.blob_meta_features & BLOB_META_FEATURE_SEPARATE != 0);
        header.set_chunk_info_v2(ctx.blob_meta_features & BLOB_META_FEATURE_CHUNK_INFO_V2 != 0);
        header.set_ci_zran(ctx.blob_meta_features & BLOB_META_FEATURE_ZRAN != 0);
        blob_ctx.blob_meta_header = header;
        */

        // Ensure that the chunks in the blob meta are sorted by uncompressed_offset and ordered
        // by chunk index so that they can be found quickly at runtime with a binary search.
        let mut blob_chunks: Vec<&mut NodeChunk> = Vec::with_capacity(10240);
        for (_, chunks) in self.file_chunk_map.values_mut() {
            for chunk in chunks.iter_mut() {
                blob_chunks.push(chunk);
            }
        }
        blob_chunks.sort_unstable_by(|a, b| {
            a.inner
                .uncompressed_offset()
                .cmp(&b.inner.uncompressed_offset())
        });
        if blob_chunks.is_empty() {
            return Ok(());
        }

        // Compute compressed_size for chunks.
        let (blob_index, blob_ctx) = blob_mgr.get_or_create_current_blob(ctx)?;
        let chunk_count = blob_chunks.len();
        let mut compressed_blob_size = 0u64;
        for idx in 0..chunk_count {
            let curr = blob_chunks[idx].inner.compressed_offset();
            let next = if idx == chunk_count - 1 {
                self.blob_size
            } else {
                blob_chunks[idx + 1].inner.compressed_offset()
            };
            if curr >= next {
                bail!("stargz: compressed offset is out of order");
            } else if next - curr > RAFS_MAX_CHUNK_SIZE {
                bail!("stargz: compressed size is too big");
            }

            let mut chunk = blob_chunks[idx].inner.deref().clone();
            let uncomp_size = chunk.uncompressed_size() as usize;
            let max_size = (next - curr) as usize;
            let max_gzip_size = compute_compressed_gzip_size(uncomp_size, max_size);
            let chunk_index = blob_ctx.alloc_chunk_index()?;
            chunk.set_index(chunk_index);
            chunk.set_blob_index(blob_index);
            chunk.set_compressed_size(max_gzip_size as u32);
            blob_ctx.add_chunk_meta_info(&chunk, None)?;
            compressed_blob_size = std::cmp::max(
                compressed_blob_size,
                chunk.compressed_offset() + chunk.compressed_size() as u64,
            );
            assert_eq!(Arc::strong_count(&blob_chunks[idx].inner), 1);
            blob_chunks[idx].inner = Arc::new(chunk);
        }

        blob_ctx.uncompressed_blob_size = self.uncompressed_offset;
        blob_ctx.compressed_blob_size = compressed_blob_size;

        Ok(())
    }

    fn fix_nodes(&mut self, bootstrap: &mut Bootstrap) -> Result<()> {
        bootstrap
            .tree
            .walk_bfs(true, &mut |n| {
                let mut node = n.lock_node();
                let node_path = node.path();
                if let Some((size, ref mut chunks)) = self.file_chunk_map.get_mut(node_path) {
                    node.inode.set_size(*size);
                    node.inode.set_child_count(chunks.len() as u32);
                    node.chunks = chunks.to_vec();
                }

                Ok(())
            })
            .context("stargz: failed to update chunk info array for nodes")?;

        for (k, v) in self.hardlink_map.iter() {
            match bootstrap.tree.get_node(k) {
                Some(n) => {
                    let mut node = n.lock_node();
                    let target = v.lock().unwrap();
                    node.inode.set_size(target.inode.size());
                    node.inode.set_child_count(target.inode.child_count());
                    node.chunks = target.chunks.clone();
                    node.set_xattr(target.info.xattrs.clone());
                }
                None => bail!(
                    "stargz: failed to get target node for hardlink {}",
                    k.display()
                ),
            }
        }

        Ok(())
    }
}

impl Builder for StargzBuilder {
    fn build(
        &mut self,
        ctx: &mut BuildContext,
        bootstrap_mgr: &mut BootstrapManager,
        blob_mgr: &mut BlobManager,
    ) -> Result<BuildOutput> {
        if ctx.fs_version != RafsVersion::V6 {
            bail!(
                "stargz: unsupported filesystem version {:?}",
                ctx.fs_version
            );
        } else if ctx.compressor != compress::Algorithm::GZip {
            bail!("stargz: invalid compression algorithm {:?}", ctx.compressor);
        } else if ctx.digester != digest::Algorithm::Sha256 {
            bail!("stargz: invalid digest algorithm {:?}", ctx.digester);
        }
        let mut blob_writer: Box<dyn Artifact> = if let Some(blob_stor) = ctx.blob_storage.clone() {
            Box::new(ArtifactWriter::new(blob_stor)?)
        } else {
            Box::<NoopArtifactWriter>::default()
        };
        let mut bootstrap_ctx = bootstrap_mgr.create_ctx()?;
        let layer_idx = u16::from(bootstrap_ctx.layered);

        // Build filesystem tree from the stargz TOC.
        let tree = timing_tracer!({ self.build_tree(ctx, layer_idx) }, "build_tree")?;

        // Build bootstrap
        let mut bootstrap = timing_tracer!(
            { build_bootstrap(ctx, bootstrap_mgr, &mut bootstrap_ctx, blob_mgr, tree) },
            "build_bootstrap"
        )?;

        self.fix_chunk_info(ctx, blob_mgr)?;
        self.fix_nodes(&mut bootstrap)?;

        // Dump blob file
        timing_tracer!(
            { Blob::dump(ctx, &bootstrap.tree, blob_mgr, blob_writer.as_mut()) },
            "dump_blob"
        )?;

        // Dump blob meta information
        if let Some((_, blob_ctx)) = blob_mgr.get_current_blob() {
            Blob::dump_meta_data(ctx, blob_ctx, blob_writer.as_mut())?;
        }

        // Dump RAFS meta/bootstrap and finalize the data blob.
        if ctx.blob_inline_meta {
            timing_tracer!(
                {
                    dump_bootstrap(
                        ctx,
                        bootstrap_mgr,
                        &mut bootstrap_ctx,
                        &mut bootstrap,
                        blob_mgr,
                        blob_writer.as_mut(),
                    )
                },
                "dump_bootstrap"
            )?;
            finalize_blob(ctx, blob_mgr, blob_writer.as_mut())?;
        } else {
            finalize_blob(ctx, blob_mgr, blob_writer.as_mut())?;
            timing_tracer!(
                {
                    dump_bootstrap(
                        ctx,
                        bootstrap_mgr,
                        &mut bootstrap_ctx,
                        &mut bootstrap,
                        blob_mgr,
                        blob_writer.as_mut(),
                    )
                },
                "dump_bootstrap"
            )?;
        }

        lazy_drop(bootstrap_ctx);

        BuildOutput::new(blob_mgr, &bootstrap_mgr.bootstrap_storage)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ArtifactStorage, ConversionType, Features, Prefetch, WhiteoutSpec};

    #[test]
    fn test_build_stargz_toc() {
        let tmp_dir = vmm_sys_util::tempdir::TempDir::new().unwrap();
        let mut tmp_dir = tmp_dir.as_path().to_path_buf();
        let root_dir = &std::env::var("CARGO_MANIFEST_DIR").expect("$CARGO_MANIFEST_DIR");
        let source_path =
            PathBuf::from(root_dir).join("../tests/texture/stargz/estargz_sample.json");
        let prefetch = Prefetch::default();
        let mut ctx = BuildContext::new(
            "".to_string(),
            true,
            0,
            compress::Algorithm::GZip,
            digest::Algorithm::Sha256,
            true,
            WhiteoutSpec::Oci,
            ConversionType::EStargzIndexToRef,
            source_path,
            prefetch,
            Some(ArtifactStorage::FileDir(tmp_dir.clone())),
            false,
            Features::new(),
            false,
        );
        ctx.fs_version = RafsVersion::V6;
        ctx.conversion_type = ConversionType::EStargzToRafs;
        let mut bootstrap_mgr =
            BootstrapManager::new(Some(ArtifactStorage::FileDir(tmp_dir.clone())), None);
        let mut blob_mgr = BlobManager::new(digest::Algorithm::Sha256);
        let mut builder = StargzBuilder::new(0x1000000, &ctx);

        let builder = builder.build(&mut ctx, &mut bootstrap_mgr, &mut blob_mgr);
        assert!(builder.is_ok());
        let builder = builder.unwrap();
        assert_eq!(
            builder.blobs,
            vec![String::from(
                "bd4eff3fe6f5a352457c076d2133583e43db895b4af08d717b3fbcaeca89834e"
            )]
        );
        assert_eq!(builder.blob_size, Some(4128));
        tmp_dir.push("e60676aef5cc0d5caca9f4c8031f5b0c8392a0611d44c8e1bbc46dbf7fe7bfef");
        assert_eq!(
            builder.bootstrap_path.unwrap(),
            tmp_dir.to_str().unwrap().to_string()
        )
    }

    #[test]
    fn test_toc_entry() {
        let root_dir = &std::env::var("CARGO_MANIFEST_DIR").expect("$CARGO_MANIFEST_DIR");
        let source_path = PathBuf::from(root_dir).join("../tests/texture/tar/all-entry-type.tar");

        let mut entry = TocEntry {
            name: source_path,
            toc_type: "".to_string(),
            size: 0x10,
            link_name: PathBuf::from("link_name"),
            mode: 0,
            uid: 1,
            gid: 1,
            uname: "user_name".to_string(),
            gname: "group_name".to_string(),
            dev_major: 255,
            dev_minor: 33,
            xattrs: Default::default(),
            digest: Default::default(),
            offset: 0,
            chunk_offset: 0,
            chunk_size: 0,
            chunk_digest: "sha256:".to_owned(),
            inner_offset: 0,
        };
        entry.chunk_digest.extend(vec!['a'; 64].iter());

        entry.toc_type = "dir".to_owned();
        assert!(entry.is_dir());
        assert!(entry.is_supported());
        assert_eq!(entry.mode(), libc::S_IFDIR);
        assert_eq!(entry.rdev(), u32::MAX);

        entry.toc_type = "req".to_owned();
        assert!(!entry.is_reg());
        entry.toc_type = "reg".to_owned();
        assert!(entry.is_reg());
        assert!(entry.is_supported());
        assert_eq!(entry.mode(), libc::S_IFREG);
        assert_eq!(entry.size(), 0x10);

        entry.toc_type = "symlink".to_owned();
        assert!(entry.is_symlink());
        assert!(entry.is_supported());
        assert_eq!(entry.mode(), libc::S_IFLNK);
        assert_eq!(entry.symlink_link_path(), Path::new("link_name"));
        assert!(entry.normalize().is_ok());

        entry.toc_type = "hardlink".to_owned();
        assert!(entry.is_supported());
        assert!(entry.is_hardlink());
        assert_eq!(entry.mode(), libc::S_IFREG);
        assert_eq!(entry.hardlink_link_path(), Path::new("link_name"));
        assert!(entry.normalize().is_ok());

        entry.toc_type = "chunk".to_owned();
        assert!(entry.is_supported());
        assert!(entry.is_chunk());
        assert_eq!(entry.mode(), 0);
        assert_eq!(entry.size(), 0);
        assert!(entry.normalize().is_err());

        entry.toc_type = "block".to_owned();
        assert!(entry.is_special());
        assert!(entry.is_blockdev());
        assert_eq!(entry.mode(), libc::S_IFBLK);

        entry.toc_type = "char".to_owned();
        assert!(entry.is_special());
        assert!(entry.is_chardev());
        assert_eq!(entry.mode(), libc::S_IFCHR);
        assert_ne!(entry.size(), 0x10);

        entry.toc_type = "fifo".to_owned();
        assert!(entry.is_fifo());
        assert!(entry.is_special());
        assert_eq!(entry.mode(), libc::S_IFIFO);
        assert_eq!(entry.rdev(), 65313);

        assert_eq!(entry.name().unwrap().to_str(), Some("all-entry-type.tar"));
        entry.name = PathBuf::from("/");
        assert_eq!(entry.name().unwrap().to_str(), Some("/"));
        assert_ne!(entry.path(), Path::new("all-entry-type.tar"));

        assert_eq!(entry.block_id().unwrap().data, [0xaa as u8; 32]);

        entry.name = PathBuf::from("");
        assert!(entry.normalize().is_err());
    }
}

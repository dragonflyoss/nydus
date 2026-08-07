// Copyright 2022 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Generate RAFS filesystem from a tarball.
//!
//! It support generating RAFS filesystem from a tar/targz/stargz file with or without data blob.
//!
//! The tarball data is arrange as a sequence of tar headers with associated file data interleaved.
//! - (tar header) (tar header) (file data) (tar header) (file data) (tar header)
//!   And to support read tarball data from FIFO, we could only go over the tarball stream once.
//!   So the workflow is as:
//! - for each tar header from the stream
//!   -- generate RAFS filesystem node from the tar header
//!   -- optionally dump file data associated with the tar header into RAFS data blob
//! - arrange all generated RAFS nodes into a RAFS filesystem tree
//! - dump the RAFS filesystem tree into RAFS metadata blob
use std::ffi::{OsStr, OsString};
use std::fs::{File, OpenOptions};
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{anyhow, bail, Context, Result};
use tar::{Archive, Entry, EntryType, Header};

use nydus_api::enosys;
use nydus_rafs::metadata::inode::{InodeWrapper, RafsInodeFlags, RafsV6Inode};
use nydus_rafs::metadata::layout::v5::RafsV5Inode;
use nydus_rafs::metadata::layout::RafsXAttrs;
use nydus_rafs::metadata::RafsVersion;
use nydus_storage::device::BlobFeatures;
use nydus_storage::meta::ZranContextGenerator;
use nydus_storage::RAFS_MAX_CHUNKS_PER_BLOB;
use nydus_utils::compact::makedev;
use nydus_utils::compress::zlib_random::{ZranReader, ZRAN_READER_BUF_SIZE};
use nydus_utils::compress::ZlibDecoder;
use nydus_utils::digest::RafsDigest;
use nydus_utils::{div_round_up, lazy_drop, root_tracer, timing_tracer, BufReaderInfo, ByteSize};

use crate::core::context::{Artifact, NoopArtifactWriter};

use super::core::blob::Blob;
use super::core::context::{
    ArtifactWriter, BlobManager, BootstrapManager, BuildContext, BuildOutput, ConversionType,
};
use super::core::node::{Node, NodeInfo};
use super::core::tree::Tree;
use super::{build_bootstrap, dump_bootstrap, finalize_blob, Builder, TarBuilder};

enum CompressionType {
    None,
    Gzip,
}

enum TarReader {
    File(File),
    BufReader(BufReader<File>),
    BufReaderInfo(BufReaderInfo<File>),
    BufReaderInfoSeekable(BufReaderInfo<File>),
    TarGzFile(Box<ZlibDecoder<File>>),
    TarGzBufReader(Box<ZlibDecoder<BufReader<File>>>),
    ZranReader(ZranReader<File>),
}

impl Read for TarReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            TarReader::File(f) => f.read(buf),
            TarReader::BufReader(f) => f.read(buf),
            TarReader::BufReaderInfo(b) => b.read(buf),
            TarReader::BufReaderInfoSeekable(b) => b.read(buf),
            TarReader::TarGzFile(f) => f.read(buf),
            TarReader::TarGzBufReader(b) => b.read(buf),
            TarReader::ZranReader(f) => f.read(buf),
        }
    }
}

impl TarReader {
    fn seekable(&self) -> bool {
        matches!(
            self,
            TarReader::File(_) | TarReader::BufReaderInfoSeekable(_)
        )
    }
}

impl Seek for TarReader {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        match self {
            TarReader::File(f) => f.seek(pos),
            TarReader::BufReaderInfoSeekable(b) => b.seek(pos),
            _ => Err(enosys!("seek() not supported!")),
        }
    }
}

struct TarballTreeBuilder<'a> {
    ty: ConversionType,
    ctx: &'a mut BuildContext,
    blob_mgr: &'a mut BlobManager,
    blob_writer: &'a mut dyn Artifact,
    buf: Vec<u8>,
    builder: TarBuilder,
}

impl<'a> TarballTreeBuilder<'a> {
    /// Create a new instance of `TarballBuilder`.
    pub fn new(
        ty: ConversionType,
        ctx: &'a mut BuildContext,
        blob_mgr: &'a mut BlobManager,
        blob_writer: &'a mut dyn Artifact,
        layer_idx: u16,
    ) -> Self {
        let builder = TarBuilder::new(ctx.explicit_uidgid, layer_idx, ctx.fs_version);
        Self {
            ty,
            ctx,
            blob_mgr,
            buf: Vec::new(),
            blob_writer,
            builder,
        }
    }

    fn build_tree(&mut self) -> Result<Tree> {
        let file = OpenOptions::new()
            .read(true)
            .open(self.ctx.source_path.clone())
            .context("tarball: can not open source file for conversion")?;
        let mut is_file = match file.metadata() {
            Ok(md) => md.file_type().is_file(),
            Err(_) => false,
        };

        let reader = match self.ty {
            ConversionType::EStargzToRef
            | ConversionType::TargzToRef
            | ConversionType::TarToRef => match Self::detect_compression_algo(file)? {
                (CompressionType::Gzip, buf_reader) => {
                    let generator = ZranContextGenerator::from_buf_reader(buf_reader)?;
                    let reader = generator.reader();
                    self.ctx.blob_zran_generator = Some(Mutex::new(generator));
                    self.ctx.blob_features.insert(BlobFeatures::ZRAN);
                    TarReader::ZranReader(reader)
                }
                (CompressionType::None, buf_reader) => {
                    self.ty = ConversionType::TarToRef;
                    let reader = BufReaderInfo::from_buf_reader(buf_reader);
                    self.ctx.blob_tar_reader = Some(reader.clone());
                    TarReader::BufReaderInfo(reader)
                }
            },
            ConversionType::EStargzToRafs
            | ConversionType::TargzToRafs
            | ConversionType::TarToRafs => match Self::detect_compression_algo(file)? {
                (CompressionType::Gzip, buf_reader) => {
                    if is_file {
                        let mut file = buf_reader.into_inner();
                        file.seek(SeekFrom::Start(0))?;
                        TarReader::TarGzFile(Box::new(ZlibDecoder::new(file)))
                    } else {
                        TarReader::TarGzBufReader(Box::new(ZlibDecoder::new(buf_reader)))
                    }
                }
                (CompressionType::None, buf_reader) => {
                    if is_file {
                        let mut file = buf_reader.into_inner();
                        file.seek(SeekFrom::Start(0))?;
                        TarReader::File(file)
                    } else {
                        TarReader::BufReader(buf_reader)
                    }
                }
            },
            ConversionType::TarToTarfs => {
                let mut reader = BufReaderInfo::from_buf_reader(BufReader::new(file));
                self.ctx.blob_tar_reader = Some(reader.clone());
                if !self.ctx.blob_id.is_empty() {
                    reader.enable_digest_calculation(false);
                } else {
                    // Disable seek when need to calculate hash value.
                    is_file = false;
                }
                // only enable seek when hash computing is disabled.
                if is_file {
                    TarReader::BufReaderInfoSeekable(reader)
                } else {
                    TarReader::BufReaderInfo(reader)
                }
            }
            _ => return Err(anyhow!("tarball: unsupported image conversion type")),
        };

        let is_seekable = reader.seekable();
        let mut tar = Archive::new(reader);
        tar.set_ignore_zeros(true);
        tar.set_preserve_mtime(true);
        tar.set_preserve_permissions(true);
        tar.set_unpack_xattrs(true);

        // Prepare scratch buffer for dumping file data.
        if self.buf.len() < self.ctx.chunk_size as usize {
            self.buf = vec![0u8; self.ctx.chunk_size as usize];
        }

        // Generate the root node in advance, it may be overwritten by entries from the tar stream.
        let root = self.builder.create_directory(&[OsString::from("/")])?;
        let mut tree = Tree::new(root);

        // Generate RAFS node for each tar entry, and optionally adding missing parents.
        let entries = if is_seekable {
            tar.entries_with_seek()
                .context("tarball: failed to read entries from tar")?
        } else {
            tar.entries()
                .context("tarball: failed to read entries from tar")?
        };
        for entry in entries {
            let mut entry = entry.context("tarball: failed to read entry from tar")?;
            let path = entry
                .path()
                .context("tarball: failed to to get path from tar entry")?;
            let path = PathBuf::from("/").join(path);
            let path = path.components().as_path();
            if !self.builder.is_stargz_special_files(path) {
                self.parse_entry(&mut tree, &mut entry, path)?;
            }
        }

        // Update directory size for RAFS V5 after generating the tree.
        if self.ctx.fs_version.is_v5() {
            Self::set_v5_dir_size(&mut tree);
        }

        Ok(tree)
    }

    fn parse_entry<R: Read>(
        &mut self,
        tree: &mut Tree,
        entry: &mut Entry<R>,
        path: &Path,
    ) -> Result<()> {
        let header = entry.header();
        let entry_type = header.entry_type();
        if entry_type.is_gnu_longname() {
            return Err(anyhow!("tarball: unsupported gnu_longname from tar header"));
        } else if entry_type.is_gnu_longlink() {
            return Err(anyhow!("tarball: unsupported gnu_longlink from tar header"));
        } else if entry_type.is_pax_local_extensions() {
            return Err(anyhow!(
                "tarball: unsupported pax_local_extensions from tar header"
            ));
        } else if entry_type.is_pax_global_extensions() {
            return Err(anyhow!(
                "tarball: unsupported pax_global_extensions from tar header"
            ));
        } else if entry_type.is_contiguous() {
            return Err(anyhow!(
                "tarball: unsupported contiguous entry type from tar header"
            ));
        } else if entry_type.is_gnu_sparse() {
            return Err(anyhow!(
                "tarball: unsupported gnu sparse file extension from tar header"
            ));
        }

        let mut file_size = entry.size();
        let name = Self::get_file_name(path)?;
        let mut mode = Self::get_mode(header)?;
        let (mut uid, mut gid) = Self::get_uid_gid(self.ctx, header)?;
        let mut mtime = header.mtime().unwrap_or_default();
        let mut flags = match self.ctx.fs_version {
            RafsVersion::V5 => RafsInodeFlags::default(),
            RafsVersion::V6 => RafsInodeFlags::default(),
        };

        // Parse special files.
        //
        // POSIX ustar defines `devmajor` and `devminor` for character and block special files
        // only, so an implementation is free to leave them NUL for a fifo, and GNU tar does
        // exactly that in all of its `gnu`, `ustar` and `posix` formats. A v7 entry carries no
        // such fields at all. A fifo has no device number anyway: `stat()` reports `st_rdev` of
        // 0 for it, which is what the directory builder stores, so store the same here instead
        // of reading fields the entry is not required to carry.
        let mut rdev = if entry_type.is_block_special() || entry_type.is_character_special() {
            let major = header
                .device_major()
                .context("tarball: failed to get device major from tar entry")?
                .ok_or_else(|| anyhow!("tarball: failed to get major device from tar entry"))?;
            let minor = header
                .device_minor()
                .context("tarball: failed to get device minor from tar entry")?
                .ok_or_else(|| anyhow!("tarball: failed to get minor device from tar entry"))?;
            makedev(major as u64, minor as u64) as u32
        } else if entry_type.is_fifo() {
            0
        } else {
            u32::MAX
        };

        // Parse symlink
        let (mut symlink, mut symlink_size) = if entry_type.is_symlink() {
            let symlink_link_path = entry
                .link_name()
                .context("tarball: failed to get target path for tar symlink entry")?
                .ok_or_else(|| anyhow!("tarball: failed to get symlink target for tar entry"))?;
            let symlink_size = symlink_link_path.as_os_str().byte_size();
            if symlink_size > u16::MAX as usize {
                bail!("tarball: symlink target from tar entry is too big");
            }
            file_size = symlink_size as u64;
            flags |= RafsInodeFlags::SYMLINK;
            (
                Some(symlink_link_path.as_os_str().to_owned()),
                symlink_size as u16,
            )
        } else {
            (None, 0)
        };

        let mut child_count = 0;
        if entry_type.is_file() {
            child_count = div_round_up(file_size, self.ctx.chunk_size as u64);
            if child_count > RAFS_MAX_CHUNKS_PER_BLOB as u64 {
                bail!("tarball: file size 0x{:x} is too big", file_size);
            }
        }

        // Parse xattrs
        let mut xattrs = RafsXAttrs::new();
        if let Some(exts) = entry.pax_extensions()? {
            for p in exts {
                match p {
                    Ok(pax) => {
                        let prefix = b"SCHILY.xattr.";
                        let key = pax.key_bytes();
                        if key.starts_with(prefix) {
                            let x_key = OsStr::from_bytes(&key[prefix.len()..]);
                            xattrs.add(x_key.to_os_string(), pax.value_bytes().to_vec())?;
                        }
                    }
                    Err(e) => {
                        return Err(anyhow!(
                            "tarball: failed to parse PaxExtension from tar header, {}",
                            e
                        ))
                    }
                }
            }
        }

        // Handle hardlink ino
        let mut hardlink_target = None;
        let ino = if entry_type.is_hard_link() {
            let link_path = entry
                .link_name()
                .context("tarball: failed to get target path for tar hardlink entry")?
                .ok_or_else(|| anyhow!("tarball: failed to get hardlink target for tar entry"))?;
            let link_path = PathBuf::from("/").join(link_path);
            let link_path = link_path.components().as_path();
            let targets = Node::generate_target_vec(link_path);
            assert!(!targets.is_empty());
            let mut tmp_tree: &Tree = tree;
            for name in &targets[1..] {
                match tmp_tree.get_child_idx(name.as_bytes()) {
                    Some(idx) => tmp_tree = &tmp_tree.children[idx],
                    None => {
                        bail!(
                            "tarball: unknown target {} for hardlink {}",
                            link_path.display(),
                            path.display()
                        );
                    }
                }
            }
            let mut tmp_node = tmp_tree.borrow_mut_node();
            if tmp_node.is_reg() {
                hardlink_target = Some(tmp_tree);
                flags |= RafsInodeFlags::HARDLINK;
                tmp_node.inode.set_has_hardlink(true);
                tmp_node.inode.ino()
            } else if tmp_node.is_dir() {
                bail!(
                    "tarball: target {} for hardlink {} is a directory",
                    link_path.display(),
                    path.display()
                );
            } else {
                // RAFS only represents hardlinks for regular files, so a hardlink to a symlink
                // or to a special file becomes an independent node cloned from the target. Such
                // nodes carry all their information in the inode, so nothing gets duplicated in
                // the data blob.
                //
                // Extracting a hardlink entry doesn't apply the metadata from its header: the
                // name is created with link(2) and resolves to the inode of the target. So all
                // metadata comes from the target node, and the generated filesystem matches what
                // extracting the tarball produces even if the two headers disagree.
                mode = tmp_node.inode.mode();
                uid = tmp_node.inode.uid();
                gid = tmp_node.inode.gid();
                mtime = tmp_node.inode.mtime();
                rdev = tmp_node.inode.rdev();
                file_size = tmp_node.inode.size();
                symlink = tmp_node.info.symlink.clone();
                symlink_size = tmp_node.inode.symlink_size();
                xattrs = tmp_node.info.xattrs.clone();
                if tmp_node.is_symlink() {
                    flags |= RafsInodeFlags::SYMLINK;
                }
                self.builder.next_ino()
            }
        } else {
            self.builder.next_ino()
        };

        let mut inode = match self.ctx.fs_version {
            RafsVersion::V5 => InodeWrapper::V5(RafsV5Inode {
                i_digest: RafsDigest::default(),
                i_parent: 0,
                i_ino: ino,
                i_projid: 0,
                i_uid: uid,
                i_gid: gid,
                i_mode: mode,
                i_size: file_size,
                i_nlink: 1,
                i_blocks: 0,
                i_flags: flags,
                i_child_index: 0,
                i_child_count: child_count as u32,
                i_name_size: name.len() as u16,
                i_symlink_size: symlink_size,
                i_rdev: rdev,
                i_mtime: mtime,
                i_mtime_nsec: 0,
                i_reserved: [0; 8],
            }),
            RafsVersion::V6 => InodeWrapper::V6(RafsV6Inode {
                i_ino: ino,
                i_projid: 0,
                i_uid: uid,
                i_gid: gid,
                i_mode: mode,
                i_size: file_size,
                i_nlink: 1,
                i_blocks: 0,
                i_flags: flags,
                i_child_count: child_count as u32,
                i_name_size: name.len() as u16,
                i_symlink_size: symlink_size,
                i_rdev: rdev,
                i_mtime: mtime,
                i_mtime_nsec: 0,
            }),
        };
        inode.set_has_xattr(!xattrs.is_empty());

        let source = PathBuf::from("/");
        let target = Node::generate_target(path, &source);
        let target_vec = Node::generate_target_vec(&target);
        let info = NodeInfo {
            explicit_uidgid: self.ctx.explicit_uidgid,
            src_ino: ino,
            src_dev: u64::MAX,
            rdev: rdev as u64,
            path: path.to_path_buf(),
            source,
            target,
            target_vec,
            symlink,
            xattrs,
            v6_force_extended_inode: false,
        };
        let mut node = Node::new(inode, info, self.builder.layer_idx);

        // Special handling of hardlink.
        // Tar hardlink header has zero file size and no file data associated, so copy value from
        // the associated regular file.
        if let Some(t) = hardlink_target {
            let n = t.borrow_mut_node();
            if n.inode.is_v5() {
                node.inode.set_digest(n.inode.digest().to_owned());
            }
            node.inode.set_size(n.inode.size());
            node.inode.set_child_count(n.inode.child_count());
            node.chunks = n.chunks.clone();
            // All names of a hardlink share a single inode, and for RAFS v6 they literally share
            // its on-disk region, whose size was reserved from the target. The xattrs must
            // therefore stay identical to the target's, even if the hardlink entry recorded
            // xattrs of its own.
            node.set_xattr(n.info.xattrs.clone());
        } else {
            node.dump_node_data_with_reader(
                self.ctx,
                self.blob_mgr,
                self.blob_writer,
                Some(entry),
                &mut self.buf,
            )?;
        }

        // Update inode.i_blocks for RAFS v5.
        if self.ctx.fs_version == RafsVersion::V5 && !entry_type.is_dir() {
            node.v5_set_inode_blocks();
        }

        self.builder.insert_into_tree(tree, node)
    }

    fn get_uid_gid(ctx: &BuildContext, header: &Header) -> Result<(u32, u32)> {
        let uid = if ctx.explicit_uidgid {
            header.uid().unwrap_or_default()
        } else {
            0
        };
        let gid = if ctx.explicit_uidgid {
            header.gid().unwrap_or_default()
        } else {
            0
        };
        if uid > u32::MAX as u64 || gid > u32::MAX as u64 {
            bail!(
                "tarball: uid {:x} or gid {:x} from tar entry is out of range",
                uid,
                gid
            );
        }

        Ok((uid as u32, gid as u32))
    }

    fn get_mode(header: &Header) -> Result<u32> {
        let mode = header
            .mode()
            .context("tarball: failed to get permission/mode from tar entry")?;
        let ty = match header.entry_type() {
            EntryType::Regular | EntryType::Link => crate::mode_bits(libc::S_IFREG),
            EntryType::Directory => crate::mode_bits(libc::S_IFDIR),
            EntryType::Symlink => crate::mode_bits(libc::S_IFLNK),
            EntryType::Block => crate::mode_bits(libc::S_IFBLK),
            EntryType::Char => crate::mode_bits(libc::S_IFCHR),
            EntryType::Fifo => crate::mode_bits(libc::S_IFIFO),
            _ => bail!("tarball: unsupported tar entry type"),
        };
        Ok((mode & !crate::mode_bits(libc::S_IFMT)) | ty)
    }

    fn get_file_name(path: &Path) -> Result<&OsStr> {
        let name = if path == Path::new("/") {
            path.as_os_str()
        } else {
            path.file_name().ok_or_else(|| {
                anyhow!(
                    "tarball: failed to get file name from tar entry with path {}",
                    path.display()
                )
            })?
        };
        if name.len() > u16::MAX as usize {
            bail!(
                "tarball: file name {} from tar entry is too long",
                name.to_str().unwrap_or_default()
            );
        }
        Ok(name)
    }

    fn set_v5_dir_size(tree: &mut Tree) {
        for c in &mut tree.children {
            Self::set_v5_dir_size(c);
        }
        let mut node = tree.borrow_mut_node();
        node.v5_set_dir_size(RafsVersion::V5, &tree.children);
    }

    fn detect_compression_algo(file: File) -> Result<(CompressionType, BufReader<File>)> {
        // Use 64K buffer to keep consistence with zlib-random.
        let mut buf_reader = BufReader::with_capacity(ZRAN_READER_BUF_SIZE, file);
        let mut buf = [0u8; 3];
        buf_reader.read_exact(&mut buf)?;
        if buf[0] == 0x1f && buf[1] == 0x8b && buf[2] == 0x08 {
            buf_reader.seek_relative(-3).unwrap();
            Ok((CompressionType::Gzip, buf_reader))
        } else {
            buf_reader.seek_relative(-3).unwrap();
            Ok((CompressionType::None, buf_reader))
        }
    }
}

/// Builder to create RAFS filesystems from tarballs.
///
/// Note that hardlinks are only preserved for regular files, since RAFS represents hardlinks by
/// sharing an inode between regular files. A tar hardlink entry whose target is a symlink or a
/// special file becomes an independent node with the metadata of its target, so the generated
/// filesystem reports `nlink` of 1 for both names instead of 2.
pub struct TarballBuilder {
    ty: ConversionType,
}

impl TarballBuilder {
    /// Create a new instance of [TarballBuilder] to build a RAFS filesystem from a tarball.
    pub fn new(conversion_type: ConversionType) -> Self {
        Self {
            ty: conversion_type,
        }
    }
}

impl Builder for TarballBuilder {
    fn build(
        &mut self,
        ctx: &mut BuildContext,
        bootstrap_mgr: &mut BootstrapManager,
        blob_mgr: &mut BlobManager,
    ) -> Result<BuildOutput> {
        let mut bootstrap_ctx = bootstrap_mgr.create_ctx()?;
        let layer_idx = u16::from(bootstrap_ctx.layered);
        let mut blob_writer: Box<dyn Artifact> = match self.ty {
            ConversionType::EStargzToRafs
            | ConversionType::EStargzToRef
            | ConversionType::TargzToRafs
            | ConversionType::TargzToRef
            | ConversionType::TarToRafs
            | ConversionType::TarToTarfs => {
                if let Some(blob_stor) = ctx.blob_storage.clone() {
                    Box::new(ArtifactWriter::new(blob_stor)?)
                } else {
                    Box::<NoopArtifactWriter>::default()
                }
            }
            _ => {
                return Err(anyhow!(
                    "tarball: unsupported image conversion type '{}'",
                    self.ty
                ))
            }
        };

        let mut tree_builder =
            TarballTreeBuilder::new(self.ty, ctx, blob_mgr, blob_writer.as_mut(), layer_idx);
        let tree = timing_tracer!({ tree_builder.build_tree() }, "build_tree")?;

        // Build bootstrap
        let mut bootstrap = timing_tracer!(
            { build_bootstrap(ctx, bootstrap_mgr, &mut bootstrap_ctx, blob_mgr, tree) },
            "build_bootstrap"
        )?;

        // Dump blob file
        timing_tracer!(
            { Blob::dump(ctx, blob_mgr, blob_writer.as_mut()) },
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

        BuildOutput::new(blob_mgr, None, &bootstrap_mgr.bootstrap_storage, &None)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::attributes::Attributes;
    use crate::{ArtifactStorage, Bootstrap, BootstrapContext, Features, Prefetch, WhiteoutSpec};
    use nydus_utils::{compress, digest};

    // Metadata of the hardlink targets in `create_hardlink_tar`, chosen to differ from the
    // metadata of the hardlink entries pointing at them.
    const TARGET_MODE: u32 = 0o755;
    const TARGET_UID: u64 = 7;
    const TARGET_GID: u64 = 8;
    const TARGET_MTIME: u64 = 111;

    #[allow(clippy::too_many_arguments)]
    fn append_entry_with_meta(
        tar: &mut tar::Builder<File>,
        path: &str,
        entry_type: EntryType,
        link_name: Option<&str>,
        data: &[u8],
        mode: u32,
        uid: u64,
        gid: u64,
        mtime: u64,
    ) {
        let mut header = Header::new_gnu();
        header.set_entry_type(entry_type);
        header.set_mode(mode);
        header.set_uid(uid);
        header.set_gid(gid);
        header.set_mtime(mtime);
        header.set_size(data.len() as u64);
        if let Some(link_name) = link_name {
            header.set_link_name(link_name).unwrap();
        }
        if entry_type == EntryType::Fifo {
            header.set_device_major(0).unwrap();
            header.set_device_minor(0).unwrap();
        }
        tar.append_data(&mut header, path, data).unwrap();
    }

    fn append_entry(
        tar: &mut tar::Builder<File>,
        path: &str,
        entry_type: EntryType,
        link_name: Option<&str>,
        data: &[u8],
    ) {
        append_entry_with_meta(tar, path, entry_type, link_name, data, 0o644, 0, 0, 0);
    }

    // Generate a tar stream containing hardlinks to a symlink, to a fifo and to a regular file.
    // The hardlinks to the symlink live in a subdirectory, so that the node created for them gets
    // an inode number greater than the inode number of its parent directory. The targets carry
    // metadata which differs from their hardlink entries, so that a node built from the target is
    // distinguishable from one built from the hardlink header.
    fn create_hardlink_tar(path: &Path) {
        let mut tar = tar::Builder::new(File::create(path).unwrap());
        append_entry(&mut tar, "foo", EntryType::Regular, None, b"hello");
        for (name, entry_type) in [("sym", EntryType::Symlink), ("fifo", EntryType::Fifo)] {
            let link_name = (entry_type == EntryType::Symlink).then_some("foo");
            append_entry_with_meta(
                &mut tar,
                name,
                entry_type,
                link_name,
                b"",
                TARGET_MODE,
                TARGET_UID,
                TARGET_GID,
                TARGET_MTIME,
            );
        }
        append_entry(&mut tar, "dir/", EntryType::Directory, None, b"");
        append_entry(
            &mut tar,
            "dir/sym-link",
            EntryType::Link,
            Some("./sym"),
            b"",
        );
        append_entry(
            &mut tar,
            "dir/fifo-link",
            EntryType::Link,
            Some("fifo"),
            b"",
        );
        append_entry(&mut tar, "dir/foo-link", EntryType::Link, Some("foo"), b"");
        tar.finish().unwrap();
    }

    fn create_context(source_path: PathBuf, version: RafsVersion) -> BuildContext {
        let mut ctx = BuildContext::new(
            "test".to_string(),
            true,
            0,
            compress::Algorithm::None,
            digest::Algorithm::Sha256,
            true,
            WhiteoutSpec::Oci,
            ConversionType::TarToRafs,
            source_path,
            Prefetch::default(),
            None,
            None,
            false,
            Features::new(),
            false,
            Attributes::default(),
        );
        ctx.fs_version = version;
        ctx
    }

    fn build_tree(ctx: &mut BuildContext) -> Result<Tree> {
        let mut blob_mgr = BlobManager::new(digest::Algorithm::Sha256, false);
        let mut blob_writer: Box<dyn Artifact> = Box::<NoopArtifactWriter>::default();
        let mut tree_builder = TarballTreeBuilder::new(
            ConversionType::TarToRafs,
            ctx,
            &mut blob_mgr,
            blob_writer.as_mut(),
            0,
        );
        tree_builder.build_tree()
    }

    fn build_rafs(ctx: &mut BuildContext) -> Bootstrap {
        let tree = build_tree(ctx).unwrap();
        let mut bootstrap_ctx = BootstrapContext::new(None, false).unwrap();
        let mut bootstrap = Bootstrap::new(tree).unwrap();
        bootstrap.build(ctx, &mut bootstrap_ctx).unwrap();
        bootstrap
    }

    fn get_node(bootstrap: &Bootstrap, path: &str) -> Node {
        bootstrap
            .tree
            .get_node(Path::new(path))
            .unwrap()
            .borrow_mut_node()
            .clone()
    }

    // The metadata of an independent node created for a hardlink entry must come from the target
    // node, since extracting the entry would create a name resolving to the inode of the target.
    fn assert_metadata_from_target(node: &Node, target: &Node, file_type: libc::mode_t) {
        assert_eq!(node.inode.mode(), target.inode.mode());
        assert_eq!(node.inode.mode(), crate::mode_bits(file_type) | TARGET_MODE);
        assert_eq!(node.inode.uid(), TARGET_UID as u32);
        assert_eq!(node.inode.gid(), TARGET_GID as u32);
        assert_eq!(node.inode.mtime(), TARGET_MTIME);
        assert_eq!(node.info.xattrs.is_empty(), target.info.xattrs.is_empty());
    }

    fn test_hardlink_to_non_regular_file(version: RafsVersion) {
        let tmp_dir = vmm_sys_util::tempdir::TempDir::new().unwrap();
        let tmp_dir = tmp_dir.as_path().to_path_buf();
        let source_path = tmp_dir.join("hardlink.tar");
        create_hardlink_tar(&source_path);
        let mut ctx = create_context(source_path.clone(), version);
        let bootstrap = build_rafs(&mut ctx);

        // A hardlink to a symlink becomes an independent symlink node with the same target,
        // instead of sharing the inode of the target as a hardlink to a regular file does. Its
        // metadata comes from the target, not from the header of the hardlink entry.
        let sym = get_node(&bootstrap, "/sym");
        let sym_link = get_node(&bootstrap, "/dir/sym-link");
        assert!(sym_link.is_symlink());
        assert_eq!(sym_link.info.symlink, Some(OsString::from("foo")));
        assert_eq!(sym_link.inode.symlink_size(), 3);
        assert_eq!(sym_link.inode.size(), 3);
        assert_ne!(sym_link.inode.ino(), sym.inode.ino());
        assert_eq!(sym_link.inode.nlink(), 1);
        // A hardlink entry has no file data, so it never gets chunks.
        assert_eq!(sym_link.inode.child_count(), 0);
        assert_metadata_from_target(&sym_link, &sym, libc::S_IFLNK);
        if version.is_v5() {
            // The digest of a v5 symlink is computed from its target, so an independent node
            // must have gone through the regular symlink dump path.
            assert_eq!(sym_link.inode.digest(), sym.inode.digest());
        }

        // Same for a hardlink to a special file, which also keeps the device number.
        let fifo = get_node(&bootstrap, "/fifo");
        let fifo_link = get_node(&bootstrap, "/dir/fifo-link");
        assert!(fifo_link.is_special());
        assert_eq!(fifo_link.inode.rdev(), fifo.inode.rdev());
        assert_ne!(fifo_link.inode.ino(), fifo.inode.ino());
        assert_eq!(fifo_link.inode.nlink(), 1);
        assert_eq!(fifo_link.inode.child_count(), 0);
        assert_metadata_from_target(&fifo_link, &fifo, libc::S_IFIFO);

        // A hardlink to a regular file is still coalesced into a single inode.
        let foo = get_node(&bootstrap, "/foo");
        let foo_link = get_node(&bootstrap, "/dir/foo-link");
        assert!(foo_link.is_hardlink());
        assert_eq!(foo_link.inode.ino(), foo.inode.ino());
        assert_eq!(foo_link.inode.nlink(), 2);
        assert_eq!(foo.inode.nlink(), 2);
        assert_eq!(foo_link.inode.size(), 5);
        assert_eq!(foo_link.inode.child_count(), 1);
        assert_eq!(foo_link.chunks.len(), 1);

        // The same tarball must also convert end to end, including blob and bootstrap dump.
        let mut ctx = create_context(source_path, version);
        ctx.blob_storage = Some(ArtifactStorage::FileDir((tmp_dir.clone(), String::new())));
        let mut bootstrap_mgr = BootstrapManager::new(
            Some(ArtifactStorage::FileDir((tmp_dir, String::new()))),
            None,
        );
        let mut blob_mgr = BlobManager::new(digest::Algorithm::Sha256, false);
        TarballBuilder::new(ConversionType::TarToRafs)
            .build(&mut ctx, &mut bootstrap_mgr, &mut blob_mgr)
            .unwrap();
    }

    #[test]
    fn test_v5_hardlink_to_non_regular_file() {
        test_hardlink_to_non_regular_file(RafsVersion::V5);
    }

    #[test]
    fn test_v6_hardlink_to_non_regular_file() {
        test_hardlink_to_non_regular_file(RafsVersion::V6);
    }

    // Append an entry whose `devmajor`/`devminor` fields are left NUL, the way Go's
    // `archive/tar` writes every entry which is not a character or block special file.
    fn append_entry_without_device_numbers(
        tar: &mut tar::Builder<File>,
        path: &str,
        entry_type: EntryType,
    ) {
        let mut header = Header::new_ustar();
        header.set_entry_type(entry_type);
        header.set_mode(0o700);
        header.set_size(0);
        header.set_path(path).unwrap();
        // `devmajor` and `devminor` occupy bytes 329..345 of a ustar header.
        header.as_mut_bytes()[329..345].fill(0);
        header.set_cksum();
        tar.append(&header, &[][..]).unwrap();
    }

    fn test_fifo_without_device_numbers(version: RafsVersion) {
        let tmp_dir = vmm_sys_util::tempdir::TempDir::new().unwrap();
        let source_path = tmp_dir.as_path().join("fifo.tar");
        let mut tar = tar::Builder::new(File::create(&source_path).unwrap());
        append_entry_without_device_numbers(&mut tar, "fifo-entry", EntryType::Fifo);
        tar.finish().unwrap();

        let mut ctx = create_context(source_path, version);
        let bootstrap = build_rafs(&mut ctx);

        let fifo = get_node(&bootstrap, "/fifo-entry");
        assert!(fifo.is_special());
        // A fifo has no device number, and `stat()` reports `st_rdev` of 0 for it, so a fifo
        // built from a directory carries 0. One built from a tarball must match.
        assert_eq!(fifo.inode.rdev(), 0);
        assert_eq!(fifo.info.rdev, 0);
    }

    #[test]
    fn test_v5_fifo_without_device_numbers() {
        test_fifo_without_device_numbers(RafsVersion::V5);
    }

    #[test]
    fn test_v6_fifo_without_device_numbers() {
        test_fifo_without_device_numbers(RafsVersion::V6);
    }

    // Character and block special files are the two types POSIX defines `devmajor`/`devminor`
    // for, so they must keep round-tripping their device number.
    fn test_device_files_keep_rdev(version: RafsVersion) {
        let tmp_dir = vmm_sys_util::tempdir::TempDir::new().unwrap();
        let source_path = tmp_dir.as_path().join("devices.tar");
        let mut tar = tar::Builder::new(File::create(&source_path).unwrap());
        for (name, entry_type) in [("chr", EntryType::Char), ("blk", EntryType::Block)] {
            let mut header = Header::new_ustar();
            header.set_entry_type(entry_type);
            header.set_mode(0o600);
            header.set_size(0);
            header.set_device_major(136).unwrap();
            header.set_device_minor(3).unwrap();
            tar.append_data(&mut header, name, &[][..]).unwrap();
        }
        tar.finish().unwrap();

        let mut ctx = create_context(source_path, version);
        let bootstrap = build_rafs(&mut ctx);

        let expected = makedev(136, 3) as u32;
        for name in ["/chr", "/blk"] {
            let node = get_node(&bootstrap, name);
            assert!(node.is_special());
            assert_eq!(node.inode.rdev(), expected);
        }
    }

    #[test]
    fn test_v5_device_files_keep_rdev() {
        test_device_files_keep_rdev(RafsVersion::V5);
    }

    #[test]
    fn test_v6_device_files_keep_rdev() {
        test_device_files_keep_rdev(RafsVersion::V6);
    }

    #[test]
    fn test_hardlink_to_directory_is_rejected() {
        let tmp_dir = vmm_sys_util::tempdir::TempDir::new().unwrap();
        let source_path = tmp_dir.as_path().join("hardlink-dir.tar");
        let mut tar = tar::Builder::new(File::create(&source_path).unwrap());
        append_entry(&mut tar, "dir/", EntryType::Directory, None, b"");
        append_entry(&mut tar, "dir-link", EntryType::Link, Some("dir"), b"");
        tar.finish().unwrap();

        let mut ctx = create_context(source_path, RafsVersion::V6);
        let err = build_tree(&mut ctx).err().unwrap();
        assert!(err.to_string().contains("is a directory"), "{}", err);
    }

    #[test]
    fn test_hardlink_to_unknown_target_is_rejected() {
        // A tar entry may only be hardlinked to an entry which appeared earlier in the stream,
        // because the tarball is parsed in a single pass.
        let tmp_dir = vmm_sys_util::tempdir::TempDir::new().unwrap();
        let source_path = tmp_dir.as_path().join("hardlink-unknown.tar");
        let mut tar = tar::Builder::new(File::create(&source_path).unwrap());
        append_entry(&mut tar, "sym-link", EntryType::Link, Some("sym"), b"");
        append_entry(&mut tar, "sym", EntryType::Symlink, Some("foo"), b"");
        tar.finish().unwrap();

        let mut ctx = create_context(source_path, RafsVersion::V6);
        let err = build_tree(&mut ctx).err().unwrap();
        assert!(err.to_string().contains("unknown target"), "{}", err);
    }

    #[test]
    fn test_malformed_pax_extension_is_rejected() {
        let tmp_dir = vmm_sys_util::tempdir::TempDir::new().unwrap();
        let source_path = tmp_dir.as_path().join("bad-pax.tar");
        let mut tar = tar::Builder::new(File::create(&source_path).unwrap());
        // A PAX record starts with its own length in decimal, here reported too long.
        let pax = "99 SCHILY.xattr.user.key=value\n";
        let mut header = Header::new_ustar();
        header.set_entry_type(EntryType::XHeader);
        header.set_mode(0o644);
        header.set_mtime(0);
        header.set_size(pax.len() as u64);
        tar.append_data(&mut header, "PaxHeaders/foo", pax.as_bytes())
            .unwrap();
        append_entry(&mut tar, "foo", EntryType::Regular, None, b"hello");
        tar.finish().unwrap();

        let mut ctx = create_context(source_path, RafsVersion::V6);
        let err = build_tree(&mut ctx).err().unwrap();
        assert!(err.to_string().contains("PaxExtension"), "{}", err);
    }

    #[test]
    fn test_build_tarfs() {
        let tmp_dir = vmm_sys_util::tempdir::TempDir::new().unwrap();
        let tmp_dir = tmp_dir.as_path().to_path_buf();
        let root_dir = &std::env::var("CARGO_MANIFEST_DIR").expect("$CARGO_MANIFEST_DIR");
        let source_path = PathBuf::from(root_dir).join("../tests/texture/tar/all-entry-type.tar");
        let prefetch = Prefetch::default();
        let mut ctx = BuildContext::new(
            "test".to_string(),
            true,
            0,
            compress::Algorithm::None,
            digest::Algorithm::Sha256,
            true,
            WhiteoutSpec::Oci,
            ConversionType::TarToTarfs,
            source_path,
            prefetch,
            Some(ArtifactStorage::FileDir((tmp_dir.clone(), String::new()))),
            None,
            false,
            Features::new(),
            false,
            Attributes::default(),
        );
        let mut bootstrap_mgr = BootstrapManager::new(
            Some(ArtifactStorage::FileDir((tmp_dir, String::new()))),
            None,
        );
        let mut blob_mgr = BlobManager::new(digest::Algorithm::Sha256, false);
        let mut builder = TarballBuilder::new(ConversionType::TarToTarfs);
        builder
            .build(&mut ctx, &mut bootstrap_mgr, &mut blob_mgr)
            .unwrap();
    }

    #[test]
    fn test_build_encrypted_tarfs() {
        let tmp_dir = vmm_sys_util::tempdir::TempDir::new().unwrap();
        let tmp_dir = tmp_dir.as_path().to_path_buf();
        let root_dir = &std::env::var("CARGO_MANIFEST_DIR").expect("$CARGO_MANIFEST_DIR");
        let source_path = PathBuf::from(root_dir).join("../tests/texture/tar/all-entry-type.tar");
        let prefetch = Prefetch::default();
        let mut ctx = BuildContext::new(
            "test".to_string(),
            true,
            0,
            compress::Algorithm::None,
            digest::Algorithm::Sha256,
            true,
            WhiteoutSpec::Oci,
            ConversionType::TarToTarfs,
            source_path,
            prefetch,
            Some(ArtifactStorage::FileDir((tmp_dir.clone(), String::new()))),
            None,
            false,
            Features::new(),
            true,
            Attributes::default(),
        );
        let mut bootstrap_mgr = BootstrapManager::new(
            Some(ArtifactStorage::FileDir((tmp_dir, String::new()))),
            None,
        );
        let mut blob_mgr = BlobManager::new(digest::Algorithm::Sha256, false);
        let mut builder = TarballBuilder::new(ConversionType::TarToTarfs);
        builder
            .build(&mut ctx, &mut bootstrap_mgr, &mut blob_mgr)
            .unwrap();
    }

    // Build a tar holding a regular file, a hardlink to it and two more entries stored after the
    // hardlink, so that an inode written at a wrong offset is observable. `xattr_on` selects
    // which of the two names records an xattr in its own PAX header.
    fn create_xattr_hardlink_tar(path: &Path, xattr_on: &str) {
        let mut tar = tar::Builder::new(File::create(path).unwrap());
        let mut append = |name: &str, entry_type: EntryType, data: &[u8]| {
            if name == xattr_on {
                // A PAX extended header record is "<len> <key>=<value>\n", where <len> counts
                // the whole record including itself.
                let body = format!(" SCHILY.xattr.user.key={}\n", "v".repeat(600));
                let mut len = body.len() + 1;
                let pax = loop {
                    let pax = format!("{}{}", len, body);
                    if pax.len() == len {
                        break pax;
                    }
                    len = pax.len();
                };
                let mut header = Header::new_ustar();
                header.set_entry_type(EntryType::XHeader);
                header.set_mode(0o644);
                header.set_mtime(0);
                header.set_size(pax.len() as u64);
                tar.append_data(&mut header, "PaxHeaders/entry", pax.as_bytes())
                    .unwrap();
            }
            let mut header = Header::new_gnu();
            header.set_entry_type(entry_type);
            header.set_mode(0o644);
            header.set_mtime(0);
            header.set_size(data.len() as u64);
            if entry_type == EntryType::Link {
                header.set_link_name("foo").unwrap();
            }
            tar.append_data(&mut header, name, data).unwrap();
        };
        append("foo", EntryType::Regular, b"hello");
        append("foo-link", EntryType::Link, b"");
        append("zzz1", EntryType::Regular, b"world");
        append("zzz2", EntryType::Regular, b"world");
        tar.finish().unwrap();
    }

    fn build_and_load_xattr_hardlink_tar(
        version: RafsVersion,
        xattr_on: &str,
    ) -> nydus_rafs::metadata::RafsSuper {
        let tmp_dir = vmm_sys_util::tempdir::TempDir::new().unwrap();
        let tmp_dir = tmp_dir.as_path().to_path_buf();
        let source_path = tmp_dir.join("xattr-hardlink.tar");
        let bootstrap_path = tmp_dir.join("bootstrap");
        create_xattr_hardlink_tar(&source_path, xattr_on);

        let mut ctx = BuildContext::new(
            "test".to_string(),
            true,
            0,
            compress::Algorithm::None,
            digest::Algorithm::Sha256,
            true,
            WhiteoutSpec::Oci,
            ConversionType::TarToRafs,
            source_path,
            Prefetch::default(),
            Some(ArtifactStorage::FileDir((tmp_dir, String::new()))),
            None,
            false,
            Features::new(),
            false,
            Attributes::default(),
        );
        ctx.fs_version = version;
        let mut bootstrap_mgr = BootstrapManager::new(
            Some(ArtifactStorage::SingleFile(bootstrap_path.clone())),
            None,
        );
        let mut blob_mgr = BlobManager::new(digest::Algorithm::Sha256, false);
        TarballBuilder::new(ConversionType::TarToRafs)
            .build(&mut ctx, &mut bootstrap_mgr, &mut blob_mgr)
            .unwrap();

        // Loading the bootstrap back is what detects an inode written at a wrong offset.
        nydus_rafs::metadata::RafsSuper::load_from_file(
            &bootstrap_path,
            Arc::new(nydus_api::ConfigV2::default()),
            false,
        )
        .unwrap()
        .0
    }

    fn xattr_count(sb: &nydus_rafs::metadata::RafsSuper, name: &str) -> usize {
        let root = sb.get_inode(sb.superblock.root_ino(), false).unwrap();
        let child = root.get_child_by_name(OsStr::new(name)).unwrap();
        let inode = sb.get_inode(child.ino(), false).unwrap();
        inode.get_xattrs().unwrap().len()
    }

    // A hardlink entry inherits the xattrs of its target, which must be reflected in the inode
    // flags: the RAFS v5 inode table reserves room for the xattr table based on the flag, while
    // the xattr table itself is written whenever the node has xattrs. If the two disagree, every
    // inode after the hardlink is written at the wrong offset and the bootstrap can't be loaded.
    #[test]
    fn test_v5_hardlink_inherits_xattr_flag_from_target() {
        let sb = build_and_load_xattr_hardlink_tar(RafsVersion::V5, "foo");
        // Both names of the hardlink resolve to the inode of the target, which carries the xattr.
        assert_eq!(xattr_count(&sb, "foo"), 1);
        assert_eq!(xattr_count(&sb, "foo-link"), 1);
        // The entries stored after the hardlink must still be readable.
        assert_eq!(xattr_count(&sb, "zzz1"), 0);
        assert_eq!(xattr_count(&sb, "zzz2"), 0);
    }

    // All names of a hardlink share one inode, and for RAFS v6 they share its on-disk region,
    // whose size is reserved from the target. A hardlink entry keeping xattrs of its own would
    // write past that region, leaking them onto the target and corrupting the inodes stored after
    // it, so the xattrs of the target win even when only the hardlink entry recorded any.
    #[test]
    fn test_v6_hardlink_xattrs_stay_identical_to_target() {
        let sb = build_and_load_xattr_hardlink_tar(RafsVersion::V6, "foo-link");
        assert_eq!(xattr_count(&sb, "foo"), 0);
        assert_eq!(xattr_count(&sb, "foo-link"), 0);
        assert_eq!(xattr_count(&sb, "zzz1"), 0);
        assert_eq!(xattr_count(&sb, "zzz2"), 0);
    }
}

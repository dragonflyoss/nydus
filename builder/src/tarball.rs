// Copyright 2022 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Generate RAFS filesystem from a tarball.
//!
//! It support generating RAFS filesystem from a tar/targz/stargz file with or without data blob.
//!
//! The tarball data is arrange as a sequence of tar headers with associated file data interleaved.
//! - (tar header) (tar header) (file data) (tar header) (file data) (tar header)
//! And to support read tarball data from FIFO, we could only go over the tarball stream once.
//! So the workflow is as:
//! - for each tar header from the stream
//! -- generate RAFS filesystem node from the tar header
//! -- optionally dump file data associated with the tar header into RAFS data blob
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
        let mode = Self::get_mode(header)?;
        let (uid, gid) = Self::get_uid_gid(self.ctx, header)?;
        let mtime = header.mtime().unwrap_or_default();
        let mut flags = match self.ctx.fs_version {
            RafsVersion::V5 => RafsInodeFlags::default(),
            RafsVersion::V6 => RafsInodeFlags::default(),
        };

        // Parse special files
        let rdev = if entry_type.is_block_special()
            || entry_type.is_character_special()
            || entry_type.is_fifo()
        {
            let major = header
                .device_major()
                .context("tarball: failed to get device major from tar entry")?
                .ok_or_else(|| anyhow!("tarball: failed to get major device from tar entry"))?;
            let minor = header
                .device_minor()
                .context("tarball: failed to get device major from tar entry")?
                .ok_or_else(|| anyhow!("tarball: failed to get minor device from tar entry"))?;
            makedev(major as u64, minor as u64) as u32
        } else {
            u32::MAX
        };

        // Parse symlink
        let (symlink, symlink_size) = if entry_type.is_symlink() {
            let symlink_link_path = entry
                .link_name()
                .context("tarball: failed to get target path for tar symlink entry")?
                .ok_or_else(|| anyhow!("tarball: failed to get symlink target tor tar entry"))?;
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

        // Handle hardlink ino
        let mut hardlink_target = None;
        let ino = if entry_type.is_hard_link() {
            let link_path = entry
                .link_name()
                .context("tarball: failed to get target path for tar symlink entry")?
                .ok_or_else(|| anyhow!("tarball: failed to get symlink target tor tar entry"))?;
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
            let mut tmp_node = tmp_tree.lock_node();
            if !tmp_node.is_reg() {
                bail!(
                    "tarball: target {} for hardlink {} is not a regular file",
                    link_path.display(),
                    path.display()
                );
            }
            hardlink_target = Some(tmp_tree);
            flags |= RafsInodeFlags::HARDLINK;
            tmp_node.inode.set_has_hardlink(true);
            tmp_node.inode.ino()
        } else {
            self.builder.next_ino()
        };

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
            let n = t.lock_node();
            if n.inode.is_v5() {
                node.inode.set_digest(n.inode.digest().to_owned());
            }
            node.inode.set_size(n.inode.size());
            node.inode.set_child_count(n.inode.child_count());
            node.chunks = n.chunks.clone();
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
            EntryType::Regular | EntryType::Link => libc::S_IFREG,
            EntryType::Directory => libc::S_IFDIR,
            EntryType::Symlink => libc::S_IFLNK,
            EntryType::Block => libc::S_IFBLK,
            EntryType::Char => libc::S_IFCHR,
            EntryType::Fifo => libc::S_IFIFO,
            _ => bail!("tarball: unsupported tar entry type"),
        };
        Ok((mode & !libc::S_IFMT as u32) | ty as u32)
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
        let mut node = tree.lock_node();
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
    use crate::{ArtifactStorage, Features, Prefetch, WhiteoutSpec};
    use nydus_utils::{compress, digest};

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
            Some(ArtifactStorage::FileDir(tmp_dir.clone())),
            false,
            Features::new(),
            false,
        );
        let mut bootstrap_mgr =
            BootstrapManager::new(Some(ArtifactStorage::FileDir(tmp_dir)), None);
        let mut blob_mgr = BlobManager::new(digest::Algorithm::Sha256);
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
            Some(ArtifactStorage::FileDir(tmp_dir.clone())),
            false,
            Features::new(),
            true,
        );
        let mut bootstrap_mgr =
            BootstrapManager::new(Some(ArtifactStorage::FileDir(tmp_dir)), None);
        let mut blob_mgr = BlobManager::new(digest::Algorithm::Sha256);
        let mut builder = TarballBuilder::new(ConversionType::TarToTarfs);
        builder
            .build(&mut ctx, &mut bootstrap_mgr, &mut blob_mgr)
            .unwrap();
    }
}

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
use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::fs::{File, OpenOptions};
use std::io::{BufReader, Read};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{Context, Result};
use tar::{Archive, Entry, EntryType, Header};

use nydus_rafs::metadata::inode::InodeWrapper;
use nydus_rafs::metadata::layout::v5::{RafsV5Inode, RafsV5InodeFlags};
use nydus_rafs::metadata::layout::RafsXAttrs;
use nydus_rafs::metadata::{Inode, RafsVersion};
use nydus_storage::device::BlobFeatures;
use nydus_storage::meta::ZranContextGenerator;
use nydus_storage::RAFS_MAX_CHUNKS_PER_BLOB;
use nydus_utils::compact::makedev;
use nydus_utils::compress::zlib_random::{ZranReader, ZRAN_READER_BUF_SIZE};
use nydus_utils::compress::ZlibDecoder;
use nydus_utils::digest::RafsDigest;
use nydus_utils::{div_round_up, BufReaderInfo, ByteSize};

use crate::builder::{build_bootstrap, dump_bootstrap, finalize_blob, Builder};
use crate::core::blob::Blob;
use crate::core::context::{
    ArtifactWriter, BlobManager, BootstrapManager, BuildContext, BuildOutput, ConversionType,
};
use crate::core::node::{Node, Overlay};
use crate::core::tree::Tree;

enum TarReader {
    File(File),
    Buf(BufReaderInfo<File>),
    TarGz(Box<ZlibDecoder<File>>),
    Zran(ZranReader<File>),
}

impl Read for TarReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            TarReader::File(f) => f.read(buf),
            TarReader::Buf(b) => b.read(buf),
            TarReader::TarGz(f) => f.read(buf),
            TarReader::Zran(f) => f.read(buf),
        }
    }
}

pub(crate) struct TarballTreeBuilder<'a> {
    ty: ConversionType,
    layer_idx: u16,
    ctx: &'a mut BuildContext,
    blob_mgr: &'a mut BlobManager,
    blob_writer: &'a mut ArtifactWriter,
    buf: Vec<u8>,
    path_inode_map: HashMap<PathBuf, (Inode, usize)>,
}

impl<'a> TarballTreeBuilder<'a> {
    /// Create a new instance of `TarballBuilder`.
    pub fn new(
        ty: ConversionType,
        ctx: &'a mut BuildContext,
        blob_mgr: &'a mut BlobManager,
        blob_writer: &'a mut ArtifactWriter,
        layer_idx: u16,
    ) -> Self {
        Self {
            ty,
            layer_idx,
            ctx,
            blob_mgr,
            buf: Vec::new(),
            blob_writer,
            path_inode_map: HashMap::new(),
        }
    }

    fn build_tree(&mut self) -> Result<Tree> {
        let file = OpenOptions::new()
            .read(true)
            .open(self.ctx.source_path.clone())
            .with_context(|| "can not open source file for conversion")?;

        let reader = match self.ty {
            ConversionType::TarToRafs => TarReader::File(file),
            ConversionType::EStargzToRafs | ConversionType::TargzToRafs => {
                TarReader::TarGz(Box::new(ZlibDecoder::new(file)))
            }
            ConversionType::EStargzToRef | ConversionType::TargzToRef => {
                // Use 64K buffer to keep consistence with zlib-random.
                let mut buf_reader = BufReader::with_capacity(ZRAN_READER_BUF_SIZE, file);
                let mut buf = [0u8; 3];
                if buf_reader.read_exact(&mut buf).is_ok()
                    && buf[0] == 0x1f
                    && buf[1] == 0x8b
                    && buf[2] == 0x08
                {
                    buf_reader.seek_relative(-3).unwrap();
                    let generator = ZranContextGenerator::from_buf_reader(buf_reader)?;
                    let reader = generator.reader();
                    self.ctx.blob_zran_generator = Some(Mutex::new(generator));
                    self.ctx.blob_features.insert(BlobFeatures::ZRAN);
                    TarReader::Zran(reader)
                } else {
                    buf_reader.seek_relative(-3).unwrap();
                    self.ty = ConversionType::TarToRef;
                    let reader = BufReaderInfo::from_buf_reader(buf_reader);
                    self.ctx.blob_tar_reader = Some(reader.clone());
                    TarReader::Buf(reader)
                }
            }
            ConversionType::TarToRef => {
                let reader = BufReaderInfo::from_buf_reader(BufReader::new(file));
                self.ctx.blob_tar_reader = Some(reader.clone());
                TarReader::Buf(reader)
            }
            _ => return Err(anyhow!("unsupported image conversion type")),
        };
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
        let mut nodes = Vec::with_capacity(10240);
        let root = self.create_directory(Path::new("/"), &nodes)?;
        nodes.push(root.clone());

        // Generate RAFS node for each tar entry, and optionally adding missing parents.
        let entries = tar
            .entries()
            .with_context(|| "failed to read entries from tar")?;
        for entry in entries {
            let mut entry = entry.with_context(|| "failed to read entry from tar")?;
            let path = entry
                .path()
                .with_context(|| "failed to to get path from tar entry")?;
            let path = PathBuf::from("/").join(path);
            let path = path.components().as_path();
            if !self.is_special_files(path) {
                self.make_lost_dirs(&path, &mut nodes)?;
                let node = self.parse_entry(&nodes, &mut entry, path)?;
                nodes.push(node);
            }
        }

        // Convert generated RAFS nodes into a tree.
        let mut tree = Tree::new(root);
        for node in nodes {
            assert!(tree.apply(&node, false, self.ctx.whiteout_spec)?);
        }

        // Update directory size for RAFS V5 after generating the tree.
        if self.ctx.fs_version.is_v5() {
            Self::set_v5_dir_size(&mut tree);
        }

        Ok(tree)
    }

    fn parse_entry<R: Read, P: AsRef<Path>>(
        &mut self,
        nodes: &[Node],
        entry: &mut Entry<R>,
        path: P,
    ) -> Result<Node> {
        let header = entry.header();
        let entry_type = header.entry_type();
        assert!(!entry_type.is_gnu_longname());
        assert!(!entry_type.is_gnu_longlink());
        assert!(!entry_type.is_pax_local_extensions());
        if entry_type.is_pax_global_extensions() {
            return Err(anyhow!("unsupported pax_global_extensions from tar header"));
        } else if entry_type.is_contiguous() {
            return Err(anyhow!("unsupported contiguous entry type from tar header"));
        } else if entry_type.is_gnu_sparse() {
            return Err(anyhow!(
                "unsupported gnu sparse file extension from tar header"
            ));
        }

        let mut file_size = entry.size();
        let name = Self::get_file_name(path.as_ref())?;
        let mode = Self::get_mode(header)?;
        let (uid, gid) = Self::get_uid_gid(self.ctx, header)?;
        let mtime = header.mtime().unwrap_or_default();
        let mut flags = match self.ctx.fs_version {
            RafsVersion::V5 => RafsV5InodeFlags::default(),
            RafsVersion::V6 => RafsV5InodeFlags::default(),
        };

        // Parse special files
        let rdev = if entry_type.is_block_special()
            || entry_type.is_character_special()
            || entry_type.is_fifo()
        {
            let major = header
                .device_major()
                .with_context(|| "failed to get device major from tar entry")?
                .ok_or_else(|| anyhow!("failed to get major device from tar entry"))?;
            let minor = header
                .device_minor()
                .with_context(|| "failed to get device major from tar entry")?
                .ok_or_else(|| anyhow!("failed to get minor device from tar entry"))?;
            makedev(major as u64, minor as u64) as u32
        } else {
            u32::MAX
        };

        // Parse symlink
        let (symlink, symlink_size) = if entry_type.is_symlink() {
            let symlink_link_path = entry
                .link_name()
                .with_context(|| "failed to get target path for tar symlink entry")?
                .ok_or_else(|| anyhow!("failed to get symlink target tor tar entry"))?;
            let symlink_size = symlink_link_path.as_os_str().byte_size();
            if symlink_size > u16::MAX as usize {
                bail!("symlink target from tar entry is too big");
            }
            file_size = symlink_size as u64;
            flags |= RafsV5InodeFlags::SYMLINK;
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
                bail!("file size 0x{:x} is too big", file_size);
            }
        }

        // Handle hardlink ino
        let mut ino = (self.path_inode_map.len() + 1) as Inode;
        let mut index = 0;
        if entry_type.is_hard_link() {
            let link_path = entry
                .link_name()
                .with_context(|| "failed to get target path for tar symlink entry")?
                .ok_or_else(|| anyhow!("failed to get symlink target tor tar entry"))?;
            let link_path = PathBuf::from("/").join(link_path);
            let link_path = link_path.components().as_path();
            if let Some((_ino, _index)) = self.path_inode_map.get(link_path) {
                ino = *_ino;
                index = *_index;
            } else {
                bail!(
                    "unknown target {} for hardlink {}",
                    link_path.display(),
                    path.as_ref().display()
                );
            }
            flags |= RafsV5InodeFlags::HARDLINK;
        } else {
            self.path_inode_map
                .insert(path.as_ref().to_path_buf(), (ino, nodes.len()));
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
                            "failed to parse PaxExtension from tar header, {}",
                            e
                        ))
                    }
                }
            }
        }

        let v5_inode = RafsV5Inode {
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
        };
        let mut inode = match self.ctx.fs_version {
            RafsVersion::V5 => InodeWrapper::V5(v5_inode),
            RafsVersion::V6 => InodeWrapper::V6(v5_inode),
        };
        inode.set_has_xattr(!xattrs.is_empty());

        let source = PathBuf::from("/");
        let target = Node::generate_target(path.as_ref(), &source);
        let target_vec = Node::generate_target_vec(&target);
        let mut node = Node {
            index: 0,
            src_ino: ino,
            src_dev: u64::MAX,
            rdev: rdev as u64,
            overlay: Overlay::UpperAddition,
            explicit_uidgid: self.ctx.explicit_uidgid,
            path: path.as_ref().to_path_buf(),
            source,
            target,
            target_vec,
            inode,
            chunks: Vec::new(),
            symlink,
            xattrs,
            layer_idx: self.layer_idx,
            ctime: 0,
            v6_offset: 0,
            v6_dirents: Vec::<(u64, OsString, u32)>::new(),
            v6_datalayout: 0,
            v6_compact_inode: false,
            v6_force_extended_inode: false,
            v6_dirents_offset: 0,
        };

        // Special handling of hardlink.
        // Tar hardlink header has zero file size and no file data associated, so copy value from
        // the associated regular file.
        if entry_type.is_hard_link() {
            let n = &nodes[index];
            node.inode.set_digest(*n.inode.digest());
            node.inode.set_size(n.inode.size());
            node.inode.set_child_count(n.inode.child_count());
            node.chunks = n.chunks.clone();
            node.xattrs = n.xattrs.clone();
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
        if !entry_type.is_dir() {
            node.set_inode_blocks();
        }

        Ok(node)
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
                "uid {:x} or gid {:x} from tar entry is out of range",
                uid,
                gid
            );
        }

        Ok((uid as u32, gid as u32))
    }

    fn get_mode(header: &Header) -> Result<u32> {
        let mode = header
            .mode()
            .with_context(|| "failed to get permission/mode from tar entry")?;
        let ty = match header.entry_type() {
            EntryType::Regular | EntryType::Link => libc::S_IFREG,
            EntryType::Directory => libc::S_IFDIR,
            EntryType::Symlink => libc::S_IFLNK,
            EntryType::Block => libc::S_IFBLK,
            EntryType::Char => libc::S_IFCHR,
            EntryType::Fifo => libc::S_IFIFO,
            _ => bail!("unsupported tar entry type"),
        };
        Ok((mode & !libc::S_IFMT as u32) | ty as u32)
    }

    fn get_file_name(path: &Path) -> Result<&OsStr> {
        let name = if path == Path::new("/") {
            path.as_os_str()
        } else {
            path.file_name().ok_or_else(|| {
                anyhow!(
                    "failed to get file name from tar entry with path {}",
                    path.display()
                )
            })?
        };
        if name.len() > u16::MAX as usize {
            bail!(
                "file name {} from tar entry is too long",
                name.to_str().unwrap_or_default()
            );
        }
        Ok(name)
    }

    fn make_lost_dirs<P: AsRef<Path>>(&mut self, path: P, nodes: &mut Vec<Node>) -> Result<()> {
        if let Some(parent_path) = path.as_ref().parent() {
            if !self.path_inode_map.contains_key(parent_path) {
                self.make_lost_dirs(parent_path, nodes)?;
                let node = self.create_directory(parent_path, nodes)?;
                nodes.push(node);
            }
        }

        Ok(())
    }

    fn create_directory(&mut self, path: &Path, nodes: &[Node]) -> Result<Node> {
        let ino = (self.path_inode_map.len() + 1) as Inode;
        let name = Self::get_file_name(path)?;
        let mut inode = InodeWrapper::new(self.ctx.fs_version);
        inode.set_ino(ino);
        inode.set_mode(0o755 | libc::S_IFDIR as u32);
        inode.set_nlink(2);
        inode.set_name_size(name.len());
        inode.set_rdev(u32::MAX);

        let source = PathBuf::from("/");
        let target = Node::generate_target(path, &source);
        let target_vec = Node::generate_target_vec(&target);
        let node = Node {
            index: 0,
            src_ino: ino,
            src_dev: u64::MAX,
            rdev: u64::MAX,
            overlay: Overlay::UpperAddition,
            explicit_uidgid: self.ctx.explicit_uidgid,
            path: path.to_path_buf(),
            source,
            target,
            target_vec,
            inode,
            chunks: Vec::new(),
            symlink: None,
            xattrs: RafsXAttrs::new(),
            layer_idx: self.layer_idx,
            ctime: 0,
            v6_offset: 0,
            v6_dirents: Vec::<(u64, OsString, u32)>::new(),
            v6_datalayout: 0,
            v6_compact_inode: false,
            v6_force_extended_inode: false,
            v6_dirents_offset: 0,
        };

        self.path_inode_map
            .insert(path.to_path_buf(), (ino, nodes.len()));

        Ok(node)
    }

    fn set_v5_dir_size(tree: &mut Tree) {
        for c in &mut tree.children {
            Self::set_v5_dir_size(c);
        }
        tree.node.v5_set_dir_size(RafsVersion::V5, &tree.children);
    }

    // Filter out special files of estargz.
    //
    // TOC MUST be a JSON file contained as the last tar entry and MUST be named stargz.index.json.
    //
    // The Landmark file MUST be a regular file entry with 4 bits contents 0xf in eStargz.
    // It MUST be recorded to TOC as a TOCEntry. Prefetch landmark MUST be named .prefetch.landmark.
    // No-prefetch landmark MUST be named .no.prefetch.landmark.
    // TODO: check "a regular file entry with 4 bits contents 0xf"
    fn is_special_files(&self, path: &Path) -> bool {
        (self.ty == ConversionType::EStargzToRafs || self.ty == ConversionType::EStargzToRef)
            && (path == Path::new("/stargz.index.json")
                || path == Path::new("/.prefetch.landmark")
                || path == Path::new("/.no.prefetch.landmark"))
    }
}

pub(crate) struct TarballBuilder {
    ty: ConversionType,
}

impl TarballBuilder {
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
        let mut bootstrap_ctx = bootstrap_mgr.create_ctx(ctx.blob_inline_meta)?;
        let layer_idx = u16::from(bootstrap_ctx.layered);
        let mut blob_writer = match self.ty {
            ConversionType::EStargzToRafs
            | ConversionType::TargzToRafs
            | ConversionType::TarToRafs
            | ConversionType::EStargzToRef
            | ConversionType::TargzToRef => {
                if let Some(blob_stor) = ctx.blob_storage.clone() {
                    ArtifactWriter::new(blob_stor, ctx.blob_inline_meta)?
                } else {
                    return Err(anyhow!("missing configuration for target path"));
                }
            }
            _ => return Err(anyhow!("unsupported image conversion type '{}'", self.ty)),
        };

        let mut tree_builder =
            TarballTreeBuilder::new(self.ty, ctx, blob_mgr, &mut blob_writer, layer_idx);
        let tree = timing_tracer!({ tree_builder.build_tree() }, "build_tree")?;

        // Build bootstrap
        let mut bootstrap = timing_tracer!(
            { build_bootstrap(ctx, bootstrap_mgr, &mut bootstrap_ctx, blob_mgr, tree) },
            "build_bootstrap"
        )?;

        // Dump blob file
        timing_tracer!(
            { Blob::dump(ctx, &mut bootstrap_ctx.nodes, blob_mgr, &mut blob_writer) },
            "dump_blob"
        )?;

        // Dump blob meta information
        if let Some((_, blob_ctx)) = blob_mgr.get_current_blob() {
            Blob::dump_meta_data(ctx, blob_ctx, &mut blob_writer)?;
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
                        &mut blob_writer,
                    )
                },
                "dump_bootstrap"
            )?;
            finalize_blob(ctx, blob_mgr, &mut blob_writer)?;
        } else {
            finalize_blob(ctx, blob_mgr, &mut blob_writer)?;
            timing_tracer!(
                {
                    dump_bootstrap(
                        ctx,
                        bootstrap_mgr,
                        &mut bootstrap_ctx,
                        &mut bootstrap,
                        blob_mgr,
                        &mut blob_writer,
                    )
                },
                "dump_bootstrap"
            )?;
        }

        BuildOutput::new(blob_mgr, &bootstrap_mgr.bootstrap_storage)
    }
}

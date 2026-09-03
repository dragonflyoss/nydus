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
use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::fs::{File, OpenOptions};
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{anyhow, bail, Context, Result};
use tar::{Archive, Entry, EntryType, Header, PaxExtensions};

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

/// Key/value pairs of a PAX extended header, framed by the leading length of each record.
type PaxRecords = Vec<(Vec<u8>, Vec<u8>)>;

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
    pax_bodies: Option<HashMap<u64, Vec<u8>>>,
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
            pax_bodies: None,
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
            let pax = self.pax_records(&mut entry)?;
            let path = Self::entry_path(&entry, pax.as_ref())?;
            let path = PathBuf::from("/").join(path);
            let path = path.components().as_path();
            if !self.builder.is_stargz_special_files(path) {
                self.parse_entry(&mut tree, &mut entry, path, pax.as_ref())?;
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
        pax: Option<&PaxRecords>,
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
        let (mut uid, mut gid) = Self::get_uid_gid(self.ctx, header, pax)?;
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
            let symlink_link_path = Self::get_link_name(entry, pax)
                .context("tarball: failed to get target path for tar symlink entry")?
                .ok_or_else(|| anyhow!("tarball: failed to get symlink target for tar entry"))?;
            let symlink_size = symlink_link_path.byte_size();
            if symlink_size > u16::MAX as usize {
                bail!("tarball: symlink target from tar entry is too big");
            }
            file_size = symlink_size as u64;
            flags |= RafsInodeFlags::SYMLINK;
            (Some(symlink_link_path), symlink_size as u16)
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
        let prefix = b"SCHILY.xattr.";
        match pax {
            Some(records) => {
                for (key, value) in records {
                    if key.starts_with(prefix) {
                        let x_key = OsStr::from_bytes(&key[prefix.len()..]);
                        xattrs.add(x_key.to_os_string(), value.clone())?;
                    }
                }
            }
            None => {
                if let Some(exts) = entry.pax_extensions()? {
                    for p in exts {
                        // `pax_records()` returns the records of a header the crate cannot read,
                        // so anything left here parses.
                        let p =
                            p.context("tarball: failed to parse PaxExtension from tar header")?;
                        let key = p.key_bytes();
                        if key.starts_with(prefix) {
                            let x_key = OsStr::from_bytes(&key[prefix.len()..]);
                            xattrs.add(x_key.to_os_string(), p.value_bytes().to_vec())?;
                        }
                    }
                }
            }
        }

        // Handle hardlink ino
        let mut hardlink_target = None;
        let ino = if entry_type.is_hard_link() {
            let link_path = Self::get_link_name(entry, pax)
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

    // A PAX extended header holds records framed as "<len> <key>=<value>\n", where <len> counts
    // the whole record including itself. That framing is what lets a value hold arbitrary bytes,
    // newlines included — a symlink to a Git LFS pointer or to an npm shim script is one.
    //
    // tar 0.4.45 splits the body on newlines before honouring <len>, so every record of such a
    // header comes back as an error, and the tail of the value comes back framed as a record of
    // its own. `Entry::path()` and `Entry::link_name()` skip the errors and take that fragment,
    // so a value holding "\n22 linkpath=/etc/evil\n" makes them report /etc/evil while a reader
    // walking the records by their length sees no `linkpath` at all. Nothing the crate returns
    // for such a header can be used, so read the records off the body here instead.
    //
    // Returns `None` when the entry has no PAX extended header, or when the crate read it, in
    // which case both agree and the caller keeps using the crate.
    fn pax_records<R: Read>(&mut self, entry: &mut Entry<R>) -> Result<Option<PaxRecords>> {
        // A global header describes every entry after it rather than one, and is unsupported.
        if entry.header().entry_type().is_pax_global_extensions() {
            return Ok(None);
        }
        // `PaxExtensions` ends its iteration on an empty line rather than reporting one, so a
        // body which opens with a newline reads as a header holding no records at all, and a
        // header always holds at least one.
        let (mut records, mut failed) = (0, false);
        match entry.pax_extensions()? {
            None => return Ok(None),
            Some(exts) => {
                for record in exts {
                    records += 1;
                    failed |= record.is_err();
                }
            }
        }
        if records > 0 && !failed {
            return Ok(None);
        }

        let header_pos = entry.raw_header_position();
        let name = String::from_utf8_lossy(&entry.header().path_bytes()).into_owned();
        let body = self.pax_body(header_pos)?.ok_or_else(|| {
            anyhow!(
                "tarball: failed to parse the PAX extended header of {}, and no header was found \
                 at offset {} of {} to read it back from",
                name,
                header_pos,
                self.ctx.source_path.display()
            )
        })?;
        let records = Self::parse_pax_body(&body).with_context(|| {
            format!(
                "tarball: failed to parse the PAX extended header of {}",
                name
            )
        })?;

        Ok(Some(records))
    }

    // The body of the PAX extended header describing the entry whose own header sits at
    // `header_pos`. The crate keeps no handle on the bodies it fails to read, so they are
    // collected in a pass of their own, over a second handle on the source.
    fn pax_body(&mut self, header_pos: u64) -> Result<Option<Vec<u8>>> {
        if self.pax_bodies.is_none() {
            let bodies = self.collect_pax_bodies()?;
            self.pax_bodies = Some(bodies);
        }
        Ok(self.pax_bodies.as_ref().unwrap().get(&header_pos).cloned())
    }

    // Walk the tarball for the PAX extended headers the crate cannot read, keyed by the offset of
    // the header of the entry each one describes. Raw iteration hands over the headers the crate
    // would otherwise consume on its own, so the tar framing stays the crate's to do.
    fn collect_pax_bodies(&self) -> Result<HashMap<u64, Vec<u8>>> {
        let file = OpenOptions::new()
            .read(true)
            .open(&self.ctx.source_path)
            .context("tarball: can not reopen source file to read a PAX extended header")?;
        if !file.metadata()?.file_type().is_file() {
            bail!(
                "tarball: can not read a PAX extended header back from {}, which is not a regular \
                 file",
                self.ctx.source_path.display()
            );
        }
        let reader: Box<dyn Read> = match Self::detect_compression_algo(file)? {
            (CompressionType::Gzip, buf_reader) => Box::new(ZlibDecoder::new(buf_reader)),
            (CompressionType::None, buf_reader) => Box::new(buf_reader),
        };

        let mut tar = Archive::new(reader);
        tar.set_ignore_zeros(true);
        let mut bodies = HashMap::new();
        let mut body: Option<Vec<u8>> = None;
        for entry in tar.entries()?.raw(true) {
            // Raw iteration frames every entry by the size in its own tar header, where the pass
            // the crate runs applies a PAX `size` record over it, and adds a block for a GNU
            // sparse header. Either puts this pass out of step with the stream, so stop at the
            // first sign of one and let the caller report the header it could not read back.
            let mut entry = match entry {
                Ok(entry) => entry,
                Err(_) => break,
            };
            let entry_type = entry.header().entry_type();
            if entry_type.is_pax_local_extensions() {
                let mut read = Vec::new();
                if entry.read_to_end(&mut read).is_err() {
                    break;
                }
                if Self::pax_body_holds(&read, b"size") {
                    break;
                }
                if !Self::tar_reads_pax_body(&read) {
                    body = Some(read);
                }
            } else if !entry_type.is_gnu_longname() && !entry_type.is_gnu_longlink() {
                // A GNU long name or long link sits between a PAX extended header and the entry
                // both describe, and is not that entry.
                if let Some(body) = body.take() {
                    bodies.insert(entry.raw_header_position(), body);
                }
            }
        }

        Ok(bodies)
    }

    // Whether the records tar reports for `body` are the records `body` holds. A header holding
    // no records reads as one tar cannot read, since that is what an unreadable one looks like
    // to `pax_records()` as well.
    fn tar_reads_pax_body(body: &[u8]) -> bool {
        let walked = match Self::parse_pax_body(body) {
            Ok(walked) if !walked.is_empty() => walked,
            _ => return false,
        };
        let mut split = PaxExtensions::new(body);
        for (key, value) in &walked {
            match split.next() {
                Some(Ok(record)) => {
                    if record.key_bytes() != key || record.value_bytes() != value {
                        return false;
                    }
                }
                _ => return false,
            }
        }

        split.next().is_none()
    }

    fn pax_body_holds(body: &[u8], key: &[u8]) -> bool {
        match Self::parse_pax_body(body) {
            Ok(records) => Self::pax_value(&records, key).is_some(),
            Err(_) => false,
        }
    }

    fn parse_pax_body(body: &[u8]) -> Result<PaxRecords> {
        let mut records = Vec::new();
        let mut rest = body;
        while !rest.is_empty() {
            let space = rest
                .iter()
                .position(|b| *b == b' ')
                .ok_or_else(|| anyhow!("record {} carries no length", records.len()))?;
            let len: usize = std::str::from_utf8(&rest[..space])
                .ok()
                .and_then(|len| len.parse().ok())
                .ok_or_else(|| anyhow!("record {} carries no length", records.len()))?;
            if len <= space + 1 || len > rest.len() || rest[len - 1] != b'\n' {
                bail!("record {} reports a length of {}", records.len(), len);
            }
            let record = &rest[space + 1..len - 1];
            let equals = record
                .iter()
                .position(|b| *b == b'=')
                .ok_or_else(|| anyhow!("record {} carries no key", records.len()))?;
            records.push((record[..equals].to_vec(), record[equals + 1..].to_vec()));
            rest = &rest[len..];
        }

        Ok(records)
    }

    // POSIX, GNU tar and Go's `archive/tar` all let the last record carrying a key win.
    fn pax_value<'r>(records: &'r PaxRecords, key: &[u8]) -> Option<&'r [u8]> {
        records
            .iter()
            .rev()
            .find(|(k, _)| k == key)
            .map(|(_, value)| value.as_slice())
    }

    fn pax_number(pax: Option<&PaxRecords>, key: &[u8]) -> Result<Option<u64>> {
        let value = match pax.and_then(|records| Self::pax_value(records, key)) {
            Some(value) => value,
            None => return Ok(None),
        };
        std::str::from_utf8(value)
            .ok()
            .and_then(|value| value.parse().ok())
            .map(Some)
            .ok_or_else(|| {
                anyhow!(
                    "tarball: PAX record {}={} from tar header is not a number",
                    String::from_utf8_lossy(key),
                    String::from_utf8_lossy(value)
                )
            })
    }

    fn entry_path<R: Read>(entry: &Entry<R>, pax: Option<&PaxRecords>) -> Result<PathBuf> {
        let records = match pax {
            None => {
                return Ok(entry
                    .path()
                    .context("tarball: failed to to get path from tar entry")?
                    .into_owned())
            }
            Some(records) => records,
        };
        Ok(match Self::pax_value(records, b"path") {
            Some(path) => PathBuf::from(OsStr::from_bytes(path)),
            None => PathBuf::from(OsStr::from_bytes(&entry.header().path_bytes())),
        })
    }

    fn get_link_name<R: Read>(
        entry: &Entry<R>,
        pax: Option<&PaxRecords>,
    ) -> Result<Option<OsString>> {
        let records = match pax {
            None => return Ok(entry.link_name()?.map(|name| name.as_os_str().to_owned())),
            Some(records) => records,
        };
        Ok(match Self::pax_value(records, b"linkpath") {
            Some(name) => Some(OsStr::from_bytes(name).to_owned()),
            None => entry
                .header()
                .link_name_bytes()
                .map(|name| OsStr::from_bytes(&name).to_owned()),
        })
    }

    fn get_uid_gid(
        ctx: &BuildContext,
        header: &Header,
        pax: Option<&PaxRecords>,
    ) -> Result<(u32, u32)> {
        // tar applies the `uid` and `gid` records to the header itself, but drops every record of
        // a header it cannot read, so a recovered one carries them here instead.
        let uid = if ctx.explicit_uidgid {
            match Self::pax_number(pax, b"uid")? {
                Some(uid) => uid,
                None => header.uid().unwrap_or_default(),
            }
        } else {
            0
        };
        let gid = if ctx.explicit_uidgid {
            match Self::pax_number(pax, b"gid")? {
                Some(gid) => gid,
                None => header.gid().unwrap_or_default(),
            }
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

    // Append a PAX extended header holding `body` verbatim, so that a record the tar crate writes
    // correctly can be framed on purpose.
    fn append_pax_header(tar: &mut tar::Builder<File>, name: &str, body: &str) {
        let mut header = Header::new_ustar();
        header.set_entry_type(EntryType::XHeader);
        header.set_mode(0o644);
        header.set_mtime(0);
        header.set_size(body.len() as u64);
        tar.append_data(&mut header, format!("PaxHeaders/{}", name), body.as_bytes())
            .unwrap();
    }

    // Frame `record` as "%d %s", where the leading decimal counts the whole record including the
    // digits of the count itself. That is self-referential, so widening the count can widen the
    // record: settle it by feeding the framed length back until it stops growing.
    fn pax_record(record: &str) -> String {
        let mut len = record.len() + 1;
        loop {
            let framed = format!("{} {}", len, record);
            if framed.len() == len {
                return framed;
            }
            len = framed.len();
        }
    }

    // Append a symlink whose ustar header carries `truncated` as its name and its target, the way
    // a writer truncates both to the 100 bytes the header holds, and `body` as the PAX extended
    // header holding what they really are.
    fn append_pax_symlink(tar: &mut tar::Builder<File>, truncated: &str, body: &str) {
        append_pax_header(tar, "entry", body);
        let mut header = Header::new_ustar();
        header.set_entry_type(EntryType::Symlink);
        header.set_mode(0o777);
        header.set_mtime(0);
        header.set_size(0);
        header.set_link_name(truncated).unwrap();
        tar.append_data(&mut header, truncated, &[][..]).unwrap();
    }

    // The Git LFS pointer shape: the target of the symlink is a three line file, which is legal —
    // the leading length of a PAX record is what makes it legal — and which tar 0.4.45 reports as
    // malformed, dropping the `path` and `linkpath` of the entry with it.
    fn test_pax_record_containing_newline(version: RafsVersion) {
        let tmp_dir = vmm_sys_util::tempdir::TempDir::new().unwrap();
        let source_path = tmp_dir.as_path().join("newline-pax.tar");
        let mut tar = tar::Builder::new(File::create(&source_path).unwrap());
        let target = "version https://git-lfs.github.com/spec/v1\n\
                      oid sha256:493670e9619d3060a3a1d3a792d0f8a55f171b047a0496b78c51287e0b253ef3\n\
                      size 31";
        let path = format!("{}/map-overlay.png", "public".repeat(20));
        assert!(target.len() > 100 && path.len() > 100);
        let body = pax_record(&format!("path={}\n", path))
            + &pax_record(&format!("linkpath={}\n", target))
            + &pax_record("SCHILY.xattr.user.key=value\n");
        append_pax_symlink(&mut tar, &path[..99], &body);
        tar.finish().unwrap();

        let mut ctx = create_context(source_path, version);
        let bootstrap = build_rafs(&mut ctx);

        // Both the name and the target come from the records, not from the 100 bytes the ustar
        // header holds, so neither is silently truncated.
        let node = get_node(&bootstrap, &format!("/{}", path));
        assert!(node.is_symlink());
        assert_eq!(node.info.symlink, Some(OsString::from(target)));
        assert_eq!(node.inode.symlink_size() as usize, target.len());
        assert_eq!(node.inode.size() as usize, target.len());
        // Records the build does read must survive the ones it does not.
        assert_eq!(
            node.info.xattrs.get(&OsString::from("user.key")),
            Some(&b"value".to_vec())
        );
        assert!(node.inode.has_xattr());
    }

    #[test]
    fn test_v5_pax_record_containing_newline() {
        test_pax_record_containing_newline(RafsVersion::V5);
    }

    #[test]
    fn test_v6_pax_record_containing_newline() {
        test_pax_record_containing_newline(RafsVersion::V6);
    }

    // Why the records may not be read off the crate: `22 linkpath=/etc/evil` lives inside the
    // value of user.a, yet splitting the body on newlines frames it as a record of its own, and
    // `Entry::link_name()` reports it over the `harmless` in the ustar header. Walking the
    // records by their length sees the value whole and no `linkpath` at all, as Go's
    // `archive/tar` does, so the image keeps agreeing with the layer it was built from.
    #[test]
    fn test_pax_record_smuggled_inside_a_value_cannot_reach_the_image() {
        let tmp_dir = vmm_sys_util::tempdir::TempDir::new().unwrap();
        let source_path = tmp_dir.as_path().join("smuggled-pax.tar");
        let mut tar = tar::Builder::new(File::create(&source_path).unwrap());
        let value = format!("AAA\n{}", pax_record("linkpath=/etc/evil\n"));
        let body = pax_record(&format!("SCHILY.xattr.user.a={}\n", value));
        append_pax_symlink(&mut tar, "harmless", &body);
        tar.finish().unwrap();

        let mut ctx = create_context(source_path, RafsVersion::V6);
        let bootstrap = build_rafs(&mut ctx);

        let node = get_node(&bootstrap, "/harmless");
        assert_eq!(node.info.symlink, Some(OsString::from("harmless")));
        assert_eq!(
            node.info.xattrs.get(&OsString::from("user.a")),
            Some(&value.as_bytes().to_vec())
        );
    }

    // POSIX, GNU tar and Go's `archive/tar` all let the last record carrying a key win, so
    // reading the first would build a node no other reader of the tarball agrees with.
    #[test]
    fn test_pax_duplicate_record_takes_the_last() {
        let tmp_dir = vmm_sys_util::tempdir::TempDir::new().unwrap();
        let source_path = tmp_dir.as_path().join("duplicate-pax.tar");
        let mut tar = tar::Builder::new(File::create(&source_path).unwrap());
        let body = pax_record("SCHILY.xattr.user.a=A\nB\n")
            + &pax_record("linkpath=first\n")
            + &pax_record("linkpath=second\n");
        append_pax_symlink(&mut tar, "harmless", &body);
        tar.finish().unwrap();

        let mut ctx = create_context(source_path, RafsVersion::V6);
        let bootstrap = build_rafs(&mut ctx);

        let node = get_node(&bootstrap, "/harmless");
        assert_eq!(node.info.symlink, Some(OsString::from("second")));
    }

    // `PaxExtensions` ends its iteration on an empty line rather than reporting one, so a body
    // opening with a newline reads as a header holding no records: every record of it would be
    // dropped, and the entry would be built from the 100 bytes of its tar header.
    #[test]
    fn test_pax_body_opening_with_an_empty_line_is_rejected() {
        let tmp_dir = vmm_sys_util::tempdir::TempDir::new().unwrap();
        let source_path = tmp_dir.as_path().join("empty-line-pax.tar");
        let mut tar = tar::Builder::new(File::create(&source_path).unwrap());
        append_pax_symlink(
            &mut tar,
            "trunc",
            &format!("\n{}", pax_record("path=evil\n")),
        );
        tar.finish().unwrap();

        let mut ctx = create_context(source_path, RafsVersion::V6);
        let err = format!("{:#}", build_tree(&mut ctx).err().unwrap());
        assert!(err.contains("PAX extended header of trunc"), "{}", err);
        assert!(err.contains("carries no length"), "{}", err);
    }

    // A `size` record overrides the size in the tar header of an entry, which is how a file of
    // 8GiB or more is written, and the pass collecting the headers frames the stream by the tar
    // header alone. It must stop there rather than read file data as a tar header.
    #[test]
    fn test_pax_size_record_stops_the_collecting_pass() {
        let tmp_dir = vmm_sys_util::tempdir::TempDir::new().unwrap();
        let source_path = tmp_dir.as_path().join("size-pax.tar");
        let mut tar = tar::Builder::new(File::create(&source_path).unwrap());
        // The tar header of `big` reports no data, its PAX header reports 1024 bytes, and 1024
        // bytes follow it.
        append_pax_header(&mut tar, "big", &pax_record("size=1024\n"));
        let mut header = Header::new_ustar();
        header.set_entry_type(EntryType::Regular);
        header.set_mode(0o644);
        header.set_mtime(0);
        header.set_size(0);
        tar.append_data(&mut header, "big", &vec![0u8; 1024][..])
            .unwrap();
        append_pax_symlink(&mut tar, "lfs", &pax_record("linkpath=one\ntwo\n"));
        tar.finish().unwrap();

        let mut ctx = create_context(source_path, RafsVersion::V6);
        let err = format!("{:#}", build_tree(&mut ctx).err().unwrap());
        // The entry which needs a header read back is named, rather than the tar header the
        // collecting pass would have found in the middle of the data of `big`.
        assert!(err.contains("PAX extended header of lfs"), "{}", err);
        assert!(err.contains("read it back from"), "{}", err);
    }

    // Walking the records is what the whole header is read by, so each way the walk can fail
    // must fail rather than resync on a fragment of a value.
    #[test]
    fn test_pax_body_framing_is_rejected() {
        for body in [
            &b"30SCHILY.xattr.user.key=value\n"[..], // no space, so no length
            &b"xx SCHILY.xattr.user.key=value\n"[..], // a length which is not a number
            &b"99 SCHILY.xattr.user.key=value\n"[..], // a length past the end of the body
            &b"30 SCHILY.xattr.user.key=value"[..],  // a record which no newline ends
            &b"11 novalue\n"[..],                    // a record which no key opens
        ] {
            assert!(
                TarballTreeBuilder::parse_pax_body(body).is_err(),
                "{}",
                String::from_utf8_lossy(body)
            );
        }

        let body = b"12 path=one\n22 linkpath=two\nthree\n".to_vec();
        assert_eq!(
            TarballTreeBuilder::parse_pax_body(&body).unwrap(),
            vec![
                (b"path".to_vec(), b"one".to_vec()),
                (b"linkpath".to_vec(), b"two\nthree".to_vec()),
            ]
        );
    }

    // A record whose leading length is not the length of the record leaves nothing to read the
    // rest of the body by, so the entry stays unconvertible rather than becoming a node built
    // from a header nobody can frame.
    #[test]
    fn test_malformed_pax_extension_is_rejected() {
        let tmp_dir = vmm_sys_util::tempdir::TempDir::new().unwrap();
        let source_path = tmp_dir.as_path().join("bad-pax.tar");
        let mut tar = tar::Builder::new(File::create(&source_path).unwrap());
        append_pax_header(&mut tar, "foo", "99 SCHILY.xattr.user.key=value\n");
        append_entry(&mut tar, "foo", EntryType::Regular, None, b"hello");
        tar.finish().unwrap();

        let mut ctx = create_context(source_path, RafsVersion::V6);
        let err = format!("{:#}", build_tree(&mut ctx).err().unwrap());
        // The entry is named, so an unconvertible image can be traced to what makes it one.
        assert!(err.contains("PAX extended header of foo"), "{}", err);
        assert!(err.contains("length of 99"), "{}", err);
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

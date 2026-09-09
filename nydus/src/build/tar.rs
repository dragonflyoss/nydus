//! Streaming OCI layer conversion: consume one gzip/plain tar layer stream in
//! order and chunk regular-file data into the blob the moment it is read — no
//! rootfs is ever staged on disk. Whiteout entries are kept as regular files
//! for `merge` to apply across layers.
//!
//! Directory metadata is kept in a small in-memory tree; when the layer is
//! consumed the tree is flattened through the same [`flatten_tree`] pass as
//! the directory builder, so both sources render identical bootstraps.

use crate::build::blob_chunk::BlobWriter;
use crate::build::inode::{flatten_tree, InodeData, InodeInfo, NamedChildren, NodeAttrs, TreeNode};
use flate2::read::GzDecoder;
use nydus_error::{Context, Error, Result};
use nydus_format::erofs::{erofs_xattr_name_split, ErofsChunkAddr, XattrEntry};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufReader, Read, Write};
use std::path::Path;

const PAX_XATTR_PREFIX: &str = "SCHILY.xattr.";

/// One filesystem object accumulated from the layer streams.
struct TarNode {
    mode: u16,
    uid: u32,
    gid: u32,
    size: u64,
    mtime: u64,
    nlink: u32,
    xattrs: Vec<XattrEntry>,
    /// Hardlink group; nodes sharing a group flatten into a single inode.
    link_group: Option<u32>,
    data: TarNodeData,
}

enum TarNodeData {
    Dir(BTreeMap<Vec<u8>, TarNode>),
    File {
        chunks: Vec<ErofsChunkAddr>,
        chunk_size_bits: u32,
    },
    /// z_erofs LZ4 compressed file: pre-rendered inode tail + block count.
    ZFile {
        tail: Vec<u8>,
        compressed_blocks: u32,
    },
    Symlink {
        target: Vec<u8>,
    },
    Device {
        rdev: u32,
    },
    Fifo,
}

impl TarNode {
    fn implicit_dir() -> Self {
        TarNode {
            mode: 0o040755,
            uid: 0,
            gid: 0,
            size: 0,
            mtime: 0,
            nlink: 1,
            xattrs: Vec::new(),
            link_group: None,
            data: TarNodeData::Dir(BTreeMap::new()),
        }
    }

    fn is_dir(&self) -> bool {
        matches!(self.data, TarNodeData::Dir(_))
    }
}

impl TreeNode<()> for TarNode {
    type LinkKey = u32;

    fn attrs(&mut self) -> Result<NodeAttrs> {
        Ok(NodeAttrs {
            mode: self.mode,
            uid: self.uid,
            gid: self.gid,
            size: self.size,
            mtime: self.mtime,
            mtime_nsec: 0,
            nlink: self.nlink,
            xattrs: std::mem::take(&mut self.xattrs),
        })
    }

    fn link_key(&mut self) -> Result<Option<u32>> {
        Ok(self.link_group)
    }

    fn children(&mut self, _ctx: &mut ()) -> Result<Option<NamedChildren<Self>>> {
        match &mut self.data {
            TarNodeData::Dir(children) => {
                // BTreeMap iterates in name order, matching the sorted-children
                // contract of the flattening pass.
                Ok(Some(std::mem::take(children).into_iter().collect()))
            }
            _ => Ok(None),
        }
    }

    fn leaf_data(&mut self, _ctx: &mut ()) -> Result<InodeData> {
        Ok(match std::mem::replace(&mut self.data, TarNodeData::Fifo) {
            TarNodeData::File {
                chunks,
                chunk_size_bits,
            } => InodeData::RegularFile {
                chunk_index_entries: chunks,
                chunk_size_bits,
            },
            TarNodeData::ZFile {
                tail,
                compressed_blocks,
            } => InodeData::ZFile {
                tail,
                compressed_blocks,
            },
            TarNodeData::Symlink { target } => InodeData::Symlink {
                target,
                startblk: 0,
            },
            TarNodeData::Device { rdev } => InodeData::Device { rdev },
            TarNodeData::Fifo => InodeData::FifoOrSocket,
            TarNodeData::Dir(_) => unreachable!("leaf_data is only called for non-directories"),
        })
    }
}

/// Splits a tar path into normalized components (drops `.`, empty and
/// trailing-slash artifacts).
fn path_components(raw: &[u8]) -> Vec<Vec<u8>> {
    raw.split(|&b| b == b'/')
        .filter(|c| !c.is_empty() && *c != b".")
        .map(|c| c.to_vec())
        .collect()
}

/// Walks (creating implicit directories) down to the directory that will
/// contain `comps`' last component, replacing any non-directory on the way.
fn ensure_dir<'a>(root: &'a mut TarNode, comps: &[Vec<u8>]) -> &'a mut TarNode {
    let mut current = root;
    for comp in comps {
        let TarNodeData::Dir(children) = &mut current.data else {
            unreachable!("ensure_dir only descends through directories");
        };
        let child = children
            .entry(comp.clone())
            .or_insert_with(TarNode::implicit_dir);
        if !child.is_dir() {
            *child = TarNode::implicit_dir();
        }
        current = child;
    }
    current
}

/// Reads the `SCHILY.xattr.*` PAX extensions of a tar entry into EROFS xattr
/// entries, sorted for deterministic bootstraps.
fn pax_xattrs<R: Read>(entry: &mut tar::Entry<R>) -> Result<Vec<XattrEntry>> {
    let mut xattrs: Vec<XattrEntry> = Vec::new();
    if let Some(extensions) = entry
        .pax_extensions()
        .context("failed to read pax extensions")?
    {
        for extension in extensions {
            let extension = extension.context("failed to parse pax extension")?;
            let Ok(key) = extension.key() else { continue };
            let Some(name) = key.strip_prefix(PAX_XATTR_PREFIX) else {
                continue;
            };
            let Some((prefix_index, suffix)) = erofs_xattr_name_split(name.as_bytes()) else {
                continue;
            };
            xattrs.push(XattrEntry {
                name_index: prefix_index,
                suffix: suffix.to_vec(),
                value: extension.value_bytes().to_vec(),
            });
        }
    }
    xattrs.sort_by(|a, b| (a.name_index, &a.suffix).cmp(&(b.name_index, &b.suffix)));
    Ok(xattrs)
}

/// Looks up an existing node by path for hardlink resolution.
fn find_node<'a>(root: &'a TarNode, comps: &[Vec<u8>]) -> Option<&'a TarNode> {
    let mut current = root;
    for comp in comps {
        let TarNodeData::Dir(children) = &current.data else {
            return None;
        };
        current = children.get(comp)?;
    }
    Some(current)
}

fn find_node_mut<'a>(root: &'a mut TarNode, comps: &[Vec<u8>]) -> Option<&'a mut TarNode> {
    let mut current = root;
    for comp in comps {
        let TarNodeData::Dir(children) = &mut current.data else {
            return None;
        };
        current = children.get_mut(comp)?;
    }
    Some(current)
}

/// Recomputes the shared-inode link counts after all layers are applied.
fn fixup_nlink(node: &mut TarNode, counts: &std::collections::HashMap<u32, u32>) {
    if let Some(group) = node.link_group {
        if let Some(count) = counts.get(&group) {
            node.nlink = *count;
        }
    }
    if let TarNodeData::Dir(children) = &mut node.data {
        for child in children.values_mut() {
            fixup_nlink(child, counts);
        }
    }
}

/// Consumes one OCI layer tarball (gzip or plain) and returns the flattened
/// inode table, streaming regular-file contents into `blob_writer` as each
/// tar entry is read. OCI whiteout entries (`.wh.*`) are kept as regular
/// files, exactly like a directory source, for `merge` to apply across
/// layers.
pub fn build_tar_layer_tree<W: Write>(
    layer: &Path,
    blob_writer: &mut BlobWriter<W>,
    chunk_size: u32,
) -> Result<Vec<InodeInfo>> {
    let chunk_size_bits = chunk_size.trailing_zeros();
    let mut root = TarNode::implicit_dir();
    let mut next_link_group = 0u32;
    let mut link_counts: std::collections::HashMap<u32, u32> = std::collections::HashMap::new();

    let reader = open_layer(layer)?;
    let mut archive = tar::Archive::new(reader);
    archive.set_ignore_zeros(true);

    for entry in archive
        .entries()
        .with_context(|| format!("failed to read layer: {}", layer.display()))?
    {
        let mut entry =
            entry.with_context(|| format!("failed to read entry: {}", layer.display()))?;
        apply_entry(
            &mut root,
            &mut entry,
            blob_writer,
            chunk_size_bits,
            &mut next_link_group,
            &mut link_counts,
        )
        .with_context(|| format!("failed to apply layer entry: {}", layer.display()))?;
    }

    fixup_nlink(&mut root, &link_counts);
    // Same normalization as the directory builder: the root mtime reflects
    // staging time, not content, and would break reproducibility.
    root.mtime = 0;
    let mut inodes = flatten_tree(root, &mut ())?;
    if let Some(root) = inodes.first_mut() {
        root.mtime = 0;
        root.mtime_nsec = 0;
    }
    Ok(inodes)
}

/// Opens a layer file, transparently decompressing gzip (sniffed by magic).
/// Never seeks, so FIFOs work: the sniffed bytes are chained back in front.
fn open_layer(path: &Path) -> Result<Box<dyn Read>> {
    let mut file =
        File::open(path).with_context(|| format!("failed to open layer: {}", path.display()))?;
    let mut magic = [0u8; 2];
    let mut filled = 0;
    while filled < 2 {
        let n = file
            .read(&mut magic[filled..])
            .with_context(|| format!("failed to read layer: {}", path.display()))?;
        if n == 0 {
            break;
        }
        filled += n;
    }
    let head = std::io::Cursor::new(magic[..filled].to_vec());
    let buffered = BufReader::with_capacity(1 << 20, head.chain(file));
    if filled == 2 && magic == [0x1f, 0x8b] {
        Ok(Box::new(GzDecoder::new(buffered)))
    } else {
        Ok(Box::new(buffered))
    }
}

/// Applies a single tar entry to the in-memory tree, streaming file data into
/// the blob writer.
fn apply_entry<R: Read, W: Write>(
    root: &mut TarNode,
    entry: &mut tar::Entry<R>,
    blob_writer: &mut BlobWriter<W>,
    chunk_size_bits: u32,
    next_link_group: &mut u32,
    link_counts: &mut std::collections::HashMap<u32, u32>,
) -> Result<()> {
    use tar::EntryType;

    let entry_type = entry.header().entry_type();
    match entry_type {
        EntryType::XHeader
        | EntryType::XGlobalHeader
        | EntryType::GNULongName
        | EntryType::GNULongLink => return Ok(()),
        _ => {}
    }

    let comps = path_components(&entry.path_bytes());
    let Some((name, parent_comps)) = comps.split_last() else {
        // The "./" root entry only carries metadata for the root directory.
        let (mode, uid, gid, mtime) = entry_meta(entry)?;
        root.mode = 0o040000 | (mode & 0o7777);
        root.uid = uid;
        root.gid = gid;
        root.mtime = mtime;
        root.xattrs = pax_xattrs(entry)?;
        return Ok(());
    };

    let (mode, uid, gid, mtime) = entry_meta(entry)?;
    let xattrs = pax_xattrs(entry)?;
    let size = entry.header().size().context("bad entry size")?;

    let node = match entry_type {
        EntryType::Directory => {
            let parent = ensure_dir(root, parent_comps);
            let TarNodeData::Dir(children) = &mut parent.data else {
                unreachable!("ensure_dir returns a directory");
            };
            let dir = children
                .entry(name.clone())
                .or_insert_with(TarNode::implicit_dir);
            if !dir.is_dir() {
                *dir = TarNode::implicit_dir();
            }
            dir.mode = 0o040000 | (mode & 0o7777);
            dir.uid = uid;
            dir.gid = gid;
            dir.mtime = mtime;
            dir.xattrs = xattrs;
            return Ok(());
        }
        EntryType::Regular | EntryType::Continuous => {
            // Stream the file data into the blob right now; this is where
            // aligned placement happens for the streaming path too.
            let data = if blob_writer.zlz4_enabled() {
                let zmeta = blob_writer.write_reader_zlz4(entry, size)?;
                TarNodeData::ZFile {
                    tail: zmeta.tail,
                    compressed_blocks: zmeta.compressed_blocks,
                }
            } else {
                let chunks = blob_writer.write_reader_chunks(entry, size)?;
                TarNodeData::File {
                    chunks,
                    chunk_size_bits,
                }
            };
            TarNode {
                mode: 0o100000 | (mode & 0o7777),
                uid,
                gid,
                size,
                mtime,
                nlink: 1,
                xattrs,
                link_group: None,
                data,
            }
        }
        EntryType::Link => {
            let target_raw = entry
                .link_name_bytes()
                .ok_or_else(|| Error::InvalidParameter("hardlink without target".to_string()))?;
            let target_comps = path_components(&target_raw);
            // Assign (or reuse) the target's hardlink group, then insert a
            // full copy so the group survives even if the target is later
            // replaced by an upper layer.
            let target = find_node_mut(root, &target_comps).ok_or_else(|| {
                Error::InvalidParameter(format!(
                    "hardlink target not found: {}",
                    String::from_utf8_lossy(&target_raw)
                ))
            })?;
            let group = match target.link_group {
                Some(group) => group,
                None => {
                    *next_link_group += 1;
                    let group = *next_link_group;
                    target.link_group = Some(group);
                    link_counts.insert(group, 1);
                    group
                }
            };
            *link_counts.entry(group).or_insert(0) += 1;
            let target = find_node(root, &target_comps).expect("target exists");
            TarNode {
                mode: target.mode,
                uid: target.uid,
                gid: target.gid,
                size: target.size,
                mtime: target.mtime,
                nlink: 1,
                xattrs: target.xattrs.clone(),
                link_group: Some(group),
                data: match &target.data {
                    TarNodeData::File {
                        chunks,
                        chunk_size_bits,
                    } => TarNodeData::File {
                        chunks: chunks.clone(),
                        chunk_size_bits: *chunk_size_bits,
                    },
                    TarNodeData::ZFile {
                        tail,
                        compressed_blocks,
                    } => TarNodeData::ZFile {
                        tail: tail.clone(),
                        compressed_blocks: *compressed_blocks,
                    },
                    TarNodeData::Symlink { target } => TarNodeData::Symlink {
                        target: target.clone(),
                    },
                    TarNodeData::Device { rdev } => TarNodeData::Device { rdev: *rdev },
                    TarNodeData::Fifo => TarNodeData::Fifo,
                    TarNodeData::Dir(_) => {
                        return Err(Error::InvalidParameter(
                            "hardlink to a directory".to_string(),
                        ))
                    }
                },
            }
        }
        EntryType::Symlink => {
            let target = entry
                .link_name_bytes()
                .ok_or_else(|| Error::InvalidParameter("symlink without target".to_string()))?
                .to_vec();
            TarNode {
                mode: 0o120000 | 0o777,
                uid,
                gid,
                size: target.len() as u64,
                mtime,
                nlink: 1,
                xattrs,
                link_group: None,
                data: TarNodeData::Symlink { target },
            }
        }
        EntryType::Char | EntryType::Block => {
            let major = entry
                .header()
                .device_major()
                .context("bad device major")?
                .unwrap_or(0);
            let minor = entry
                .header()
                .device_minor()
                .context("bad device minor")?
                .unwrap_or(0);
            let type_bits = if entry_type == EntryType::Char {
                0o020000
            } else {
                0o060000
            };
            TarNode {
                mode: type_bits | (mode & 0o7777),
                uid,
                gid,
                size: 0,
                mtime,
                nlink: 1,
                xattrs,
                link_group: None,
                // SAFETY-free rdev packing: same encoding the kernel reports
                // in stat.st_rdev for major/minor pairs of this range.
                data: TarNodeData::Device {
                    rdev: libc::makedev(major, minor) as u32,
                },
            }
        }
        EntryType::Fifo => TarNode {
            mode: 0o010000 | (mode & 0o7777),
            uid,
            gid,
            size: 0,
            mtime,
            nlink: 1,
            xattrs,
            link_group: None,
            data: TarNodeData::Fifo,
        },
        // Silently dropping an entry would yield a wrong image.
        other => {
            return Err(Error::Unsupported(format!(
                "unsupported tar entry type {other:?}: {}",
                String::from_utf8_lossy(&entry.path_bytes())
            )))
        }
    };

    let parent = ensure_dir(root, parent_comps);
    let TarNodeData::Dir(children) = &mut parent.data else {
        unreachable!("ensure_dir returns a directory");
    };
    children.insert(name.clone(), node);
    Ok(())
}

/// Extracts the common (mode, uid, gid, mtime) header fields of a tar entry.
fn entry_meta<R: Read>(entry: &tar::Entry<R>) -> Result<(u16, u32, u32, u64)> {
    let header = entry.header();
    let mode = header.mode().context("bad entry mode")? as u16;
    let uid = header.uid().context("bad entry uid")? as u32;
    let gid = header.gid().context("bad entry gid")? as u32;
    let mtime = header.mtime().context("bad entry mtime")?;
    Ok((mode, uid, gid, mtime))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::build::inode::ChildRef;
    use nydus_format::blob::BlobMetadataCompressor;
    use nydus_format::erofs::{
        EROFS_BLOCK_SIZE, EROFS_FT_CHRDEV, EROFS_FT_DIR, EROFS_FT_FIFO, EROFS_FT_REG_FILE,
        EROFS_FT_SYMLINK, EROFS_XATTR_INDEX_SECURITY, EROFS_XATTR_INDEX_USER,
    };
    use std::io::Write;

    const MTIME: u64 = 1_700_000_000;

    fn header(entry_type: tar::EntryType, path: &str, size: u64, mode: u32) -> tar::Header {
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(entry_type);
        header.set_path(path).unwrap();
        header.set_size(size);
        header.set_mode(mode);
        header.set_uid(1000);
        header.set_gid(2000);
        header.set_mtime(MTIME);
        header
    }

    /// Appends a PAX extended header carrying the given `SCHILY.xattr.*`
    /// records ahead of the next entry.
    fn append_pax_xattrs(builder: &mut tar::Builder<Vec<u8>>, xattrs: &[(&str, &[u8])]) {
        let mut body = Vec::new();
        for (name, value) in xattrs {
            let record = [
                format!("{PAX_XATTR_PREFIX}{name}=").into_bytes(),
                value.to_vec(),
                b"\n".to_vec(),
            ]
            .concat();
            // PAX records are "<len> key=value\n" where len counts itself.
            let mut len = record.len() + 1;
            len += len.to_string().len();
            if len.to_string().len() + record.len() + 1 != len {
                len += 1;
            }
            body.extend_from_slice(format!("{len} ").as_bytes());
            body.extend_from_slice(&record);
        }
        let mut header = tar::Header::new_ustar();
        header.set_entry_type(tar::EntryType::XHeader);
        header.set_size(body.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append(&header, body.as_slice()).unwrap();
    }

    fn build(tar_bytes: &[u8]) -> Result<Vec<InodeInfo>> {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("layer.tar");
        std::fs::write(&path, tar_bytes).unwrap();
        let mut blob_writer = BlobWriter::from_writer(
            Vec::new(),
            EROFS_BLOCK_SIZE,
            1 << 20,
            BlobMetadataCompressor::None,
        )
        .unwrap();
        build_tar_layer_tree(&path, &mut blob_writer, EROFS_BLOCK_SIZE)
    }

    fn children(inodes: &[InodeInfo], index: usize) -> &[ChildRef] {
        match &inodes[index].data {
            InodeData::Directory { children, .. } => children,
            _ => panic!("inode {index} is not a directory"),
        }
    }

    fn child<'a>(inodes: &'a [InodeInfo], dir: usize, name: &str) -> (&'a ChildRef, &'a InodeInfo) {
        let child = children(inodes, dir)
            .iter()
            .find(|child| child.name == name.as_bytes())
            .unwrap_or_else(|| panic!("{name} missing"));
        (child, &inodes[child.inode_index])
    }

    #[test]
    fn regular_files_stream_into_chunks_and_keep_tar_metadata() {
        let mut builder = tar::Builder::new(Vec::new());
        let payload = vec![0xa5u8; EROFS_BLOCK_SIZE as usize + 100];
        let mut h = header(
            tar::EntryType::Regular,
            "./usr/bin/tool",
            payload.len() as u64,
            0o755,
        );
        h.set_cksum();
        builder.append(&h, payload.as_slice()).unwrap();
        let mut h = header(tar::EntryType::Regular, "usr/bin/empty", 0, 0o644);
        h.set_cksum();
        builder.append(&h, &b""[..]).unwrap();
        let tar_bytes = builder.into_inner().unwrap();

        let inodes = build(&tar_bytes).unwrap();
        let (usr_ref, _) = child(&inodes, 0, "usr");
        assert_eq!(usr_ref.file_type, EROFS_FT_DIR);
        let (_, usr) = child(&inodes, 0, "usr");
        // Implicit directories get root-owned 0755.
        assert_eq!(usr.mode & 0o7777, 0o755);
        assert_eq!((usr.uid, usr.gid), (0, 0));
        let bin_index = child(&inodes, usr_ref.inode_index, "bin").0.inode_index;

        let (tool_ref, tool) = child(&inodes, bin_index, "tool");
        assert_eq!(tool_ref.file_type, EROFS_FT_REG_FILE);
        assert_eq!(tool.mode, 0o100755);
        assert_eq!((tool.uid, tool.gid, tool.mtime), (1000, 2000, MTIME));
        assert_eq!(tool.size, payload.len() as u64);
        let InodeData::RegularFile {
            chunk_index_entries,
            ..
        } = &tool.data
        else {
            panic!("tool must be chunk based");
        };
        assert_eq!(chunk_index_entries.len(), 2, "two 4KiB chunks");

        let (_, empty) = child(&inodes, bin_index, "empty");
        assert_eq!(empty.size, 0);
        let InodeData::RegularFile {
            chunk_index_entries,
            ..
        } = &empty.data
        else {
            panic!("empty must be chunk based");
        };
        assert!(chunk_index_entries.is_empty());
        // Root mtime is normalized for reproducibility.
        assert_eq!(inodes[0].mtime, 0);
    }

    #[test]
    fn explicit_directories_override_implicit_ones() {
        let mut builder = tar::Builder::new(Vec::new());
        let mut h = header(tar::EntryType::Regular, "a/b/file", 1, 0o600);
        h.set_cksum();
        builder.append(&h, &b"x"[..]).unwrap();
        let mut h = header(tar::EntryType::Directory, "a/b/", 0, 0o700);
        h.set_cksum();
        builder.append(&h, &b""[..]).unwrap();
        let mut h = header(tar::EntryType::Directory, "./", 0, 0o711);
        h.set_cksum();
        builder.append(&h, &b""[..]).unwrap();
        let inodes = build(&builder.into_inner().unwrap()).unwrap();

        assert_eq!(inodes[0].mode, 0o040711, "root entry sets root mode");
        assert_eq!((inodes[0].uid, inodes[0].gid), (1000, 2000));
        let a = child(&inodes, 0, "a").0.inode_index;
        let (_, b) = child(&inodes, a, "b");
        assert_eq!(b.mode, 0o040700);
        assert_eq!((b.uid, b.gid, b.mtime), (1000, 2000, MTIME));
        assert_eq!(
            children(&inodes, child(&inodes, a, "b").0.inode_index).len(),
            1
        );
    }

    #[test]
    fn hardlinks_share_one_inode_with_the_right_nlink() {
        let mut builder = tar::Builder::new(Vec::new());
        let mut h = header(tar::EntryType::Regular, "bin/busybox", 5, 0o755);
        h.set_cksum();
        builder.append(&h, &b"hello"[..]).unwrap();
        for name in ["bin/sh", "bin/ls"] {
            let mut h = header(tar::EntryType::Link, name, 0, 0o755);
            h.set_link_name("bin/busybox").unwrap();
            h.set_cksum();
            builder.append(&h, &b""[..]).unwrap();
        }
        let inodes = build(&builder.into_inner().unwrap()).unwrap();

        let bin = child(&inodes, 0, "bin").0.inode_index;
        let indexes: Vec<usize> = ["busybox", "sh", "ls"]
            .iter()
            .map(|name| child(&inodes, bin, name).0.inode_index)
            .collect();
        assert!(indexes.iter().all(|&i| i == indexes[0]), "one inode");
        assert_eq!(inodes[indexes[0]].nlink, 3);
        assert_eq!(inodes[indexes[0]].size, 5);
        assert_eq!(children(&inodes, bin).len(), 3);
    }

    #[test]
    fn hardlink_to_a_missing_target_is_an_error() {
        let mut builder = tar::Builder::new(Vec::new());
        let mut h = header(tar::EntryType::Link, "sh", 0, 0o755);
        h.set_link_name("busybox").unwrap();
        h.set_cksum();
        builder.append(&h, &b""[..]).unwrap();
        let err = build(&builder.into_inner().unwrap())
            .err()
            .expect("must fail");
        let report = err.report().to_string();
        assert!(report.contains("hardlink target not found"), "{report}");
    }

    #[test]
    fn symlinks_devices_fifos_and_whiteouts_map_to_their_inode_types() {
        let mut builder = tar::Builder::new(Vec::new());
        let mut h = header(tar::EntryType::Symlink, "lib64", 0, 0o777);
        h.set_link_name("usr/lib").unwrap();
        h.set_cksum();
        builder.append(&h, &b""[..]).unwrap();
        let mut h = header(tar::EntryType::Char, "dev/null", 0, 0o666);
        h.set_device_major(1).unwrap();
        h.set_device_minor(3).unwrap();
        h.set_cksum();
        builder.append(&h, &b""[..]).unwrap();
        let mut h = header(tar::EntryType::Fifo, "run/pipe", 0, 0o600);
        h.set_cksum();
        builder.append(&h, &b""[..]).unwrap();
        let mut h = header(tar::EntryType::Regular, "etc/.wh.old.conf", 0, 0o644);
        h.set_cksum();
        builder.append(&h, &b""[..]).unwrap();
        let mut h = header(tar::EntryType::Regular, "opt/.wh..wh..opq", 0, 0o644);
        h.set_cksum();
        builder.append(&h, &b""[..]).unwrap();
        let inodes = build(&builder.into_inner().unwrap()).unwrap();

        let (link_ref, link) = child(&inodes, 0, "lib64");
        assert_eq!(link_ref.file_type, EROFS_FT_SYMLINK);
        assert_eq!(link.mode, 0o120777);
        assert_eq!(link.size, "usr/lib".len() as u64);
        assert!(matches!(&link.data, InodeData::Symlink { target, .. } if target == b"usr/lib"));

        let dev = child(&inodes, 0, "dev").0.inode_index;
        let (null_ref, null) = child(&inodes, dev, "null");
        assert_eq!(null_ref.file_type, EROFS_FT_CHRDEV);
        assert_eq!(null.mode, 0o020666);
        assert!(matches!(
            null.data,
            InodeData::Device { rdev } if rdev == libc::makedev(1, 3) as u32
        ));

        let run = child(&inodes, 0, "run").0.inode_index;
        let (pipe_ref, pipe) = child(&inodes, run, "pipe");
        assert_eq!(pipe_ref.file_type, EROFS_FT_FIFO);
        assert!(matches!(pipe.data, InodeData::FifoOrSocket));

        // Whiteouts survive as plain regular files for `merge`.
        let etc = child(&inodes, 0, "etc").0.inode_index;
        assert_eq!(
            child(&inodes, etc, ".wh.old.conf").0.file_type,
            EROFS_FT_REG_FILE
        );
        let opt = child(&inodes, 0, "opt").0.inode_index;
        assert_eq!(
            child(&inodes, opt, ".wh..wh..opq").0.file_type,
            EROFS_FT_REG_FILE
        );
    }

    #[test]
    fn pax_xattrs_become_sorted_erofs_xattrs() {
        let mut builder = tar::Builder::new(Vec::new());
        append_pax_xattrs(
            &mut builder,
            &[
                ("user.note", b"hi"),
                ("security.capability", &[1, 0, 0, 2]),
                ("unknown.prefix", b"dropped"),
            ],
        );
        let mut h = header(tar::EntryType::Regular, "bin/ping", 1, 0o755);
        h.set_cksum();
        builder.append(&h, &b"p"[..]).unwrap();
        let inodes = build(&builder.into_inner().unwrap()).unwrap();

        let bin = child(&inodes, 0, "bin").0.inode_index;
        let (_, ping) = child(&inodes, bin, "ping");
        let names: Vec<(u8, &[u8], &[u8])> = ping
            .xattrs
            .iter()
            .map(|x| (x.name_index, x.suffix.as_slice(), x.value.as_slice()))
            .collect();
        assert_eq!(
            names,
            vec![
                (EROFS_XATTR_INDEX_USER, &b"note"[..], &b"hi"[..]),
                (
                    EROFS_XATTR_INDEX_SECURITY,
                    &b"capability"[..],
                    &[1u8, 0, 0, 2][..]
                ),
            ]
        );
    }

    #[test]
    fn gzip_layers_are_sniffed_and_unsupported_entries_rejected() {
        let mut builder = tar::Builder::new(Vec::new());
        let mut h = header(tar::EntryType::Regular, "f", 3, 0o644);
        h.set_cksum();
        builder.append(&h, &b"abc"[..]).unwrap();
        let plain = builder.into_inner().unwrap();
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(&plain).unwrap();
        let gz = encoder.finish().unwrap();
        let inodes = build(&gz).unwrap();
        assert_eq!(child(&inodes, 0, "f").1.size, 3);

        let mut builder = tar::Builder::new(Vec::new());
        // 'V' is a GNU volume header: a valid entry nydus has no use for.
        let mut h = header(tar::EntryType::new(b'V'), "volume", 0, 0o644);
        h.set_cksum();
        builder.append(&h, &b""[..]).unwrap();
        let err = build(&builder.into_inner().unwrap())
            .err()
            .expect("must fail");
        let report = err.report().to_string();
        assert!(report.contains("unsupported tar entry type"), "{report}");
    }
}

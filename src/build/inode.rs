use crate::build::blob_chunk::{BlobWriter, ChunkIndex};
use crate::metadata::*;
use anyhow::{bail, Context, Result};
use std::collections::HashMap;
use std::fs;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

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

    /// Inline xattr entries: (prefix_index, name_suffix, value).
    pub xattrs: Vec<(u8, Vec<u8>, Vec<u8>)>,
}

/// File-type-specific data for an inode.
pub enum InodeData {
    /// Regular file: chunk indexes for chunk-based layout.
    RegularFile {
        /// List of chunk indexes (EROFS_CHUNK_INDEX_SIZE bytes each) for the file's data chunks.
        chunk_indexes: Vec<ChunkIndex>,

        /// Number of bits for the chunk size (e.g. 12 for 4KB chunks).
        chunk_size_bits: u32,
    },

    /// Directory: sorted children.
    Directory {
        // List of child entries (name, file type, inode index in the inodes vector).
        children: Vec<DirEntry>,

        /// Starting block address of the directory data (set during layout).
        startblk: u64,

        /// Size of the directory data in bytes (set during layout).
        data_size: usize,

        /// NID of the parent directory (set during layout, 0 for root).
        parent_nid: u64,
    },

    /// Symbolic link: target path.
    Symlink { target: Vec<u8> },

    /// Character/block device.
    Device { rdev: u32 },

    /// FIFO or socket (no data).
    FifoOrSocket,
}

/// A directory entry referencing a child inode.
pub struct DirEntry {
    /// Entry name.
    pub name: String,

    /// File type.
    pub file_type: u8,

    /// Index of the child inode in the inodes vector.
    pub inode_idx: usize,
}

/// Convert a Unix file mode to an EROFS file type value for directory entries.
pub fn mode_to_erofs_file_type(mode: u16) -> u8 {
    match mode as u32 & libc::S_IFMT {
        libc::S_IFREG => EROFS_FT_REG_FILE,
        libc::S_IFDIR => EROFS_FT_DIR,
        libc::S_IFCHR => EROFS_FT_CHRDEV,
        libc::S_IFBLK => EROFS_FT_BLKDEV,
        libc::S_IFIFO => EROFS_FT_FIFO,
        libc::S_IFSOCK => EROFS_FT_SOCK,
        libc::S_IFLNK => EROFS_FT_SYMLINK,
        _ => 0,
    }
}

/// Calculate the size of an inode's metadata (header + xattr ibody + chunk indexes) for the final
/// image.
pub fn erofs_inode_size(inode: &InodeInfo, _chunk_bits: u32, _blksz_bits: u32) -> usize {
    let inode_isize = if inode.is_extended {
        EROFS_INODE_EXTENDED_SIZE
    } else {
        EROFS_INODE_COMPACT_SIZE
    };

    let xattr_isize = erofs_xattr_ibody_size(&inode.xattrs);
    match &inode.data {
        InodeData::RegularFile { chunk_indexes, .. } => {
            if chunk_indexes.is_empty() {
                inode_isize + xattr_isize
            } else {
                round_up(inode_isize + xattr_isize, EROFS_CHUNK_INDEX_SIZE)
                    + chunk_indexes.len() * EROFS_CHUNK_INDEX_SIZE
            }
        }
        InodeData::Directory { .. } => inode_isize + xattr_isize,
        InodeData::Symlink { target } => inode_isize + xattr_isize + target.len(),
        InodeData::Device { .. } | InodeData::FifoOrSocket => inode_isize + xattr_isize,
    }
}

/// Set the root directory's trusted.lepton.prefetch_blobs xattr to a comma-separated list of
/// unique non-zero device IDs.
pub fn set_root_prefetch_blobs_xattr(inode: &mut InodeInfo, device_ids: &[u16]) -> Result<()> {
    let mut prefetch_device_ids = Vec::new();
    for device_id in device_ids.iter().copied() {
        if device_id != 0 && !prefetch_device_ids.contains(&device_id) {
            prefetch_device_ids.push(device_id);
        }
    }

    if prefetch_device_ids.is_empty() {
        return Ok(());
    }

    let value = prefetch_device_ids
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(",");
    if value.len() > u16::MAX as usize {
        bail!("root prefetch xattr value exceeds EROFS xattr value size limit");
    }

    inode.xattrs.retain(|(index, suffix, _)| {
        !(*index == EROFS_XATTR_INDEX_TRUSTED
            && suffix.as_slice() == LEPTON_XATTR_SUFFIX_PREFETCH_BLOBS)
    });

    inode.xattrs.push((
        EROFS_XATTR_INDEX_TRUSTED,
        LEPTON_XATTR_SUFFIX_PREFETCH_BLOBS.to_vec(),
        value.into_bytes(),
    ));

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
pub fn build_tree(
    source: &Path,
    blob_writer: &mut BlobWriter,
    chunk_size: u32,
) -> Result<Vec<InodeInfo>> {
    let mut inodes: Vec<InodeInfo> = Vec::new();
    let mut inode_counter: u32 = 0;
    let mut hardlink_map: HashMap<(u64, u64), usize> = HashMap::new();

    build_tree_recursive(
        source,
        blob_writer,
        chunk_size,
        &mut inodes,
        &mut inode_counter,
        &mut hardlink_map,
    )?;

    Ok(inodes)
}

/// Recursively create inodes for `path` and its descendants, appending to
/// `inodes` in DFS pre-order and returning the index of `path`'s inode.
///
/// Directories push their inode first, then recurse into children in sorted
/// name order; regular files write chunks via `blob_writer`; symlinks store
/// the target inline; devices record `rdev`. Non-directory entries with
/// `nlink > 1` are deduplicated through `hardlink_map` (keyed by source
/// `(dev, ino)`) so later links reuse the existing inode index.
#[allow(clippy::only_used_in_recursion)]
fn build_tree_recursive(
    path: &Path,
    blob_writer: &mut BlobWriter,
    chunk_size: u32,
    inodes: &mut Vec<InodeInfo>,
    inode_counter: &mut u32,
    hardlink_map: &mut HashMap<(u64, u64), usize>,
) -> Result<usize> {
    let meta = fs::symlink_metadata(path)
        .with_context(|| format!("failed to stat: {}", path.display()))?;

    let ft = meta.file_type();
    let mode = meta.mode() as u16;
    let uid = meta.uid();
    let gid = meta.gid();
    let mtime = meta.mtime() as u64;
    let mtime_nsec = meta.mtime_nsec() as u32;
    let nlink = meta.nlink() as u32;

    *inode_counter += 1;
    let ino = *inode_counter;
    let is_extended = needs_erofs_extended_inode(&meta);
    let xattrs = read_xattrs_from_path(path);
    if ft.is_dir() {
        let inode_idx = inodes.len();
        inodes.push(InodeInfo {
            mode,
            uid,
            gid,
            size: 0,
            mtime,
            mtime_nsec,
            nlink,
            ino,
            nid: 0,
            meta_offset: 0,
            is_extended,
            data: InodeData::Directory {
                children: Vec::new(),
                startblk: 0,
                data_size: 0,
                parent_nid: 0,
            },
            xattrs,
        });

        let mut entries: Vec<fs::DirEntry> = fs::read_dir(path)
            .with_context(|| format!("failed to read directory: {}", path.display()))?
            .collect::<Result<Vec<_>, _>>()?;
        entries.sort_by_cached_key(|entry| entry.file_name());

        let mut children = Vec::new();
        for entry in &entries {
            let child_path = entry.path();
            let child_meta = fs::symlink_metadata(&child_path)
                .with_context(|| format!("failed to stat: {}", child_path.display()))?;
            let hardlink_key = (!child_meta.file_type().is_dir() && child_meta.nlink() > 1)
                .then(|| (child_meta.dev(), child_meta.ino()));

            let child_idx = match hardlink_key.and_then(|key| hardlink_map.get(&key).copied()) {
                Some(existing_idx) => existing_idx,
                None => {
                    let idx = build_tree_recursive(
                        &child_path,
                        blob_writer,
                        chunk_size,
                        inodes,
                        inode_counter,
                        hardlink_map,
                    )?;

                    if let Some(key) = hardlink_key {
                        hardlink_map.insert(key, idx);
                    }

                    idx
                }
            };

            children.push(DirEntry {
                name: entry.file_name().to_string_lossy().into_owned(),
                file_type: mode_to_erofs_file_type(child_meta.mode() as u16),
                inode_idx: child_idx,
            });
        }

        if let InodeData::Directory {
            children: ref mut dir_children,
            ..
        } = inodes[inode_idx].data
        {
            *dir_children = children;
        }

        Ok(inode_idx)
    } else if ft.is_file() {
        let file_size = meta.size();
        let chunk_indexes = blob_writer.write_file_chunks(path, file_size)?;
        let inode_idx = inodes.len();
        inodes.push(InodeInfo {
            mode,
            uid,
            gid,
            size: file_size,
            mtime,
            mtime_nsec,
            nlink,
            ino,
            nid: 0,
            meta_offset: 0,
            is_extended,
            data: InodeData::RegularFile {
                chunk_indexes,
                chunk_size_bits: chunk_size.trailing_zeros(),
            },
            xattrs,
        });

        Ok(inode_idx)
    } else if ft.is_symlink() {
        let target = fs::read_link(path)
            .with_context(|| format!("failed to read symlink: {}", path.display()))?
            .into_os_string()
            .into_vec();

        let inode_idx = inodes.len();
        inodes.push(InodeInfo {
            mode,
            uid,
            gid,
            size: target.len() as u64,
            mtime,
            mtime_nsec,
            nlink,
            ino,
            nid: 0,
            meta_offset: 0,
            is_extended,
            data: InodeData::Symlink { target },
            xattrs,
        });

        Ok(inode_idx)
    } else {
        let rdev = meta.rdev() as u32;
        let file_type = mode as u32 & libc::S_IFMT;
        let is_dev = file_type == libc::S_IFCHR || file_type == libc::S_IFBLK;
        let inode_idx = inodes.len();
        inodes.push(InodeInfo {
            mode,
            uid,
            gid,
            size: 0,
            mtime,
            mtime_nsec,
            nlink,
            ino,
            nid: 0,
            meta_offset: 0,
            is_extended,
            data: if is_dev {
                InodeData::Device { rdev }
            } else {
                InodeData::FifoOrSocket
            },
            xattrs,
        });

        Ok(inode_idx)
    }
}

/// Serialize an inode to bytes and write it at the given offset in a buffer.
pub fn serialize_inode(inode: &InodeInfo, epoch: u64) -> Vec<u8> {
    let blkszbits = EROFS_BLKSZBITS as u32;
    let inode_size = erofs_inode_size(inode, blkszbits, blkszbits);
    let mut buf = vec![0u8; inode_size];

    let xattr_size = erofs_xattr_ibody_size(&inode.xattrs);
    let i_xattr_icount = erofs_xattr_icount(xattr_size);

    match &inode.data {
        InodeData::RegularFile {
            chunk_indexes,
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
                let i_format = erofs_compact_i_format(datalayout, true);
                let i_mtime = inode.mtime.wrapping_sub(epoch) as u32;
                let hdr = ErofsInodeCompact::new(
                    i_format,
                    inode.mode,
                    0,
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
            let extent_offset = round_up(base + xattr_size, EROFS_CHUNK_INDEX_SIZE);
            for (i, ci) in chunk_indexes.iter().enumerate() {
                let idx = ErofsChunkIndex::new(ci.blkaddr, ci.device_id);
                let off = extent_offset + i * EROFS_CHUNK_INDEX_SIZE;
                buf[off..off + EROFS_CHUNK_INDEX_SIZE].copy_from_slice(idx.as_bytes());
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
                let i_format = erofs_compact_i_format(datalayout, false);
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
        InodeData::Symlink { target } => {
            let datalayout = EROFS_INODE_FLAT_INLINE;
            let inline_off = if inode.is_extended {
                EROFS_INODE_EXTENDED_SIZE + xattr_size
            } else {
                EROFS_INODE_COMPACT_SIZE + xattr_size
            };

            if inode.is_extended {
                let i_format = erofs_extended_i_format(datalayout);
                let hdr = ErofsInodeExtended::new(
                    i_format,
                    inode.mode,
                    0,
                    inode.size,
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
                let i_format = erofs_compact_i_format(datalayout, true);
                let i_mtime = inode.mtime.wrapping_sub(epoch) as u32;
                let hdr = ErofsInodeCompact::new(
                    i_format,
                    inode.mode,
                    0,
                    inode.size as u32,
                    i_mtime,
                    0,
                    inode.ino,
                    inode.uid as u16,
                    inode.gid as u16,
                );
                buf[..EROFS_INODE_COMPACT_SIZE].copy_from_slice(hdr.as_bytes());
                write_erofs_xattr_ibody(&mut buf, EROFS_INODE_COMPACT_SIZE, &inode.xattrs);
            }
            buf[inline_off..inline_off + target.len()].copy_from_slice(target);
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
                let i_format = erofs_compact_i_format(datalayout, true);
                let i_mtime = inode.mtime.wrapping_sub(epoch) as u32;
                let hdr = ErofsInodeCompact::new(
                    i_format,
                    inode.mode,
                    0,
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
                let i_format = erofs_compact_i_format(datalayout, true);
                let i_mtime = inode.mtime.wrapping_sub(epoch) as u32;
                let hdr = ErofsInodeCompact::new(
                    i_format,
                    inode.mode,
                    0,
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
fn write_erofs_xattr_ibody(
    buf: &mut [u8],
    offset: usize,
    xattrs: &[(u8, Vec<u8>, Vec<u8>)],
) -> usize {
    if xattrs.is_empty() {
        return 0;
    }

    // Carve out the whole ibody region up front: bounds are checked exactly
    // once and fail fast; every write below stays inside this region.
    let ibody_size = erofs_xattr_ibody_size(xattrs);
    let ibody = &mut buf[offset..offset + ibody_size];

    // Entries start right after the header; `entry_start` stays 4-byte aligned.
    let mut entry_start = EROFS_XATTR_IBODY_HEADER_SIZE;
    for (name_index, name_suffix, value) in xattrs {
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
        entry_start = round_up(value_start + value.len(), 4);
    }

    ibody_size
}

/// Read xattrs from a filesystem path, returning (prefix_index, suffix_bytes, value) triples.
fn read_xattrs_from_path(path: &Path) -> Vec<(u8, Vec<u8>, Vec<u8>)> {
    use std::os::unix::ffi::OsStrExt;
    let Ok(names) = xattr::list(path) else {
        return Vec::new();
    };

    names
        .filter_map(|name| {
            let (prefix_index, suffix) = erofs_xattr_name_split(name.as_bytes())?;
            let value = xattr::get(path, &name).ok().flatten().unwrap_or_default();
            Some((prefix_index, suffix.to_vec(), value))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root_inode_with_xattrs(xattrs: Vec<(u8, Vec<u8>, Vec<u8>)>) -> InodeInfo {
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
            (
                EROFS_XATTR_INDEX_TRUSTED,
                LEPTON_XATTR_SUFFIX_PREFETCH_BLOBS.to_vec(),
                b"old".to_vec(),
            ),
            (EROFS_XATTR_INDEX_USER, b"keep".to_vec(), b"value".to_vec()),
        ]);

        set_root_prefetch_blobs_xattr(&mut inode, &[2, 5, 2, 0, 1]).unwrap();

        let prefetch_xattrs = inode
            .xattrs
            .iter()
            .filter(|(index, suffix, _)| {
                *index == EROFS_XATTR_INDEX_TRUSTED
                    && suffix.as_slice() == LEPTON_XATTR_SUFFIX_PREFETCH_BLOBS
            })
            .collect::<Vec<_>>();
        assert_eq!(prefetch_xattrs.len(), 1);
        assert_eq!(prefetch_xattrs[0].2, b"2,5,1");
        assert!(inode.xattrs.iter().any(|(index, suffix, value)| {
            *index == EROFS_XATTR_INDEX_USER
                && suffix.as_slice() == b"keep"
                && value.as_slice() == b"value"
        }));
    }
}

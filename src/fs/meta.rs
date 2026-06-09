use std::io;

use crate::metadata::*;

use super::{CachedDirEntry, DirEntry, ErofsReader};

impl ErofsReader {
    /// Get a zero-copy inode view from the mmap.
    pub fn inode(&self, nid: u64) -> io::Result<ErofsInode<'_>> {
        let offset = self.nid_to_offset(nid);
        let data = self.mmap_slice(offset, EROFS_INODE_EXTENDED_SIZE)?;
        ErofsInode::cast(data)
    }

    /// Iterate directory entries without materializing the whole directory in memory.
    pub fn for_each_dir_entry<F>(
        &self,
        nid: u64,
        inode: &ErofsInode<'_>,
        mut cb: F,
    ) -> io::Result<()>
    where
        F: FnMut(u64, u8, &[u8]) -> io::Result<bool>,
    {
        let dir_size = inode.size() as usize;
        if dir_size == 0 {
            return Ok(());
        }

        match self.read_flat_data(nid, inode, 0, dir_size) {
            Ok(data) => Self::parse_dir_entries(data, dir_size, &mut cb),
            Err(_) => {
                let data = self.read_flat_data_vec(nid, inode, 0, dir_size)?;
                Self::parse_dir_entries(&data, dir_size, &mut cb)
            }
        }
    }

    /// Read directory entries from a directory inode.
    pub fn read_dir(&self, nid: u64, inode: &ErofsInode<'_>) -> io::Result<Vec<DirEntry>> {
        let mut entries = Vec::new();
        self.for_each_dir_entry(nid, inode, |entry_nid, file_type, name| {
            entries.push(DirEntry {
                nid: entry_nid,
                file_type,
                name: String::from_utf8_lossy(name).into_owned(),
            });
            Ok(true)
        })?;
        Ok(entries)
    }

    pub(crate) fn read_dir_cached(
        &self,
        nid: u64,
        inode: &ErofsInode<'_>,
    ) -> io::Result<Vec<CachedDirEntry>> {
        let mut entries = Vec::new();
        self.for_each_dir_entry(nid, inode, |entry_nid, file_type, name| {
            entries.push(CachedDirEntry {
                nid: entry_nid,
                file_type,
                name: name.to_vec(),
            });
            Ok(true)
        })?;
        Ok(entries)
    }

    fn parse_dir_entries<F>(data: &[u8], dir_size: usize, cb: &mut F) -> io::Result<()>
    where
        F: FnMut(u64, u8, &[u8]) -> io::Result<bool>,
    {
        let block_size = EROFS_BLOCK_SIZE as usize;
        let mut pos = 0;

        while pos < dir_size {
            let block_end = std::cmp::min(pos + block_size, dir_size);
            let block_data = &data[pos..block_end];
            let block_len = block_end - pos;

            if block_len < EROFS_DIRENT_SIZE {
                break;
            }

            let first_de: &ErofsDirent = cast_ref(&block_data[..EROFS_DIRENT_SIZE]);
            let first_nameoff = first_de.nameoff() as usize;
            let dirent_count = first_nameoff / EROFS_DIRENT_SIZE;

            for i in 0..dirent_count {
                let de_off = i * EROFS_DIRENT_SIZE;
                if de_off + EROFS_DIRENT_SIZE > block_len {
                    break;
                }
                let de: &ErofsDirent = cast_ref(&block_data[de_off..de_off + EROFS_DIRENT_SIZE]);
                let nameoff = de.nameoff() as usize;

                let name_end = if i + 1 < dirent_count {
                    let next_de: &ErofsDirent =
                        cast_ref(&block_data[(i + 1) * EROFS_DIRENT_SIZE..]);
                    next_de.nameoff() as usize
                } else {
                    let mut end = nameoff;
                    while end < block_len && block_data[end] != 0 {
                        end += 1;
                    }
                    end
                };

                if nameoff >= block_len || name_end > block_len {
                    break;
                }
                if !cb(de.nid(), de.file_type(), &block_data[nameoff..name_end])? {
                    return Ok(());
                }
            }

            pos += block_size;
        }
        Ok(())
    }

    /// Read flat data (FLAT_PLAIN / FLAT_INLINE) as an mmap slice.
    /// NOTE: For FLAT_INLINE data that spans blocks+inline, use read_flat_data_vec() instead.
    pub(crate) fn read_flat_data<'a>(
        &'a self,
        nid: u64,
        inode: &ErofsInode<'_>,
        offset: u64,
        size: usize,
    ) -> io::Result<&'a [u8]> {
        let layout = inode.data_layout();
        match layout {
            EROFS_INODE_FLAT_PLAIN => {
                let startblk = inode.startblk();
                let data_offset = (startblk * EROFS_BLOCK_SIZE as u64 + offset) as usize;
                self.mmap_slice(data_offset, size)
            }
            EROFS_INODE_FLAT_INLINE => {
                let file_size = inode.size() as usize;
                let blk_sz = EROFS_BLOCK_SIZE as usize;
                let tail_size = if file_size % blk_sz == 0 && file_size > 0 {
                    0
                } else {
                    file_size % blk_sz
                };
                let blocks_size = file_size - tail_size;

                if blocks_size == 0 {
                    // All data is inline (small file/dir)
                    let inode_offset = self.nid_to_offset(nid);
                    let header_size = inode.header_size() + inode.xattr_size();
                    let data_offset = inode_offset + header_size + offset as usize;
                    self.mmap_slice(data_offset, size)
                } else if (offset as usize) < blocks_size && (offset as usize + size) <= blocks_size
                {
                    // All requested data is in the block region
                    let startblk = inode.startblk();
                    let data_offset = (startblk * EROFS_BLOCK_SIZE as u64 + offset) as usize;
                    self.mmap_slice(data_offset, size)
                } else if (offset as usize) >= blocks_size {
                    // All requested data is in the inline tail
                    let inode_offset = self.nid_to_offset(nid);
                    let header_size = inode.header_size() + inode.xattr_size();
                    let inline_offset = offset as usize - blocks_size;
                    let data_offset = inode_offset + header_size + inline_offset;
                    self.mmap_slice(data_offset, size)
                } else {
                    // Data spans blocks+inline boundary — cannot return a single slice
                    Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "FLAT_INLINE read spans block+inline boundary, use read_flat_data_vec()",
                    ))
                }
            }
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("not a flat data layout: {layout}"),
            )),
        }
    }

    /// Read flat data (FLAT_PLAIN / FLAT_INLINE) into an owned Vec.
    /// Handles FLAT_INLINE data that spans block region + inline tail.
    pub(crate) fn read_flat_data_vec(
        &self,
        nid: u64,
        inode: &ErofsInode<'_>,
        offset: u64,
        size: usize,
    ) -> io::Result<Vec<u8>> {
        let layout = inode.data_layout();
        if layout == EROFS_INODE_FLAT_INLINE {
            let file_size = inode.size() as usize;
            let blk_sz = EROFS_BLOCK_SIZE as usize;
            let tail_size = if file_size % blk_sz == 0 && file_size > 0 {
                0
            } else {
                file_size % blk_sz
            };
            let blocks_size = file_size - tail_size;

            // Check if read spans block+inline boundary
            if blocks_size > 0
                && (offset as usize) < blocks_size
                && (offset as usize + size) > blocks_size
            {
                let mut result = Vec::with_capacity(size);

                // Read block portion
                let block_read_size = blocks_size - offset as usize;
                let startblk = inode.startblk();
                let block_offset = (startblk * EROFS_BLOCK_SIZE as u64 + offset) as usize;
                let block_data = self.mmap_slice(block_offset, block_read_size)?;
                result.extend_from_slice(block_data);

                // Read inline tail portion
                let inline_read_size = size - block_read_size;
                let inode_offset = self.nid_to_offset(nid);
                let header_size = inode.header_size() + inode.xattr_size();
                let inline_data = self.mmap_slice(inode_offset + header_size, inline_read_size)?;
                result.extend_from_slice(inline_data);

                return Ok(result);
            }
        }

        // Non-spanning cases — delegate to slice version
        let slice = self.read_flat_data(nid, inode, offset, size)?;
        Ok(slice.to_vec())
    }

    /// Read symlink target (sync, mmap-only).
    pub fn read_symlink(&self, nid: u64, inode: &ErofsInode<'_>) -> io::Result<Vec<u8>> {
        let size = inode.size() as usize;
        self.read_flat_data_vec(nid, inode, 0, size)
    }

    /// Read all inline xattr entries for an inode.
    /// Returns a list of (full_name_bytes, value) pairs.
    pub fn read_xattrs(
        &self,
        nid: u64,
        inode: &ErofsInode<'_>,
    ) -> io::Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let xattr_size = inode.xattr_size();
        if xattr_size == 0 {
            return Ok(Vec::new());
        }

        let inode_offset = self.nid_to_offset(nid);
        let xattr_offset = inode_offset + inode.header_size();
        let xattr_data = self.mmap_slice(xattr_offset, xattr_size)?;

        // Skip the ibody header (12 bytes) and shared xattr references
        if xattr_data.len() < EROFS_XATTR_IBODY_HEADER_SIZE {
            return Ok(Vec::new());
        }
        let h_shared_count = xattr_data[4] as usize;
        let entries_start = EROFS_XATTR_IBODY_HEADER_SIZE + h_shared_count * 4;
        if entries_start >= xattr_data.len() {
            return Ok(Vec::new());
        }

        let mut result = Vec::new();
        let mut pos = entries_start;

        while pos + EROFS_XATTR_ENTRY_HEADER_SIZE <= xattr_data.len() {
            let e_name_len = xattr_data[pos] as usize;
            let e_name_index = xattr_data[pos + 1];
            let e_value_size =
                u16::from_le_bytes([xattr_data[pos + 2], xattr_data[pos + 3]]) as usize;

            let name_start = pos + EROFS_XATTR_ENTRY_HEADER_SIZE;
            let name_end = name_start + e_name_len;
            let value_start = name_end;
            let value_end = value_start + e_value_size;

            if value_end > xattr_data.len() {
                break;
            }

            // Build full name: prefix + suffix (both as bytes)
            let suffix = &xattr_data[name_start..name_end];
            let full_name = match erofs_xattr_prefix(e_name_index) {
                Some(prefix) => [prefix, suffix].concat(),
                None => suffix.to_vec(),
            };

            let value = xattr_data[value_start..value_end].to_vec();
            result.push((full_name, value));

            // Advance to next entry (4-byte aligned)
            pos = round_up(value_end, EROFS_XATTR_ENTRY_HEADER_SIZE);
        }

        Ok(result)
    }
}

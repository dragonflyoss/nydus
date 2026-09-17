use std::io;

use nydus_format::erofs::{
    cast_ref, erofs_xattr_prefix, ErofsDirent, ErofsInode, EROFS_BLOCK_SIZE, EROFS_DIRENT_SIZE,
    EROFS_INODE_EXTENDED_SIZE, EROFS_INODE_FLAT_INLINE, EROFS_INODE_FLAT_PLAIN,
    EROFS_XATTR_ENTRY_HEADER_SIZE, EROFS_XATTR_IBODY_HEADER_SIZE,
};
use nydus_format::utils::align_up_usize;

use super::{ErofsReader, RawDirEntry};

impl ErofsReader {
    /// Get a zero-copy inode view from the mmap.
    pub fn inode(&self, nid: u64) -> io::Result<ErofsInode<'_>> {
        let offset = self.nid_to_offset(nid);
        let data = self.mmap_slice(offset, EROFS_INODE_EXTENDED_SIZE)?;
        ErofsInode::parse(data)
    }

    /// Size of a FLAT_INLINE inode's block-backed region; bytes past it live
    /// in the inline tail. A file ending exactly on a block boundary has no
    /// tail.
    pub(crate) fn block_region_size(inode: &ErofsInode<'_>) -> usize {
        let file_size = inode.size() as usize;
        let blk_sz = EROFS_BLOCK_SIZE as usize;
        if file_size % blk_sz == 0 && file_size > 0 {
            file_size
        } else {
            file_size - file_size % blk_sz
        }
    }

    /// Iterate directory entries without materializing the whole directory in memory.
    /// Returning `false` from the callback stops iteration.
    pub fn for_each_dir_entry<F>(
        &self,
        nid: u64,
        inode: &ErofsInode<'_>,
        mut cb: F,
    ) -> io::Result<()>
    where
        F: FnMut(u64, u8, &[u8]) -> io::Result<bool>,
    {
        self.for_each_dir_entry_from(nid, inode, 0, |entry_nid, file_type, name, _| {
            cb(entry_nid, file_type, name)
        })
    }

    /// Iterate from a logical directory byte offset, seeking directly to its block.
    /// The callback receives the next dirent's offset (or the next block / EOF
    /// after a block's last entry). Pass back the last accepted entry's offset
    /// to resume; returning `false` stops iteration without consuming the entry.
    pub fn for_each_dir_entry_from<F>(
        &self,
        nid: u64,
        inode: &ErofsInode<'_>,
        offset: u64,
        mut cb: F,
    ) -> io::Result<()>
    where
        F: FnMut(u64, u8, &[u8], u64) -> io::Result<bool>,
    {
        let dir_size = inode.size();
        if offset >= dir_size {
            return Ok(());
        }
        let block_size = EROFS_BLOCK_SIZE as u64;
        let mut pos = offset / block_size * block_size;
        let mut start = ((offset % block_size) as usize).div_ceil(EROFS_DIRENT_SIZE);

        while pos < dir_size {
            let block_len = (dir_size - pos).min(block_size) as usize;
            // Reading one block at a time also keeps FLAT_INLINE tails zero-copy.
            let data = self.read_flat_data(nid, inode, pos, block_len)?;
            let (block_data, count) = Self::dir_block(data, block_len, 0)
                .filter(|(_, count)| *count > 0)
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid directory block")
                })?;
            for i in start..count {
                let (entry_nid, name) =
                    Self::dir_block_entry(block_data, count, i).ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidData, "invalid directory entry")
                    })?;
                let de: &ErofsDirent = cast_ref(&block_data[i * EROFS_DIRENT_SIZE..]);
                let next_offset = if i + 1 < count {
                    pos + ((i + 1) * EROFS_DIRENT_SIZE) as u64
                } else {
                    pos + block_len as u64
                };
                if !cb(entry_nid, de.file_type(), name, next_offset)? {
                    return Ok(());
                }
            }
            pos += block_len as u64;
            start = 0;
        }
        Ok(())
    }

    /// Read directory entries from a directory inode.
    pub fn read_dir(&self, nid: u64, inode: &ErofsInode<'_>) -> io::Result<Vec<RawDirEntry>> {
        let mut entries = Vec::new();
        self.for_each_dir_entry(nid, inode, |entry_nid, file_type, name| {
            entries.push(RawDirEntry {
                nid: entry_nid,
                file_type,
                name: name.to_vec(),
            });
            Ok(true)
        })?;
        Ok(entries)
    }

    /// Look up `name` in directory `nid` by binary search over the sorted
    /// EROFS dirents (across blocks, then within the block), the same
    /// algorithm the kernel driver uses. Returns the child nid, or `None`
    /// when the name is absent or the directory data is malformed.
    pub fn lookup_dir_entry(
        &self,
        nid: u64,
        inode: &ErofsInode<'_>,
        name: &[u8],
    ) -> io::Result<Option<u64>> {
        let dir_size = inode.size() as usize;
        if dir_size == 0 {
            return Ok(None);
        }
        match self.read_flat_data(nid, inode, 0, dir_size) {
            Ok(data) => Ok(Self::find_dir_entry(data, dir_size, name)),
            Err(_) => {
                let data = self.read_flat_data_vec(nid, inode, 0, dir_size)?;
                Ok(Self::find_dir_entry(&data, dir_size, name))
            }
        }
    }

    /// Entry `index` of one directory block as `(nid, name)`. `dirent_count`
    /// must come from [`dir_block`], which bounds it by the bytes that
    /// physically fit, so the dirent casts below cannot go out of range; only
    /// the untrusted name offsets still need checking.
    fn dir_block_entry(
        block_data: &[u8],
        dirent_count: usize,
        index: usize,
    ) -> Option<(u64, &[u8])> {
        let block_len = block_data.len();
        let de_off = index * EROFS_DIRENT_SIZE;
        let de: &ErofsDirent = cast_ref(&block_data[de_off..de_off + EROFS_DIRENT_SIZE]);
        let nameoff = de.nameoff() as usize;
        let name_end = if index + 1 < dirent_count {
            let next: &ErofsDirent = cast_ref(&block_data[(index + 1) * EROFS_DIRENT_SIZE..]);
            next.nameoff() as usize
        } else {
            let mut end = nameoff.min(block_len);
            while end < block_len && block_data[end] != 0 {
                end += 1;
            }
            end
        };
        if nameoff >= block_len || name_end > block_len || name_end < nameoff {
            return None;
        }
        Some((de.nid(), &block_data[nameoff..name_end]))
    }

    /// Directory block `index` of a directory of `dir_size` bytes, with its
    /// entry count capped by what physically fits in the block.
    fn dir_block(data: &[u8], dir_size: usize, index: usize) -> Option<(&[u8], usize)> {
        let block_size = EROFS_BLOCK_SIZE as usize;
        let start = index * block_size;
        let end = (start + block_size).min(dir_size);
        let block_data = &data[start..end];
        if block_data.len() < EROFS_DIRENT_SIZE {
            return None;
        }
        let first: &ErofsDirent = cast_ref(&block_data[..EROFS_DIRENT_SIZE]);
        let count = (first.nameoff() as usize / EROFS_DIRENT_SIZE)
            .min(block_data.len() / EROFS_DIRENT_SIZE);
        Some((block_data, count))
    }

    fn find_dir_entry(data: &[u8], dir_size: usize, target: &[u8]) -> Option<u64> {
        let block_size = EROFS_BLOCK_SIZE as usize;
        let nblocks = dir_size.div_ceil(block_size);

        // Rightmost block whose first entry name is <= target.
        let (mut lo, mut hi) = (0usize, nblocks);
        while hi - lo > 1 {
            let mid = (lo + hi) / 2;
            let first_name = Self::dir_block(data, dir_size, mid)
                .and_then(|(bd, count)| Self::dir_block_entry(bd, count, 0))
                .map(|(_, name)| name)?;
            if first_name <= target {
                lo = mid;
            } else {
                hi = mid;
            }
        }

        let (block_data, count) = Self::dir_block(data, dir_size, lo)?;
        let (mut left, mut right) = (0usize, count);
        while left < right {
            let mid = left + (right - left) / 2;
            let (entry_nid, entry_name) = Self::dir_block_entry(block_data, count, mid)?;
            match entry_name.cmp(target) {
                std::cmp::Ordering::Equal => return Some(entry_nid),
                std::cmp::Ordering::Less => left = mid + 1,
                std::cmp::Ordering::Greater => right = mid,
            }
        }
        None
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
                let blocks_size = Self::block_region_size(inode);

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
            let blocks_size = Self::block_region_size(inode);

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

        // Each shared-xattr reference after the ibody header is one u32 id.
        const SHARED_XATTR_ID_SIZE: usize = 4;
        // Entries are packed on 4-byte boundaries.
        const XATTR_ENTRY_ALIGN: usize = 4;

        // Skip the ibody header (12 bytes) and shared xattr references
        if xattr_data.len() < EROFS_XATTR_IBODY_HEADER_SIZE {
            return Ok(Vec::new());
        }

        let shared_count = xattr_data[4] as usize;
        let entries_start = EROFS_XATTR_IBODY_HEADER_SIZE + shared_count * SHARED_XATTR_ID_SIZE;
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
            pos = align_up_usize(value_end, XATTR_ENTRY_ALIGN).expect("alignment overflowed");
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nydus_format::erofs::{
        ErofsInodeCompact, ErofsSuperblock, EROFS_FT_REG_FILE, EROFS_SUPER_OFFSET,
    };
    use std::io::Write;

    fn directory_reader(data: &[u8]) -> ErofsReader {
        let block_size = EROFS_BLOCK_SIZE as usize;
        let mut image = vec![0; 2 * block_size + data.len()];
        let sb = ErofsSuperblock::new(
            0,
            0,
            0,
            1,
            0,
            image.len().div_ceil(block_size) as u64,
            1,
            0,
            0,
            &[0; 16],
        )
        .unwrap();
        let sb_offset = EROFS_SUPER_OFFSET as usize;
        image[sb_offset..sb_offset + sb.as_bytes().len()].copy_from_slice(sb.as_bytes());
        let inode = ErofsInodeCompact::new(
            0,
            libc::S_IFDIR as u16 | 0o755,
            2,
            data.len() as u32,
            0,
            2,
            0,
            0,
            0,
        );
        image[block_size..block_size + inode.as_bytes().len()].copy_from_slice(inode.as_bytes());
        image[2 * block_size..].copy_from_slice(data);
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(&image).unwrap();
        ErofsReader::open_metadata_only(file.path()).unwrap()
    }

    #[test]
    fn directory_iteration_seeks_past_previous_blocks_and_entries() {
        let block_size = EROFS_BLOCK_SIZE as usize;
        let mut data = vec![0; block_size + 39];
        // The preceding block is invalid, as is the first entry of this block.
        // Resuming at the third entry must not parse either of them.
        for (index, nameoff) in [37, 36, 38].into_iter().enumerate() {
            let entry = ErofsDirent::new(index as u64 + 1, nameoff, EROFS_FT_REG_FILE);
            let start = block_size + index * EROFS_DIRENT_SIZE;
            data[start..start + EROFS_DIRENT_SIZE].copy_from_slice(entry.as_bytes());
        }
        data[block_size + 38] = b'z';
        let reader = directory_reader(&data);
        let inode = reader.inode(0).unwrap();
        for offset in [0, block_size as u64] {
            let err = reader
                .for_each_dir_entry_from(0, &inode, offset, |_, _, _, _| {
                    panic!("malformed entry must not reach the callback")
                })
                .unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        }
        let mut seen = Vec::new();
        reader
            .for_each_dir_entry_from(
                0,
                &inode,
                (block_size + 2 * EROFS_DIRENT_SIZE) as u64,
                |nid, ft, name, next| {
                    seen.push((nid, ft, name.to_vec(), next));
                    Ok(true)
                },
            )
            .unwrap();
        assert_eq!(
            seen,
            vec![(3, EROFS_FT_REG_FILE, b"z".to_vec(), inode.size())]
        );
    }

    #[test]
    fn directory_iteration_handles_empty_and_invalid_blocks() {
        for data in [
            vec![],
            vec![0; EROFS_DIRENT_SIZE - 1],
            vec![0; EROFS_DIRENT_SIZE],
            ErofsDirent::new(1, u16::MAX, EROFS_FT_REG_FILE)
                .as_bytes()
                .to_vec(),
        ] {
            let reader = directory_reader(&data);
            let inode = reader.inode(0).unwrap();
            let result = reader.for_each_dir_entry_from(0, &inode, 0, |_, _, _, _| {
                panic!("empty or invalid directory must not yield entries")
            });
            if data.is_empty() {
                result.unwrap();
            } else {
                assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
            }
        }
    }
}

use nydus_format::erofs::{EROFS_BLOCK_SIZE, EROFS_SLOTSIZE};
use nydus_format::utils::align_up_usize;

/// Metadata layout allocator.
///
/// Manages a contiguous byte buffer representing the metadata area
/// starting at `meta_blkaddr` (block 1 = byte 4096 in the image).
///
/// Two-phase usage:
/// 1. Allocate inode slots with `alloc_inode()` — returns (offset, nid).
/// 2. Call `pad_to_block()` to align for directory data.
/// 3. Allocate directory data blocks with `alloc_dir_data()`.
/// 4. Write serialized data at the reserved offsets with `write_at()`.
pub(crate) struct MetadataLayout {
    /// The metadata byte buffer.
    buf: Vec<u8>,

    /// Current allocation cursor.
    cursor: usize,

    /// Starting block address of the metadata area in the image.
    meta_blkaddr: u32,
}

impl Default for MetadataLayout {
    fn default() -> Self {
        Self::new()
    }
}

impl MetadataLayout {
    pub(crate) fn new() -> Self {
        Self::with_meta_blkaddr(1)
    }

    /// A layout whose metadata area starts at `meta_blkaddr` instead of the
    /// default block 1, for images whose device table pushes the metadata
    /// region past block 0.
    pub(crate) fn with_meta_blkaddr(meta_blkaddr: u32) -> Self {
        Self {
            buf: Vec::new(),
            cursor: 0,
            meta_blkaddr,
        }
    }

    /// The serialized metadata area.
    pub(crate) fn buf(&self) -> &[u8] {
        &self.buf
    }

    /// Allocate space for an inode. Returns `(offset_in_buf, nid)`.
    ///
    /// `has_inline` marks inodes whose tail-packed data is stored right behind
    /// the inode header (`EROFS_INODE_FLAT_INLINE`). The kernel requires that
    /// tail to stay inside the inode's own metadata block, so such an inode is
    /// pushed to the next block instead of straddling the boundary.
    pub(crate) fn alloc_inode(&mut self, size: usize, has_inline: bool) -> (usize, u64) {
        let block = EROFS_BLOCK_SIZE as usize;
        if has_inline && self.cursor % block + size > block {
            self.cursor = align_up_usize(self.cursor, block).expect("alignment overflowed");
        }

        let aligned = align_up_usize(size, EROFS_SLOTSIZE as usize).expect("alignment overflowed");
        let offset = self.cursor;
        self.cursor += aligned;
        if self.buf.len() < self.cursor {
            self.buf.resize(self.cursor, 0);
        }

        let nid = (offset / EROFS_SLOTSIZE as usize) as u64;
        (offset, nid)
    }

    /// Pad the metadata buffer to the next block boundary.
    pub(crate) fn pad_to_block(&mut self) -> usize {
        let aligned =
            align_up_usize(self.cursor, EROFS_BLOCK_SIZE as usize).expect("alignment overflowed");
        self.cursor = aligned;
        if self.buf.len() < self.cursor {
            self.buf.resize(self.cursor, 0);
        }

        self.cursor
    }

    /// Allocate block-aligned space for directory data.
    /// Returns (offset_in_buf, start_block_address).
    pub(crate) fn alloc_dir_data(&mut self, size: usize) -> (usize, u64) {
        self.cursor =
            align_up_usize(self.cursor, EROFS_BLOCK_SIZE as usize).expect("alignment overflowed");
        let offset = self.cursor;
        let aligned_size =
            align_up_usize(size, EROFS_BLOCK_SIZE as usize).expect("alignment overflowed");
        self.cursor += aligned_size;
        if self.buf.len() < self.cursor {
            self.buf.resize(self.cursor, 0);
        }

        let startblk = self.meta_blkaddr as u64 + (offset / EROFS_BLOCK_SIZE as usize) as u64;
        (offset, startblk)
    }

    /// Write data at a previously allocated offset.
    pub(crate) fn write_at(&mut self, offset: usize, data: &[u8]) {
        self.buf[offset..offset + data.len()].copy_from_slice(data);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BLOCK: usize = EROFS_BLOCK_SIZE as usize;
    const SLOT: usize = EROFS_SLOTSIZE as usize;

    /// Fill the metadata area up to `remaining` bytes before the block end.
    fn fill_to_block_tail(layout: &mut MetadataLayout, remaining: usize) {
        while (BLOCK - layout.cursor % BLOCK) > remaining {
            layout.alloc_inode(SLOT, false);
        }
        assert_eq!(BLOCK - layout.cursor % BLOCK, remaining);
    }

    #[test]
    fn inline_inode_skips_block_boundary() {
        let mut layout = MetadataLayout::new();
        fill_to_block_tail(&mut layout, 64);

        // 32B header + 96B target would run 64 bytes past the block end.
        let (offset, nid) = layout.alloc_inode(SLOT + 96, true);

        assert_eq!(offset % BLOCK, 0, "inline inode must start a new block");
        assert_eq!(nid, (offset / SLOT) as u64);
        assert!(
            offset % BLOCK + SLOT + 96 <= BLOCK,
            "inline data must stay inside one block"
        );
    }

    #[test]
    fn inline_inode_that_fits_is_not_moved() {
        let mut layout = MetadataLayout::new();
        fill_to_block_tail(&mut layout, 128);
        let expected = layout.cursor;

        let (offset, _) = layout.alloc_inode(SLOT + 96, true);

        assert_eq!(offset, expected, "must not waste a block when it fits");
    }

    #[test]
    fn non_inline_inode_may_straddle_blocks() {
        let mut layout = MetadataLayout::new();
        fill_to_block_tail(&mut layout, 64);
        let expected = layout.cursor;

        // Chunk indexes are read one at a time, so they may cross blocks.
        let (offset, _) = layout.alloc_inode(SLOT + 96, false);

        assert_eq!(offset, expected);
    }

    #[test]
    fn inline_inode_exactly_filling_block_tail_stays() {
        let mut layout = MetadataLayout::new();
        fill_to_block_tail(&mut layout, 128);
        let expected = layout.cursor;

        let (offset, _) = layout.alloc_inode(128, true);

        assert_eq!(offset, expected);
        assert_eq!(layout.cursor % BLOCK, 0);
    }
}

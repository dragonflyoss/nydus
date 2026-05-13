use super::{EROFS_BLOCK_SIZE, EROFS_SLOTSIZE};

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
pub struct MetadataLayout {
    /// The metadata byte buffer.
    pub buf: Vec<u8>,
    /// Current allocation cursor.
    cursor: usize,
    /// Starting block address of the metadata area in the image.
    pub meta_blkaddr: u32,
}

impl Default for MetadataLayout {
    fn default() -> Self {
        Self::new()
    }
}

impl MetadataLayout {
    pub fn new() -> Self {
        Self {
            buf: Vec::new(),
            cursor: 0,
            meta_blkaddr: 1,
        }
    }

    /// Allocate space for an inode. Returns `(offset_in_buf, nid)`.
    pub fn alloc_inode(&mut self, size: usize) -> (usize, u64) {
        let aligned = round_up_usize(size, EROFS_SLOTSIZE as usize);
        let offset = self.cursor;
        self.cursor += aligned;
        if self.buf.len() < self.cursor {
            self.buf.resize(self.cursor, 0);
        }
        let nid = (offset / EROFS_SLOTSIZE as usize) as u64;
        (offset, nid)
    }

    /// Pad the metadata buffer to the next block boundary.
    pub fn pad_to_block(&mut self) -> usize {
        let aligned = round_up_usize(self.cursor, EROFS_BLOCK_SIZE as usize);
        self.cursor = aligned;
        if self.buf.len() < self.cursor {
            self.buf.resize(self.cursor, 0);
        }
        self.cursor
    }

    /// Allocate block-aligned space for directory data.
    /// Returns (offset_in_buf, start_block_address).
    pub fn alloc_dir_data(&mut self, size: usize) -> (usize, u64) {
        self.cursor = round_up_usize(self.cursor, EROFS_BLOCK_SIZE as usize);
        let offset = self.cursor;
        let aligned_size = round_up_usize(size, EROFS_BLOCK_SIZE as usize);
        self.cursor += aligned_size;
        if self.buf.len() < self.cursor {
            self.buf.resize(self.cursor, 0);
        }
        let startblk = self.meta_blkaddr as u64 + (offset / EROFS_BLOCK_SIZE as usize) as u64;
        (offset, startblk)
    }

    /// Write data at a previously allocated offset.
    pub fn write_at(&mut self, offset: usize, data: &[u8]) {
        self.buf[offset..offset + data.len()].copy_from_slice(data);
    }

    /// Total number of blocks used by metadata (rounded up).
    pub fn total_blocks(&self) -> u64 {
        round_up_usize(self.buf.len(), EROFS_BLOCK_SIZE as usize) as u64 / EROFS_BLOCK_SIZE as u64
    }
}

fn round_up_usize(val: usize, align: usize) -> usize {
    (val + align - 1) & !(align - 1)
}

use std::io;
use std::io::Write;

use crate::metadata::*;

use super::ErofsReader;

impl ErofsReader {
    fn chunkbits(&self, inode: &ErofsInode<'_>) -> u32 {
        self.sb().blkszbits as u32 + (inode.chunk_format() as u32 & 0x1F)
    }

    fn chunk_indexes<'a>(&'a self, nid: u64, inode: &ErofsInode<'_>) -> io::Result<&'a [u8]> {
        if inode.data_layout() != EROFS_INODE_CHUNK_BASED {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "not a chunk-based inode",
            ));
        }
        let chunkbits = self.chunkbits(inode);
        let chunksize = 1u64 << chunkbits;
        let nchunks = inode.size().div_ceil(chunksize) as usize;
        let inode_offset = self.nid_to_offset(nid);
        let header_size = inode.header_size() + inode.xattr_size();
        let ci_offset = inode_offset + header_size;
        let ci_total = nchunks * EROFS_CHUNK_INDEX_SIZE;
        self.mmap_slice(ci_offset, ci_total)
    }

    fn chunk_index_at(ci_data: &[u8], i: usize) -> &ErofsChunkIndex {
        let off = i * EROFS_CHUNK_INDEX_SIZE;
        cast_ref::<ErofsChunkIndex>(&ci_data[off..])
    }

    // ------------------------------------------------------------------
    // Zero-copy write: mmap slices → Writer directly (no intermediate Vec)
    // ------------------------------------------------------------------

    /// Write file data directly to a writer, avoiding intermediate allocation.
    /// Returns the number of bytes written.
    pub fn write_file_data_to(
        &self,
        nid: u64,
        inode: &ErofsInode<'_>,
        offset: u64,
        size: u32,
        w: &mut dyn Write,
    ) -> io::Result<usize> {
        if offset >= inode.size() {
            return Ok(0);
        }
        let actual_size = std::cmp::min(size as u64, inode.size() - offset) as usize;
        let layout = inode.data_layout();

        match layout {
            EROFS_INODE_FLAT_PLAIN | EROFS_INODE_FLAT_INLINE => {
                self.write_flat_data_to(nid, inode, offset, actual_size, w)
            }
            EROFS_INODE_CHUNK_BASED => self.write_chunk_data_to(nid, inode, offset, actual_size, w),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported data layout: {}", layout),
            )),
        }
    }

    fn write_flat_data_to(
        &self,
        nid: u64,
        inode: &ErofsInode<'_>,
        offset: u64,
        size: usize,
        w: &mut dyn Write,
    ) -> io::Result<usize> {
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

            if blocks_size > 0
                && (offset as usize) < blocks_size
                && (offset as usize + size) > blocks_size
            {
                // Read spans block+inline boundary — two writes
                let block_read_size = blocks_size - offset as usize;
                let startblk = inode.startblk();
                let block_offset = (startblk * EROFS_BLOCK_SIZE as u64 + offset) as usize;
                let block_data = self.mmap_slice(block_offset, block_read_size)?;
                w.write_all(block_data)?;

                let inline_read_size = size - block_read_size;
                let inode_offset = self.nid_to_offset(nid);
                let header_size = inode.header_size() + inode.xattr_size();
                let inline_data = self.mmap_slice(inode_offset + header_size, inline_read_size)?;
                w.write_all(inline_data)?;
                return Ok(size);
            }
        }
        // Non-spanning: single mmap slice → writer
        let slice = self.read_flat_data(nid, inode, offset, size)?;
        w.write_all(slice)?;
        Ok(size)
    }

    fn write_chunk_data_to(
        &self,
        nid: u64,
        inode: &ErofsInode<'_>,
        offset: u64,
        size: usize,
        w: &mut dyn Write,
    ) -> io::Result<usize> {
        let chunkbits = self.chunkbits(inode);
        let chunksize = 1u64 << chunkbits;
        let ci_data = self.chunk_indexes(nid, inode)?;
        let nchunks = inode.size().div_ceil(chunksize) as usize;

        let mut remaining = size;
        let mut file_pos = offset;

        while remaining > 0 {
            let chunk_idx = (file_pos / chunksize) as usize;
            let chunk_off = file_pos % chunksize;
            let to_read = std::cmp::min(remaining, (chunksize - chunk_off) as usize);

            if chunk_idx >= nchunks {
                break;
            }

            let ci = Self::chunk_index_at(ci_data, chunk_idx);
            let blkaddr = ci.blkaddr();
            if blkaddr == u64::MAX {
                // Hole — write zeros (use small stack buffer to avoid large alloc)
                let zeros = [0u8; 4096];
                let mut left = to_read;
                while left > 0 {
                    let n = std::cmp::min(left, zeros.len());
                    w.write_all(&zeros[..n])?;
                    left -= n;
                }
            } else if ci.device_id() > 0 {
                let blob_offset = (blkaddr * EROFS_BLOCK_SIZE as u64 + chunk_off) as usize;
                let slice = self.blob_mmap_slice(blob_offset, to_read)?;
                w.write_all(slice)?;
            } else {
                let data_offset = (blkaddr * EROFS_BLOCK_SIZE as u64 + chunk_off) as usize;
                let slice = self.mmap_slice(data_offset, to_read)?;
                w.write_all(slice)?;
            }

            file_pos += to_read as u64;
            remaining -= to_read;
        }

        Ok(size - remaining)
    }

    // ------------------------------------------------------------------
    // File data read — sync (kept for compatibility)
    // ------------------------------------------------------------------

    pub fn read_file_data_sync(
        &self,
        nid: u64,
        inode: &ErofsInode<'_>,
        offset: u64,
        size: u32,
    ) -> io::Result<Vec<u8>> {
        if offset >= inode.size() {
            return Ok(Vec::new());
        }
        let actual_size = std::cmp::min(size as u64, inode.size() - offset) as usize;
        let layout = inode.data_layout();

        match layout {
            EROFS_INODE_FLAT_PLAIN | EROFS_INODE_FLAT_INLINE => {
                self.read_flat_data_vec(nid, inode, offset, actual_size)
            }
            EROFS_INODE_CHUNK_BASED => self.read_chunk_data_sync(nid, inode, offset, actual_size),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported data layout: {}", layout),
            )),
        }
    }

    // ------------------------------------------------------------------
    // File data read — async
    // ------------------------------------------------------------------

    pub async fn read_file_data(
        &self,
        nid: u64,
        inode: &ErofsInode<'_>,
        offset: u64,
        size: u32,
    ) -> io::Result<Vec<u8>> {
        if offset >= inode.size() {
            return Ok(Vec::new());
        }
        let actual_size = std::cmp::min(size as u64, inode.size() - offset) as usize;
        let layout = inode.data_layout();

        match layout {
            EROFS_INODE_FLAT_PLAIN | EROFS_INODE_FLAT_INLINE => {
                self.read_flat_data_vec(nid, inode, offset, actual_size)
            }
            EROFS_INODE_CHUNK_BASED => {
                self.read_chunk_data_async(nid, inode, offset, actual_size)
                    .await
            }
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported data layout: {}", layout),
            )),
        }
    }

    // ------------------------------------------------------------------
    // Chunk data — sync
    // ------------------------------------------------------------------

    fn read_chunk_data_sync(
        &self,
        nid: u64,
        inode: &ErofsInode<'_>,
        offset: u64,
        size: usize,
    ) -> io::Result<Vec<u8>> {
        let chunkbits = self.chunkbits(inode);
        let chunksize = 1u64 << chunkbits;
        let ci_data = self.chunk_indexes(nid, inode)?;
        let nchunks = inode.size().div_ceil(chunksize) as usize;

        let mut result = vec![0u8; size];
        let mut remaining = size;
        let mut file_pos = offset;
        let mut buf_pos = 0;

        while remaining > 0 {
            let chunk_idx = (file_pos / chunksize) as usize;
            let chunk_off = file_pos % chunksize;
            let to_read = std::cmp::min(remaining, (chunksize - chunk_off) as usize);

            if chunk_idx >= nchunks {
                break;
            }

            let ci = Self::chunk_index_at(ci_data, chunk_idx);
            let blkaddr = ci.blkaddr();
            if blkaddr == u64::MAX {
                // Hole — zeros
            } else if ci.device_id() > 0 {
                let blob_offset = (blkaddr * EROFS_BLOCK_SIZE as u64 + chunk_off) as usize;
                let slice = self.blob_mmap_slice(blob_offset, to_read)?;
                result[buf_pos..buf_pos + to_read].copy_from_slice(slice);
            } else {
                let data_offset = (blkaddr * EROFS_BLOCK_SIZE as u64 + chunk_off) as usize;
                let slice = self.mmap_slice(data_offset, to_read)?;
                result[buf_pos..buf_pos + to_read].copy_from_slice(slice);
            }

            file_pos += to_read as u64;
            buf_pos += to_read;
            remaining -= to_read;
        }

        Ok(result)
    }

    // ------------------------------------------------------------------
    // Chunk data — async
    // ------------------------------------------------------------------

    async fn read_chunk_data_async(
        &self,
        nid: u64,
        inode: &ErofsInode<'_>,
        offset: u64,
        size: usize,
    ) -> io::Result<Vec<u8>> {
        let chunkbits = self.chunkbits(inode);
        let chunksize = 1u64 << chunkbits;
        let ci_data = self.chunk_indexes(nid, inode)?;
        let nchunks = inode.size().div_ceil(chunksize) as usize;

        let mut result = vec![0u8; size];
        let mut remaining = size;
        let mut file_pos = offset;
        let mut buf_pos = 0;

        while remaining > 0 {
            let chunk_idx = (file_pos / chunksize) as usize;
            let chunk_off = file_pos % chunksize;
            let to_read = std::cmp::min(remaining, (chunksize - chunk_off) as usize);

            if chunk_idx >= nchunks {
                break;
            }

            let ci = Self::chunk_index_at(ci_data, chunk_idx);
            let blkaddr = ci.blkaddr();
            if blkaddr == u64::MAX {
                // Hole — zeros
            } else if ci.device_id() > 0 {
                let blob_offset = (blkaddr * EROFS_BLOCK_SIZE as u64 + chunk_off) as usize;
                let slice = self.blob_mmap_slice(blob_offset, to_read)?;
                result[buf_pos..buf_pos + to_read].copy_from_slice(slice);
            } else {
                let data_offset = (blkaddr * EROFS_BLOCK_SIZE as u64 + chunk_off) as usize;
                let slice = self.mmap_slice(data_offset, to_read)?;
                result[buf_pos..buf_pos + to_read].copy_from_slice(slice);
            }

            file_pos += to_read as u64;
            buf_pos += to_read;
            remaining -= to_read;
        }

        Ok(result)
    }
}

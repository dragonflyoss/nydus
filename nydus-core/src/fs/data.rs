use std::io;
use std::io::Write;

use crate::metadata::*;

use super::{ErofsReader, RawBlobInfo};

/// Resolve an absolute byte offset in the flattened device to the blob that
/// backs it, returning `(blob_index, offset_within_blob)`. Returns `None` when
/// the address is bootstrap-local (not in any blob's mapped range).
fn locate_flat_blob(blob_layout: &[RawBlobInfo], abs_byte: u64) -> Option<(u16, u64)> {
    let block_size = EROFS_BLOCK_SIZE as u64;
    for info in blob_layout {
        let start = info.mapped_blkaddr * block_size;
        let end = start + info.blocks * block_size;
        if abs_byte >= start && abs_byte < end {
            return Some((info.blob_index, abs_byte - start));
        }
    }
    None
}

impl ErofsReader {
    fn chunkbits(&self, inode: &ErofsInode<'_>) -> u32 {
        self.sb().blkszbits as u32 + (inode.chunk_format() as u32 & 0x1F)
    }

    fn chunk_index_bytes<'a>(&'a self, nid: u64, inode: &ErofsInode<'_>) -> io::Result<&'a [u8]> {
        if inode.data_layout() != EROFS_INODE_CHUNK_BASED {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "not a chunk-based inode",
            ));
        }
        let chunkbits = self.chunkbits(inode);
        let chunk_size = 1u64 << chunkbits;
        let nchunks = inode.size().div_ceil(chunk_size) as usize;
        let inode_offset = self.nid_to_offset(nid);
        let header_size = inode.header_size() + inode.xattr_size();
        let index_offset = inode_offset + round_up(header_size, EROFS_CHUNK_INDEX_SIZE);
        let index_total = nchunks * EROFS_CHUNK_INDEX_SIZE;
        self.mmap_slice(index_offset, index_total)
    }

    fn chunk_index_entry_at(index_bytes: &[u8], i: usize) -> &ErofsChunkIndex {
        let off = i * EROFS_CHUNK_INDEX_SIZE;
        cast_ref::<ErofsChunkIndex>(&index_bytes[off..])
    }

    pub fn read_chunk_index_entries(
        &self,
        nid: u64,
        inode: &ErofsInode<'_>,
    ) -> io::Result<Vec<ChunkIndex>> {
        if inode.size() == 0 {
            return Ok(Vec::new());
        }

        let chunkbits = self.chunkbits(inode);
        let chunk_size = 1u64 << chunkbits;
        let index_bytes = self.chunk_index_bytes(nid, inode)?;
        let nchunks = inode.size().div_ceil(chunk_size) as usize;
        let mut result = Vec::with_capacity(nchunks);
        for index in 0..nchunks {
            let entry = Self::chunk_index_entry_at(index_bytes, index);
            result.push(ChunkIndex {
                blkaddr: entry.blkaddr(),
                device_id: entry.device_id(),
            });
        }
        Ok(result)
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
                format!("unsupported data layout: {layout}"),
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
            let blocks_size = Self::inline_blocks_size(inode);

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
        let chunk_size = 1u64 << chunkbits;
        let index_bytes = self.chunk_index_bytes(nid, inode)?;
        let nchunks = inode.size().div_ceil(chunk_size) as usize;
        let blob_layout = self.blob_infos()?;

        let mut remaining = size;
        let mut file_pos = offset;

        while remaining > 0 {
            let chunk_index = (file_pos / chunk_size) as usize;
            let chunk_off = file_pos % chunk_size;
            let to_read = std::cmp::min(remaining, (chunk_size - chunk_off) as usize);

            if chunk_index >= nchunks {
                break;
            }

            let entry = Self::chunk_index_entry_at(index_bytes, chunk_index);
            let blkaddr = entry.blkaddr();
            if blkaddr == EROFS_NULL_ADDR {
                // Hole — write zeros (use small stack buffer to avoid large alloc)
                let zeros = [0u8; 4096];
                let mut left = to_read;
                while left > 0 {
                    let n = std::cmp::min(left, zeros.len());
                    w.write_all(&zeros[..n])?;
                    left -= n;
                }
            } else if entry.device_id() > 0 {
                // Legacy separate-blob layout: blob-relative address.
                self.write_blob_to(
                    entry.device_id(),
                    blkaddr * EROFS_BLOCK_SIZE as u64,
                    chunk_off,
                    to_read,
                    w,
                )?;
            } else {
                // Flattened layout: device_id 0 with an absolute address.
                let abs = blkaddr * EROFS_BLOCK_SIZE as u64;
                if let Some((blob_index, blob_rel)) = locate_flat_blob(&blob_layout, abs) {
                    self.write_blob_to(blob_index, blob_rel, chunk_off, to_read, w)?;
                } else {
                    let data_offset = (abs + chunk_off) as usize;
                    let slice = self.mmap_slice(data_offset, to_read)?;
                    w.write_all(slice)?;
                }
            }

            file_pos += to_read as u64;
            remaining -= to_read;
        }

        Ok(size - remaining)
    }

    // ------------------------------------------------------------------
    // File data read
    // ------------------------------------------------------------------

    pub fn read_file_data(
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
            EROFS_INODE_CHUNK_BASED => self.read_chunk_data(nid, inode, offset, actual_size),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported data layout: {layout}"),
            )),
        }
    }

    // ------------------------------------------------------------------
    // Chunk data — sync
    // ------------------------------------------------------------------

    fn read_chunk_data(
        &self,
        nid: u64,
        inode: &ErofsInode<'_>,
        offset: u64,
        size: usize,
    ) -> io::Result<Vec<u8>> {
        let chunkbits = self.chunkbits(inode);
        let chunk_size = 1u64 << chunkbits;
        let index_bytes = self.chunk_index_bytes(nid, inode)?;
        let nchunks = inode.size().div_ceil(chunk_size) as usize;
        let blob_layout = self.blob_infos()?;

        let mut result = vec![0u8; size];
        let mut remaining = size;
        let mut file_pos = offset;
        let mut buf_pos = 0;

        while remaining > 0 {
            let chunk_index = (file_pos / chunk_size) as usize;
            let chunk_off = file_pos % chunk_size;
            let to_read = std::cmp::min(remaining, (chunk_size - chunk_off) as usize);

            if chunk_index >= nchunks {
                break;
            }

            let entry = Self::chunk_index_entry_at(index_bytes, chunk_index);
            self.read_chunk_slice(
                &blob_layout,
                entry,
                chunk_off,
                &mut result[buf_pos..buf_pos + to_read],
            )?;

            file_pos += to_read as u64;
            buf_pos += to_read;
            remaining -= to_read;
        }

        Ok(result)
    }

    /// Resolve one chunk's data into `dst`. Handles holes, the legacy
    /// separate-blob layout (non-zero device_id, blob-relative address) and the
    /// flattened layout (device_id 0 with an absolute address, resolved to a
    /// blob or to bootstrap-local data).
    fn read_chunk_slice(
        &self,
        blob_layout: &[RawBlobInfo],
        entry: &ErofsChunkIndex,
        chunk_off: u64,
        dst: &mut [u8],
    ) -> io::Result<()> {
        let blkaddr = entry.blkaddr();
        if blkaddr == EROFS_NULL_ADDR {
            // Hole — zero the destination explicitly rather than relying on
            // callers to hand in a fresh zeroed buffer.
            dst.fill(0);
            return Ok(());
        }
        if entry.device_id() > 0 {
            return self.read_blob_into(
                entry.device_id(),
                blkaddr * EROFS_BLOCK_SIZE as u64,
                chunk_off,
                dst,
            );
        }
        let abs = blkaddr * EROFS_BLOCK_SIZE as u64;
        if let Some((blob_index, blob_rel)) = locate_flat_blob(blob_layout, abs) {
            self.read_blob_into(blob_index, blob_rel, chunk_off, dst)
        } else {
            let data_offset = (abs + chunk_off) as usize;
            let slice = self.mmap_slice(data_offset, dst.len())?;
            dst.copy_from_slice(slice);
            Ok(())
        }
    }

    /// Resolve an absolute byte offset in the flattened device to the blob that
    /// backs it, returning `(blob_index, offset_within_blob)`, or `None` when it
    /// is bootstrap-local. Used by the prefetch/on-demand fetch path.
    pub(crate) fn flat_blob_at(&self, abs_byte: u64) -> io::Result<Option<(u16, u64)>> {
        let blob_layout = self.blob_infos()?;
        Ok(locate_flat_blob(&blob_layout, abs_byte))
    }
}

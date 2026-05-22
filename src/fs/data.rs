use std::io;
use std::io::Write;

use crate::build::blobchunk::ChunkIndex;
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
        let ci_offset = inode_offset + round_up(header_size, EROFS_CHUNK_INDEX_SIZE);
        let ci_total = nchunks * EROFS_CHUNK_INDEX_SIZE;
        self.mmap_slice(ci_offset, ci_total)
    }

    fn chunk_index_at(ci_data: &[u8], i: usize) -> &ErofsChunkIndex {
        let off = i * EROFS_CHUNK_INDEX_SIZE;
        cast_ref::<ErofsChunkIndex>(&ci_data[off..])
    }

    pub fn read_chunk_indexes(
        &self,
        nid: u64,
        inode: &ErofsInode<'_>,
    ) -> io::Result<Vec<ChunkIndex>> {
        if inode.size() == 0 {
            return Ok(Vec::new());
        }

        let chunkbits = self.chunkbits(inode);
        let chunksize = 1u64 << chunkbits;
        let ci_data = self.chunk_indexes(nid, inode)?;
        let nchunks = inode.size().div_ceil(chunksize) as usize;
        let mut result = Vec::with_capacity(nchunks);
        for index in 0..nchunks {
            let ci = Self::chunk_index_at(ci_data, index);
            result.push(ChunkIndex {
                blkaddr: ci.blkaddr(),
                device_id: ci.device_id(),
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
                self.write_blob_to(
                    ci.device_id(),
                    blkaddr * EROFS_BLOCK_SIZE as u64,
                    chunk_off,
                    to_read,
                    w,
                )?;
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
                self.read_blob_into(
                    ci.device_id(),
                    blkaddr * EROFS_BLOCK_SIZE as u64,
                    chunk_off,
                    &mut result[buf_pos..buf_pos + to_read],
                )?;
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
                self.read_blob_into(
                    ci.device_id(),
                    blkaddr * EROFS_BLOCK_SIZE as u64,
                    chunk_off,
                    &mut result[buf_pos..buf_pos + to_read],
                )?;
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

#[cfg(test)]
mod tests {
    use std::io::Write;

    use tempfile::NamedTempFile;

    use super::ErofsReader;
    use crate::build::blobchunk::ChunkIndex;
    use crate::build::bootstrap::render_bootstrap;
    use crate::build::inode::{DirEntry as BuildDirEntry, InodeData, InodeInfo};
    use crate::metadata::{
        xattr_ibody_size, EROFS_BLKSZBITS, EROFS_BLOCK_SIZE, EROFS_FT_REG_FILE,
        EROFS_XATTR_INDEX_USER,
    };

    #[test]
    fn reads_large_xattrs_and_chunk_indexes_after_large_ibody() {
        let file_xattrs: Vec<(u8, Vec<u8>, Vec<u8>)> = (0..8)
            .map(|index| {
                (
                    EROFS_XATTR_INDEX_USER,
                    format!("large_{index:02}").into_bytes(),
                    vec![b'A' + index as u8; 700],
                )
            })
            .collect();
        assert!(xattr_ibody_size(&file_xattrs) > EROFS_BLOCK_SIZE as usize);

        let mut inodes = vec![
            InodeInfo {
                mode: 0o040755,
                uid: 0,
                gid: 0,
                size: 0,
                mtime: 1_700_000_000,
                mtime_nsec: 0,
                nlink: 2,
                ino: 1,
                nid: 0,
                meta_offset: 0,
                is_extended: true,
                data: InodeData::Directory {
                    children: vec![BuildDirEntry {
                        name: "huge_xattrs".into(),
                        file_type: EROFS_FT_REG_FILE,
                        inode_idx: 1,
                    }],
                    startblk: 0,
                    dir_data_size: 0,
                    parent_nid: 0,
                },
                xattrs: Vec::new(),
            },
            InodeInfo {
                mode: 0o100644,
                uid: 0,
                gid: 0,
                size: (EROFS_BLOCK_SIZE as u64) * 2,
                mtime: 1_700_000_123,
                mtime_nsec: 123_456_789,
                nlink: 1,
                ino: 2,
                nid: 0,
                meta_offset: 0,
                is_extended: false,
                data: InodeData::RegularFile {
                    chunk_indexes: vec![
                        ChunkIndex {
                            blkaddr: 11,
                            device_id: 0,
                        },
                        ChunkIndex {
                            blkaddr: 22,
                            device_id: 0,
                        },
                    ],
                    chunkbits: EROFS_BLKSZBITS as u32,
                },
                xattrs: file_xattrs.clone(),
            },
        ];

        let bootstrap = render_bootstrap(
            &mut inodes,
            1_700_000_000,
            EROFS_BLKSZBITS as u32,
            &[],
            &[0u8; 16],
        )
        .expect("render bootstrap");
        let mut image = NamedTempFile::new().expect("create temp image");
        image.write_all(&bootstrap).expect("write bootstrap");

        let reader = ErofsReader::open_layer(image.path()).expect("open bootstrap");
        let file_nid = inodes[1].nid;
        let inode = reader.inode(file_nid).expect("read inode");

        let xattrs = reader.read_xattrs(file_nid, &inode).expect("read xattrs");
        assert_eq!(xattrs.len(), file_xattrs.len());
        for ((name, value), (_, suffix, expected_value)) in xattrs.iter().zip(file_xattrs.iter()) {
            let expected_name = [b"user.".as_slice(), suffix.as_slice()].concat();
            assert_eq!(name, &expected_name);
            assert_eq!(value, expected_value);
        }

        let chunk_indexes = reader
            .read_chunk_indexes(file_nid, &inode)
            .expect("read chunk indexes");
        assert_eq!(chunk_indexes.len(), 2);
        assert_eq!(chunk_indexes[0].blkaddr, 11);
        assert_eq!(chunk_indexes[0].device_id, 0);
        assert_eq!(chunk_indexes[1].blkaddr, 22);
        assert_eq!(chunk_indexes[1].device_id, 0);
    }
}

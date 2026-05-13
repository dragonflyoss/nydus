use crate::metadata::EROFS_BLOCK_SIZE;
use anyhow::{Context, Result};
use blake3;
use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

/// Represents a chunk stored in the blob device.
#[derive(Clone)]
struct BlobChunk {
    blkaddr: u64,
}

/// Information about a single chunk index to be stored in an inode.
#[derive(Clone)]
pub struct ChunkIndex {
    pub blkaddr: u64,
    pub device_id: u16,
}

/// Manages writing chunk data to a separate blob device with SHA256 dedup.
pub struct BlobWriter {
    file: File,
    chunksize: u32,
    next_blkaddr: u64,
    dedup: HashMap<[u8; 32], BlobChunk>,
    pub saved_by_dedup: u64,
}

impl BlobWriter {
    pub fn new(path: &Path, chunksize: u32) -> Result<Self> {
        let file = File::create(path)
            .with_context(|| format!("failed to create blob device: {}", path.display()))?;
        Ok(Self {
            file,
            chunksize,
            next_blkaddr: 0,
            dedup: HashMap::new(),
            saved_by_dedup: 0,
        })
    }

    pub fn total_blocks(&self) -> u64 {
        self.next_blkaddr
    }

    /// Process a regular file: read it in chunk-sized pieces, dedup via BLAKE3,
    /// write unique chunks to the blob device.
    pub fn write_file_chunks(&mut self, path: &Path, file_size: u64) -> Result<Vec<ChunkIndex>> {
        if file_size == 0 {
            return Ok(Vec::new());
        }

        let mut f =
            File::open(path).with_context(|| format!("failed to open file: {}", path.display()))?;

        let cs = self.chunksize as u64;
        let nchunks = file_size.div_ceil(cs);
        let mut indexes = Vec::with_capacity(nchunks as usize);
        let mut chunk_buf = vec![0u8; self.chunksize as usize];

        for i in 0..nchunks {
            let remaining = file_size - i * cs;
            let to_read = remaining.min(cs) as usize;

            f.read_exact(&mut chunk_buf[..to_read])
                .with_context(|| format!("failed to read file: {}", path.display()))?;

            let hash: [u8; 32] = *blake3::hash(&chunk_buf[..to_read]).as_bytes();

            let write_len = to_read.div_ceil(EROFS_BLOCK_SIZE as usize) * EROFS_BLOCK_SIZE as usize;
            let nblocks = (write_len / EROFS_BLOCK_SIZE as usize) as u64;

            let blkaddr = if let Some(existing) = self.dedup.get(&hash) {
                self.saved_by_dedup += write_len as u64;
                existing.blkaddr
            } else {
                let addr = self.next_blkaddr;
                self.file
                    .write_all(&chunk_buf[..to_read])
                    .context("failed to write to blob device")?;
                if write_len > to_read {
                    let padding = vec![0u8; write_len - to_read];
                    self.file
                        .write_all(&padding)
                        .context("failed to write padding to blob device")?;
                }
                self.next_blkaddr += nblocks;
                self.dedup.insert(hash, BlobChunk { blkaddr: addr });
                addr
            };

            indexes.push(ChunkIndex {
                blkaddr,
                device_id: 1,
            });
        }
        Ok(indexes)
    }
}

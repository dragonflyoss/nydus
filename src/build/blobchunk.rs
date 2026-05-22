use crate::metadata::{BlobMeta, BlobMetaChunk, EROFS_BLOB_ID_SIZE, EROFS_BLOCK_SIZE};
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
    blobmeta_chunks: Vec<BlobMetaChunk>,
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
            blobmeta_chunks: Vec::new(),
            saved_by_dedup: 0,
        })
    }

    pub fn total_blocks(&self) -> u64 {
        self.next_blkaddr
    }

    pub fn blobmeta_chunks(&self) -> &[BlobMetaChunk] {
        &self.blobmeta_chunks
    }

    pub fn blobmeta(
        &self,
        blob_id: [u8; EROFS_BLOB_ID_SIZE],
        source_offset_bias: u64,
    ) -> Result<BlobMeta> {
        BlobMeta::from_chunks(blob_id, self.blobmeta_chunks.clone())
            .with_compressed_offset_bias(source_offset_bias)
    }

    pub fn write_blobmeta(
        &self,
        path: &Path,
        blob_id: [u8; EROFS_BLOB_ID_SIZE],
        source_offset_bias: u64,
    ) -> Result<()> {
        self.blobmeta(blob_id, source_offset_bias)?.save(path)
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
                let entry = BlobMetaChunk::new(
                    addr * EROFS_BLOCK_SIZE as u64,
                    write_len as u32,
                    addr * EROFS_BLOCK_SIZE as u64,
                    write_len as u32,
                )?;
                self.blobmeta_chunks.push(entry);
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn blobmeta_chunk_round_trips_minimal_fields() {
        let entry = BlobMetaChunk::new(0x2000, 0x3000, 0x12345, 0x400).unwrap();

        assert_eq!(entry.uncompressed_offset(), 0x2000);
        assert_eq!(entry.uncompressed_size(), 0x3000);
        assert_eq!(entry.compressed_offset(), 0x12345);
        assert_eq!(entry.compressed_size(), 0x400);
    }

    #[test]
    fn blob_writer_tracks_unique_blobmeta_chunks() {
        let dir = tempdir().unwrap();
        let blob_path = dir.path().join("blob.data");
        let file_a = dir.path().join("a.bin");
        let file_b = dir.path().join("b.bin");

        let mut content_a = vec![b'a'; 4096];
        content_a.extend(vec![b'b'; 904]);
        fs::write(&file_a, &content_a).unwrap();
        fs::write(&file_b, vec![b'a'; 4096]).unwrap();

        let mut writer = BlobWriter::new(&blob_path, 4096).unwrap();
        let indexes_a = writer
            .write_file_chunks(&file_a, content_a.len() as u64)
            .unwrap();
        let indexes_b = writer.write_file_chunks(&file_b, 4096).unwrap();

        assert_eq!(indexes_a.len(), 2);
        assert_eq!(indexes_b.len(), 1);
        assert_eq!(indexes_a[0].blkaddr, 0);
        assert_eq!(indexes_b[0].blkaddr, 0);
        assert_eq!(indexes_a[1].blkaddr, 1);
        assert_eq!(writer.total_blocks(), 2);
        assert_eq!(writer.saved_by_dedup, 4096);

        let entries = writer.blobmeta_chunks();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].uncompressed_offset(), 0);
        assert_eq!(entries[0].uncompressed_size(), 4096);
        assert_eq!(entries[0].compressed_offset(), 0);
        assert_eq!(entries[0].compressed_size(), 4096);
        assert_eq!(entries[1].uncompressed_offset(), 4096);
        assert_eq!(entries[1].uncompressed_size(), 4096);
        assert_eq!(entries[1].compressed_offset(), 4096);
        assert_eq!(entries[1].compressed_size(), 4096);
    }

    #[test]
    fn blob_writer_writes_blobmeta_file() {
        let dir = tempdir().unwrap();
        let blob_path = dir.path().join("blob.data");
        let blobmeta_path = dir.path().join("blob.blob.meta");
        let input_path = dir.path().join("input.bin");
        let blob_id = [7u8; EROFS_BLOB_ID_SIZE];
        fs::write(&input_path, vec![b'x'; 4096]).unwrap();

        let mut writer = BlobWriter::new(&blob_path, 4096).unwrap();
        writer.write_file_chunks(&input_path, 4096).unwrap();
        writer
            .write_blobmeta(&blobmeta_path, blob_id, 8192)
            .unwrap();

        let raw = fs::read(&blobmeta_path).unwrap();
        assert_eq!(raw.len(), 8192);

        let blobmeta = BlobMeta::load(&blobmeta_path).unwrap();
        assert_eq!(blobmeta.header().chunk_count(), 1);
        assert_eq!(blobmeta.header().chunk_bytes(), 24);
        assert_eq!(blobmeta.chunks()[0].uncompressed_offset(), 0);
        assert_eq!(blobmeta.chunks()[0].compressed_offset(), 8192);
    }
}

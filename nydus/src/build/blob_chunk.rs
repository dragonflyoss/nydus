use crc32c::crc32c;
use nydus_error::{Context, Error, Result};
use nydus_format::blob::{
    BlobMetadata, BlobMetadataBlockGroup, BlobMetadataChunk, BlobMetadataCompressor,
    DEFAULT_NYDUS_BLOB_METADATA_BLOCK_GROUP_SIZE,
};
use nydus_format::erofs::{ErofsChunkAddr, EROFS_BLOB_ID_SIZE, EROFS_BLOCK_SIZE, EROFS_NULL_ADDR};
use nydus_format::utils::align_up_usize;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Write};
use std::mem;
use std::path::Path;

/// Manages writing chunk data to a separate blob device.
pub struct BlobWriter<W> {
    writer: W,
    file_chunk_size: u32,
    block_group_size: u32,
    compressor: BlobMetadataCompressor,
    next_blkaddr: u64,
    next_compressed_offset: u64,
    data_hasher: Sha256,
    block_group_block_offset: u64,
    block_group_buffer: Vec<u8>,
    blob_metadata_block_groups: Vec<BlobMetadataBlockGroup>,
    blob_metadata_chunks: Vec<BlobMetadataChunk>,
}

const MAX_COMPRESSED_SIZE_PERCENT: u128 = 70;

impl BlobWriter<File> {
    pub fn new(path: &Path, chunk_size: u32) -> Result<Self> {
        Self::new_with_compressor(path, chunk_size, BlobMetadataCompressor::None)
    }

    pub fn new_with_compressor(
        path: &Path,
        file_chunk_size: u32,
        compressor: BlobMetadataCompressor,
    ) -> Result<Self> {
        if file_chunk_size < EROFS_BLOCK_SIZE {
            return Err(Error::InvalidParameter(
                "blob writer file chunk size must be at least one EROFS block".to_string(),
            ));
        }
        if !file_chunk_size.is_power_of_two() || file_chunk_size % EROFS_BLOCK_SIZE != 0 {
            return Err(Error::InvalidParameter(
                "blob writer file chunk size must be power-of-two and block-aligned".to_string(),
            ));
        }

        let file = File::create(path)
            .with_context(|| format!("failed to create blob device: {}", path.display()))?;
        let block_group_size = file_chunk_size.max(DEFAULT_NYDUS_BLOB_METADATA_BLOCK_GROUP_SIZE);
        Self::from_writer(file, file_chunk_size, block_group_size, compressor)
    }
}

impl<W: Write> BlobWriter<W> {
    pub fn from_writer(
        writer: W,
        file_chunk_size: u32,
        block_group_size: u32,
        compressor: BlobMetadataCompressor,
    ) -> Result<Self> {
        if file_chunk_size < EROFS_BLOCK_SIZE {
            return Err(Error::InvalidParameter(
                "blob writer file chunk size must be at least one EROFS block".to_string(),
            ));
        }
        if !file_chunk_size.is_power_of_two() || file_chunk_size % EROFS_BLOCK_SIZE != 0 {
            return Err(Error::InvalidParameter(
                "blob writer file chunk size must be power-of-two and block-aligned".to_string(),
            ));
        }
        if block_group_size < file_chunk_size {
            return Err(Error::InvalidParameter(
                "blob writer block_group size must be at least the file chunk size".to_string(),
            ));
        }
        // The blob meta header stores the block group's block count as a log2
        // exponent (`block_group_block_count_bits`), so it must be a power of
        // two; being a power of two >= the (block-aligned) chunk size also
        // makes it block aligned by construction.
        if !block_group_size.is_power_of_two() {
            return Err(Error::InvalidParameter(
                "blob writer block_group size must be a power of two".to_string(),
            ));
        }

        Ok(Self {
            writer,
            file_chunk_size,
            block_group_size,
            compressor,
            next_blkaddr: 0,
            next_compressed_offset: 0,
            data_hasher: Sha256::new(),
            block_group_block_offset: 0,
            block_group_buffer: Vec::with_capacity(block_group_size as usize),
            blob_metadata_block_groups: Vec::new(),
            blob_metadata_chunks: Vec::new(),
        })
    }

    pub fn total_blocks(&self) -> u64 {
        self.next_blkaddr
    }

    pub fn data_size(&self) -> u64 {
        self.next_compressed_offset
    }

    pub fn data_digest(&self) -> [u8; EROFS_BLOB_ID_SIZE] {
        let mut digest = [0u8; EROFS_BLOB_ID_SIZE];
        digest.copy_from_slice(&self.data_hasher.clone().finalize());
        digest
    }

    pub fn into_parts(self) -> (W, Sha256) {
        (self.writer, self.data_hasher)
    }

    pub fn blob_metadata_chunks(&self) -> &[BlobMetadataChunk] {
        &self.blob_metadata_chunks
    }

    pub fn blob_metadata_block_groups(&self) -> &[BlobMetadataBlockGroup] {
        &self.blob_metadata_block_groups
    }

    pub fn blob_metadata(&self, source_offset_bias: u64) -> Result<BlobMetadata> {
        Ok(BlobMetadata::new(
            self.compressor,
            self.file_chunk_size / EROFS_BLOCK_SIZE,
            self.blob_metadata_chunks.clone(),
            self.blob_metadata_block_groups.clone(),
        )?
        .checked_add_compressed_offset(source_offset_bias)?)
    }

    pub fn write_blob_metadata(&mut self, path: &Path, source_offset_bias: u64) -> Result<()> {
        self.finish()?;
        Ok(self.blob_metadata(source_offset_bias)?.save(path)?)
    }

    pub fn finish(&mut self) -> Result<()> {
        self.flush_block_group()?;
        self.writer.flush().context("failed to flush blob device")
    }

    /// Process a regular file: read it in chunk-sized pieces and append every
    /// chunk to the blob device. Chunk-level digests are recorded in blob meta;
    /// deduplication is intentionally disabled for now.
    pub fn write_file_chunks(
        &mut self,
        path: &Path,
        file_size: u64,
    ) -> Result<Vec<ErofsChunkAddr>> {
        if file_size == 0 {
            return Ok(Vec::new());
        }

        let mut f = File::open(path)
            .with_context(|| format!("failed to open source file: {}", path.display()))?;

        let chunk_size = self.file_chunk_size as u64;
        let chunk_count = file_size.div_ceil(chunk_size);
        let mut indexes = Vec::with_capacity(chunk_count as usize);
        let mut chunk_buf = vec![0u8; self.file_chunk_size as usize];
        for i in 0..chunk_count {
            let remaining = file_size - i * chunk_size;
            let to_read = remaining.min(chunk_size) as usize;

            f.read_exact(&mut chunk_buf[..to_read])
                .with_context(|| format!("failed to read source file: {}", path.display()))?;

            // A fully-zero chunk (a real filesystem hole reads back as zeros,
            // and so does zero-filled data) is not stored at all: it gets a
            // null chunk index (all 48 address bits set on disk), which every
            // read path already decodes as a hole and satisfies with zeros.
            // No blob data, no blob-meta chunk entry, and no blob cache
            // traffic is ever spent on it — native EROFS mounts handle the
            // null address the same way in-kernel.
            if chunk_buf[..to_read].iter().all(|&byte| byte == 0) {
                indexes.push(ErofsChunkAddr {
                    blkaddr: EROFS_NULL_ADDR,
                    device_id: 0,
                });
                continue;
            }

            // Pad only up to the last block of the chunk's real data, not to the
            // full file chunk size. A full chunk is already block-aligned, while
            // a partial (tail) chunk keeps zero padding confined to its final
            // block so block groups pack dense real blocks instead of large zero runs.
            let write_len =
                align_up_usize(to_read, EROFS_BLOCK_SIZE as usize).expect("alignment overflowed");
            let blkaddr = self.append_chunk(&chunk_buf[..to_read], write_len)?;

            indexes.push(ErofsChunkAddr {
                blkaddr,
                device_id: 1,
            });
        }

        Ok(indexes)
    }

    fn append_chunk(&mut self, data: &[u8], write_len: usize) -> Result<u64> {
        let addr = self.next_blkaddr;
        let block_count = u32::try_from(write_len / EROFS_BLOCK_SIZE as usize).map_err(|err| {
            Error::Overflow(format!("blob meta chunk block count exceeds u32: {err}"))
        })?;

        // Block-aligned chunk payload: real bytes followed by zero padding only
        // in its final block.
        let mut uncompressed = vec![0u8; write_len];
        uncompressed[..data.len()].copy_from_slice(data);
        self.next_blkaddr += block_count as u64;

        // Record the chunk by its absolute block position; chunks are tracked
        // independently of block groups as a digest index only.
        let digest = *blake3::hash(&uncompressed).as_bytes();
        let chunk = BlobMetadataChunk::new(digest, addr, block_count)?;
        self.blob_metadata_chunks.push(chunk);

        // Feed the bytes into the block group stream, which packs whole blocks up to
        // the block group size regardless of chunk boundaries.
        self.append_to_block_group_stream(&uncompressed)?;

        Ok(addr)
    }

    /// Append block-aligned data to the current block group, flushing whenever it
    /// fills to the block group size. A chunk may straddle a block group boundary, so block groups
    /// are pure block runs of exactly `block_group_size` (except the last).
    fn append_to_block_group_stream(&mut self, mut data: &[u8]) -> Result<()> {
        let block_group_size = self.block_group_size as usize;
        while !data.is_empty() {
            let space = block_group_size - self.block_group_buffer.len();
            let take = space.min(data.len());
            self.block_group_buffer.extend_from_slice(&data[..take]);
            data = &data[take..];
            if self.block_group_buffer.len() == block_group_size {
                self.flush_block_group()?;
            }
        }
        Ok(())
    }

    fn flush_block_group(&mut self) -> Result<()> {
        if self.block_group_buffer.is_empty() {
            return Ok(());
        }

        let uncompressed = mem::take(&mut self.block_group_buffer);
        self.block_group_buffer = Vec::with_capacity(self.block_group_size as usize);
        let crc32 = crc32c(&uncompressed);
        let compressed = match self.compressor {
            BlobMetadataCompressor::None => None,
            BlobMetadataCompressor::Zstd => {
                let compressed = zstd::bulk::compress(&uncompressed, 0)
                    .context("failed to compress blob meta block group with zstd")?;
                if compression_is_worthwhile(compressed.len(), uncompressed.len()) {
                    Some(compressed)
                } else {
                    None
                }
            }
        };
        let encoded = compressed.as_deref().unwrap_or(&uncompressed);

        // Encoded block group payloads are packed back-to-back in the data region.
        // No block padding is inserted between compressed block groups; they are read
        // by byte range, and only the data region as a whole is later aligned
        // (by the build assembler) so the embedded bootstrap starts on a block.
        let compressed_offset = self.next_compressed_offset;
        self.writer
            .write_all(encoded)
            .context("failed to write to blob device")?;
        self.data_hasher.update(encoded);
        self.next_compressed_offset = compressed_offset + encoded.len() as u64;

        let block_count =
            u32::try_from(uncompressed.len() / EROFS_BLOCK_SIZE as usize).map_err(|err| {
                Error::Overflow(format!(
                    "blob meta block group uncompressed block count exceeds u32: {err}"
                ))
            })?;
        let entry = BlobMetadataBlockGroup::new(
            self.block_group_block_offset,
            block_count,
            compressed_offset,
            encoded.len() as u32,
            crc32,
        )?;
        self.blob_metadata_block_groups.push(entry);
        self.block_group_block_offset += block_count as u64;
        Ok(())
    }
}

/// Format-compatibility policy shared by build and `nydus optimize`: a block group
/// is stored compressed only when it saves at least 30% — both paths must
/// agree or an optimized blob would encode block groups differently from its source.
pub(crate) fn compression_is_worthwhile(compressed_len: usize, uncompressed_len: usize) -> bool {
    (compressed_len as u128) * 100 <= (uncompressed_len as u128) * MAX_COMPRESSED_SIZE_PERCENT
}

#[cfg(test)]
mod tests {
    use super::*;
    use nydus_format::blob::DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn blob_metadata_block_group_round_trips_minimal_fields() {
        let payload = vec![0u8; 0x3000];
        // Compressed byte offset is a plain byte position (not block aligned).
        let entry = BlobMetadataBlockGroup::new(2, 3, 0x12345, 0x400, crc32c(&payload)).unwrap();

        assert_eq!(entry.uncompressed_block_offset(), 2);
        assert_eq!(entry.uncompressed_block_count(), 3);
        assert_eq!(entry.uncompressed_offset(), 0x2000);
        assert_eq!(entry.uncompressed_size(), 0x3000);
        assert_eq!(entry.compressed_offset(), 0x12345);
        assert_eq!(entry.compressed_size(), 0x400);
        assert_eq!(entry.crc32(), crc32c(&payload));
    }

    #[test]
    fn blob_writer_tracks_unique_blob_metadata_chunks() {
        let dir = tempdir().unwrap();
        let blob_path = dir.path().join("blob.data");
        let file_a = dir.path().join("a.bin");
        let file_b = dir.path().join("b.bin");

        let mut content_a = vec![b'a'; DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE as usize];
        content_a.extend(vec![b'b'; EROFS_BLOCK_SIZE as usize]);
        fs::write(&file_a, &content_a).unwrap();
        fs::write(
            &file_b,
            vec![b'a'; DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE as usize],
        )
        .unwrap();

        // Pin the block group size to the chunk size so the 513-block layout
        // below packs across several block groups.
        let mut writer = BlobWriter::from_writer(
            File::create(&blob_path).unwrap(),
            DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE,
            DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE,
            BlobMetadataCompressor::None,
        )
        .unwrap();
        let indexes_a = writer
            .write_file_chunks(&file_a, content_a.len() as u64)
            .unwrap();
        let indexes_b = writer
            .write_file_chunks(&file_b, DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE as u64)
            .unwrap();
        writer.finish().unwrap();

        assert_eq!(indexes_a.len(), 2);
        assert_eq!(indexes_b.len(), 1);
        assert_eq!(indexes_a[0].blkaddr, 0);
        assert_eq!(indexes_a[1].blkaddr, 256);
        // Dense packing: file_a's 4KiB tail chunk occupies a single block, so
        // file_b starts right after it instead of being padded to a full chunk.
        assert_eq!(indexes_b[0].blkaddr, 257);
        assert_eq!(writer.total_blocks(), 513);

        let entries = writer.blob_metadata_chunks();
        let block_groups = writer.blob_metadata_block_groups();
        assert_eq!(entries.len(), 3);
        assert_eq!(block_groups.len(), 3);
        // Chunks record absolute block offsets, independent of block groups.
        assert_eq!(entries[0].uncompressed_block_offset(), 0);
        assert_eq!(entries[0].uncompressed_block_count(), 256);
        assert_eq!(entries[1].uncompressed_block_offset(), 256);
        assert_eq!(entries[1].uncompressed_block_count(), 1);
        assert_eq!(entries[2].uncompressed_block_offset(), 257);
        assert_eq!(entries[2].uncompressed_block_count(), 256);
        // Block groups pack whole blocks up to the block group size (256 blocks) regardless
        // of chunk boundaries: file_a's tail block and file_b's leading blocks
        // share block group 1, and the remainder spills into block group 2.
        assert_eq!(block_groups[0].uncompressed_block_offset(), 0);
        assert_eq!(block_groups[0].uncompressed_block_count(), 256);
        assert_eq!(block_groups[0].compressed_offset(), 0);
        assert_eq!(
            block_groups[0].compressed_size(),
            DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE
        );
        assert_eq!(block_groups[1].uncompressed_block_offset(), 256);
        assert_eq!(block_groups[1].uncompressed_block_count(), 256);
        assert_eq!(
            block_groups[1].compressed_offset(),
            DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE as u64
        );
        assert_eq!(
            block_groups[1].compressed_size(),
            DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE
        );
        assert_eq!(block_groups[2].uncompressed_block_offset(), 512);
        assert_eq!(block_groups[2].uncompressed_block_count(), 1);
        // Block groups pack back-to-back in the data region with no inter-block group padding.
        assert_eq!(
            block_groups[2].compressed_offset(),
            2 * DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE as u64
        );
        assert_eq!(block_groups[2].compressed_size(), EROFS_BLOCK_SIZE);
    }

    #[test]
    fn blob_writer_allows_small_file_chunks_with_default_size_blob_metadata_block_groups() {
        let dir = tempdir().unwrap();
        let blob_path = dir.path().join("blob.data");
        let input_path = dir.path().join("input.bin");
        let mut content = vec![b'a'; EROFS_BLOCK_SIZE as usize];
        content.extend(vec![b'b'; EROFS_BLOCK_SIZE as usize]);
        fs::write(&input_path, &content).unwrap();

        let mut writer = BlobWriter::new(&blob_path, EROFS_BLOCK_SIZE).unwrap();
        let indexes = writer
            .write_file_chunks(&input_path, content.len() as u64)
            .unwrap();
        writer.finish().unwrap();
        let blob_metadata = writer.blob_metadata(0).unwrap();

        assert_eq!(indexes.len(), 2);
        assert_eq!(indexes[0].blkaddr, 0);
        assert_eq!(indexes[1].blkaddr, 1);
        assert_eq!(blob_metadata.header().chunk_size(), EROFS_BLOCK_SIZE);
        assert_eq!(blob_metadata.chunks().len(), 2);
        assert_eq!(blob_metadata.block_groups().len(), 1);
        assert_eq!(blob_metadata.chunks()[0].uncompressed_block_count(), 1);
        assert_eq!(blob_metadata.chunks()[0].uncompressed_size(), 4096);
        assert_eq!(blob_metadata.chunks()[1].uncompressed_block_offset(), 1);
        assert_eq!(blob_metadata.block_groups()[0].uncompressed_size(), 8192);
    }

    #[test]
    fn blob_writer_turns_zero_chunks_into_holes() {
        let dir = tempdir().unwrap();
        let blob_path = dir.path().join("blob.data");
        let input_path = dir.path().join("input.bin");
        // chunk 0: data, chunk 1: all zeros, chunk 2: data (partial tail).
        let mut content = vec![b'a'; EROFS_BLOCK_SIZE as usize];
        content.extend(vec![0u8; EROFS_BLOCK_SIZE as usize]);
        content.extend(vec![b'c'; 100]);
        fs::write(&input_path, &content).unwrap();

        let mut writer = BlobWriter::new(&blob_path, EROFS_BLOCK_SIZE).unwrap();
        let indexes = writer
            .write_file_chunks(&input_path, content.len() as u64)
            .unwrap();
        writer.finish().unwrap();
        let blob_metadata = writer.blob_metadata(0).unwrap();

        // The all-zero chunk becomes a hole: a null chunk index with no blob
        // reference, no blob-meta chunk entry, and no bytes in the data region.
        assert_eq!(indexes.len(), 3);
        assert_eq!(indexes[0].blkaddr, 0);
        assert_eq!(indexes[1].blkaddr, EROFS_NULL_ADDR);
        assert_eq!(indexes[2].blkaddr, 1);
        assert_eq!(blob_metadata.chunks().len(), 2);
        assert_eq!(blob_metadata.chunks()[1].uncompressed_block_offset(), 1);
        assert_eq!(writer.total_blocks(), 2);
        let data = fs::read(&blob_path).unwrap();
        assert_eq!(data.len(), 2 * EROFS_BLOCK_SIZE as usize);
        assert!(!data[..EROFS_BLOCK_SIZE as usize].iter().any(|&b| b != b'a'));

        // The on-disk null index encodes the all-ones sentinel.
        let raw =
            nydus_format::erofs::ErofsChunkIndex::new(indexes[1].blkaddr, indexes[1].device_id);
        assert_eq!(raw.blkaddr(), EROFS_NULL_ADDR);
    }

    #[test]
    fn blob_writer_handles_fully_zero_file() {
        let dir = tempdir().unwrap();
        let blob_path = dir.path().join("blob.data");
        let input_path = dir.path().join("input.bin");
        let content = vec![0u8; 2 * EROFS_BLOCK_SIZE as usize];
        fs::write(&input_path, &content).unwrap();

        let mut writer = BlobWriter::new(&blob_path, EROFS_BLOCK_SIZE).unwrap();
        let indexes = writer
            .write_file_chunks(&input_path, content.len() as u64)
            .unwrap();
        writer.finish().unwrap();

        // Every chunk is a hole: nothing lands in the blob at all.
        assert_eq!(indexes.len(), 2);
        assert!(indexes.iter().all(|ci| ci.blkaddr == EROFS_NULL_ADDR));
        assert!(writer.blob_metadata_chunks().is_empty());
        assert!(writer.blob_metadata_block_groups().is_empty());
        assert_eq!(writer.total_blocks(), 0);
        assert_eq!(fs::read(&blob_path).unwrap().len(), 0);
    }

    #[test]
    fn blob_writer_stores_uncompressed_when_zstd_saves_too_little() {
        let dir = tempdir().unwrap();
        let blob_path = dir.path().join("blob.data");
        let input_path = dir.path().join("input.bin");
        let content = pseudo_random_bytes(DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE as usize);
        fs::write(&input_path, &content).unwrap();

        let mut writer = BlobWriter::new_with_compressor(
            &blob_path,
            DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE,
            BlobMetadataCompressor::Zstd,
        )
        .unwrap();
        writer
            .write_file_chunks(&input_path, content.len() as u64)
            .unwrap();
        writer.finish().unwrap();

        let block_groups = writer.blob_metadata_block_groups();
        assert_eq!(writer.blob_metadata_chunks().len(), 1);
        assert_eq!(block_groups.len(), 1);
        assert_eq!(block_groups[0].uncompressed_block_count(), 256);
        assert_eq!(
            block_groups[0].uncompressed_size(),
            DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE as u64
        );
        assert_eq!(
            u64::from(block_groups[0].compressed_size()),
            block_groups[0].uncompressed_size()
        );
        assert_eq!(fs::read(&blob_path).unwrap(), content);
    }

    #[test]
    fn blob_writer_writes_blob_metadata_file() {
        let dir = tempdir().unwrap();
        let blob_path = dir.path().join("blob.data");
        let blob_metadata_path = dir.path().join("blob.blob.meta");
        let input_path = dir.path().join("input.bin");
        fs::write(&input_path, vec![b'x'; 4096]).unwrap();

        let mut writer =
            BlobWriter::new(&blob_path, DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE).unwrap();
        writer.write_file_chunks(&input_path, 4096).unwrap();
        writer
            .write_blob_metadata(&blob_metadata_path, 8192)
            .unwrap();

        let raw = fs::read(&blob_metadata_path).unwrap();
        // 4 KiB header block + one chunk + one block group, padded to a block.
        assert_eq!(raw.len(), 8192);

        let blob_metadata = BlobMetadata::from_path(&blob_metadata_path, false).unwrap();
        assert_eq!(blob_metadata.header().chunk_count(), 1);
        assert_eq!(blob_metadata.header().block_group_count(), 1);
        assert_eq!(blob_metadata.header().chunk_table_size(), 48);
        assert_eq!(blob_metadata.header().block_group_table_size(), 40);
        assert_eq!(blob_metadata.header().padded_size(), 8192);
        assert_eq!(blob_metadata.chunks()[0].uncompressed_block_offset(), 0);
        assert_eq!(blob_metadata.block_groups()[0].compressed_offset(), 8192);
    }

    fn pseudo_random_bytes(len: usize) -> Vec<u8> {
        let mut value = 0x1234_5678_9abc_def0u64;
        (0..len)
            .map(|_| {
                value ^= value << 13;
                value ^= value >> 7;
                value ^= value << 17;
                value as u8
            })
            .collect()
    }
}

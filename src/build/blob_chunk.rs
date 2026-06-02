use crate::metadata::{
    align_to_block, BlobMeta, BlobMetaChunk, BlobMetaCompressor, BlobMetaGroup,
    BLOB_META_DEFAULT_CHUNK_SIZE, EROFS_BLOB_ID_SIZE, EROFS_BLOCK_SIZE,
};
use anyhow::{bail, Context, Result};
use crc32c::crc32c;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Write};
use std::mem;
use std::path::Path;

/// Information about a single chunk index to be stored in an inode.
#[derive(Clone)]
pub struct ChunkIndex {
    pub blkaddr: u64,
    pub device_id: u16,
}

/// Manages writing chunk data to a separate blob device with SHA256 dedup.
pub struct BlobWriter {
    file: File,
    file_chunk_size: u32,
    group_size: u32,
    compressor: BlobMetaCompressor,
    next_blkaddr: u64,
    next_compressed_offset: u64,
    data_hasher: Sha256,
    group_uncompressed_block_offset: u64,
    group_buffer: Vec<u8>,
    blob_meta_groups: Vec<BlobMetaGroup>,
    blob_meta_chunks: Vec<BlobMetaChunk>,
    pub saved_by_dedup: u64,
}

const MAX_COMPRESSED_SIZE_PERCENT: u128 = 70;

impl BlobWriter {
    pub fn new(path: &Path, chunksize: u32) -> Result<Self> {
        Self::new_with_compressor(path, chunksize, BlobMetaCompressor::None)
    }

    pub fn new_with_compressor(
        path: &Path,
        file_chunk_size: u32,
        compressor: BlobMetaCompressor,
    ) -> Result<Self> {
        if file_chunk_size < EROFS_BLOCK_SIZE {
            bail!("blob writer file chunksize must be at least one EROFS block");
        }
        if !file_chunk_size.is_power_of_two() || file_chunk_size % EROFS_BLOCK_SIZE != 0 {
            bail!("blob writer file chunksize must be power-of-two and block-aligned");
        }

        let file = File::create(path)
            .with_context(|| format!("failed to create blob device: {}", path.display()))?;
        Self::from_file(file, file_chunk_size, compressor)
    }

    pub fn from_file(
        file: File,
        file_chunk_size: u32,
        compressor: BlobMetaCompressor,
    ) -> Result<Self> {
        if file_chunk_size < EROFS_BLOCK_SIZE {
            bail!("blob writer file chunksize must be at least one EROFS block");
        }
        if !file_chunk_size.is_power_of_two() || file_chunk_size % EROFS_BLOCK_SIZE != 0 {
            bail!("blob writer file chunksize must be power-of-two and block-aligned");
        }

        let group_size = file_chunk_size.max(BLOB_META_DEFAULT_CHUNK_SIZE);

        Ok(Self {
            file,
            file_chunk_size,
            group_size,
            compressor,
            next_blkaddr: 0,
            next_compressed_offset: 0,
            data_hasher: Sha256::new(),
            group_uncompressed_block_offset: 0,
            group_buffer: Vec::with_capacity(group_size as usize),
            blob_meta_groups: Vec::new(),
            blob_meta_chunks: Vec::new(),
            saved_by_dedup: 0,
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

    pub fn into_file(self) -> File {
        self.file
    }

    pub fn into_file_and_data_hasher(self) -> (File, Sha256) {
        (self.file, self.data_hasher)
    }

    pub fn blob_meta_chunks(&self) -> &[BlobMetaChunk] {
        &self.blob_meta_chunks
    }

    pub fn blob_meta_groups(&self) -> &[BlobMetaGroup] {
        &self.blob_meta_groups
    }

    pub fn blob_meta(
        &self,
        blob_id: [u8; EROFS_BLOB_ID_SIZE],
        source_offset_bias: u64,
    ) -> Result<BlobMeta> {
        BlobMeta::from_parts_with_options(
            blob_id,
            self.file_chunk_size / EROFS_BLOCK_SIZE,
            self.compressor,
            self.blob_meta_groups.clone(),
            self.blob_meta_chunks.clone(),
        )?
        .with_compressed_offset_bias(source_offset_bias)
    }

    pub fn write_blob_meta(
        &mut self,
        path: &Path,
        blob_id: [u8; EROFS_BLOB_ID_SIZE],
        source_offset_bias: u64,
    ) -> Result<()> {
        self.finish()?;
        self.blob_meta(blob_id, source_offset_bias)?.save(path)
    }

    pub fn finish(&mut self) -> Result<()> {
        self.flush_group()?;
        self.file.flush().context("failed to flush blob device")
    }

    /// Process a regular file: read it in chunk-sized pieces and append every
    /// chunk to the blob device. Chunk-level digests are recorded in blob meta;
    /// deduplication is intentionally disabled for now.
    pub fn write_file_chunks(&mut self, path: &Path, file_size: u64) -> Result<Vec<ChunkIndex>> {
        if file_size == 0 {
            return Ok(Vec::new());
        }

        let mut f =
            File::open(path).with_context(|| format!("failed to open file: {}", path.display()))?;

        let cs = self.file_chunk_size as u64;
        let nchunks = file_size.div_ceil(cs);
        let mut indexes = Vec::with_capacity(nchunks as usize);
        let mut chunk_buf = vec![0u8; self.file_chunk_size as usize];

        for i in 0..nchunks {
            let remaining = file_size - i * cs;
            let to_read = remaining.min(cs) as usize;

            f.read_exact(&mut chunk_buf[..to_read])
                .with_context(|| format!("failed to read file: {}", path.display()))?;

            let write_len = self.file_chunk_size as usize;
            let blkaddr = self.append_unique_chunk(&chunk_buf[..to_read], write_len)?;

            indexes.push(ChunkIndex {
                blkaddr,
                device_id: 1,
            });
        }

        Ok(indexes)
    }

    fn append_unique_chunk(&mut self, data: &[u8], write_len: usize) -> Result<u64> {
        if write_len > self.group_size as usize {
            bail!("blob chunk is larger than blob meta group size");
        }

        let addr = self.next_blkaddr;
        let mut uncompressed = vec![0u8; write_len];
        uncompressed[..data.len()].copy_from_slice(data);
        self.next_blkaddr += (write_len / EROFS_BLOCK_SIZE as usize) as u64;

        if !self.group_buffer.is_empty()
            && self.group_buffer.len() + uncompressed.len() > self.group_size as usize
        {
            self.flush_group()?;
        }

        if self.group_buffer.is_empty() {
            self.group_uncompressed_block_offset = addr;
        }

        let group_index = u32::try_from(self.blob_meta_groups.len())
            .context("blob meta group index exceeds u32")?;
        let group_uncompressed_block_offset = u32::try_from(
            addr.checked_sub(self.group_uncompressed_block_offset)
                .context("blob meta chunk precedes its group")?,
        )
        .context("blob meta chunk group offset exceeds u32")?;
        let uncompressed_block_count = u32::try_from(write_len / EROFS_BLOCK_SIZE as usize)
            .context("blob meta chunk block count exceeds u32")?;
        let digest = *blake3::hash(&uncompressed).as_bytes();
        let chunk = BlobMetaChunk::new(
            digest,
            group_index,
            group_uncompressed_block_offset,
            uncompressed_block_count,
        )?;
        self.group_buffer.extend_from_slice(&uncompressed);
        self.blob_meta_chunks.push(chunk);

        if self.group_buffer.len() == self.group_size as usize {
            self.flush_group()?;
        }

        Ok(addr)
    }

    fn flush_group(&mut self) -> Result<()> {
        if self.group_buffer.is_empty() {
            return Ok(());
        }

        let uncompressed = mem::take(&mut self.group_buffer);
        self.group_buffer = Vec::with_capacity(self.group_size as usize);
        let crc32 = crc32c(&uncompressed);
        let compressed = match self.compressor {
            BlobMetaCompressor::None => None,
            BlobMetaCompressor::Zstd => {
                let compressed = zstd::bulk::compress(&uncompressed, 0)
                    .context("failed to compress blob meta group with zstd")?;
                if compression_is_worthwhile(compressed.len(), uncompressed.len()) {
                    Some(compressed)
                } else {
                    None
                }
            }
        };
        let encoded = compressed.as_deref().unwrap_or(&uncompressed);

        let compressed_offset = self.next_compressed_offset;
        if compressed_offset % EROFS_BLOCK_SIZE as u64 != 0 {
            bail!("blob meta group compressed offset is not block aligned");
        }
        self.file
            .write_all(encoded)
            .context("failed to write to blob device")?;
        self.data_hasher.update(encoded);
        let compressed_end = compressed_offset + encoded.len() as u64;
        let padded_end = align_to_block(compressed_end);
        let padding_size = usize::try_from(padded_end - compressed_end)
            .context("blob meta group padding size exceeds usize")?;
        if padding_size > 0 {
            let padding = vec![0u8; padding_size];
            self.file
                .write_all(&padding)
                .context("failed to pad blob device group")?;
            self.data_hasher.update(&padding);
        }
        self.next_compressed_offset = padded_end;

        let entry = BlobMetaGroup::new(
            self.group_uncompressed_block_offset,
            u32::try_from(uncompressed.len() / EROFS_BLOCK_SIZE as usize)
                .context("blob meta group uncompressed block count exceeds u32")?,
            compressed_offset / EROFS_BLOCK_SIZE as u64,
            encoded.len() as u32,
            crc32,
        )?;
        self.blob_meta_groups.push(entry);
        Ok(())
    }
}

fn compression_is_worthwhile(compressed_len: usize, uncompressed_len: usize) -> bool {
    (compressed_len as u128) * 100 <= (uncompressed_len as u128) * MAX_COMPRESSED_SIZE_PERCENT
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn blob_meta_group_round_trips_minimal_fields() {
        let payload = vec![0u8; 0x3000];
        let entry = BlobMetaGroup::new(2, 3, 0x12, 0x400, crc32c(&payload)).unwrap();

        assert_eq!(entry.uncompressed_block_offset(), 2);
        assert_eq!(entry.uncompressed_block_count(), 3);
        assert_eq!(entry.uncompressed_byte_offset(), 0x2000);
        assert_eq!(entry.uncompressed_byte_size(), 0x3000);
        assert_eq!(entry.compressed_block_offset(), 0x12);
        assert_eq!(entry.compressed_byte_offset(), 0x12000);
        assert_eq!(entry.compressed_size(), 0x400);
        assert_eq!(entry.crc32(), crc32c(&payload));
    }

    #[test]
    fn blob_writer_tracks_unique_blob_meta_chunks() {
        let dir = tempdir().unwrap();
        let blob_path = dir.path().join("blob.data");
        let file_a = dir.path().join("a.bin");
        let file_b = dir.path().join("b.bin");

        let mut content_a = vec![b'a'; BLOB_META_DEFAULT_CHUNK_SIZE as usize];
        content_a.extend(vec![b'b'; EROFS_BLOCK_SIZE as usize]);
        fs::write(&file_a, &content_a).unwrap();
        fs::write(&file_b, vec![b'a'; BLOB_META_DEFAULT_CHUNK_SIZE as usize]).unwrap();

        let mut writer = BlobWriter::new(&blob_path, BLOB_META_DEFAULT_CHUNK_SIZE).unwrap();
        let indexes_a = writer
            .write_file_chunks(&file_a, content_a.len() as u64)
            .unwrap();
        let indexes_b = writer
            .write_file_chunks(&file_b, BLOB_META_DEFAULT_CHUNK_SIZE as u64)
            .unwrap();
        writer.finish().unwrap();

        assert_eq!(indexes_a.len(), 2);
        assert_eq!(indexes_b.len(), 1);
        assert_eq!(indexes_a[0].blkaddr, 0);
        assert_eq!(indexes_b[0].blkaddr, 512);
        assert_eq!(indexes_a[1].blkaddr, 256);
        assert_eq!(writer.total_blocks(), 768);
        assert_eq!(writer.saved_by_dedup, 0);

        let entries = writer.blob_meta_chunks();
        let groups = writer.blob_meta_groups();
        assert_eq!(entries.len(), 3);
        assert_eq!(groups.len(), 3);
        assert_eq!(entries[0].group_index(), 0);
        assert_eq!(entries[0].group_uncompressed_block_offset(), 0);
        assert_eq!(entries[0].uncompressed_block_count(), 256);
        assert_eq!(
            entries[0].uncompressed_byte_size(),
            BLOB_META_DEFAULT_CHUNK_SIZE as u64
        );
        assert_eq!(groups[0].compressed_byte_offset(), 0);
        assert_eq!(groups[0].compressed_size(), BLOB_META_DEFAULT_CHUNK_SIZE);
        assert_eq!(entries[1].group_index(), 1);
        assert_eq!(entries[1].group_uncompressed_block_offset(), 0);
        assert_eq!(entries[1].uncompressed_block_count(), 256);
        assert_eq!(
            entries[1].uncompressed_byte_size(),
            BLOB_META_DEFAULT_CHUNK_SIZE as u64
        );
        assert_eq!(
            groups[1].compressed_byte_offset(),
            BLOB_META_DEFAULT_CHUNK_SIZE as u64
        );
        assert_eq!(groups[1].compressed_size(), BLOB_META_DEFAULT_CHUNK_SIZE);
        assert_eq!(entries[2].group_index(), 2);
        assert_eq!(entries[2].group_uncompressed_block_offset(), 0);
        assert_eq!(
            groups[2].compressed_byte_offset(),
            BLOB_META_DEFAULT_CHUNK_SIZE as u64 * 2
        );
        assert_eq!(groups[2].compressed_size(), BLOB_META_DEFAULT_CHUNK_SIZE);
    }

    #[test]
    fn blob_writer_allows_small_file_chunks_with_one_megabyte_blob_meta_groups() {
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
        let blob_meta = writer.blob_meta([0u8; EROFS_BLOB_ID_SIZE], 0).unwrap();

        assert_eq!(indexes.len(), 2);
        assert_eq!(indexes[0].blkaddr, 0);
        assert_eq!(indexes[1].blkaddr, 1);
        assert_eq!(blob_meta.header().chunk_size(), EROFS_BLOCK_SIZE);
        assert_eq!(blob_meta.chunks().len(), 2);
        assert_eq!(blob_meta.groups().len(), 1);
        assert_eq!(blob_meta.chunks()[0].uncompressed_block_count(), 1);
        assert_eq!(blob_meta.chunks()[0].uncompressed_byte_size(), 4096);
        assert_eq!(blob_meta.chunks()[1].group_uncompressed_block_offset(), 1);
        assert_eq!(blob_meta.groups()[0].uncompressed_byte_size(), 8192);
    }

    #[test]
    fn blob_writer_stores_uncompressed_when_zstd_saves_too_little() {
        let dir = tempdir().unwrap();
        let blob_path = dir.path().join("blob.data");
        let input_path = dir.path().join("input.bin");
        let content = pseudo_random_bytes(BLOB_META_DEFAULT_CHUNK_SIZE as usize);
        fs::write(&input_path, &content).unwrap();

        let mut writer = BlobWriter::new_with_compressor(
            &blob_path,
            BLOB_META_DEFAULT_CHUNK_SIZE,
            BlobMetaCompressor::Zstd,
        )
        .unwrap();
        writer
            .write_file_chunks(&input_path, content.len() as u64)
            .unwrap();
        writer.finish().unwrap();

        let groups = writer.blob_meta_groups();
        assert_eq!(writer.blob_meta_chunks().len(), 1);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].uncompressed_block_count(), 256);
        assert_eq!(
            groups[0].uncompressed_byte_size(),
            BLOB_META_DEFAULT_CHUNK_SIZE as u64
        );
        assert_eq!(
            u64::from(groups[0].compressed_size()),
            groups[0].uncompressed_byte_size()
        );
        assert_eq!(fs::read(&blob_path).unwrap(), content);
    }

    #[test]
    fn blob_writer_writes_blob_meta_file() {
        let dir = tempdir().unwrap();
        let blob_path = dir.path().join("blob.data");
        let blob_meta_path = dir.path().join("blob.blob.meta");
        let input_path = dir.path().join("input.bin");
        let blob_id = [7u8; EROFS_BLOB_ID_SIZE];
        fs::write(&input_path, vec![b'x'; 4096]).unwrap();

        let mut writer = BlobWriter::new(&blob_path, BLOB_META_DEFAULT_CHUNK_SIZE).unwrap();
        writer.write_file_chunks(&input_path, 4096).unwrap();
        writer
            .write_blob_meta(&blob_meta_path, blob_id, 8192)
            .unwrap();

        let raw = fs::read(&blob_meta_path).unwrap();
        assert_eq!(raw.len(), 4096);

        let blob_meta = BlobMeta::load(&blob_meta_path).unwrap();
        assert_eq!(blob_meta.header().chunk_count(), 1);
        assert_eq!(blob_meta.header().group_count(), 1);
        assert_eq!(blob_meta.header().chunk_bytes(), 48);
        assert_eq!(blob_meta.header().group_bytes(), 32);
        assert_eq!(blob_meta.header().metadata_size(), 4096);
        assert_eq!(blob_meta.chunks()[0].group_uncompressed_block_offset(), 0);
        assert_eq!(blob_meta.groups()[0].compressed_byte_offset(), 8192);
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

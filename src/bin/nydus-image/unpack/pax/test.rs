use std::{io::Read, sync::Arc};

use nydus_storage::backend::{BackendResult, BlobReader};
use nydus_storage::device::BlobChunkInfo;
use nydus_utils::compress::{self, Algorithm};
use nydus_utils::metrics::BackendMetrics;

use super::ChunkReader;

struct MockBlobReader {
    data: Vec<u8>,
    metrics: Arc<BackendMetrics>,
}

impl MockBlobReader {
    fn new(data: Vec<u8>) -> Self {
        Self {
            data,
            metrics: Default::default(),
        }
    }
}

impl BlobReader for MockBlobReader {
    fn try_read(&self, buf: &mut [u8], offset: u64) -> BackendResult<usize> {
        let offset = offset as usize;
        if offset >= self.data.len() {
            return Ok(0_usize);
        }

        let end = self.data.len().min(offset as usize + buf.len());
        buf.clone_from_slice(&self.data[offset..end]);

        Ok(end - offset)
    }

    fn metrics(&self) -> &BackendMetrics {
        self.metrics.as_ref()
    }

    fn blob_size(&self) -> BackendResult<u64> {
        todo!();
    }
}

struct MockChunkInfo {
    compress_offset: u64,
    compress_size: u32,
    uncompress_offset: u64,
    uncompress_size: u32,
    is_compressed: bool,
}

impl MockChunkInfo {
    fn new(
        compress_offset: u64,
        compress_size: u32,
        uncompress_offset: u64,
        uncompress_size: u32,
        is_compressed: bool,
    ) -> Self {
        Self {
            compress_offset,
            compress_size,
            uncompress_offset,
            uncompress_size,
            is_compressed,
        }
    }
}

impl BlobChunkInfo for MockChunkInfo {
    fn is_compressed(&self) -> bool {
        self.is_compressed
    }

    fn uncompressed_size(&self) -> u32 {
        self.uncompress_size
    }

    fn uncompressed_offset(&self) -> u64 {
        self.uncompress_offset
    }

    fn compressed_size(&self) -> u32 {
        self.compress_size
    }

    fn compressed_offset(&self) -> u64 {
        self.compress_offset
    }

    fn id(&self) -> u32 {
        todo!();
    }

    fn as_any(&self) -> &dyn std::any::Any {
        todo!();
    }

    fn blob_index(&self) -> u32 {
        todo!();
    }

    fn chunk_id(&self) -> &nydus_utils::digest::RafsDigest {
        todo!();
    }
}

#[test]
fn test_read_chunk() {
    let mut reader = create_default_chunk_reader();
    let mut buf = [0u8; 256];

    assert_eq!(256, reader.read(&mut buf).unwrap());
    assert_eq!(buf, [1u8; 256]);

    assert_eq!(256, reader.read(&mut buf).unwrap());
    assert_eq!(buf, [2u8; 256]);

    assert_eq!(0, reader.read(&mut buf).unwrap());
    assert_eq!(buf, [2u8; 256]);
}

#[test]
fn test_read_chunk_smaller_buffer() {
    let mut reader = create_default_chunk_reader();
    let mut buf = [0u8; 255];

    assert_eq!(255, reader.read(&mut buf).unwrap());
    assert_eq!(buf, [1u8; 255]);

    assert_eq!(255, reader.read(&mut buf).unwrap());
    assert_eq!(buf[0], 1u8);
    assert_eq!(buf[1..255], [2u8; 254]);

    assert_eq!(2, reader.read(&mut buf).unwrap());
    assert_eq!(buf[0..2], [2u8; 2]);

    assert_eq!(0, reader.read(&mut buf).unwrap());
}

#[test]
fn test_read_chunk_larger_buffer() {
    let mut reader = create_default_chunk_reader();
    let mut buf = [0u8; 257];

    assert_eq!(257, reader.read(&mut buf).unwrap());
    assert_eq!(buf[..256], [1u8; 256]);
    assert_eq!(buf[256], 2u8);

    assert_eq!(255, reader.read(&mut buf).unwrap());
    assert_eq!(buf[..255], [2u8; 255]);

    assert_eq!(0, reader.read(&mut buf).unwrap());
}

#[test]
fn test_read_chunk_zero_buffer() {
    let mut reader = create_default_chunk_reader();
    let mut buf = [0u8; 0];

    assert_eq!(0, reader.read(&mut buf).unwrap());
    assert_eq!(0, reader.read(&mut buf).unwrap());
    assert_eq!(0, reader.read(&mut buf).unwrap());
}

#[test]
fn test_read_chunk_compress() {
    let mut reader = create_compress_chunk_reader();
    let mut buf = [0u8; 256];

    assert_eq!(256, reader.read(&mut buf).unwrap());
    assert_eq!(buf, [1u8; 256]);

    assert_eq!(256, reader.read(&mut buf).unwrap());
    assert_eq!(buf, [2u8; 256]);

    assert_eq!(256, reader.read(&mut buf).unwrap());
    assert_eq!(buf, [3u8; 256]);

    assert_eq!(256, reader.read(&mut buf).unwrap());
    assert_eq!(buf, [4u8; 256]);

    assert_eq!(0, reader.read(&mut buf).unwrap());
    assert_eq!(buf, [4u8; 256]);
}

fn create_compress_chunk_reader() -> ChunkReader {
    let chunk = [[1u8; 256], [2u8; 256], [3u8; 256], [4u8; 256]].concat();

    let (compressed_chunk, is_compressed) = compress::compress(&chunk, Algorithm::GZip).unwrap();
    assert!(is_compressed, "expect compressed chunk");

    let meta = Arc::new(MockChunkInfo::new(
        0,
        compressed_chunk.len() as u32,
        0,
        chunk.len() as u32,
        true,
    ));

    let blob_reader = Arc::new(MockBlobReader::new(compressed_chunk.into_owned()));

    ChunkReader::new(Algorithm::GZip, blob_reader, vec![meta])
}

fn create_default_chunk_reader() -> ChunkReader {
    let chunk1 = [1u8; 256];
    let chunk2 = [2u8; 256];

    let chunk_meta1 = Arc::new(MockChunkInfo::new(
        0,
        chunk1.len() as u32,
        0,
        chunk1.len() as u32,
        false,
    ));
    let chunk_meta2 = Arc::new(MockChunkInfo::new(
        chunk1.len() as u64,
        chunk2.len() as u32,
        chunk1.len() as u64,
        chunk2.len() as u32,
        false,
    ));

    let blob_reader = Arc::new(MockBlobReader::new([chunk1, chunk2].concat()));

    ChunkReader::new(Algorithm::None, blob_reader, vec![chunk_meta1, chunk_meta2])
}

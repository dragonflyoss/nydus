pub mod dummy;
pub mod local;

use std::io;
use std::io::Cursor;
use std::sync::Arc;

use crate::metadata::{BlobMeta, BlobMetaChunk, BlobMetaCompressor, EROFS_BLOB_ID_SIZE};
use crate::storage::backend::BlobBackend;

pub use dummy::DummyBlobCache;
pub use local::LocalBlobCache;

pub trait BlobCache: Send + Sync {
    fn read_at(&self, offset: u64, dst: &mut [u8]) -> io::Result<()>;
}

#[derive(Default)]
pub(crate) struct BlobCacheBuffers {
    encoded: Vec<u8>,
    decoded: Vec<u8>,
}

pub(crate) fn chunks_for_range(
    blobmeta: &BlobMeta,
    offset: u64,
    len: usize,
) -> io::Result<Vec<(usize, BlobMetaChunk)>> {
    blobmeta
        .chunks_for_uncompressed_range(offset, len)
        .map_err(|err| io::Error::new(io::ErrorKind::NotFound, err))
}

pub(crate) fn fetch_decode_validate_into<'a>(
    blob_id: &[u8; EROFS_BLOB_ID_SIZE],
    blobmeta: &BlobMeta,
    backend: &Arc<dyn BlobBackend>,
    chunk: &BlobMetaChunk,
    buffers: &'a mut BlobCacheBuffers,
) -> io::Result<&'a [u8]> {
    let decoded_len = chunk.uncompressed_size() as usize;
    if is_stored_plain_chunk(blobmeta, chunk) {
        buffers.decoded.resize(decoded_len, 0);
        backend.read_range_into(blob_id, chunk.compressed_offset(), &mut buffers.decoded)?;
        validate_decoded_chunk(chunk, &buffers.decoded)?;
        return Ok(&buffers.decoded);
    }

    buffers.encoded.resize(chunk.compressed_size() as usize, 0);
    backend.read_range_into(blob_id, chunk.compressed_offset(), &mut buffers.encoded)?;

    buffers.decoded.clear();
    buffers.decoded.reserve(decoded_len);
    zstd::stream::copy_decode(&mut Cursor::new(&buffers.encoded), &mut buffers.decoded)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;

    validate_decoded_chunk(chunk, &buffers.decoded)?;
    Ok(&buffers.decoded)
}

fn is_stored_plain_chunk(blobmeta: &BlobMeta, chunk: &BlobMetaChunk) -> bool {
    blobmeta.compressor() == BlobMetaCompressor::None
        || chunk.compressed_size() == chunk.uncompressed_size()
}

pub(crate) fn validate_decoded_chunk(chunk: &BlobMetaChunk, decoded: &[u8]) -> io::Result<()> {
    if decoded.len() != chunk.uncompressed_size() as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "decoded blob meta chunk length mismatch: expected {}, got {}",
                chunk.uncompressed_size(),
                decoded.len()
            ),
        ));
    }

    let crc32 = crc32c::crc32c(decoded);
    if crc32 != chunk.crc32() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "blob meta chunk crc32 mismatch",
        ));
    }

    Ok(())
}

pub(crate) fn range_in_chunk(
    chunk: &BlobMetaChunk,
    logical_offset: u64,
    dst_remaining: usize,
) -> (usize, usize) {
    let chunk_offset = (logical_offset - chunk.uncompressed_offset()) as usize;
    let available = chunk.uncompressed_size() as usize - chunk_offset;
    (chunk_offset, available.min(dst_remaining))
}

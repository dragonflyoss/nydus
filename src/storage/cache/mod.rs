pub mod local;

use std::io;
use std::io::Cursor;
use std::ops::Range;
use std::sync::Arc;

use crate::metadata::{BlobMeta, BlobMetaCompressor, BlobMetaGroup, EROFS_BLOB_ID_SIZE};
use crate::storage::backend::{BlobBackend, ReadContext, RequestSource};

pub use local::LocalBlobCache;
pub trait BlobCache: Send + Sync {
    fn read_at(&self, offset: u64, dst: &mut [u8]) -> io::Result<()>;

    /// Fetch, decode, validate, cache, and mark ready every group of this blob.
    /// Used by blob-level prefetch after a filesystem is mounted.
    fn prefetch_all(&self) -> io::Result<()>;
}

/// Group together consecutive groups whose accumulated uncompressed size reaches
/// `target_uncompressed`, so each batch can be fetched with a single contiguous
/// read. Each batch always contains at least one group.
pub(crate) fn plan_prefetch_batches(
    groups: &[BlobMetaGroup],
    target_uncompressed: u64,
) -> Vec<Range<usize>> {
    let mut batches = Vec::new();
    let mut start = 0usize;
    while start < groups.len() {
        let mut end = start + 1;
        let mut accumulated = groups[start].uncompressed_byte_size();
        while end < groups.len() && accumulated < target_uncompressed {
            accumulated = accumulated.saturating_add(groups[end].uncompressed_byte_size());
            end += 1;
        }
        batches.push(start..end);
        start = end;
    }
    batches
}

/// Decode and validate a single group from an in-memory window of compressed
/// bytes that starts at blob offset `window_base_offset`, writing the validated
/// uncompressed bytes into `decoded`.
pub(crate) fn decode_group_from_window(
    blob_meta: &BlobMeta,
    group: &BlobMetaGroup,
    window_base_offset: u64,
    window_bytes: &[u8],
    decoded: &mut Vec<u8>,
) -> io::Result<()> {
    let relative_start = group
        .compressed_byte_offset()
        .checked_sub(window_base_offset)
        .and_then(|start| usize::try_from(start).ok())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "blob meta group offset outside prefetch window",
            )
        })?;
    let relative_end = relative_start + group.compressed_size() as usize;
    let encoded = window_bytes
        .get(relative_start..relative_end)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "blob meta group range outside prefetch window",
            )
        })?;

    let decoded_len = usize::try_from(group.uncompressed_byte_size()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "blob meta group uncompressed size exceeds usize",
        )
    })?;

    decoded.clear();
    if is_stored_plain_group(blob_meta, group) {
        decoded.extend_from_slice(encoded);
    } else {
        decoded.reserve(decoded_len);
        zstd::stream::copy_decode(&mut Cursor::new(encoded), &mut *decoded)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    }

    validate_decoded_group(group, decoded)
}

#[derive(Default)]
pub(crate) struct BlobCacheBuffers {
    encoded: Vec<u8>,
    decoded: Vec<u8>,
}

pub(crate) fn fetch_decode_validate_group_into<'a>(
    blob_id: &[u8; EROFS_BLOB_ID_SIZE],
    blob_meta: &BlobMeta,
    backend: &Arc<dyn BlobBackend>,
    group: &BlobMetaGroup,
    buffers: &'a mut BlobCacheBuffers,
    source: RequestSource,
) -> io::Result<&'a [u8]> {
    let ctx = ReadContext::group(
        source,
        group.uncompressed_byte_offset(),
        group.uncompressed_byte_size(),
    );
    let decoded_len = usize::try_from(group.uncompressed_byte_size()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "blob meta group uncompressed size exceeds usize",
        )
    })?;
    if is_stored_plain_group(blob_meta, group) {
        buffers.decoded.resize(decoded_len, 0);
        backend.read_range_into(
            blob_id,
            group.compressed_byte_offset(),
            &mut buffers.decoded,
            ctx,
        )?;
        validate_decoded_group(group, &buffers.decoded)?;
        return Ok(&buffers.decoded);
    }

    buffers.encoded.resize(group.compressed_size() as usize, 0);
    backend.read_range_into(
        blob_id,
        group.compressed_byte_offset(),
        &mut buffers.encoded,
        ctx,
    )?;

    buffers.decoded.clear();
    buffers.decoded.reserve(decoded_len);
    zstd::stream::copy_decode(&mut Cursor::new(&buffers.encoded), &mut buffers.decoded)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;

    validate_decoded_group(group, &buffers.decoded)?;
    Ok(&buffers.decoded)
}

fn is_stored_plain_group(blob_meta: &BlobMeta, group: &BlobMetaGroup) -> bool {
    blob_meta.compressor() == BlobMetaCompressor::None
        || u64::from(group.compressed_size()) == group.uncompressed_byte_size()
}

pub(crate) fn validate_decoded_group(group: &BlobMetaGroup, decoded: &[u8]) -> io::Result<()> {
    let expected = group.uncompressed_byte_size();
    if decoded.len() as u64 != expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "decoded blob meta group length mismatch: expected {}, got {}",
                expected,
                decoded.len()
            ),
        ));
    }

    let crc32 = crc32c::crc32c(decoded);
    if crc32 != group.crc32() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "blob meta group crc32 mismatch",
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata::{BLOB_META_DEFAULT_CHUNK_SIZE, EROFS_BLOCK_SIZE};

    fn group(uncompressed_block_offset: u64, uncompressed_block_count: u32) -> BlobMetaGroup {
        BlobMetaGroup::new(
            uncompressed_block_offset,
            uncompressed_block_count,
            uncompressed_block_offset * EROFS_BLOCK_SIZE as u64,
            uncompressed_block_count * EROFS_BLOCK_SIZE,
            0,
        )
        .unwrap()
    }

    #[test]
    fn plan_prefetch_batches_keeps_one_group_per_window_at_default_target() {
        let blocks = BLOB_META_DEFAULT_CHUNK_SIZE / EROFS_BLOCK_SIZE;
        let groups = vec![
            group(0, blocks),
            group(blocks as u64, blocks),
            group(2 * blocks as u64, blocks),
        ];
        let batches = plan_prefetch_batches(&groups, BLOB_META_DEFAULT_CHUNK_SIZE as u64);
        assert_eq!(batches, vec![0..1, 1..2, 2..3]);
    }

    #[test]
    fn plan_prefetch_batches_merges_small_groups_and_keeps_tail() {
        let groups = vec![group(0, 1), group(1, 1), group(2, 1)];
        // Target equal to two blocks: first two groups merge, last is its own batch.
        let target = 2 * EROFS_BLOCK_SIZE as u64;
        let batches = plan_prefetch_batches(&groups, target);
        assert_eq!(batches, vec![0..2, 2..3]);
    }

    #[test]
    fn plan_prefetch_batches_isolates_group_larger_than_target() {
        let groups = vec![group(0, 4), group(4, 1)];
        let batches = plan_prefetch_batches(&groups, EROFS_BLOCK_SIZE as u64);
        assert_eq!(batches, vec![0..1, 1..2]);
    }
}

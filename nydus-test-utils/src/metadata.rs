//! Blob meta for data regions the tests lay out themselves, so a test
//! controls the chunk group geometry a real build would decide for it.

use nydus_format::blob::{
    BlobMetadata, BlobMetadataChunkGroup, BlobMetadataChunkGroupDigest,
    BlobMetadataChunkGroupRedirect, BlobMetadataChunkLength, BlobMetadataCompressor,
    BlobMetadataDigester,
};
use nydus_format::erofs::EROFS_BLOCK_SIZE;

/// Encodes `groups`, each a list of chunks, with `compressor` into a data
/// region and the blob meta describing it. `max_bytes_per_chunk_group` is
/// the group bound, the index stride is one block, and BLAKE3 digests are
/// recorded when `digests` is set. A group is stored compressed when that
/// shrinks it and plain otherwise. Groups tile the address space back to
/// back, each chunk on its own blocks.
pub fn encode(
    compressor: BlobMetadataCompressor,
    max_bytes_per_chunk_group: u32,
    groups: &[Vec<Vec<u8>>],
    digests: bool,
) -> (Vec<u8>, BlobMetadata) {
    let mut data = Vec::new();
    let mut chunk_groups = Vec::new();
    let mut chunk_lengths = Vec::new();
    let mut chunk_group_digests = Vec::new();
    let mut logical_block_offset = 0u32;
    for group in groups {
        let payload = group.concat();
        let encoded = match compressor {
            BlobMetadataCompressor::None => None,
            BlobMetadataCompressor::Zstd => Some(zstd::bulk::compress(&payload, 0).unwrap()),
            BlobMetadataCompressor::Lz4Block => Some(lz4_flex::block::compress(&payload)),
        }
        .filter(|encoded| encoded.len() < payload.len());
        chunk_groups.push(BlobMetadataChunkGroup::new(
            data.len() as u64,
            logical_block_offset,
            chunk_lengths.len() as u32,
            payload.len() as u32,
            crc32c::crc32c(&payload),
        ));
        data.extend_from_slice(encoded.as_deref().unwrap_or(&payload));
        for chunk in group {
            chunk_lengths.push(BlobMetadataChunkLength::new(chunk.len() as u32));
            logical_block_offset += (chunk.len() as u32).div_ceil(EROFS_BLOCK_SIZE);
        }
        chunk_group_digests.push(BlobMetadataChunkGroupDigest::from_chunks(
            group.iter().map(Vec::as_slice),
        ));
    }
    if !digests {
        chunk_group_digests.clear();
    }
    chunk_groups.push(BlobMetadataChunkGroup::new(
        data.len() as u64,
        logical_block_offset,
        chunk_lengths.len() as u32,
        0,
        0,
    ));

    let metadata = BlobMetadata::new(
        max_bytes_per_chunk_group / EROFS_BLOCK_SIZE,
        1,
        compressor,
        digests.then_some(BlobMetadataDigester::Blake3),
        chunk_groups,
        chunk_lengths,
        chunk_group_digests,
        Vec::new(),
    )
    .unwrap();
    (data, metadata)
}

/// The padded address space `groups` occupy, every chunk on its own blocks
/// and the groups back to back: what a fully filled cache file holds.
pub fn padded_image(groups: &[Vec<Vec<u8>>]) -> Vec<u8> {
    let block_size = EROFS_BLOCK_SIZE as usize;
    let blocks: usize = groups
        .iter()
        .flatten()
        .map(|chunk| chunk.len().div_ceil(block_size))
        .sum();
    let mut image = vec![0u8; blocks * block_size];
    let mut offset = 0;
    for chunk in groups.iter().flatten() {
        image[offset..offset + chunk.len()].copy_from_slice(chunk);
        offset += chunk.len().div_ceil(block_size) * block_size;
    }
    image
}

/// The meta of a plain blob holding `payload` as one chunk in one group,
/// without digests. `payload` is at most one block.
pub fn single_chunk(payload: &[u8]) -> BlobMetadata {
    let (chunk_groups, chunk_lengths) = single_chunk_tables(payload);
    BlobMetadata::new(
        1,
        1,
        BlobMetadataCompressor::None,
        None,
        chunk_groups,
        chunk_lengths,
        Vec::new(),
        Vec::new(),
    )
    .unwrap()
}

/// The incremental twin of [`single_chunk`], the meta of an upper blob
/// that only an image with a parent can serve.
pub fn incremental(payload: &[u8]) -> BlobMetadata {
    let (chunk_groups, chunk_lengths) = single_chunk_tables(payload);
    BlobMetadata::new_incremental(
        1,
        1,
        BlobMetadataCompressor::None,
        None,
        chunk_groups,
        chunk_lengths,
        Vec::new(),
    )
    .unwrap()
}

/// The redirect twin of [`single_chunk`], the meta of an ondemand blob
/// whose one group copies group 0 of the blob in device slot
/// `source_blob_index`, a plain single-chunk blob of the same `payload`.
pub fn redirect(payload: &[u8], source_blob_index: u16) -> BlobMetadata {
    let (chunk_groups, chunk_lengths) = single_chunk_tables(payload);
    BlobMetadata::new(
        1,
        1,
        BlobMetadataCompressor::None,
        None,
        chunk_groups,
        chunk_lengths,
        Vec::new(),
        vec![BlobMetadataChunkGroupRedirect::new(source_blob_index, 0).unwrap()],
    )
    .unwrap()
}

/// The ChunkGroupTable and ChunkLengthTable of one plain chunk, `payload`.
fn single_chunk_tables(
    payload: &[u8],
) -> (Vec<BlobMetadataChunkGroup>, Vec<BlobMetadataChunkLength>) {
    assert!(payload.len() <= EROFS_BLOCK_SIZE as usize);
    let length = payload.len() as u32;
    (
        vec![
            BlobMetadataChunkGroup::new(0, 0, 0, length, crc32c::crc32c(payload)),
            BlobMetadataChunkGroup::new(u64::from(length), 1, 1, 0, 0),
        ],
        vec![BlobMetadataChunkLength::new(length)],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn groups() -> Vec<Vec<Vec<u8>>> {
        vec![
            vec![vec![0x11; 4096], vec![0x22; 100]],
            vec![vec![0x33; 4096 - 1]],
        ]
    }

    #[test]
    fn encode_describes_the_groups_it_lays_out() {
        let test_cases = vec![
            (BlobMetadataCompressor::None, false, 4096 + 100 + 4095),
            (BlobMetadataCompressor::Zstd, true, 4096 + 100 + 4095),
        ];

        for (compressor, digests, plain_size) in test_cases {
            let (data, metadata) = encode(compressor, 16384, &groups(), digests);
            assert_eq!(metadata.chunk_group_count(), 2);
            assert_eq!(metadata.chunk_count(), 3);
            assert_eq!(metadata.compressor(), compressor);
            assert_eq!(metadata.chunk_group_digest(0).is_some(), digests);
            assert_eq!(
                compressor == BlobMetadataCompressor::None,
                data.len() == plain_size
            );
            assert_eq!(
                metadata.chunk_group(1).unwrap().compressed_offset(),
                metadata.chunk_group(0).unwrap().compressed_size() as u64
            );
        }
    }

    #[test]
    fn padded_image_puts_every_chunk_on_its_own_blocks() {
        let image = padded_image(&groups());
        assert_eq!(image.len(), 3 * 4096);
        assert_eq!(&image[..4096], &[0x11; 4096]);
        assert_eq!(&image[4096..4096 + 100], &[0x22; 100]);
        assert!(image[4096 + 100..8192].iter().all(|byte| *byte == 0));
        assert_eq!(&image[8192..8192 + 4095], &[0x33; 4095]);
        assert_eq!(image[12287], 0);
    }

    #[test]
    fn single_chunk_twins_differ_only_in_kind() {
        let payload = vec![0xab; 4096];
        let plain = single_chunk(&payload);
        let incremental = incremental(&payload);
        let redirect = redirect(&payload, 1);

        for metadata in [&plain, &incremental, &redirect] {
            assert_eq!(metadata.chunk_group_count(), 1);
            assert_eq!(metadata.chunk_count(), 1);
            assert_eq!(metadata.chunk_group(0).unwrap().uncompressed_size(), 4096);
        }
        assert!(!plain.is_incremental() && !plain.is_redirect());
        assert!(incremental.is_incremental());
        assert!(redirect.is_redirect());
    }
}

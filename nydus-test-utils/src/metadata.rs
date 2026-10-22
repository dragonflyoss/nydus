//! Blob meta for chunk groups the tests lay out themselves, so a test
//! controls the geometry a real build would decide for it.

use nydus_format::blob::{
    BlobMetadata, BlobMetadataChunkGroup, BlobMetadataChunkGroupDigest,
    BlobMetadataChunkGroupRedirect, BlobMetadataChunkLength, BlobMetadataCompressor,
    BlobMetadataDigester,
};
use nydus_format::erofs::EROFS_BLOCK_SIZE;

/// Lays out `chunk_groups`, each a list of chunks, with `compressor` into a
/// compressed data region and returns it with the blob meta describing it.
/// `max_bytes_per_chunk_group` is the group bound, the index stride is one
/// block, and every group is digested by `digester`, or none without one. A
/// group is stored compressed when that shrinks it and plain otherwise. The
/// groups tile the logical blocks back to back, each chunk on its own
/// blocks.
pub fn from_chunk_groups(
    compressor: BlobMetadataCompressor,
    max_bytes_per_chunk_group: u32,
    chunk_groups: &[Vec<Vec<u8>>],
    digester: Option<BlobMetadataDigester>,
) -> (Vec<u8>, BlobMetadata) {
    let mut data = Vec::new();
    let mut chunk_group_entries = Vec::new();
    let mut chunk_lengths = Vec::new();
    let mut chunk_group_digests = Vec::new();
    let mut logical_block_offset = 0u32;
    for chunk_group in chunk_groups {
        let payload = chunk_group.concat();
        let encoded = compressor
            .compress(&payload)
            .unwrap()
            .filter(|encoded| encoded.len() < payload.len());

        chunk_group_entries.push(BlobMetadataChunkGroup::new(
            data.len() as u64,
            logical_block_offset,
            chunk_lengths.len() as u32,
            payload.len() as u32,
            crc32c::crc32c(&payload),
        ));
        data.extend_from_slice(encoded.as_deref().unwrap_or(&payload));

        for chunk in chunk_group {
            chunk_lengths.push(BlobMetadataChunkLength::new(chunk.len() as u32));
            logical_block_offset += (chunk.len() as u32).div_ceil(EROFS_BLOCK_SIZE);
        }

        chunk_group_digests.push(BlobMetadataChunkGroupDigest::from_chunks(
            chunk_group.iter().map(Vec::as_slice),
        ));
    }

    if digester.is_none() {
        chunk_group_digests.clear();
    }

    chunk_group_entries.push(BlobMetadataChunkGroup::new(
        data.len() as u64,
        logical_block_offset,
        chunk_lengths.len() as u32,
        0,
        0,
    ));

    let blob_metadata = BlobMetadata::new(
        max_bytes_per_chunk_group / EROFS_BLOCK_SIZE,
        1,
        compressor,
        digester,
        chunk_group_entries,
        chunk_lengths,
        chunk_group_digests,
        Vec::new(),
    )
    .unwrap();

    (data, blob_metadata)
}

/// The blob meta of a plain blob with one chunk group holding `payload` as
/// its one chunk, without digests. `payload` is at most one block.
pub fn single_chunk_group(payload: &[u8]) -> BlobMetadata {
    let length = payload.len() as u32;
    let chunk_groups = vec![
        BlobMetadataChunkGroup::new(0, 0, 0, length, crc32c::crc32c(payload)),
        BlobMetadataChunkGroup::new(u64::from(length), 1, 1, 0, 0),
    ];
    let chunk_lengths = vec![BlobMetadataChunkLength::new(length)];

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

/// [`single_chunk_group`] as [`BlobMetadata::new_upper`] creates it: the blob
/// meta of an upper blob, the data an incremental build writes on top of a
/// parent image.
pub fn single_chunk_group_upper(payload: &[u8]) -> BlobMetadata {
    let length = payload.len() as u32;
    let chunk_groups = vec![
        BlobMetadataChunkGroup::new(0, 0, 0, length, crc32c::crc32c(payload)),
        BlobMetadataChunkGroup::new(u64::from(length), 1, 1, 0, 0),
    ];
    let chunk_lengths = vec![BlobMetadataChunkLength::new(length)];

    BlobMetadata::new_upper(
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

/// [`single_chunk_group`] with a ChunkGroupRedirectTable: the blob meta of a
/// ondemand blob, whose one group copies group 0 of the blob in device slot
/// `source_blob_index`.
pub fn single_chunk_group_ondemand(payload: &[u8], source_blob_index: u16) -> BlobMetadata {
    let length = payload.len() as u32;
    let chunk_groups = vec![
        BlobMetadataChunkGroup::new(0, 0, 0, length, crc32c::crc32c(payload)),
        BlobMetadataChunkGroup::new(u64::from(length), 1, 1, 0, 0),
    ];
    let chunk_lengths = vec![BlobMetadataChunkLength::new(length)];

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_chunk_groups_describes_the_data_region_it_lays_out() {
        let chunk_groups = vec![
            vec![vec![0x11; 4096], vec![0x22; 100]],
            vec![vec![0x33; 4096 - 1]],
        ];
        let test_cases = vec![
            (BlobMetadataCompressor::None, None, 4096 + 100 + 4095),
            (
                BlobMetadataCompressor::Zstd,
                Some(BlobMetadataDigester::Blake3),
                4096 + 100 + 4095,
            ),
        ];

        for (compressor, digester, plain_size) in test_cases {
            let (data, blob_metadata) =
                from_chunk_groups(compressor, 16384, &chunk_groups, digester);
            assert_eq!(blob_metadata.chunk_group_count(), 2);
            assert_eq!(blob_metadata.chunk_count(), 3);
            assert_eq!(blob_metadata.compressor(), compressor);
            assert_eq!(
                blob_metadata.chunk_group_digest(0).is_some(),
                digester.is_some()
            );
            assert_eq!(
                compressor == BlobMetadataCompressor::None,
                data.len() == plain_size
            );
            assert_eq!(
                blob_metadata.chunk_group(1).unwrap().compressed_offset(),
                blob_metadata.chunk_group(0).unwrap().compressed_size() as u64
            );
        }
    }

    #[test]
    fn single_chunk_group_twins_differ_only_in_kind() {
        let payload = vec![0xab; 4096];
        let plain = single_chunk_group(&payload);
        let upper = single_chunk_group_upper(&payload);
        let ondemand = single_chunk_group_ondemand(&payload, 1);

        for blob_metadata in [&plain, &upper, &ondemand] {
            assert_eq!(blob_metadata.chunk_group_count(), 1);
            assert_eq!(blob_metadata.chunk_count(), 1);
            assert_eq!(
                blob_metadata.chunk_group(0).unwrap().uncompressed_size(),
                4096
            );
        }
        assert!(!plain.is_incremental() && !plain.is_ondemand());
        assert!(upper.is_incremental());
        assert!(ondemand.is_ondemand());
    }
}

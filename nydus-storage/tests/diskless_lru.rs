use std::sync::Arc;

use nydus_backend::ReadKind;
use nydus_format::blob::BlobMetadataCompressor;
use nydus_storage::cache::{BlobCaches, CacheOptions};
use nydus_test_utils::fault::FaultBackend;
use nydus_test_utils::metadata::from_chunk_groups;

#[test]
fn read_at_shares_one_lru_budget_of_decoded_groups_across_blobs() {
    let test_cases = vec![(4096, 128u16), (4 << 20, 8)];

    for (group_size, resident) in test_cases {
        let mut backend = FaultBackend::in_memory();
        let mut entries = Vec::new();
        for index in 1..=resident + 1 {
            let mut id = [0; 32];
            id[..2].copy_from_slice(&index.to_le_bytes());
            let groups = vec![vec![vec![index as u8; group_size]]];
            let (data, meta) = from_chunk_groups(
                BlobMetadataCompressor::Zstd,
                group_size as u32,
                &groups,
                None,
            );
            backend = backend.with_blob(id, data, &meta);
            entries.push((index, id));
        }
        let backend = Arc::new(backend);
        let caches = BlobCaches::new(
            entries,
            backend.clone(),
            None,
            None,
            CacheOptions::default(),
        )
        .unwrap();
        let read = |index: u16| {
            let mut bytes = [0; 31];
            let cache = caches.cache(index, ReadKind::Ondemand).unwrap();
            cache.read_at(19, &mut bytes).unwrap();
            assert_eq!(bytes, [index as u8; 31], "group_size={group_size}");
        };
        let filled = usize::from(resident);

        for index in 1..=resident {
            read(index);
        }
        assert_eq!(backend.reads().len(), filled, "group_size={group_size}");

        read(1);
        read(resident + 1);
        assert_eq!(backend.reads().len(), filled + 1, "group_size={group_size}");

        read(1);
        assert_eq!(backend.reads().len(), filled + 1, "group_size={group_size}");

        read(2);
        assert_eq!(backend.reads().len(), filled + 2, "group_size={group_size}");
        assert_eq!(
            backend.metadata_calls(),
            filled + 1,
            "group_size={group_size}"
        );

        read(2);
        assert_eq!(backend.reads().len(), filled + 2, "group_size={group_size}");
    }
}

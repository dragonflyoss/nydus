//! Verify the real per-image decoded-group budget, not process RSS (which
//! includes transient decode buffers, allocator retention, and the fixture).

use std::sync::Arc;

use nydus_backend::ReadKind;
use nydus_format::blob::BlobMetadataCompressor;
use nydus_storage::cache::{BlobCaches, CacheOptions};
use nydus_test_utils::fault::FaultBackend;
use nydus_test_utils::metadata::from_chunk_groups;

fn exercise_budget(group_size: usize, resident: u16) {
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
        let cache = caches.cache(index, ReadKind::Ondemand).unwrap();
        let mut bytes = [0; 31];
        cache.read_at(19, &mut bytes).unwrap();
        assert_eq!(
            bytes, [index as u8; 31],
            "blob key must be part of the LRU key"
        );
    };
    for index in 1..=resident {
        read(index);
    }
    assert_eq!(backend.reads().len(), usize::from(resident));
    // Refresh the oldest entry, then overflow the common image budget from
    // another blob. FIFO and independent per-blob caches both fail this test.
    read(1);
    read(resident + 1);
    let filled = backend.reads().len();
    assert_eq!(filled, usize::from(resident) + 1);
    read(1);
    assert_eq!(
        backend.reads().len(),
        filled,
        "recently used group was evicted"
    );
    read(2);
    assert_eq!(
        backend.reads().len(),
        filled + 1,
        "oldest group was not evicted"
    );
    assert_eq!(backend.metadata_calls(), usize::from(resident) + 1);
    read(2);
    assert_eq!(
        backend.reads().len(),
        filled + 1,
        "refetched group was not retained"
    );
}

#[test]
fn entry_budget_is_shared_across_129_blobs_and_uses_lru_order() {
    exercise_budget(4096, 128);
}

#[test]
fn decoded_byte_budget_is_shared_across_blobs_and_uses_lru_order() {
    // Nine 4 MiB groups cross the 32 MiB byte bound long before 128 entries.
    exercise_budget(4 << 20, 8);
}

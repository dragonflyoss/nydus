use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use nydus_format::erofs::ZAlgorithm;

const MAX_BYTES: usize = 32 << 20;
const MAX_ENTRIES: usize = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct PclusterKey {
    pub blob_index: u16,
    pub offset: u64,
    pub physical_len: usize,
    pub logical_len: usize,
    pub algorithm: ZAlgorithm,
}

#[derive(Default)]
pub(super) struct PclusterCache {
    state: Mutex<CacheState>,
}

#[derive(Default)]
struct CacheState {
    entries: VecDeque<(PclusterKey, Arc<[u8]>)>,
    bytes: usize,
}

impl PclusterCache {
    pub(super) fn get(&self, key: PclusterKey) -> Option<Arc<[u8]>> {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        let index = state.entries.iter().position(|(entry, _)| *entry == key)?;
        let entry = state.entries.remove(index)?;
        let data = Arc::clone(&entry.1);
        state.entries.push_back(entry);
        Some(data)
    }

    pub(super) fn insert(&self, key: PclusterKey, data: &[u8]) {
        if data.len() > MAX_BYTES {
            return;
        }
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        if state.entries.iter().any(|(entry, _)| *entry == key) {
            return;
        }
        while state.bytes + data.len() > MAX_BYTES || state.entries.len() >= MAX_ENTRIES {
            if let Some((_, evicted)) = state.entries.pop_front() {
                state.bytes -= evicted.len();
            }
        }
        state.bytes += data.len();
        state.entries.push_back((key, Arc::from(data)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(offset: u64, logical_len: usize) -> PclusterKey {
        PclusterKey {
            blob_index: 1,
            offset,
            physical_len: 4096,
            logical_len,
            algorithm: ZAlgorithm::Zstd,
        }
    }

    #[test]
    fn pcluster_cache_evicts_lru_and_bounds_bytes() {
        let cache = PclusterCache::default();
        let data = vec![42; MAX_BYTES / 2];
        let first = key(0, data.len());
        let second = key(4096, data.len());
        let third = key(8192, data.len());
        cache.insert(first, &data);
        cache.insert(second, &data);
        let held = cache.get(first).unwrap();
        cache.insert(third, &data);
        assert!(cache.get(second).is_none());
        assert!(cache.get(first).is_some());
        assert_eq!(&*held, &data);
        assert_eq!(cache.state.lock().unwrap().bytes, MAX_BYTES);
        cache.insert(third, &data);
        assert_eq!(cache.state.lock().unwrap().bytes, MAX_BYTES);
        cache.insert(key(12288, MAX_BYTES + 1), &vec![0; MAX_BYTES + 1]);
        assert_eq!(cache.state.lock().unwrap().bytes, MAX_BYTES);
    }

    #[test]
    fn pcluster_cache_bounds_entries_and_separates_decode_identity() {
        let cache = PclusterCache::default();
        for offset in 0..=MAX_ENTRIES as u64 {
            cache.insert(key(offset, 1), &[42]);
        }
        assert!(cache.get(key(0, 1)).is_none());
        let last = key(MAX_ENTRIES as u64, 1);
        assert!(cache.get(last).is_some());
        assert!(cache
            .get(PclusterKey {
                blob_index: 2,
                ..last
            })
            .is_none());
        assert!(cache
            .get(PclusterKey {
                algorithm: ZAlgorithm::Lz4,
                ..last
            })
            .is_none());
        assert!(cache
            .get(PclusterKey {
                logical_len: 2,
                ..last
            })
            .is_none());
        assert!(cache
            .get(PclusterKey {
                physical_len: 8192,
                ..last
            })
            .is_none());
        assert!(PclusterCache::default().get(last).is_none());
        assert_eq!(cache.state.lock().unwrap().entries.len(), MAX_ENTRIES);
    }
}

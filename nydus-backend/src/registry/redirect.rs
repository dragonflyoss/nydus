//! The cache of signed URLs a registry redirected blob `GET`s to.

use std::num::NonZeroUsize;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use lru::LruCache;

/// The number of blobs whose redirect URLs are remembered at once.
const CAPACITY: usize = 1000;

/// The default time a redirect URL is trusted before the next read re-resolves
/// it.
///
/// Signed CDN links expire on their own schedule, this only bounds how stale
/// a hit can be, an expired link is also evicted the moment it answers `401`
/// or `403`.
pub(super) const DEFAULT_TTL: Duration = Duration::from_secs(10 * 60);

/// A cached redirect and when it was learned.
#[derive(Debug, Clone)]
struct Entry {
    /// The signed URL the blob `GET` was redirected to.
    url: String,

    /// The instant the redirect was cached.
    created_at: Instant,
}

/// The redirect URLs of recently read blobs, keyed by blob hex digest.
///
/// Bounded and aged so a long-lived mount does not hoard expired links.
pub(crate) struct RedirectCache {
    /// The redirects by blob hex digest, least recently used first out.
    entries: Mutex<LruCache<String, Entry>>,

    /// The time an entry is trusted after it was cached.
    ttl: Duration,
}

/// Implements the redirect cache.
impl RedirectCache {
    /// Creates an empty cache whose entries expire after `ttl`.
    pub(crate) fn new(ttl: Duration) -> Self {
        Self {
            entries: Mutex::new(LruCache::new(NonZeroUsize::new(CAPACITY).unwrap())),
            ttl,
        }
    }

    /// Returns the redirect URL of `hex` when one is cached and still fresh,
    /// dropping an expired entry on the way.
    pub(crate) fn get(&self, hex: &str) -> Option<String> {
        let mut entries = self.entries.lock().unwrap();
        let entry = entries.get(hex)?;
        if entry.created_at.elapsed() >= self.ttl {
            entries.pop(hex);
            return None;
        }

        Some(entry.url.clone())
    }

    /// Remembers `url` as the redirect of `hex`, evicting the least recently
    /// used blob when full.
    pub(crate) fn insert(&self, hex: &str, url: String) {
        self.entries.lock().unwrap().put(
            hex.to_string(),
            Entry {
                url,
                created_at: Instant::now(),
            },
        );
    }

    /// Forgets the redirect of `hex`, after the link answered `401` or `403`.
    pub(crate) fn remove(&self, hex: &str) {
        self.entries.lock().unwrap().pop(hex);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_returns_what_insert_stored_until_remove() {
        let cache = RedirectCache::new(DEFAULT_TTL);
        assert_eq!(cache.get("a"), None);

        cache.insert("a", "http://cdn/a".to_string());
        assert_eq!(cache.get("a").as_deref(), Some("http://cdn/a"));

        cache.remove("a");
        assert_eq!(cache.get("a"), None);
    }

    #[test]
    fn get_drops_an_expired_entry() {
        let cache = RedirectCache::new(Duration::from_millis(20));
        cache.insert("a", "http://cdn/a".to_string());
        assert!(cache.get("a").is_some());

        std::thread::sleep(Duration::from_millis(30));
        assert_eq!(cache.get("a"), None);
        assert_eq!(cache.entries.lock().unwrap().len(), 0);
    }

    #[test]
    fn insert_evicts_the_least_recently_used_entry_when_full() {
        let cache = RedirectCache::new(DEFAULT_TTL);
        for i in 0..CAPACITY {
            cache.insert(&format!("blob-{i}"), format!("http://cdn/{i}"));
        }
        assert!(cache.get("blob-0").is_some());

        cache.insert("blob-new", "http://cdn/new".to_string());
        assert!(cache.get("blob-0").is_some());
        assert_eq!(cache.get("blob-1"), None);
        assert_eq!(cache.entries.lock().unwrap().len(), CAPACITY);
    }
}

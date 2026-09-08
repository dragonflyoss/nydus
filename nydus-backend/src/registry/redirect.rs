//! The cache of signed URLs a registry redirected blob `GET`s to.

use std::num::NonZeroUsize;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use lru::LruCache;

/// How many blobs' redirect URLs are remembered at once.
const CAPACITY: NonZeroUsize = NonZeroUsize::new(1000).unwrap();

/// How long a redirect URL is trusted before the next read re-resolves it.
/// Signed CDN links expire on their own schedule, this only bounds how stale
/// a hit can be, an expired link is also evicted the moment it answers `401`
/// or `403`.
const TTL: Duration = Duration::from_secs(10 * 60);

/// A cached redirect and when it was learned.
struct Entry {
    url: String,
    cached_at: Instant,
}

/// The redirect URLs of recently read blobs, keyed by blob hex digest.
/// Bounded and aged so a long-lived mount does not hoard expired links.
pub(crate) struct RedirectCache {
    entries: Mutex<LruCache<String, Entry>>,
    ttl: Duration,
}

impl RedirectCache {
    /// Create an empty cache with the default capacity and TTL.
    pub(crate) fn new() -> Self {
        Self::with_ttl(TTL)
    }

    /// Create an empty cache whose entries expire after `ttl`.
    fn with_ttl(ttl: Duration) -> Self {
        Self {
            entries: Mutex::new(LruCache::new(CAPACITY)),
            ttl,
        }
    }

    /// The redirect URL of `hex` if one is cached and still fresh, an expired
    /// entry being dropped on the way.
    pub(crate) fn get(&self, hex: &str) -> Option<String> {
        let mut entries = self.entries.lock().unwrap();
        let entry = entries.get(hex)?;
        if entry.cached_at.elapsed() >= self.ttl {
            entries.pop(hex);
            return None;
        }
        Some(entry.url.clone())
    }

    /// Remember `url` as the redirect of `hex`, evicting the least recently
    /// used blob when full.
    pub(crate) fn insert(&self, hex: &str, url: String) {
        self.entries.lock().unwrap().put(
            hex.to_string(),
            Entry {
                url,
                cached_at: Instant::now(),
            },
        );
    }

    /// Forget the redirect of `hex`, after the link answered `401` or `403`.
    pub(crate) fn remove(&self, hex: &str) {
        self.entries.lock().unwrap().pop(hex);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_get_and_remove() {
        let cache = RedirectCache::new();
        assert_eq!(cache.get("a"), None);

        cache.insert("a", "http://cdn/a".to_string());
        assert_eq!(cache.get("a").as_deref(), Some("http://cdn/a"));

        cache.remove("a");
        assert_eq!(cache.get("a"), None);
    }

    #[test]
    fn an_expired_entry_is_dropped_on_read() {
        let cache = RedirectCache::with_ttl(Duration::from_millis(20));
        cache.insert("a", "http://cdn/a".to_string());
        assert!(cache.get("a").is_some());

        std::thread::sleep(Duration::from_millis(30));
        assert_eq!(cache.get("a"), None);
        assert_eq!(cache.entries.lock().unwrap().len(), 0);
    }

    #[test]
    fn the_least_recently_used_entry_is_evicted_when_full() {
        let cache = RedirectCache::new();
        for i in 0..CAPACITY.get() {
            cache.insert(&format!("blob-{i}"), format!("http://cdn/{i}"));
        }
        assert!(cache.get("blob-0").is_some());

        cache.insert("blob-new", "http://cdn/new".to_string());
        assert!(cache.get("blob-0").is_some());
        assert_eq!(cache.get("blob-1"), None);
        assert_eq!(cache.entries.lock().unwrap().len(), CAPACITY.get());
    }
}

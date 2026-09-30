//! DNS resolution for the registry backend, backed by the system resolver
//! (`getaddrinfo`, through [`tokio::net::lookup_host`]).
//!
//! Results are cached and concurrent lookups for the same host are
//! de-duplicated with a small singleflight built on
//! [`futures::future::Shared`]. This avoids a thundering herd of identical DNS
//! queries when many blob requests start at once after mount.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures::future::{BoxFuture, FutureExt, Shared};
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use tokio::sync::RwLock;

/// TTL applied to successful lookups; the system resolver reports no record TTL.
const POSITIVE_CACHE_TTL: Duration = Duration::from_secs(60);

/// TTL applied to failed lookups, to avoid hammering the DNS server.
const NEGATIVE_CACHE_TTL: Duration = Duration::from_secs(60);

/// A cached DNS result, either a set of addresses or an error message.
#[derive(Clone)]
struct CachedLookup {
    valid_until: Instant,
    result: Result<Arc<Vec<IpAddr>>, String>,
}

type SharedLookup = Shared<BoxFuture<'static, Arc<CachedLookup>>>;

#[derive(Default)]
struct ResolverState {
    cache: RwLock<HashMap<String, Arc<CachedLookup>>>,
    inflight: Mutex<HashMap<String, SharedLookup>>,
}

/// A `reqwest`-compatible resolver that caches and de-duplicates lookups.
#[derive(Clone, Default)]
pub(crate) struct SystemResolver {
    state: Arc<ResolverState>,
}

impl Resolve for SystemResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let state = self.state.clone();
        Box::pin(async move {
            let host = name.as_str().to_string();
            let cached = resolve_cached(state, host).await;
            match &cached.result {
                Ok(addrs) => {
                    let iter = SocketAddrs {
                        iter: addrs.as_ref().clone().into_iter(),
                    };
                    Ok(Box::new(iter) as Addrs)
                }
                Err(err) => Err(err.clone().into()),
            }
        })
    }
}

async fn resolve_cached(state: Arc<ResolverState>, host: String) -> Arc<CachedLookup> {
    // Fast path: a still-valid cache entry.
    {
        let cache = state.cache.read().await;
        if let Some(entry) = cache.get(&host) {
            if entry.valid_until > Instant::now() {
                return entry.clone();
            }
        }
    }

    // Singleflight: only one lookup per host runs concurrently.
    let shared = {
        let mut inflight = state.inflight.lock().unwrap();
        if let Some(existing) = inflight.get(&host) {
            existing.clone()
        } else {
            let fut = lookup_and_cache(state.clone(), host.clone())
                .boxed()
                .shared();
            inflight.insert(host.clone(), fut.clone());
            fut
        }
    };

    shared.await
}

async fn lookup_and_cache(state: Arc<ResolverState>, host: String) -> Arc<CachedLookup> {
    let cached = match tokio::net::lookup_host((host.as_str(), 0u16)).await {
        Ok(addrs) => Arc::new(CachedLookup {
            valid_until: Instant::now() + POSITIVE_CACHE_TTL,
            result: Ok(Arc::new(addrs.map(|addr| addr.ip()).collect())),
        }),
        Err(err) => Arc::new(CachedLookup {
            valid_until: Instant::now() + NEGATIVE_CACHE_TTL,
            result: Err(err.to_string()),
        }),
    };

    state
        .cache
        .write()
        .await
        .insert(host.clone(), cached.clone());
    state.inflight.lock().unwrap().remove(&host);
    cached
}

struct SocketAddrs {
    iter: std::vec::IntoIter<IpAddr>,
}

impl Iterator for SocketAddrs {
    type Item = SocketAddr;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next().map(|ip| SocketAddr::new(ip, 0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_localhost() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let resolver = SystemResolver::default();
            let name: Name = "localhost".parse().unwrap();
            let addrs = resolver.resolve(name).await.unwrap();
            assert!(addrs.count() > 0);
        });
    }

    #[test]
    fn caches_repeated_lookups() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let resolver = SystemResolver::default();
            let state = resolver.state.clone();
            let _ = resolve_cached(state.clone(), "localhost".to_string()).await;
            assert!(state.cache.read().await.contains_key("localhost"));
            // Second resolution should hit the cache and dedup cleanly.
            let again = resolve_cached(state, "localhost".to_string()).await;
            assert!(again.result.is_ok());
        });
    }
}

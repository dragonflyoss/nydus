//! DNS resolution for the registry backend, backed by
//! [hickory-resolver](https://github.com/hickory-dns/hickory-dns).
//!
//! Results are cached with their record TTL (failures use a short negative
//! TTL), and concurrent lookups for the same host are de-duplicated with a
//! small singleflight built on [`futures::future::Shared`]. This avoids a
//! thundering herd of identical DNS queries when many blob requests start at
//! once after mount.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures::future::{BoxFuture, FutureExt, Shared};
use hickory_resolver::config::LookupIpStrategy;
use hickory_resolver::TokioResolver;
use once_cell::sync::OnceCell;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use tokio::sync::RwLock;

/// TTL applied to failed lookups, to avoid hammering the DNS server.
const NEGATIVE_CACHE_TTL: Duration = Duration::from_secs(60);

/// A cached DNS result, either a set of addresses or an error message.
#[derive(Clone)]
struct CachedLookup {
    valid_until: Instant,
    result: Result<Arc<Vec<IpAddr>>, String>,
}

type SharedLookup = Shared<BoxFuture<'static, Arc<CachedLookup>>>;

struct ResolverState {
    resolver: TokioResolver,
    cache: RwLock<HashMap<String, Arc<CachedLookup>>>,
    inflight: Mutex<HashMap<String, SharedLookup>>,
}

/// A `reqwest`-compatible resolver that caches and de-duplicates lookups.
#[derive(Clone, Default)]
pub(crate) struct HickoryResolver {
    // Construction is delayed because there may be no Tokio runtime when the
    // resolver is created; it is initialized lazily on first use.
    state: Arc<OnceCell<Arc<ResolverState>>>,
}

impl HickoryResolver {
    fn state(&self) -> Result<Arc<ResolverState>, String> {
        self.state
            .get_or_try_init(|| {
                let mut builder =
                    TokioResolver::builder_tokio().map_err(|e| format!("dns init failed: {e}"))?;
                builder.options_mut().ip_strategy = LookupIpStrategy::Ipv4thenIpv6;
                Ok::<_, String>(Arc::new(ResolverState {
                    resolver: builder.build(),
                    cache: RwLock::new(HashMap::new()),
                    inflight: Mutex::new(HashMap::new()),
                }))
            })
            .cloned()
    }
}

impl Resolve for HickoryResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let this = self.clone();
        Box::pin(async move {
            let state = this.state().map_err(|e| -> BoxError { e.into() })?;
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

type BoxError = Box<dyn std::error::Error + Send + Sync>;

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
    let cached = match state.resolver.lookup_ip(host.as_str()).await {
        Ok(lookup) => Arc::new(CachedLookup {
            valid_until: lookup.valid_until(),
            result: Ok(Arc::new(lookup.iter().collect())),
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
            let resolver = HickoryResolver::default();
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
            let resolver = HickoryResolver::default();
            let state = resolver.state().unwrap();
            let _ = resolve_cached(state.clone(), "localhost".to_string()).await;
            assert!(state.cache.read().await.contains_key("localhost"));
            // Second resolution should hit the cache and dedup cleanly.
            let again = resolve_cached(state, "localhost".to_string()).await;
            assert!(again.result.is_ok());
        });
    }
}

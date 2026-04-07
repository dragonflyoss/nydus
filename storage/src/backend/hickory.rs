//! DNS resolution via the [hickory-resolver](https://github.com/hickory-dns/hickory-dns) crate

use hickory_resolver::{config::LookupIpStrategy, ResolveError, TokioResolver};
use once_cell::sync::OnceCell;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use tokio::sync::RwLock;

use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::{Duration, Instant};

use nydus_utils::singleflight::{Group, SingleflightError};

/// TTL for caching failed DNS lookups to prevent overwhelming DNS servers.
const NEGATIVE_CACHE_TTL: Duration = Duration::from_secs(60);

/// Cached DNS lookup result with TTL information.
#[derive(Clone)]
struct CachedLookup {
    /// Resolved IP addresses (empty if lookup failed).
    addrs: Vec<IpAddr>,
    /// The time when this cache entry expires.
    valid_until: Instant,
    /// Error message if the lookup failed, None if successful.
    error: Option<String>,
}

/// Inner state shared across clones of the resolver.
struct ResolverState {
    /// The underlying hickory-dns resolver.
    resolver: TokioResolver,
    /// Cache of DNS lookup results keyed by domain_name.
    cache: RwLock<HashMap<String, Arc<CachedLookup>>>,
    /// Singleflight group for deduplicating concurrent lookups.
    singleflight: Group,
}

impl fmt::Debug for ResolverState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResolverState")
            .field("resolver", &"TokioResolver")
            .field("cache", &"RwLock<HashMap<...>>")
            .finish()
    }
}

/// Wrapper around an `AsyncResolver`, which implements the `Resolve` trait.
#[derive(Debug, Default, Clone)]
pub(crate) struct HickoryDnsResolver {
    /// Since we might not have been called in the context of a
    /// Tokio Runtime in initialization, so we must delay the actual
    /// construction of the resolver.
    state: Arc<OnceCell<ResolverState>>,
    /// Count of total DNS lookups performed (for testing/metrics).
    lookup_count: Arc<AtomicU64>,
}

struct SocketAddrs {
    iter: std::vec::IntoIter<IpAddr>,
}

#[derive(Debug)]
struct HickoryDnsSystemConfError(ResolveError);

impl Resolve for HickoryDnsResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let resolver = self.clone();
        Box::pin(async move {
            let state = resolver.state.get_or_try_init(new_resolver_state)?;
            let domain_name = name.as_str().to_string();

            // Fast path: check if we have a valid cached result.
            {
                let cache = state.cache.read().await;
                if let Some(cached) = cache.get(&domain_name) {
                    if cached.valid_until > Instant::now() {
                        // Check if this is a cached error (negative cache).
                        if let Some(ref err) = cached.error {
                            return Err(err.clone().into());
                        }
                        let addrs: Addrs = Box::new(SocketAddrs {
                            iter: cached.addrs.clone().into_iter(),
                        });
                        return Ok(addrs);
                    }
                }
            }

            // Use singleflight to deduplicate concurrent lookups.
            let lookup_count = resolver.lookup_count.clone();
            let domain_name_clone = domain_name.clone();

            let call_result = state
                .singleflight
                .do_call(&domain_name, || async {
                    // Perform the actual DNS lookup.
                    lookup_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let lookup_result = state.resolver.lookup_ip(domain_name_clone.as_str()).await;

                    let cached = match lookup_result {
                        Ok(lookup) => {
                            let valid_until = lookup.valid_until();
                            trace!(
                                "Resolved {} to {:?}, valid until {:?}",
                                domain_name_clone,
                                lookup.iter().collect::<Vec<IpAddr>>(),
                                valid_until.duration_since(std::time::Instant::now())
                            );
                            let addrs: Vec<IpAddr> = lookup.iter().collect();
                            Arc::new(CachedLookup {
                                addrs,
                                valid_until,
                                error: None,
                            })
                        }
                        Err(e) => {
                            // Create a negative cache entry with NEGATIVE_CACHE_TTL.
                            Arc::new(CachedLookup {
                                addrs: Vec::new(),
                                valid_until: Instant::now() + NEGATIVE_CACHE_TTL,
                                error: Some(e.to_string()),
                            })
                        }
                    };

                    // Update cache inside singleflight - only the executor writes.
                    {
                        let mut cache = state.cache.write().await;
                        cache.insert(domain_name_clone.clone(), cached.clone());
                    }

                    // Return Ok with the cached result (both success and error cases).
                    // The error info is stored in cached.error field.
                    Ok::<_, std::convert::Infallible>(cached)
                })
                .await;

            // Process the result - cache is already updated by the executor.
            let cached = match call_result {
                Ok(result) => result.value,
                Err(SingleflightError::FunctionError(infallible)) => match infallible {},
                Err(SingleflightError::TypeMismatch) => {
                    return Err("DNS singleflight internal error: type mismatch".into());
                }
                Err(SingleflightError::Cancelled) => {
                    return Err("DNS singleflight call was cancelled".into());
                }
            };

            // Return the result.
            if let Some(ref err) = cached.error {
                Err(err.clone().into())
            } else {
                let addrs: Addrs = Box::new(SocketAddrs {
                    iter: cached.addrs.clone().into_iter(),
                });
                Ok(addrs)
            }
        })
    }
}

impl Iterator for SocketAddrs {
    type Item = SocketAddr;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next().map(|ip_addr| SocketAddr::new(ip_addr, 0))
    }
}

/// Create a new resolver state with the default configuration,
/// which reads from `/etc/resolve.conf`. The options are
/// overridden to look up for both IPv4 and IPv6 addresses
/// to work with "happy eyeballs" algorithm.
fn new_resolver_state() -> Result<ResolverState, HickoryDnsSystemConfError> {
    let mut builder = TokioResolver::builder_tokio().map_err(HickoryDnsSystemConfError)?;
    let opts = builder.options_mut();
    opts.ip_strategy = LookupIpStrategy::Ipv4thenIpv6;
    let resolver = builder.build();
    Ok(ResolverState {
        resolver,
        cache: RwLock::new(HashMap::new()),
        singleflight: Group::new(),
    })
}

impl fmt::Display for HickoryDnsSystemConfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("error reading DNS system conf for hickory-dns")
    }
}

impl std::error::Error for HickoryDnsSystemConfError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::dns::Resolve;
    use std::sync::atomic::Ordering;

    const CONCURRENT: usize = 1000;
    const SEQUENTIAL: usize = 50;

    #[tokio::test]
    async fn test_resolve_baidu_com() {
        let resolver = HickoryDnsResolver::default();
        let name: Name = "baidu.com".parse().unwrap();

        let addrs = resolver.resolve(name).await.expect("DNS resolution failed");
        let addrs_vec: Vec<_> = addrs.collect();

        assert!(!addrs_vec.is_empty(), "Should resolve to at least one IP");
        assert_eq!(
            resolver.lookup_count.load(Ordering::Relaxed),
            1,
            "Should perform exactly one DNS lookup"
        );
        println!("Resolved baidu.com to: {:?}", addrs_vec);
    }

    #[tokio::test]
    async fn test_concurrent_resolve_singleflight() {
        let resolver = HickoryDnsResolver::default();

        // Spawn multiple concurrent resolve tasks for the same domain.
        let mut handles = Vec::new();
        for _ in 0..CONCURRENT {
            let resolver_clone = resolver.clone();
            let handle = tokio::spawn(async move {
                let name: Name = "baidu.com".parse().unwrap();
                resolver_clone.resolve(name).await
            });
            handles.push(handle);
        }

        // Wait for all tasks to complete.
        let results: Vec<_> = futures::future::join_all(handles).await;

        // All should succeed.
        for result in results {
            let addrs = result
                .expect("Task panicked")
                .expect("DNS resolution failed");
            let addrs_vec: Vec<_> = addrs.collect();
            assert!(!addrs_vec.is_empty());
        }

        // Singleflight: only one actual DNS lookup should have occurred.
        let lookup_count = resolver.lookup_count.load(Ordering::Relaxed);
        assert_eq!(
            lookup_count, 1,
            "Singleflight should result in exactly 1 DNS lookup, got {}",
            lookup_count
        );
    }

    #[tokio::test]
    async fn test_cache_hit_within_ttl() {
        let resolver = HickoryDnsResolver::default();

        // First resolve to populate the cache.
        let name1: Name = "baidu.com".parse().unwrap();
        let addrs1 = resolver
            .resolve(name1)
            .await
            .expect("First DNS resolution failed");
        let addrs1_vec: Vec<_> = addrs1.collect();

        assert_eq!(
            resolver.lookup_count.load(Ordering::Relaxed),
            1,
            "First resolve should perform one DNS lookup"
        );

        // Perform sequential resolves, all should hit the cache.
        for i in 0..SEQUENTIAL {
            let name: Name = "baidu.com".parse().unwrap();
            let addrs = resolver
                .resolve(name)
                .await
                .unwrap_or_else(|_| panic!("DNS resolution {} failed", i + 2));
            let addrs_vec: Vec<_> = addrs.collect();

            // Results should be the same as the first resolve.
            assert_eq!(
                addrs1_vec,
                addrs_vec,
                "Cached result should match on iteration {}",
                i + 2
            );
        }

        // Lookup count should still be 1 after 51 total resolves (all cache hits after first).
        assert_eq!(
            resolver.lookup_count.load(Ordering::Relaxed),
            1,
            "All subsequent resolves should hit cache, total lookup count should be 1"
        );

        // Verify cache is populated.
        let state = resolver.state.get().expect("State should be initialized");
        let cache = state.cache.read().await;
        assert!(
            cache.contains_key("baidu.com"),
            "Cache should contain baidu.com"
        );
        let cached = cache.get("baidu.com").expect("Cache entry should exist");
        assert!(
            cached.valid_until > Instant::now(),
            "Cache should still be valid"
        );
    }

    #[tokio::test]
    async fn test_error_handling_allows_retry() {
        // Use an invalid domain that should fail.
        let resolver = HickoryDnsResolver::default();

        // First attempt should fail.
        let invalid_name1: Name = "this-domain-definitely-does-not-exist-12345.invalid"
            .parse()
            .unwrap();
        let result1 = resolver.resolve(invalid_name1).await;
        assert!(result1.is_err(), "Should fail for invalid domain");

        assert_eq!(
            resolver.lookup_count.load(Ordering::Relaxed),
            1,
            "First failed resolve should perform one DNS lookup"
        );

        // After error, cache SHOULD contain the failed entry (negative caching).
        let state = resolver.state.get().expect("State should be initialized");
        let cache = state.cache.read().await;
        assert!(
            cache.contains_key("this-domain-definitely-does-not-exist-12345.invalid"),
            "Failed lookups should be cached (negative caching)"
        );
        // Verify it's a negative cache entry.
        let cached = cache
            .get("this-domain-definitely-does-not-exist-12345.invalid")
            .expect("Cache entry should exist");
        assert!(cached.error.is_some(), "Should be cached as error");
        assert!(
            cached.valid_until > Instant::now(),
            "Negative cache should still be valid"
        );
        drop(cache);

        // Second attempt should hit the negative cache (no new DNS lookup).
        let invalid_name2: Name = "this-domain-definitely-does-not-exist-12345.invalid"
            .parse()
            .unwrap();
        let result2 = resolver.resolve(invalid_name2).await;
        assert!(result2.is_err(), "Should fail again for invalid domain");

        // Negative cache hit, so no additional lookup should occur.
        assert_eq!(
            resolver.lookup_count.load(Ordering::Relaxed),
            1,
            "Negative cache hit should not trigger another DNS lookup"
        );
    }

    #[tokio::test]
    async fn test_negative_cache_sequential_hits() {
        let resolver = HickoryDnsResolver::default();
        let invalid_domain = "sequential-test-nonexistent-domain.invalid";

        // First resolve to populate the negative cache.
        let name1: Name = invalid_domain.parse().unwrap();
        let result1 = resolver.resolve(name1).await;
        assert!(result1.is_err(), "Should fail for invalid domain");

        assert_eq!(
            resolver.lookup_count.load(Ordering::Relaxed),
            1,
            "First failed resolve should perform one DNS lookup"
        );

        // Perform sequential resolves, all should hit the negative cache.
        for i in 0..SEQUENTIAL {
            let name: Name = invalid_domain.parse().unwrap();
            let result = resolver.resolve(name).await;
            assert!(
                result.is_err(),
                "Should fail for invalid domain on iteration {}",
                i + 2
            );
        }

        // Lookup count should still be 1 after 51 total resolves (all negative cache hits after first).
        assert_eq!(
            resolver.lookup_count.load(Ordering::Relaxed),
            1,
            "All subsequent resolves should hit negative cache, total lookup count should be 1"
        );

        // Verify negative cache is still populated.
        let state = resolver.state.get().expect("State should be initialized");
        let cache = state.cache.read().await;
        assert!(
            cache.contains_key(invalid_domain),
            "Negative cache should contain the invalid domain"
        );
        let cached = cache.get(invalid_domain).expect("Cache entry should exist");
        assert!(cached.error.is_some(), "Should be cached as error");
        assert!(
            cached.valid_until > Instant::now(),
            "Negative cache should still be valid"
        );
    }

    #[tokio::test]
    async fn test_negative_cache_expiry_allows_retry() {
        use std::time::Duration;

        let resolver = HickoryDnsResolver::default();
        let invalid_domain = "retry-test-nonexistent-domain.invalid";

        // First attempt should fail.
        let invalid_name1: Name = invalid_domain.parse().unwrap();
        let result1 = resolver.resolve(invalid_name1).await;
        assert!(result1.is_err(), "Should fail for invalid domain");

        assert_eq!(
            resolver.lookup_count.load(Ordering::Relaxed),
            1,
            "First failed resolve should perform one DNS lookup"
        );

        // Simulate negative cache expiry by modifying the cache entry.
        {
            let state = resolver.state.get().expect("State should be initialized");
            let mut cache = state.cache.write().await;

            if let Some(cached) = cache.get(invalid_domain) {
                let expired_cached = Arc::new(CachedLookup {
                    addrs: cached.addrs.clone(),
                    valid_until: Instant::now() - Duration::from_secs(1),
                    error: cached.error.clone(),
                });
                cache.insert(invalid_domain.to_string(), expired_cached);
            }
        }

        // After negative cache expires, retry should trigger a new DNS lookup.
        let invalid_name2: Name = invalid_domain.parse().unwrap();
        let result2 = resolver.resolve(invalid_name2).await;
        assert!(result2.is_err(), "Should fail again for invalid domain");

        // Retry after negative cache expiry should trigger another lookup.
        assert_eq!(
            resolver.lookup_count.load(Ordering::Relaxed),
            2,
            "Retry after negative cache expiry should perform another DNS lookup"
        );
    }

    #[tokio::test]
    async fn test_concurrent_error_singleflight() {
        let resolver = HickoryDnsResolver::default();
        let invalid_domain = "another-nonexistent-domain-xyz.invalid";

        // Spawn multiple concurrent resolve tasks for the invalid domain.
        let mut handles = Vec::new();
        for _ in 0..CONCURRENT {
            let resolver_clone = resolver.clone();
            let domain = invalid_domain.to_string();
            let handle = tokio::spawn(async move {
                let name: Name = domain.parse().unwrap();
                resolver_clone.resolve(name).await
            });
            handles.push(handle);
        }

        // Wait for all tasks to complete.
        let results: Vec<_> = futures::future::join_all(handles).await;

        // All should fail.
        for result in results {
            let resolve_result = result.expect("Task panicked");
            assert!(resolve_result.is_err(), "Should fail for invalid domain");
        }

        // Singleflight for errors: only one actual DNS lookup should have occurred.
        let lookup_count = resolver.lookup_count.load(Ordering::Relaxed);
        assert_eq!(
            lookup_count, 1,
            "Concurrent error lookups should result in exactly 1 DNS lookup, got {}",
            lookup_count
        );

        // Verify cache DOES contain the failed entry (negative caching).
        let state = resolver.state.get().expect("State should be initialized");
        let cache = state.cache.read().await;
        assert!(
            cache.contains_key(invalid_domain),
            "Failed lookups should be cached (negative caching)"
        );
        let cached = cache.get(invalid_domain).expect("Cache entry should exist");
        assert!(cached.error.is_some(), "Should be cached as error");
    }

    #[tokio::test]
    async fn test_multiple_domains_independent() {
        let resolver = HickoryDnsResolver::default();

        // Resolve different domains concurrently.
        let domains = vec!["baidu.com", "qq.com", "taobao.com"];
        let mut handles = Vec::new();

        for domain in &domains {
            let resolver_clone = resolver.clone();
            let domain = domain.to_string();
            let handle = tokio::spawn(async move {
                let name: Name = domain.parse().unwrap();
                resolver_clone.resolve(name).await
            });
            handles.push(handle);
        }

        let results: Vec<_> = futures::future::join_all(handles).await;

        // All should succeed.
        for (i, result) in results.into_iter().enumerate() {
            let addrs = result
                .expect("Task panicked")
                .unwrap_or_else(|_| panic!("DNS resolution failed for {}", domains[i]));
            let addrs_vec: Vec<_> = addrs.collect();
            assert!(
                !addrs_vec.is_empty(),
                "Should resolve {} to at least one IP",
                domains[i]
            );
            println!("Resolved {} to: {:?}", domains[i], addrs_vec);
        }

        // Each domain should result in exactly one DNS lookup.
        let lookup_count = resolver.lookup_count.load(Ordering::Relaxed);
        assert_eq!(
            lookup_count,
            domains.len() as u64,
            "Each domain should trigger exactly one DNS lookup, got {}",
            lookup_count
        );

        // Verify all domains are cached.
        let state = resolver.state.get().expect("State should be initialized");
        let cache = state.cache.read().await;
        for domain in &domains {
            assert!(
                cache.contains_key(*domain),
                "Cache should contain {}",
                domain
            );
        }
    }

    #[tokio::test]
    async fn test_ttl_expiry_triggers_new_lookup() {
        use std::time::Duration;

        let resolver = HickoryDnsResolver::default();

        // First resolve to populate the cache.
        let name1: Name = "baidu.com".parse().unwrap();
        let addrs1 = resolver
            .resolve(name1)
            .await
            .expect("First DNS resolution failed");
        let _: Vec<_> = addrs1.collect();

        assert_eq!(
            resolver.lookup_count.load(Ordering::Relaxed),
            1,
            "First resolve should perform one DNS lookup"
        );

        // Simulate TTL expiry by manually modifying the cache entry.
        {
            let state = resolver.state.get().expect("State should be initialized");
            let mut cache = state.cache.write().await;

            // Replace the cached entry with an expired one.
            if let Some(cached) = cache.get("baidu.com") {
                let expired_cached = Arc::new(CachedLookup {
                    addrs: cached.addrs.clone(),
                    // Set valid_until to a past time to simulate TTL expiry.
                    valid_until: Instant::now() - Duration::from_secs(1),
                    error: None,
                });
                cache.insert("baidu.com".to_string(), expired_cached);
            }
        }

        // Second resolve should trigger a new DNS lookup due to TTL expiry.
        let name2: Name = "baidu.com".parse().unwrap();
        let addrs2 = resolver
            .resolve(name2)
            .await
            .expect("Second DNS resolution failed");
        let _: Vec<_> = addrs2.collect();

        // Lookup count should now be 2 (TTL expired, so new lookup was performed).
        assert_eq!(
            resolver.lookup_count.load(Ordering::Relaxed),
            2,
            "TTL expiry should trigger a new DNS lookup"
        );

        // Verify the cache is updated with fresh data.
        let state = resolver.state.get().expect("State should be initialized");
        let cache = state.cache.read().await;
        let cached = cache
            .get("baidu.com")
            .expect("Cache entry should exist after refresh");
        assert!(
            cached.valid_until > Instant::now(),
            "Cache should be refreshed with a valid TTL"
        );
    }

    #[tokio::test]
    async fn test_concurrent_resolve_after_ttl_expiry() {
        use std::time::Duration;

        let resolver = HickoryDnsResolver::default();

        // First resolve to populate the cache.
        let name1: Name = "baidu.com".parse().unwrap();
        let _ = resolver
            .resolve(name1)
            .await
            .expect("First DNS resolution failed");

        assert_eq!(
            resolver.lookup_count.load(Ordering::Relaxed),
            1,
            "First resolve should perform one DNS lookup"
        );

        // Simulate TTL expiry.
        {
            let state = resolver.state.get().expect("State should be initialized");
            let mut cache = state.cache.write().await;

            if let Some(cached) = cache.get("baidu.com") {
                let expired_cached = Arc::new(CachedLookup {
                    addrs: cached.addrs.clone(),
                    valid_until: Instant::now() - Duration::from_secs(1),
                    error: None,
                });
                cache.insert("baidu.com".to_string(), expired_cached);
            }
        }

        // Spawn multiple concurrent resolve tasks after TTL expiry.
        let mut handles = Vec::new();
        for _ in 0..CONCURRENT {
            let resolver_clone = resolver.clone();
            let handle = tokio::spawn(async move {
                let name: Name = "baidu.com".parse().unwrap();
                resolver_clone.resolve(name).await
            });
            handles.push(handle);
        }

        // Wait for all tasks to complete.
        let results: Vec<_> = futures::future::join_all(handles).await;

        // All should succeed.
        for result in results {
            let addrs = result
                .expect("Task panicked")
                .expect("DNS resolution failed");
            let addrs_vec: Vec<_> = addrs.collect();
            assert!(!addrs_vec.is_empty());
        }

        // Singleflight after TTL expiry: only one additional DNS lookup should occur.
        let lookup_count = resolver.lookup_count.load(Ordering::Relaxed);
        assert_eq!(
            lookup_count, 2,
            "Concurrent resolves after TTL expiry should result in exactly 2 total lookups (1 initial + 1 refresh), got {}",
            lookup_count
        );
    }
}

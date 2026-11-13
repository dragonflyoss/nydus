//! The DNS resolver of the origin client.

use std::fs;
use std::io;
use std::net::SocketAddr;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use hickory_resolver::config::LookupIpStrategy;
use hickory_resolver::TokioResolver;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use tracing::{info, warn};

/// What tells one version of a configuration file from the next: its device,
/// inode, size and modification time, `None` while the file is missing.
type Stamp = Option<(u64, u64, u64, i64, i64)>;

/// A value built from configuration files and built again once they change.
struct Reloading<T> {
    /// The configuration files.
    paths: Vec<PathBuf>,

    /// The stamps of the files the value was built from, and the value.
    state: Mutex<(Vec<Stamp>, Option<Arc<T>>)>,
}

/// Implements the reloading value.
impl<T> Reloading<T> {
    /// Creates a value of the files at `paths`, built at its first use.
    fn new(paths: Vec<PathBuf>) -> Self {
        Self {
            paths,
            state: Mutex::new((Vec::new(), None)),
        }
    }

    /// Returns the value, built with `build` when there is none yet or the
    /// files changed since. A build that fails keeps the value of the
    /// earlier files and is tried again at the next call.
    fn get(&self, build: impl FnOnce() -> io::Result<T>) -> io::Result<Arc<T>> {
        let stamps: Vec<Stamp> = self
            .paths
            .iter()
            .map(|path| {
                let metadata = fs::metadata(path).ok()?;
                Some((
                    metadata.dev(),
                    metadata.ino(),
                    metadata.size(),
                    metadata.mtime(),
                    metadata.mtime_nsec(),
                ))
            })
            .collect();

        let mut state = self.state.lock().unwrap();
        if let Some(value) = state.1.as_ref().filter(|_| state.0 == stamps) {
            return Ok(value.clone());
        }

        match (build(), &state.1) {
            (Ok(value), previous) => {
                if previous.is_some() {
                    info!("the system DNS configuration changed, resolving with the new one");
                }
                let value = Arc::new(value);
                *state = (stamps, Some(value.clone()));
                Ok(value)
            }
            (Err(err), Some(previous)) => {
                warn!("failed to read the changed system DNS configuration, keeping the earlier one: {err}");
                Ok(previous.clone())
            }
            (Err(err), None) => Err(err),
        }
    }
}

/// The resolver of the origin client: hickory over the system DNS
/// configuration, as reqwest's `hickory-dns` feature builds it.
///
/// reqwest reads the configuration once per client. A client lives as long
/// as its mount, so a mount would go on asking the name servers it started
/// with after the node was given others, and fail every request once they
/// are gone. This resolver follows `/etc/resolv.conf` and `/etc/hosts`, as
/// the libc resolvers do.
pub(crate) struct Resolver {
    /// The hickory resolver of the current configuration.
    resolver: Arc<Reloading<TokioResolver>>,
}

/// Implements the origin resolver.
impl Resolver {
    /// Creates the resolver of the system DNS configuration.
    pub(crate) fn new() -> Self {
        Self {
            resolver: Arc::new(Reloading::new(vec![
                PathBuf::from("/etc/resolv.conf"),
                PathBuf::from("/etc/hosts"),
            ])),
        }
    }
}

/// Implements DNS resolution for reqwest.
impl Resolve for Resolver {
    /// Resolves `name` with the resolver of the current configuration.
    fn resolve(&self, name: Name) -> Resolving {
        let resolver = self.resolver.clone();
        Box::pin(async move {
            // Built here, on the runtime the lookups run on.
            let resolver = resolver.get(|| {
                let mut builder = TokioResolver::builder_tokio().map_err(io::Error::other)?;
                builder.options_mut().ip_strategy = LookupIpStrategy::Ipv4AndIpv6;
                Ok(builder.build())
            })?;
            let lookup = resolver.lookup_ip(name.as_str()).await?;
            let addrs: Addrs = Box::new(lookup.into_iter().map(|ip| SocketAddr::new(ip, 0)));
            Ok(addrs)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use tempfile::tempdir;

    #[test]
    fn get_builds_again_only_once_a_file_changed() {
        let dir = tempdir().unwrap();
        let resolv_conf = dir.path().join("resolv.conf");
        let hosts = dir.path().join("hosts");
        let reloading = Reloading::new(vec![resolv_conf.clone(), hosts.clone()]);
        let builds = AtomicU32::new(0);
        let build = || Ok(builds.fetch_add(1, Ordering::SeqCst) + 1);
        let failing = || Err(io::Error::other("invalid configuration"));

        assert!(reloading.get(failing).is_err());
        assert_eq!(*reloading.get(build).unwrap(), 1);
        assert_eq!(*reloading.get(build).unwrap(), 1);

        fs::write(&resolv_conf, "nameserver 10.0.0.1\n").unwrap();
        assert_eq!(*reloading.get(build).unwrap(), 2);
        assert_eq!(*reloading.get(build).unwrap(), 2);

        fs::write(&hosts, "10.0.0.2 registry\n").unwrap();
        assert_eq!(*reloading.get(build).unwrap(), 3);

        fs::write(&resolv_conf, "nameserver 10.0.0.1\nnameserver 10.0.0.3\n").unwrap();
        assert_eq!(*reloading.get(failing).unwrap(), 3);
        assert_eq!(*reloading.get(build).unwrap(), 4);

        fs::remove_file(&resolv_conf).unwrap();
        assert_eq!(*reloading.get(build).unwrap(), 5);
        assert_eq!(*reloading.get(build).unwrap(), 5);
    }

    #[tokio::test]
    async fn resolve_answers_from_the_system_configuration() {
        let resolver = Resolver::new();
        let name: Name = "localhost".parse().unwrap();
        let addrs: Vec<SocketAddr> = resolver.resolve(name).await.unwrap().collect();
        assert!(addrs.iter().any(|addr| addr.ip().is_loopback()));
    }
}

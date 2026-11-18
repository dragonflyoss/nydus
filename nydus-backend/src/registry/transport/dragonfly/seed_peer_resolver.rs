//! The Dragonfly seed peer resolver, shared by the processes on a host.

use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{debug, error, warn};

use dragonfly_api::common::v2::Host;
use dragonfly_client_request::{SchedulerClient, SeedPeer};

/// Resolves the seed peers of a scheduler like a gRPC resolver, sharing them
/// through a cache file that is replaced with `rename(2)`, so a reader never
/// waits for a writer.
///
/// ```text
/// read ─┬─ fresh ─────────────────────────────────────────────────────────▶ seed peers
///       └─ expired ─▶ LOCK_EX ─┬─ taken ─▶ list ─▶ write .tmp ─▶ rename ─▶ seed peers
///                              └─ held by another process ─┬─ expired seed peers ─▶ serve them
///                                                          └─ none ─▶ wait, read again
/// ```
///
/// A listing that fails or finds no seed peer keeps the cached ones and is
/// retried sooner; a process that cannot use the cache file lists alone.
pub(crate) struct SeedPeerResolver {
    /// The scheduler endpoint.
    scheduler_endpoint: String,

    /// The cache file path.
    path: PathBuf,

    /// Whether the cache file has been found unshared.
    unshared: AtomicBool,
}

/// Implements the seed peer resolver.
impl SeedPeerResolver {
    /// The interval between listings.
    pub(crate) const REFRESH_INTERVAL: Duration = Duration::from_secs(60);

    /// The retry interval after a failed listing.
    pub(crate) const RETRY_INTERVAL: Duration = Duration::from_secs(10);

    /// The timeout of each scheduler request.
    const LIST_TIMEOUT: Duration = Duration::from_secs(5);

    /// The longest a listing takes, DNS resolution included, and so the time
    /// to wait for another process listing: two [`Self::LIST_TIMEOUT`]s plus
    /// the SDK's 3s health checks.
    const WAIT_TIMEOUT: Duration = Duration::from_secs(15);

    /// The interval between reads while another process lists.
    const POLL_INTERVAL: Duration = Duration::from_millis(100);

    /// Creates the resolver of `scheduler_endpoint`, caching in `dir`.
    pub(crate) fn new(dir: &Path, scheduler_endpoint: String) -> Self {
        let hash = hex::encode(Sha256::digest(scheduler_endpoint.as_bytes()));
        Self {
            path: dir.join(format!("{}.v1.json", &hash[..16])),
            scheduler_endpoint,
            unshared: AtomicBool::new(false),
        }
    }

    /// Resolves the seed peers, listing them when the cache file is expired,
    /// failing only when this process lists them alone and listing fails.
    pub(crate) async fn resolve(&self) -> io::Result<SeedPeerState> {
        let wait_timeout = tokio::time::sleep(Self::WAIT_TIMEOUT);
        tokio::pin!(wait_timeout);

        loop {
            let err = match self.read() {
                Ok(Some(cached)) if cached.is_fresh() => return Ok(cached),
                Ok(cached) => match self.refresh().await {
                    Ok(refreshed) => return Ok(refreshed),
                    Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                        // Serve the expired seed peers while another process
                        // lists them, reading again after a retry interval.
                        if let Some(cached) = cached {
                            return Ok(SeedPeerState {
                                next_refresh_at: SystemTime::now() + Self::RETRY_INTERVAL,
                                ..cached
                            });
                        }

                        tokio::select! {
                            _ = tokio::time::sleep(Self::POLL_INTERVAL) => continue,
                            _ = &mut wait_timeout => {
                                warn!(
                                    "timed out waiting for another process to list dragonfly seed peers through {}, listing them alone",
                                    self.path.display()
                                );
                                return self.list().await;
                            }
                        }
                    }
                    Err(err) => err,
                },
                Err(err) => err,
            };

            if self.unshared.swap(true, Ordering::Relaxed) {
                debug!(
                    "dragonfly seed peers not shared through {}, listing them alone: {err}",
                    self.path.display()
                );
            } else {
                warn!(
                    "dragonfly seed peers not shared through {}, listing them alone: {err}",
                    self.path.display()
                );
            }
            return self.list().await;
        }
    }

    /// Reads the cache file, `None` when missing, invalid or for another
    /// scheduler.
    fn read(&self) -> io::Result<Option<SeedPeerState>> {
        let mut file = match Self::open(&self.path, OpenOptions::new().read(true)) {
            Ok(file) => file,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(err),
        };

        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        Ok(serde_json::from_slice::<SeedPeerState>(&bytes)
            .ok()
            .filter(|cached| cached.scheduler_endpoint == self.scheduler_endpoint))
    }

    /// Lists the seed peers into the cache file, holding the lock file.
    async fn refresh(&self) -> io::Result<SeedPeerState> {
        let lock = Self::open(
            &self.path.with_extension("json.lock"),
            OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(false)
                .mode(0o600),
        )?;
        Self::try_lock(&lock)?;

        // Return what another process refreshed meanwhile.
        let cached = self.read()?;
        if let Some(cached) = cached.as_ref().filter(|cached| cached.is_fresh()) {
            return Ok(cached.clone());
        }

        // Keep the cached seed peers when listing fails, retrying sooner.
        let refreshed = self.list().await.unwrap_or_else(|err| {
            error!("{err}, retrying in {:?}", Self::RETRY_INTERVAL);
            SeedPeerState {
                scheduler_endpoint: self.scheduler_endpoint.clone(),
                next_refresh_at: SystemTime::now() + Self::RETRY_INTERVAL,
                seed_peers: cached.map(|cached| cached.seed_peers).unwrap_or_default(),
            }
        });

        // Replace the cache file at once, serving the seed peers even when
        // sharing them fails.
        let tmp_path = self.path.with_extension("json.tmp");
        serde_json::to_vec(&refreshed)
            .map_err(io::Error::from)
            .and_then(|bytes| {
                Self::open(
                    &tmp_path,
                    OpenOptions::new()
                        .write(true)
                        .create(true)
                        .truncate(true)
                        .mode(0o600),
                )?
                .write_all(&bytes)?;
                fs::rename(&tmp_path, &self.path)
            })
            .unwrap_or_else(|err| {
                warn!(
                    "failed to share dragonfly seed peers through {}: {err}",
                    self.path.display()
                )
            });

        Ok(refreshed)
    }

    /// Lists the seed peers from the scheduler, failing when it lists none
    /// or takes longer than [`Self::WAIT_TIMEOUT`].
    async fn list(&self) -> io::Result<SeedPeerState> {
        let result = tokio::time::timeout(Self::WAIT_TIMEOUT, async {
            SchedulerClient::new(&self.scheduler_endpoint, Self::LIST_TIMEOUT)
                .await?
                .list_seed_peers()
                .await
        })
        .await;

        let seed_peers = match result {
            Ok(Ok(seed_peers)) if !seed_peers.is_empty() => seed_peers,
            Ok(Ok(_)) => {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!(
                        "failed to list dragonfly seed peers from {}: none listed",
                        self.scheduler_endpoint
                    ),
                ))
            }
            Ok(Err(err)) => {
                return Err(io::Error::other(format!(
                    "failed to list dragonfly seed peers from {}: {err}",
                    self.scheduler_endpoint
                )))
            }
            Err(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!(
                        "failed to list dragonfly seed peers from {} within {:?}",
                        self.scheduler_endpoint,
                        Self::WAIT_TIMEOUT
                    ),
                ))
            }
        };

        Ok(SeedPeerState {
            scheduler_endpoint: self.scheduler_endpoint.clone(),
            next_refresh_at: SystemTime::now() + Self::REFRESH_INTERVAL,
            seed_peers: seed_peers.into_iter().map(SeedPeerAddress::from).collect(),
        })
    }

    /// Opens `path`, refusing symlinks, FIFOs and non-regular files.
    fn open(path: &Path, options: &mut OpenOptions) -> io::Result<File> {
        let file = options
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)?;
        if !file.metadata()?.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{} is not a regular file", path.display()),
            ));
        }

        Ok(file)
    }

    /// Takes an exclusive lock without waiting, like `File::try_lock` in Rust
    /// 1.89.
    fn try_lock(file: &File) -> io::Result<()> {
        // SAFETY: flock takes no pointers.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(())
    }
}

/// The seed peers listed from a scheduler.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct SeedPeerState {
    /// The scheduler endpoint.
    scheduler_endpoint: String,

    /// The time to list the seed peers again.
    #[serde(with = "humantime_serde")]
    pub(crate) next_refresh_at: SystemTime,

    /// The seed peers.
    seed_peers: Vec<SeedPeerAddress>,
}

/// Implements the seed peer state.
impl SeedPeerState {
    /// Returns whether the seed peers are fresh, a due time beyond the refresh
    /// interval counting as stale.
    fn is_fresh(&self) -> bool {
        let now = SystemTime::now();
        now < self.next_refresh_at
            && self.next_refresh_at <= now + SeedPeerResolver::REFRESH_INTERVAL
    }

    /// Returns the seed peers for the SDK, skipping unnamed and duplicated ones.
    pub(crate) fn seed_peers(&self) -> Vec<SeedPeer> {
        let mut names = HashSet::with_capacity(self.seed_peers.len());
        self.seed_peers
            .iter()
            .filter(|seed_peer| !seed_peer.name.is_empty() && names.insert(seed_peer.name.as_str()))
            .cloned()
            .map(SeedPeer::from)
            .collect()
    }
}

/// The address of a seed peer in the cache file.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct SeedPeerAddress {
    /// The host id.
    id: String,

    /// The host name, the hashring key.
    name: String,

    /// The hostname.
    hostname: String,

    /// The IP address.
    ip: String,

    /// The gRPC port.
    port: i32,

    /// The proxy port.
    proxy_port: i32,

    /// Whether the seed peer is healthy.
    healthy: bool,
}

/// Implements the conversion from the SDK seed peer.
impl From<SeedPeer> for SeedPeerAddress {
    /// Keeps the cached fields of the host.
    fn from(seed_peer: SeedPeer) -> Self {
        Self {
            id: seed_peer.host.id,
            name: seed_peer.host.name,
            hostname: seed_peer.host.hostname,
            ip: seed_peer.host.ip,
            port: seed_peer.host.port,
            proxy_port: seed_peer.host.proxy_port,
            healthy: seed_peer.healthy,
        }
    }
}

/// Implements the conversion to the SDK seed peer.
impl From<SeedPeerAddress> for SeedPeer {
    /// Fills the cached fields of the host, leaving the rest default.
    fn from(seed_peer: SeedPeerAddress) -> Self {
        Self {
            host: Host {
                id: seed_peer.id,
                name: seed_peer.name,
                hostname: seed_peer.hostname,
                ip: seed_peer.ip,
                port: seed_peer.port,
                proxy_port: seed_peer.proxy_port,
                ..Default::default()
            },
            healthy: seed_peer.healthy,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;
    use std::fs;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use tempfile::tempdir;
    use url::Url;

    const SCHEDULER_ENDPOINT: &str = "http://127.0.0.1:1/";

    fn seed_peer_address(name: &str) -> SeedPeerAddress {
        SeedPeerAddress {
            id: name.to_string(),
            name: name.to_string(),
            hostname: name.to_string(),
            ip: "10.0.0.1".to_string(),
            port: 65000,
            proxy_port: 4001,
            healthy: true,
        }
    }

    fn lock_file(seed_peer_resolver: &SeedPeerResolver) -> File {
        let lock = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(seed_peer_resolver.path.with_extension("json.lock"))
            .unwrap();
        SeedPeerResolver::try_lock(&lock).unwrap();
        lock
    }

    fn seed_peer_state(scheduler_endpoint: &str, next_refresh_at: SystemTime) -> SeedPeerState {
        SeedPeerState {
            scheduler_endpoint: scheduler_endpoint.to_string(),
            next_refresh_at,
            seed_peers: vec![seed_peer_address("seed-peer-0")],
        }
    }

    #[test]
    fn cache_file_keeps_the_v1_name_and_format() {
        let dir = tempdir().unwrap();
        let scheduler_endpoint: String = Url::parse("http://127.0.0.1:1").unwrap().into();
        let seed_peer_resolver = SeedPeerResolver::new(dir.path(), scheduler_endpoint.clone());
        let cached = seed_peer_state(
            &scheduler_endpoint,
            SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000),
        );

        assert_eq!(
            seed_peer_resolver.path,
            dir.path().join("e87f700bacfeed52.v1.json")
        );
        assert_eq!(
            serde_json::to_string(&cached).unwrap(),
            r#"{"scheduler_endpoint":"http://127.0.0.1:1/","next_refresh_at":"2027-01-15T08:00:00Z","seed_peers":[{"id":"seed-peer-0","name":"seed-peer-0","hostname":"seed-peer-0","ip":"10.0.0.1","port":65000,"proxy_port":4001,"healthy":true}]}"#
        );
    }

    #[test]
    fn seed_peers_skips_unnamed_and_duplicated_seed_peers() {
        let cached = SeedPeerState {
            scheduler_endpoint: SCHEDULER_ENDPOINT.to_string(),
            next_refresh_at: SystemTime::now(),
            seed_peers: vec![
                seed_peer_address("seed-peer-0"),
                seed_peer_address(""),
                seed_peer_address("seed-peer-0"),
                seed_peer_address("seed-peer-1"),
            ],
        };

        let names: Vec<String> = cached
            .seed_peers()
            .into_iter()
            .map(|seed_peer| seed_peer.host.name)
            .collect();
        assert_eq!(names, ["seed-peer-0", "seed-peer-1"]);
    }

    #[tokio::test]
    async fn resolve_reads_a_fresh_cache_file_without_listing() {
        let dir = tempdir().unwrap();
        let seed_peer_resolver = SeedPeerResolver::new(dir.path(), SCHEDULER_ENDPOINT.to_string());
        let fresh = seed_peer_state(
            SCHEDULER_ENDPOINT,
            SystemTime::now() + Duration::from_secs(20),
        );
        fs::write(
            &seed_peer_resolver.path,
            serde_json::to_vec(&fresh).unwrap(),
        )
        .unwrap();

        assert_eq!(seed_peer_resolver.resolve().await.unwrap(), fresh);
    }

    #[tokio::test]
    async fn resolve_keeps_the_seed_peers_of_an_expired_cache_file_when_listing_fails() {
        let dir = tempdir().unwrap();
        let seed_peer_resolver = SeedPeerResolver::new(dir.path(), SCHEDULER_ENDPOINT.to_string());
        let expired = seed_peer_state(SCHEDULER_ENDPOINT, SystemTime::now());
        fs::write(
            &seed_peer_resolver.path,
            serde_json::to_vec(&expired).unwrap(),
        )
        .unwrap();

        let listed_at = SystemTime::now();
        let resolved = seed_peer_resolver.resolve().await.unwrap();

        assert_eq!(resolved.seed_peers, expired.seed_peers);
        assert!(resolved.next_refresh_at >= listed_at + SeedPeerResolver::RETRY_INTERVAL);
        assert!(resolved.next_refresh_at <= SystemTime::now() + SeedPeerResolver::RETRY_INTERVAL);
        assert_eq!(seed_peer_resolver.read().unwrap(), Some(resolved));
    }

    #[tokio::test]
    async fn resolve_lists_again_a_cache_file_due_beyond_the_refresh_interval() {
        let dir = tempdir().unwrap();
        let seed_peer_resolver = SeedPeerResolver::new(dir.path(), SCHEDULER_ENDPOINT.to_string());
        let skewed = seed_peer_state(
            SCHEDULER_ENDPOINT,
            SystemTime::now() + Duration::from_secs(3600),
        );
        fs::write(
            &seed_peer_resolver.path,
            serde_json::to_vec(&skewed).unwrap(),
        )
        .unwrap();

        let resolved = seed_peer_resolver.resolve().await.unwrap();

        assert_eq!(resolved.seed_peers, skewed.seed_peers);
        assert!(resolved.next_refresh_at <= SystemTime::now() + SeedPeerResolver::RETRY_INTERVAL);
    }

    #[tokio::test]
    async fn resolve_lists_again_a_cache_file_left_half_written_or_for_another_scheduler() {
        let test_cases = vec![
            b"{\"scheduler_endpoint\":".to_vec(),
            serde_json::to_vec(&seed_peer_state(
                "http://127.0.0.1:2",
                SystemTime::now() + Duration::from_secs(20),
            ))
            .unwrap(),
        ];

        for content in test_cases {
            let dir = tempdir().unwrap();
            let seed_peer_resolver =
                SeedPeerResolver::new(dir.path(), SCHEDULER_ENDPOINT.to_string());
            fs::write(&seed_peer_resolver.path, &content).unwrap();

            let resolved = seed_peer_resolver.resolve().await.unwrap();

            assert!(resolved.seed_peers.is_empty());
            assert_eq!(resolved.scheduler_endpoint, SCHEDULER_ENDPOINT);
            assert_eq!(seed_peer_resolver.read().unwrap(), Some(resolved));
        }
    }

    #[tokio::test]
    async fn resolve_writes_the_cache_file_private() {
        let dir = tempdir().unwrap();
        let seed_peer_resolver = SeedPeerResolver::new(dir.path(), SCHEDULER_ENDPOINT.to_string());

        seed_peer_resolver.resolve().await.unwrap();

        assert_eq!(
            fs::metadata(&seed_peer_resolver.path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert!(!seed_peer_resolver.path.with_extension("json.tmp").exists());
    }

    #[tokio::test]
    async fn resolve_lists_alone_without_a_cache_directory() {
        let test_cases = vec![false, true];

        for occupied in test_cases {
            let dir = tempdir().unwrap();
            let cache_dir = dir.path().join("dragonfly");
            if occupied {
                fs::write(&cache_dir, b"").unwrap();
            }
            let seed_peer_resolver =
                SeedPeerResolver::new(&cache_dir, SCHEDULER_ENDPOINT.to_string());

            let err = seed_peer_resolver.resolve().await.unwrap_err();

            assert!(err
                .to_string()
                .contains("failed to list dragonfly seed peers"));
            assert!(!cache_dir.is_dir());
        }
    }

    #[tokio::test]
    async fn resolve_does_not_follow_a_symlinked_cache_file() {
        let dir = tempdir().unwrap();
        let seed_peer_resolver = SeedPeerResolver::new(dir.path(), SCHEDULER_ENDPOINT.to_string());
        let target = dir.path().join("target");
        fs::write(&target, b"target").unwrap();
        symlink(&target, &seed_peer_resolver.path).unwrap();

        assert!(seed_peer_resolver.resolve().await.is_err());
        assert_eq!(fs::read(&target).unwrap(), b"target");
    }

    #[tokio::test]
    async fn resolve_does_not_block_on_a_fifo_cache_file() {
        let dir = tempdir().unwrap();
        let seed_peer_resolver = SeedPeerResolver::new(dir.path(), SCHEDULER_ENDPOINT.to_string());
        let path = CString::new(seed_peer_resolver.path.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);

        let resolved = tokio::time::timeout(Duration::from_secs(10), seed_peer_resolver.resolve())
            .await
            .unwrap();

        assert!(resolved.is_err());
    }

    #[tokio::test]
    async fn refresh_returns_a_cache_file_another_process_refreshed() {
        let dir = tempdir().unwrap();
        let seed_peer_resolver = SeedPeerResolver::new(dir.path(), SCHEDULER_ENDPOINT.to_string());
        let fresh = seed_peer_state(
            SCHEDULER_ENDPOINT,
            SystemTime::now() + Duration::from_secs(20),
        );
        fs::write(
            &seed_peer_resolver.path,
            serde_json::to_vec(&fresh).unwrap(),
        )
        .unwrap();

        assert_eq!(seed_peer_resolver.refresh().await.unwrap(), fresh);
    }

    #[test]
    fn read_serves_the_cache_file_while_another_process_lists() {
        let dir = tempdir().unwrap();
        let seed_peer_resolver = SeedPeerResolver::new(dir.path(), SCHEDULER_ENDPOINT.to_string());
        let fresh = seed_peer_state(
            SCHEDULER_ENDPOINT,
            SystemTime::now() + Duration::from_secs(20),
        );
        fs::write(
            &seed_peer_resolver.path,
            serde_json::to_vec(&fresh).unwrap(),
        )
        .unwrap();
        let lock = lock_file(&seed_peer_resolver);

        assert_eq!(seed_peer_resolver.read().unwrap(), Some(fresh));
        drop(lock);
    }

    #[tokio::test]
    async fn resolve_serves_the_expired_seed_peers_while_another_process_lists() {
        let dir = tempdir().unwrap();
        let seed_peer_resolver = SeedPeerResolver::new(dir.path(), SCHEDULER_ENDPOINT.to_string());
        let expired = seed_peer_state(SCHEDULER_ENDPOINT, SystemTime::now());
        fs::write(
            &seed_peer_resolver.path,
            serde_json::to_vec(&expired).unwrap(),
        )
        .unwrap();
        let lock = lock_file(&seed_peer_resolver);

        let resolved_at = SystemTime::now();
        let resolved = seed_peer_resolver.resolve().await.unwrap();

        assert_eq!(resolved.seed_peers, expired.seed_peers);
        assert!(resolved.next_refresh_at >= resolved_at + SeedPeerResolver::RETRY_INTERVAL);
        assert!(resolved.next_refresh_at <= SystemTime::now() + SeedPeerResolver::RETRY_INTERVAL);
        assert_eq!(seed_peer_resolver.read().unwrap(), Some(expired));
        drop(lock);
    }

    #[tokio::test]
    async fn resolve_waits_for_another_process_listing_without_a_cache_file() {
        let dir = tempdir().unwrap();
        let seed_peer_resolver = SeedPeerResolver::new(dir.path(), SCHEDULER_ENDPOINT.to_string());
        let refreshed = seed_peer_state(
            SCHEDULER_ENDPOINT,
            SystemTime::now() + Duration::from_secs(20),
        );
        let lock = lock_file(&seed_peer_resolver);

        let refreshing = std::thread::spawn({
            let path = seed_peer_resolver.path.clone();
            let refreshed = refreshed.clone();
            move || {
                std::thread::sleep(Duration::from_millis(300));
                fs::write(path, serde_json::to_vec(&refreshed).unwrap()).unwrap();
                drop(lock);
            }
        });
        let resolved = seed_peer_resolver.resolve().await.unwrap();
        refreshing.join().unwrap();

        assert_eq!(resolved, refreshed);
    }
}

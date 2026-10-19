//! YAML storage configuration for nydus: the typed schema, loading and
//! validation.
//!
//! The schema sections mirror the crates that consume them — [`BackendConfig`]
//! for `nydus-backend`, [`StorageConfig`] and [`PrefetchConfig`] for
//! `nydus-storage` — so the data plane consumes these structs directly as
//! constructor settings while the control plane loads and validates the file.
//!
//! It also owns the package identity — the name and the git commit constants
//! baked in by its build script — the CLI version flag parser built on them,
//! and the binary's default directories.

use nydus_error::{Context, Error, Result};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::CertificateDer;
use serde::Deserialize;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;
use url::Url;

/// The name of the package.
pub const NAME: &str = "nydus";

/// The short git commit hash of the package.
pub const GIT_COMMIT_SHORT_HASH: &str = {
    match option_env!("GIT_COMMIT_SHORT_HASH") {
        Some(hash) => hash,
        None => "unknown",
    }
};

/// The git commit date of the package.
pub const GIT_COMMIT_DATE: &str = {
    match option_env!("GIT_COMMIT_DATE") {
        Some(hash) => hash,
        None => "unknown",
    }
};

/// Returns the default log directory for nydus.
pub fn default_log_dir() -> PathBuf {
    PathBuf::from("/var/log/nydus/")
}

/// Returns the default timeout of a request to the origin registry. Kept
/// short because a read holds the chunk group's fetch claim for its whole duration,
/// and the readers waiting behind that claim are FUSE worker threads.
#[inline]
fn default_registry_http_request_timeout() -> Duration {
    Duration::from_secs(5)
}

/// Returns the default maximum number of retry attempts of the registry
/// backend per request.
#[inline]
fn default_registry_http_max_retries() -> u32 {
    3
}

/// Returns the default async worker thread count of each of the registry
/// backend's runtimes. The workers only drive socket I/O for the connection
/// pool; the synchronous callers block on their own threads.
#[inline]
pub fn default_registry_http_worker_threads() -> usize {
    2
}

/// Returns the default upper bound on each runtime's on-demand blocking
/// pool, where only DNS lookups (`getaddrinfo`) run.
#[inline]
pub fn default_registry_http_max_blocking_threads() -> usize {
    8
}

/// Returns the default number of concurrently prefetched blobs.
#[inline]
pub fn default_prefetch_concurrent_blob_count() -> usize {
    10
}

/// Returns the default timeout of prefetching one blob. Generous, because a
/// blob prefetch downloads every chunk group of the blob in the background; the
/// bound only exists to unwedge a stalled blob.
#[inline]
pub fn default_prefetch_blob_timeout() -> Duration {
    Duration::from_secs(60 * 60)
}

/// Returns the default interval before a failed prefetch read is sent once
/// more.
#[inline]
pub fn default_prefetch_retry_interval() -> Duration {
    Duration::from_secs(6 * 60 * 60)
}

/// Returns the default timeout of each attempt of a request through the
/// Dragonfly seed peers.
#[inline]
fn default_registry_dragonfly_request_timeout() -> Duration {
    Duration::from_secs(5)
}

/// Returns the default maximum number of retries of an on-demand blob `GET`
/// through Dragonfly on a transient failure.
#[inline]
fn default_registry_dragonfly_max_retries() -> u32 {
    1
}

/// Returns the default rate limit of origin requests issued when the Dragonfly
/// seed peers cannot serve an on-demand read, one request per second per
/// process.
#[inline]
fn default_registry_dragonfly_back_to_source_request_rate_limit() -> u64 {
    1
}

/// Returns the default for skipping decoded chunk group checksum
/// verification.
#[inline]
fn default_storage_skip_verify_checksums() -> bool {
    true
}

/// The local backend configuration, serving blobs from a directory.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalConfig {
    /// The directory holding the blob files.
    pub dir: PathBuf,
}

/// The backend configuration: which blob backend serves reads. The `type`
/// tag selects the implementation and the `config` map holds its settings.
#[derive(Debug, Clone, Deserialize)]
#[serde(
    tag = "type",
    content = "config",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum BackendConfig {
    /// Serve blobs from a local directory.
    Local(LocalConfig),

    /// Serve blobs from an OCI image registry. Parsed unconditionally so a
    /// build without the `registry` feature rejects the configuration
    /// loudly at backend construction instead of silently ignoring it. Boxed
    /// as it dwarfs the local variant.
    Registry(Box<RegistryConfig>),
}

/// The blob backend, the `type` tag of [`BackendConfig`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackendKind {
    /// The local directory backend.
    Local,

    /// The registry backend.
    Registry,
}

/// How the registry backend fetches bytes. The local backend has none.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Protocol {
    /// Reading the origin over HTTP.
    Http,

    /// Reading the Dragonfly seed peers through the SDK.
    Dragonfly,
}

/// What triggered a backend read. Retry, throttling and Dragonfly priority
/// key off it.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ReadKind {
    /// A user-triggered read blocking a FUSE request.
    #[default]
    OnDemand,

    /// A background prefetch read after mount.
    Prefetch,
}

/// Implements the display of a read kind as its `ondemand` or `prefetch`
/// label, the value metrics and logs carry.
impl fmt::Display for ReadKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ReadKind::OnDemand => "ondemand",
            ReadKind::Prefetch => "prefetch",
        })
    }
}

/// The registry backend configuration, serving blobs from an OCI image
/// registry.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryConfig {
    /// The registry address, an `http` or `https` origin carrying no path,
    /// query or fragment, e.g. `https://registry-1.docker.io` or
    /// `http://127.0.0.1:5000`. The scheme selects between TLS and plain HTTP.
    pub addr: Url,

    /// The image repository (no tag or digest), e.g. `library/ubuntu`.
    pub repository: String,

    /// The optional credentials: base64-encoded `username:password` for HTTP
    /// Basic auth (the value sent verbatim after `Basic `).
    #[serde(default)]
    pub auth: Option<String>,

    /// The HTTP client configuration of requests to the origin registry:
    /// timeouts, retries, and TLS trust.
    #[serde(default)]
    pub http: HttpConfig,

    /// The optional Dragonfly configuration. When set, blob `GET`s are routed
    /// through the Dragonfly client SDK for P2P distribution instead of
    /// hitting the origin registry directly. Parsed unconditionally so a
    /// build without the `dragonfly` feature rejects the block loudly when
    /// the configuration is loaded instead of silently ignoring it.
    #[serde(default)]
    pub dragonfly: Option<DragonflyConfig>,
}

/// The HTTP client configuration for the registry backend.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HttpConfig {
    /// The timeout of a request to the origin registry (connect + read), e.g.
    /// `5s` or `1m`, greater than zero. A request fetches one chunk group, so
    /// this bounds a single chunk group download.
    #[serde(
        default = "default_registry_http_request_timeout",
        with = "humantime_serde"
    )]
    pub request_timeout: Duration,

    /// The maximum number of retry attempts per request, applied by the HTTP
    /// client's retry middleware on direct origin requests and on origin
    /// requests issued when Dragonfly cannot serve a read, where every attempt
    /// also waits for a back-to-source rate limit slot. A prefetch read still
    /// failing after them is sent once more after `prefetch.retry_interval`.
    #[serde(default = "default_registry_http_max_retries")]
    pub max_retries: u32,

    /// The optional proxy configuration. When set, every registry request is
    /// routed through the proxy. When unset, ambient proxy environment
    /// variables are ignored and connections go directly to the origin.
    #[serde(default)]
    pub proxy: Option<ProxyConfig>,

    /// The TLS configuration for connections to the registry.
    #[serde(default)]
    pub tls: TlsConfig,

    /// The async worker threads of each runtime that drives the registry
    /// client's sockets, `2` by default and at least `1`. Every registry
    /// backend built from a configuration runs on two runtimes of its own
    /// with these bounds, one for on-demand reads and one for prefetch.
    #[serde(default = "default_registry_http_worker_threads")]
    pub worker_threads: usize,

    /// The upper bound on each runtime's on-demand blocking threads, which
    /// serve DNS lookups and are released after 10 s idle, `8` by default and
    /// at least `1`.
    #[serde(default = "default_registry_http_max_blocking_threads")]
    pub max_blocking_threads: usize,
}

/// The proxy configuration for the registry backend's HTTP client.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyConfig {
    /// The HTTP forward-proxy address including the scheme, e.g.
    /// `http://127.0.0.1:65001`. Requests keep their original upstream URL,
    /// so a proxy like a Dragonfly `dfdaemon` knows what to back-source.
    pub addr: String,
}

/// Implement Default for HttpConfig.
impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            request_timeout: default_registry_http_request_timeout(),
            max_retries: default_registry_http_max_retries(),
            proxy: None,
            tls: TlsConfig::default(),
            worker_threads: default_registry_http_worker_threads(),
            max_blocking_threads: default_registry_http_max_blocking_threads(),
        }
    }
}

/// The TLS configuration for connections to the registry.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TlsConfig {
    /// Skip TLS certificate verification (also tolerates self-signed
    /// certificates). Ignored for an `http` address.
    #[serde(default)]
    pub skip_verify: bool,

    /// The CA certificate path with PEM format to trust in addition to the
    /// system roots; the file may bundle multiple certificates. Useful for
    /// registries fronted by a private CA.
    #[serde(default)]
    pub ca_cert: Option<PathBuf>,
}

/// Implement TlsConfig.
impl TlsConfig {
    /// Load the CA certificates in DER format from [`Self::ca_cert`]; the PEM
    /// file may bundle multiple certificates. Returns `None` when no path is
    /// configured.
    pub fn load_ca_cert_der(&self) -> Result<Option<Vec<CertificateDer<'static>>>> {
        let Some(path) = &self.ca_cert else {
            return Ok(None);
        };

        let certs = CertificateDer::pem_file_iter(path)
            .map_err(|err| {
                Error::InvalidConfig(format!("failed to read CA cert {}: {err}", path.display()))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|err| {
                Error::InvalidConfig(format!("invalid CA cert {}: {err}", path.display()))
            })?;

        if certs.is_empty() {
            return Err(Error::InvalidConfig(format!(
                "CA cert {} contains no certificates",
                path.display()
            )));
        }

        Ok(Some(certs))
    }
}

/// The Dragonfly configuration for the registry backend, routing blob `GET`s
/// through the Dragonfly client SDK.
///
/// A seed peer answers with the error type header saying which layer failed,
/// and the status code decides what nydus does next:
///
/// ```text
/// nydus ──GET──▶ seed peer ──▶ dfdaemon ──miss──▶ origin registry
///                    │             │                    │
///                proxy error   dfdaemon error      backend error
/// ```
///
/// | Layer    | Status                                | Meaning                                         |
/// |----------|---------------------------------------|-------------------------------------------------|
/// | proxy    | `400` / `401` / `403`                 | bad request, bad proxy credentials, blocklisted |
/// | proxy    | `429`                                 | the seed peer is rate limited                   |
/// | dfdaemon | `400` / `422`                         | invalid request, or the origin sent no length   |
/// | dfdaemon | `507`                                 | the seed peer has no room for the blob          |
/// | dfdaemon | `500`                                 | scheduling, peer download or streaming failed   |
/// | backend  | the origin's own status               | the origin refused or failed the request        |
///
/// Whatever the layer, the status alone drives the outcome. A definitive answer
/// is settled at once for both read kinds, a transient one splits by read kind:
///
/// ```text
///                        ┌─ 2xx / 3xx ─────────────────▶ served
///                        │
/// seed peer answer ──────┼─ 401 ───────────────────────▶ auth handshake, resent
///                        │
///                        ├─ 400 / 403 / 404 / 422 ─────▶ read fails
///                        │
///                        └─ 429 / 5xx / 408 / timeout ─┬─ on-demand ─▶ retry, then origin
///                                                      │
///                                                      └─ prefetch ──▶ retried once, hours later
/// ```
///
/// | Answer                        | On-demand                                      | Prefetch                              |
/// |-------------------------------|------------------------------------------------|---------------------------------------|
/// | `2xx` / `3xx`                 | served, a `3xx` followed through Dragonfly     | same                                  |
/// | `401`                         | registry auth handshake, then resent once      | same                                  |
/// | `400` / `403` / `404` / `422` | read fails, no retry, no origin                | same                                  |
/// | `429` / `5xx` / `408`         | retried on the next seed peer, then the origin | retried once hours later, no origin   |
///
/// On-demand reads retry `max_retries` times and reach the origin under
/// `back_to_source.request_rate_limit`. A timeout or connection failure counts
/// as a transient answer.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DragonflyConfig {
    /// The Dragonfly scheduler service address with the scheme, e.g.
    /// `http://dragonfly-scheduler.dragonfly-system.svc:8002`.
    pub scheduler_endpoint: String,

    /// The timeout of each attempt of a request through the seed peers, e.g.
    /// `30s` or `1m`. A request fetches one chunk group, so this bounds a
    /// single chunk group download from a seed peer.
    #[serde(
        default = "default_registry_dragonfly_request_timeout",
        with = "humantime_serde"
    )]
    pub request_timeout: Duration,

    /// The maximum number of retries of an on-demand blob `GET` through
    /// Dragonfly on a transient failure (timeout, connection, dfdaemon, `5xx`,
    /// `408` or `429`), each sent to the next seed peer after an exponential
    /// backoff, at most 3. Any other answer returns at once. A prefetch read
    /// is instead sent once more after a random delay of hours.
    #[serde(default = "default_registry_dragonfly_max_retries")]
    pub max_retries: u32,

    /// The origin reads issued when the Dragonfly seed peers cannot serve an
    /// on-demand read.
    #[serde(default)]
    pub back_to_source: BackToSourceConfig,
}

/// The configuration of origin reads issued when the Dragonfly seed peers
/// cannot serve an on-demand read.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BackToSourceConfig {
    /// The rate limit of origin requests in requests per second, `1` by
    /// default and at least `1`. Only these reads are shaped, direct reads
    /// and auth token fetches never are.
    #[serde(default = "default_registry_dragonfly_back_to_source_request_rate_limit")]
    pub request_rate_limit: u64,
}

/// Implement Default for BackToSourceConfig.
impl Default for BackToSourceConfig {
    fn default() -> Self {
        Self {
            request_rate_limit: default_registry_dragonfly_back_to_source_request_rate_limit(),
        }
    }
}

/// The storage configuration: where downloaded blob data is kept.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct StorageConfig {
    /// The directory storing each blob's decoded chunk cache file. When
    /// unset (or the whole `storage` section is omitted), blob data is not
    /// written to disk: every read fetches from the backend directly and the
    /// kernel page cache is the only reuse layer. Modes that hand the cache
    /// file to the kernel (fanotify, NBD, ublk, userfaultfd, virtio-pmem)
    /// require a directory.
    #[serde(default)]
    pub dir: Option<PathBuf>,

    /// Skip verifying decoded chunk groups against their stored checksums
    /// before they are served (the default). Set to `false` to verify every
    /// decoded chunk group when the transport is not trusted end to end.
    #[serde(default = "default_storage_skip_verify_checksums")]
    pub skip_verify_checksums: bool,

    /// Compressed bytes one on-demand backend read covers: the chunk groups
    /// whose compressed ranges overlap the fetch-size-aligned cell holding the
    /// missed group, trimmed at groups already cached or being fetched.
    /// Larger sizes make fewer, larger requests (better over high latency),
    /// smaller sizes transfer fewer unused bytes (better over limited
    /// bandwidth). Zero fetches the missed group alone. Default 2 MiB.
    #[serde(default = "default_storage_fetch_size")]
    pub fetch_size: u64,
}

fn default_storage_fetch_size() -> u64 {
    2 * 1024 * 1024
}

/// Implement Default for StorageConfig.
impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            dir: None,
            skip_verify_checksums: default_storage_skip_verify_checksums(),
            fetch_size: default_storage_fetch_size(),
        }
    }
}

/// The prefetch configuration, controlling background blob prefetch.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PrefetchConfig {
    /// The number of concurrently prefetched blobs.
    #[serde(default = "default_prefetch_concurrent_blob_count")]
    pub concurrent_blob_count: usize,

    /// The timeout of prefetching one whole blob, e.g. `1h`, while
    /// `http.request_timeout` bounds each chunk group request within it; `0s`
    /// disables the bound.
    #[serde(default = "default_prefetch_blob_timeout", with = "humantime_serde")]
    pub blob_timeout: Duration,

    /// The interval before a prefetch read that the origin or the seed peers
    /// answered with `429`, `5xx` or `408` is sent once more, e.g. `6h`, the
    /// default: hours, so an outage or rate limit has time to clear. The
    /// actual interval is random between this and twice this, so a fleet of
    /// instances does not retry in lockstep.
    #[serde(default = "default_prefetch_retry_interval", with = "humantime_serde")]
    pub retry_interval: Duration,

    /// The scope of blob prefetch: nothing, only the "ondemand" blob, all
    /// blobs, or `auto` (the default): the "ondemand" blob when the image has
    /// one, otherwise all blobs.
    #[serde(default)]
    pub scope: PrefetchScope,
}

/// The scope of blob prefetch: which blobs it pulls.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum PrefetchScope {
    /// Disable prefetch: nothing is pulled ahead of demand, not even an
    /// "ondemand" blob.
    None,

    /// Pull only the "ondemand" blob (produced by `nydus optimize`), which
    /// holds the recorded working set in access order, without pulling the
    /// whole image. On an image without an ondemand blob nothing is
    /// prefetched.
    Ondemand,

    /// Pull all blobs: the priority blobs first, in declared order (an
    /// optimized image lists its ondemand blob first), then every remaining
    /// blob — the entire image ends up in the local cache.
    All,

    /// Decide per image once the blob metadata is available: [`Ondemand`]
    /// when a priority blob is an ondemand blob, otherwise [`All`], so an
    /// optimized image streams only its recorded working set while an
    /// unoptimized one streams every blob like a classic nydusd mount.
    ///
    /// [`Ondemand`]: PrefetchScope::Ondemand
    /// [`All`]: PrefetchScope::All
    #[default]
    Auto,
}

/// Implement Default for PrefetchConfig.
impl Default for PrefetchConfig {
    fn default() -> Self {
        Self {
            concurrent_blob_count: default_prefetch_concurrent_blob_count(),
            blob_timeout: default_prefetch_blob_timeout(),
            retry_interval: default_prefetch_retry_interval(),
            scope: PrefetchScope::default(),
        }
    }
}

/// The configuration for nydus, typically loaded from a YAML file passed to
/// `nydus fuse --config` or constructed by an embedding application before
/// creating a `NydusCore` (in the `nydus-core` crate).
///
/// ```yaml
/// backend:
///   type: local
///   config:
///     dir: /path/to/blobs
/// storage:
///   dir: /path/to/cache
/// prefetch:
///   scope: auto
/// ```
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// The backend configuration: where blob data is fetched from.
    pub backend: BackendConfig,

    /// The storage configuration: where downloaded blob data is kept. When
    /// omitted, reads run diskless straight from the backend.
    #[serde(default)]
    pub storage: StorageConfig,

    /// The prefetch configuration for background blob prefetch.
    #[serde(default)]
    pub prefetch: PrefetchConfig,
}

/// Implement the config operation of nydus.
impl Config {
    /// Load a nydus configuration from a YAML file and validate it.
    pub fn load(path: &Path) -> Result<Self> {
        let contents = fs::read_to_string(path)
            .with_context(|| format!("failed to read config {}", path.display()))?;
        Self::from_yaml(&contents)
    }

    /// Parse a nydus configuration from a YAML string and validate it.
    pub fn from_yaml(contents: &str) -> Result<Self> {
        let config: Self =
            serde_yaml::from_str(contents).context("failed to parse nydus config")?;
        config.validate()?;
        Ok(config)
    }

    /// Validate the constraints the schema alone cannot express.
    fn validate(&self) -> Result<()> {
        if self.prefetch.concurrent_blob_count == 0 {
            return Err(Error::InvalidConfig(
                "prefetch.concurrent_blob_count must be at least 1".to_string(),
            ));
        }

        if let BackendConfig::Registry(registry) = &self.backend {
            if registry.http.request_timeout.is_zero() {
                return Err(Error::InvalidConfig(
                    "http.request_timeout must be greater than 0s".to_string(),
                ));
            }

            if registry.http.worker_threads == 0 {
                return Err(Error::InvalidConfig(
                    "http.worker_threads must be at least 1".to_string(),
                ));
            }

            if registry.http.max_blocking_threads == 0 {
                return Err(Error::InvalidConfig(
                    "http.max_blocking_threads must be at least 1".to_string(),
                ));
            }

            #[cfg(not(feature = "dragonfly"))]
            if let Some(dragonfly) = &registry.dragonfly {
                return Err(Error::InvalidConfig(format!(
                    "dragonfly.scheduler_endpoint is set ({}) but this build lacks the `dragonfly` feature",
                    dragonfly.scheduler_endpoint
                )));
            }

            if let Some(dragonfly) = &registry.dragonfly {
                if dragonfly.max_retries > 3 {
                    return Err(Error::InvalidConfig(
                        "dragonfly.max_retries must not exceed 3".to_string(),
                    ));
                }

                if dragonfly.back_to_source.request_rate_limit == 0 {
                    return Err(Error::InvalidConfig(
                        "dragonfly.back_to_source.request_rate_limit must be at least 1"
                            .to_string(),
                    ));
                }
            }
        }
        Ok(())
    }
}

/// A custom value parser for the version flag.
#[derive(Debug, Clone)]
pub struct VersionValueParser;

/// Implement the TypedValueParser trait for VersionValueParser.
impl clap::builder::TypedValueParser for VersionValueParser {
    type Value = bool;

    fn parse_ref(
        &self,
        cmd: &clap::Command,
        _arg: Option<&clap::Arg>,
        value: &std::ffi::OsStr,
    ) -> std::result::Result<Self::Value, clap::Error> {
        if value == std::ffi::OsStr::new("true") {
            println!(
                "{} {} ({}, {})",
                cmd.get_name(),
                cmd.get_version().unwrap_or("unknown"),
                GIT_COMMIT_SHORT_HASH,
                GIT_COMMIT_DATE,
            );

            std::process::exit(0);
        }

        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::builder::TypedValueParser;
    use std::ffi::OsStr;
    use std::io::Write;

    #[cfg(not(feature = "dragonfly"))]
    #[test]
    fn load_config_file_rejects_the_dragonfly_block_without_the_feature() {
        let path = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/config.yaml"));
        let err = Config::load(path).unwrap_err();
        assert!(
            err.to_string().contains("lacks the `dragonfly` feature"),
            "{err}"
        );
    }

    #[cfg(feature = "dragonfly")]
    #[test]
    fn load_config_file_correctly() {
        let path = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/config.yaml"));
        let config = Config::load(path).unwrap();

        let BackendConfig::Registry(registry) = &config.backend else {
            panic!("expected a registry backend, got {:?}", config.backend);
        };
        assert_eq!(registry.addr.as_str(), "http://127.0.0.1:5000/");
        assert_eq!(registry.repository, "library/nydus-demo");
        assert_eq!(
            registry.auth.as_deref(),
            Some("dGVzdHVzZXI6dGVzdHBhc3N3b3Jk")
        );
        assert_eq!(registry.http.request_timeout, Duration::from_secs(30));
        assert_eq!(registry.http.max_retries, 5);
        assert_eq!(
            registry.http.proxy.as_ref().unwrap().addr,
            "http://127.0.0.1:65001"
        );
        assert!(registry.http.tls.skip_verify);
        assert_eq!(
            registry.http.tls.ca_cert.as_deref(),
            Some(Path::new("/etc/nydus/certs/registry-ca.pem"))
        );
        let dragonfly = registry.dragonfly.as_ref().unwrap();
        assert_eq!(dragonfly.scheduler_endpoint, "http://127.0.0.1:8002");
        assert_eq!(dragonfly.request_timeout, Duration::from_secs(10));
        assert_eq!(dragonfly.max_retries, 2);
        assert_eq!(dragonfly.back_to_source.request_rate_limit, 2);

        assert_eq!(
            config.storage.dir.as_deref(),
            Some(Path::new("/var/lib/nydus/cache"))
        );
        assert!(!config.storage.skip_verify_checksums);

        assert_eq!(config.prefetch.concurrent_blob_count, 4);
        assert_eq!(config.prefetch.blob_timeout, Duration::from_secs(120));
        assert_eq!(config.prefetch.scope, PrefetchScope::All);
    }

    #[test]
    fn deserialize_local_backend_correctly() {
        let yaml = r#"
type: local
config:
  dir: /blobs
"#;

        let backend: BackendConfig = serde_yaml::from_str(yaml).unwrap();
        let BackendConfig::Local(local) = &backend else {
            panic!("expected a local backend, got {backend:?}");
        };
        assert_eq!(local.dir, Path::new("/blobs"));
    }

    #[test]
    fn deserialize_registry_backend_correctly() {
        let yaml = r#"
type: registry
config:
  addr: http://127.0.0.1:5000
  repository: library/ubuntu
  auth: YWxpY2U6c2VjcmV0
  http:
    request_timeout: 30s
    max_retries: 5
    tls:
      skip_verify: true
      ca_cert: /etc/nydus/certs/registry-ca.pem
  dragonfly:
    scheduler_endpoint: http://127.0.0.1:8002
"#;

        let backend: BackendConfig = serde_yaml::from_str(yaml).unwrap();
        let BackendConfig::Registry(registry) = &backend else {
            panic!("expected a registry backend, got {backend:?}");
        };
        assert_eq!(registry.addr.as_str(), "http://127.0.0.1:5000/");
        assert_eq!(registry.repository, "library/ubuntu");
        assert_eq!(registry.auth.as_deref(), Some("YWxpY2U6c2VjcmV0"));
        assert_eq!(registry.http.request_timeout, Duration::from_secs(30));
        assert_eq!(registry.http.max_retries, 5);
        assert!(registry.http.tls.skip_verify);
        assert_eq!(
            registry.http.tls.ca_cert.as_deref(),
            Some(Path::new("/etc/nydus/certs/registry-ca.pem"))
        );
        assert_eq!(
            registry.dragonfly.as_ref().unwrap().scheduler_endpoint,
            "http://127.0.0.1:8002"
        );
    }

    #[test]
    fn dragonfly_knobs_default_and_deserialize() {
        let defaults: DragonflyConfig =
            serde_yaml::from_str("scheduler_endpoint: http://127.0.0.1:8002\n").unwrap();
        assert_eq!(
            defaults.request_timeout,
            default_registry_dragonfly_request_timeout()
        );
        assert_eq!(
            defaults.max_retries,
            default_registry_dragonfly_max_retries()
        );
        assert_eq!(
            defaults.back_to_source.request_rate_limit,
            default_registry_dragonfly_back_to_source_request_rate_limit()
        );

        let yaml = r#"
scheduler_endpoint: http://127.0.0.1:8002
request_timeout: 5s
max_retries: 0
back_to_source:
  request_rate_limit: 3
"#;
        let dragonfly: DragonflyConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(dragonfly.request_timeout, Duration::from_secs(5));
        assert_eq!(dragonfly.max_retries, 0);
        assert_eq!(dragonfly.back_to_source.request_rate_limit, 3);
    }

    #[test]
    fn registry_backend_defaults() {
        let yaml = r#"
type: registry
config:
  addr: https://registry-1.docker.io
  repository: library/ubuntu
"#;

        let backend: BackendConfig = serde_yaml::from_str(yaml).unwrap();
        let BackendConfig::Registry(registry) = &backend else {
            panic!("expected a registry backend, got {backend:?}");
        };
        assert_eq!(
            registry.http.request_timeout,
            default_registry_http_request_timeout()
        );
        assert_eq!(
            registry.http.max_retries,
            default_registry_http_max_retries()
        );
        assert!(registry.http.proxy.is_none());
        assert!(!registry.http.tls.skip_verify);
        assert!(registry.http.tls.ca_cert.is_none());
        assert_eq!(
            registry.http.worker_threads,
            default_registry_http_worker_threads()
        );
        assert_eq!(
            registry.http.max_blocking_threads,
            default_registry_http_max_blocking_threads()
        );
        assert!(registry.auth.is_none());
        assert!(registry.dragonfly.is_none());
    }

    #[test]
    fn deserialize_registry_http_runtime_threads() {
        let yaml = r#"
type: registry
config:
  addr: https://registry-1.docker.io
  repository: library/ubuntu
  http:
    worker_threads: 4
    max_blocking_threads: 16
"#;

        let backend: BackendConfig = serde_yaml::from_str(yaml).unwrap();
        let BackendConfig::Registry(registry) = &backend else {
            panic!("expected a registry backend, got {backend:?}");
        };
        assert_eq!(registry.http.worker_threads, 4);
        assert_eq!(registry.http.max_blocking_threads, 16);
        // The other http fields keep their defaults alongside the new keys.
        assert_eq!(
            registry.http.request_timeout,
            default_registry_http_request_timeout()
        );
    }

    #[test]
    fn rejects_unknown_backend_type() {
        let yaml = r#"
type: s3
config:
  bucket: blobs
"#;

        let err = serde_yaml::from_str::<BackendConfig>(yaml).unwrap_err();
        assert!(err.to_string().contains("unknown variant `s3`"));
    }

    #[test]
    fn rejects_missing_backend_config() {
        assert!(serde_yaml::from_str::<BackendConfig>("type: local\n").is_err());
    }

    #[test]
    fn rejects_unknown_backend_keys() {
        let yaml = r#"
type: local
config:
  dir: /blobs
junk: 1
"#;
        assert!(serde_yaml::from_str::<BackendConfig>(yaml).is_err());
        let yaml = r#"
type: registry
config:
  addr: http://127.0.0.1:5000
  repository: library/ubuntu
  junk: 1
"#;
        assert!(serde_yaml::from_str::<BackendConfig>(yaml).is_err());
    }

    #[test]
    fn deserialize_storage_correctly() {
        let storage: StorageConfig = serde_yaml::from_str("dir: /var/lib/nydus/cache\n").unwrap();
        assert_eq!(
            storage.dir.as_deref(),
            Some(Path::new("/var/lib/nydus/cache"))
        );
        assert!(storage.skip_verify_checksums);

        let storage: StorageConfig =
            serde_yaml::from_str("dir: /cache\nskip_verify_checksums: false\n").unwrap();
        assert!(!storage.skip_verify_checksums);
    }

    #[test]
    fn rejects_unknown_storage_key() {
        assert!(serde_yaml::from_str::<StorageConfig>("dir: /cache\njunk: 1\n").is_err());
    }

    #[test]
    fn storage_defaults_to_diskless_when_omitted() {
        let yaml = r#"
backend:
  type: local
  config:
    dir: /blobs
"#;

        let config = Config::from_yaml(yaml).unwrap();
        assert!(config.storage.dir.is_none());
    }

    #[test]
    fn deserialize_prefetch_correctly() {
        let yaml = r#"
concurrent_blob_count: 8
blob_timeout: 2m
scope: all
"#;

        let prefetch: PrefetchConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(prefetch.concurrent_blob_count, 8);
        assert_eq!(prefetch.blob_timeout, Duration::from_secs(120));
        assert_eq!(prefetch.scope, PrefetchScope::All);
    }

    #[test]
    fn prefetch_default() {
        let prefetch = PrefetchConfig::default();
        assert_eq!(
            prefetch.concurrent_blob_count,
            default_prefetch_concurrent_blob_count()
        );
        assert_eq!(prefetch.blob_timeout, default_prefetch_blob_timeout());
        assert_eq!(prefetch.scope, PrefetchScope::Auto);
    }

    #[test]
    fn prefetch_scope_accepts_every_spelling() {
        for (yaml, scope) in [
            ("scope: none\n", PrefetchScope::None),
            ("scope: ondemand\n", PrefetchScope::Ondemand),
            ("scope: all\n", PrefetchScope::All),
            ("scope: auto\n", PrefetchScope::Auto),
        ] {
            let prefetch: PrefetchConfig = serde_yaml::from_str(yaml).unwrap();
            assert_eq!(prefetch.scope, scope, "{yaml}");
        }
        for yaml in ["scope: everything\n", "scope: opt\n"] {
            assert!(
                serde_yaml::from_str::<PrefetchConfig>(yaml).is_err(),
                "{yaml}"
            );
        }
    }

    #[test]
    fn registry_addr_is_parsed_as_a_url() {
        let test_cases = vec![
            ("http://127.0.0.1:5000", Some("http://127.0.0.1:5000/")),
            (
                "https://registry-1.docker.io",
                Some("https://registry-1.docker.io/"),
            ),
            (
                "https://registry.example.com/mirror",
                Some("https://registry.example.com/mirror"),
            ),
            ("registry.example.com", None),
        ];

        for (addr, expected) in test_cases {
            let yaml = format!(
                "backend:\n  type: registry\n  config:\n    addr: {addr}\n    repository: library/ubuntu\n"
            );
            let parsed = Config::from_yaml(&yaml)
                .ok()
                .map(|config| match config.backend {
                    BackendConfig::Registry(registry) => registry.addr.to_string(),
                    backend => panic!("expected a registry backend, got {backend:?}"),
                });
            assert_eq!(parsed.as_deref(), expected, "addr={addr}");
        }
    }

    #[test]
    fn rejects_zero_registry_http_bounds() {
        let test_cases = vec![
            (
                "request_timeout: 0s",
                "http.request_timeout must be greater than 0s",
            ),
            (
                "worker_threads: 0",
                "http.worker_threads must be at least 1",
            ),
            (
                "max_blocking_threads: 0",
                "http.max_blocking_threads must be at least 1",
            ),
        ];

        for (field, expected) in test_cases {
            let yaml = format!(
                "backend:\n  type: registry\n  config:\n    addr: http://127.0.0.1:5000\n    repository: library/ubuntu\n    http:\n      {field}\n"
            );
            let err = Config::from_yaml(&yaml).unwrap_err();
            assert_eq!(err.to_string(), expected);
        }
    }

    #[cfg(feature = "dragonfly")]
    #[test]
    fn rejects_dragonfly_values_out_of_range() {
        let test_cases = vec![
            ("max_retries: 4", "dragonfly.max_retries must not exceed 3"),
            (
                "back_to_source:\n        request_rate_limit: 0",
                "dragonfly.back_to_source.request_rate_limit must be at least 1",
            ),
        ];

        for (field, expected) in test_cases {
            let yaml = format!(
                "backend:\n  type: registry\n  config:\n    addr: http://127.0.0.1:5000\n    repository: library/ubuntu\n    dragonfly:\n      scheduler_endpoint: http://127.0.0.1:8002\n      {field}\n"
            );
            let err = Config::from_yaml(&yaml).unwrap_err();
            assert_eq!(err.to_string(), expected);
        }
    }

    #[test]
    fn prefetch_partial_fields_fall_back_to_defaults() {
        let prefetch: PrefetchConfig = serde_yaml::from_str("scope: none\n").unwrap();
        assert_eq!(prefetch.scope, PrefetchScope::None);
        assert_eq!(
            prefetch.concurrent_blob_count,
            default_prefetch_concurrent_blob_count()
        );
    }

    #[test]
    fn rejects_unknown_prefetch_key() {
        assert!(serde_yaml::from_str::<PrefetchConfig>("enabled: true\n").is_err());
    }

    #[test]
    fn deserialize_config_correctly() {
        let yaml = r#"
backend:
  type: local
  config:
    dir: /var/lib/nydus/blobs
storage:
  dir: /var/lib/nydus/cache
prefetch:
  concurrent_blob_count: 8
"#;

        let config = Config::from_yaml(yaml).unwrap();
        let BackendConfig::Local(local) = &config.backend else {
            panic!("expected a local backend, got {:?}", config.backend);
        };
        assert_eq!(local.dir, Path::new("/var/lib/nydus/blobs"));
        assert_eq!(
            config.storage.dir.as_deref(),
            Some(Path::new("/var/lib/nydus/cache"))
        );
        assert_eq!(config.prefetch.concurrent_blob_count, 8);
    }

    #[test]
    fn prefetch_defaults_when_omitted() {
        let yaml = r#"
backend:
  type: local
  config:
    dir: /blobs
storage:
  dir: /cache
"#;

        let config = Config::from_yaml(yaml).unwrap();
        assert_eq!(
            config.prefetch.concurrent_blob_count,
            default_prefetch_concurrent_blob_count()
        );
        assert_eq!(config.prefetch.scope, PrefetchScope::Auto);
    }

    #[test]
    fn load_reports_missing_file() {
        let err = Config::load(Path::new("/nonexistent/nydus.yaml")).unwrap_err();
        assert_eq!(
            err.to_string(),
            "failed to read config /nonexistent/nydus.yaml"
        );
        assert!(err.io_error().is_some());
    }

    #[test]
    fn rejects_unknown_top_level_key() {
        let yaml = r#"
backend:
  type: local
  config:
    dir: /blobs
storage:
  dir: /cache
junk: 1
"#;

        let err = Config::from_yaml(yaml).unwrap_err();
        assert_eq!(err.to_string(), "failed to parse nydus config");
    }

    #[test]
    fn rejects_zero_prefetch_concurrent_blob_count() {
        let yaml = r#"
backend:
  type: local
  config:
    dir: /blobs
storage:
  dir: /cache
prefetch:
  concurrent_blob_count: 0
"#;

        let err = Config::from_yaml(yaml).unwrap_err();
        assert_eq!(
            err.to_string(),
            "prefetch.concurrent_blob_count must be at least 1"
        );
    }

    /// A throwaway self-signed test CA (CN=nydus-test-ca, 1-day validity).
    const TEST_CA_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIBhjCCASugAwIBAgIUMNliJgii9SrYpkxqWpnEufwCqJkwCgYIKoZIzj0EAwIw
GDEWMBQGA1UEAwwNbnlkdXMtdGVzdC1jYTAeFw0yNjA4MTQwNTI1MTJaFw0yNjA4
MTUwNTI1MTJaMBgxFjAUBgNVBAMMDW55ZHVzLXRlc3QtY2EwWTATBgcqhkjOPQIB
BggqhkjOPQMBBwNCAASlz1ln2JmyEyPwuoG2511q8jCVRzjxoC++PjxeabnX8kIp
5aRORqm8CkbokMUOx+ruhMJH6pi9hl6LFERvlwwzo1MwUTAdBgNVHQ4EFgQUwGYO
6bT2akEE5W747hzi6ladVz8wHwYDVR0jBBgwFoAUwGYO6bT2akEE5W747hzi6lad
Vz8wDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNJADBGAiEAkw7Dc6E8oqmm
tV53OA5UQIvMDO2jdkxiJ7mpQf1l7KkCIQC/ex2sVgEuCUMPo4zDQJLOL29rY5Gt
Y+f+/xlWpHEkSQ==
-----END CERTIFICATE-----
";

    fn tls_config(ca_cert: Option<PathBuf>) -> TlsConfig {
        TlsConfig {
            ca_cert,
            ..Default::default()
        }
    }

    #[test]
    fn load_ca_cert_der_returns_none_when_not_configured() {
        assert!(tls_config(None).load_ca_cert_der().unwrap().is_none());
    }

    #[test]
    fn load_ca_cert_der_loads_a_pem_bundle() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        // Two concatenated certificates parse as a bundle.
        write!(file, "{TEST_CA_CERT_PEM}{TEST_CA_CERT_PEM}").unwrap();

        let certs = tls_config(Some(file.path().to_path_buf()))
            .load_ca_cert_der()
            .unwrap()
            .unwrap();
        assert_eq!(certs.len(), 2);
    }

    #[test]
    fn load_ca_cert_der_rejects_a_missing_or_empty_file() {
        let err = tls_config(Some(PathBuf::from("/nonexistent/ca.pem")))
            .load_ca_cert_der()
            .unwrap_err();
        assert!(err.to_string().contains("failed to read CA cert"));

        let file = tempfile::NamedTempFile::new().unwrap();
        let err = tls_config(Some(file.path().to_path_buf()))
            .load_ca_cert_der()
            .unwrap_err();
        assert!(err.to_string().contains("contains no certificates"));
    }

    #[test]
    fn version_value_parser_references_non_real_values() {
        let parser = VersionValueParser;
        let cmd = clap::Command::new("test_app");
        let value = OsStr::new("false");
        let result = parser.parse_ref(&cmd, None, value);
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn read_kind_displays_its_label() {
        let test_cases = vec![
            (ReadKind::OnDemand, "ondemand"),
            (ReadKind::Prefetch, "prefetch"),
        ];

        for (kind, expected) in test_cases {
            assert_eq!(kind.to_string(), expected);
        }
    }
}

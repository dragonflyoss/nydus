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
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

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

/// Returns the default per-request timeout of the registry backend. Kept
/// short because a read holds the group's fetch claim for its whole duration,
/// and the readers waiting behind that claim are FUSE worker threads.
#[inline]
fn default_registry_http_timeout() -> Duration {
    Duration::from_secs(5)
}

/// Returns the default maximum number of retry attempts of the registry
/// backend per request.
#[inline]
fn default_registry_http_max_retries() -> u32 {
    3
}

/// Returns the default number of concurrently prefetched blobs.
#[inline]
pub fn default_prefetch_concurrent_blob_count() -> usize {
    10
}

/// Returns the default per-blob prefetch timeout. Generous, because a blob
/// prefetch downloads every group of the blob in the background; the bound
/// only exists to unwedge a stalled blob.
#[inline]
pub fn default_prefetch_timeout() -> Duration {
    Duration::from_secs(60 * 60)
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
    /// build without the `backend-registry` feature rejects the configuration
    /// loudly at backend construction instead of silently ignoring it.
    Registry(RegistryConfig),
}

/// Implement BackendConfig.
impl BackendConfig {
    /// The `type` tag this configuration is selected by.
    pub fn kind(&self) -> &'static str {
        match self {
            BackendConfig::Local(_) => "local",
            BackendConfig::Registry(_) => "registry",
        }
    }
}

/// The registry backend configuration, serving blobs from an OCI image
/// registry.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryConfig {
    /// The registry address including the scheme, e.g.
    /// `https://registry-1.docker.io` or `http://127.0.0.1:5000`. The scheme
    /// selects between TLS and plain HTTP.
    pub addr: String,

    /// The image repository (no tag or digest), e.g. `library/ubuntu`.
    pub repository: String,

    /// The optional credentials: base64-encoded `username:password` for HTTP
    /// Basic auth (the value sent verbatim after `Basic `).
    #[serde(default)]
    pub auth: Option<String>,

    /// The HTTP client configuration: timeouts, retries, and TLS trust. The
    /// timeout and retry limits also apply to Dragonfly SDK requests.
    #[serde(default)]
    pub http: HttpConfig,

    /// The optional Dragonfly configuration. When set, blob `GET`s are routed
    /// through the Dragonfly client SDK for P2P distribution instead of
    /// hitting the origin registry directly. Only honored when built with the
    /// `backend-dragonfly-proxy` feature; parsed unconditionally so a build
    /// without the feature can reject the block loudly instead of silently
    /// ignoring it.
    #[serde(default)]
    pub dragonfly: Option<DragonflyConfig>,
}

/// The HTTP client configuration for the registry backend.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HttpConfig {
    /// The per-request timeout (connect + read), e.g. `5s` or `1m`; `0s`
    /// disables the timeout. A request fetches one chunk group, so this
    /// bounds a single group download.
    #[serde(default = "default_registry_http_timeout", with = "humantime_serde")]
    pub timeout: Duration,

    /// The maximum number of retry attempts per request, applied by the HTTP
    /// client's retry middleware and by the Dragonfly SDK.
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
            timeout: default_registry_http_timeout(),
            max_retries: default_registry_http_max_retries(),
            proxy: None,
            tls: TlsConfig::default(),
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
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DragonflyConfig {
    /// The Dragonfly scheduler endpoint (gRPC), e.g. `http://127.0.0.1:65000`.
    pub scheduler_endpoint: String,
}

/// The storage configuration: where downloaded blob data is kept.
#[derive(Debug, Clone, Default, Deserialize)]
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
}

/// The prefetch configuration, controlling background blob prefetch.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PrefetchConfig {
    /// The number of concurrently prefetched blobs.
    #[serde(default = "default_prefetch_concurrent_blob_count")]
    pub concurrent_blob_count: usize,

    /// The per-blob prefetch timeout, e.g. `1h`: bounds how long prefetching
    /// one whole blob may take, while `http.timeout` bounds each group
    /// request within it; `0s` disables the bound.
    #[serde(default = "default_prefetch_timeout", with = "humantime_serde")]
    pub timeout: Duration,

    /// The scope of blob prefetch: nothing, only the "ondemand" redirect blob
    /// (the default), or all blobs.
    #[serde(default)]
    pub scope: PrefetchScope,
}

/// The scope of blob prefetch: which blobs it pulls.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum PrefetchScope {
    /// Disable prefetch: nothing is pulled ahead of demand.
    None,

    /// Pull only the "ondemand" redirect blob (produced by `nydus optimize`),
    /// which warms the hot working set in recorded access order without
    /// pulling the whole image. On an image without a redirect blob nothing
    /// is prefetched.
    #[default]
    Ondemand,

    /// Pull all blobs: the priority blobs first, in declared order, then
    /// every remaining blob — the entire image ends up in the local cache.
    All,
}

/// Implement Default for PrefetchConfig.
impl Default for PrefetchConfig {
    fn default() -> Self {
        Self {
            concurrent_blob_count: default_prefetch_concurrent_blob_count(),
            timeout: default_prefetch_timeout(),
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
///   scope: ondemand
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

    #[test]
    fn load_config_file_correctly() {
        let path = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/config.yaml"));
        let config = Config::load(path).unwrap();

        let BackendConfig::Registry(registry) = &config.backend else {
            panic!("expected a registry backend, got {:?}", config.backend);
        };
        assert_eq!(registry.addr, "http://127.0.0.1:5000");
        assert_eq!(registry.repository, "library/nydus-demo");
        assert_eq!(
            registry.auth.as_deref(),
            Some("dGVzdHVzZXI6dGVzdHBhc3N3b3Jk")
        );
        assert_eq!(registry.http.timeout, Duration::from_secs(30));
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
        assert_eq!(
            registry.dragonfly.as_ref().unwrap().scheduler_endpoint,
            "http://127.0.0.1:65000"
        );

        assert_eq!(
            config.storage.dir.as_deref(),
            Some(Path::new("/var/lib/nydus/cache"))
        );

        assert_eq!(config.prefetch.concurrent_blob_count, 4);
        assert_eq!(config.prefetch.timeout, Duration::from_secs(120));
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
        assert_eq!(backend.kind(), "local");
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
    timeout: 30s
    max_retries: 5
    tls:
      skip_verify: true
      ca_cert: /etc/nydus/certs/registry-ca.pem
  dragonfly:
    scheduler_endpoint: http://127.0.0.1:65000
"#;

        let backend: BackendConfig = serde_yaml::from_str(yaml).unwrap();
        let BackendConfig::Registry(registry) = &backend else {
            panic!("expected a registry backend, got {backend:?}");
        };
        assert_eq!(registry.addr, "http://127.0.0.1:5000");
        assert_eq!(registry.repository, "library/ubuntu");
        assert_eq!(registry.auth.as_deref(), Some("YWxpY2U6c2VjcmV0"));
        assert_eq!(registry.http.timeout, Duration::from_secs(30));
        assert_eq!(registry.http.max_retries, 5);
        assert!(registry.http.tls.skip_verify);
        assert_eq!(
            registry.http.tls.ca_cert.as_deref(),
            Some(Path::new("/etc/nydus/certs/registry-ca.pem"))
        );
        assert_eq!(
            registry.dragonfly.as_ref().unwrap().scheduler_endpoint,
            "http://127.0.0.1:65000"
        );
        assert_eq!(backend.kind(), "registry");
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
        assert_eq!(registry.http.timeout, default_registry_http_timeout());
        assert_eq!(
            registry.http.max_retries,
            default_registry_http_max_retries()
        );
        assert!(registry.http.proxy.is_none());
        assert!(!registry.http.tls.skip_verify);
        assert!(registry.http.tls.ca_cert.is_none());
        assert!(registry.auth.is_none());
        assert!(registry.dragonfly.is_none());
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
        // Unknown key next to `type`/`config`.
        let yaml = r#"
type: local
config:
  dir: /blobs
junk: 1
"#;
        assert!(serde_yaml::from_str::<BackendConfig>(yaml).is_err());

        // Unknown key inside the selected backend's settings.
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
timeout: 2m
scope: all
"#;

        let prefetch: PrefetchConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(prefetch.concurrent_blob_count, 8);
        assert_eq!(prefetch.timeout, Duration::from_secs(120));
        assert_eq!(prefetch.scope, PrefetchScope::All);
    }

    #[test]
    fn prefetch_default() {
        let prefetch = PrefetchConfig::default();
        assert_eq!(
            prefetch.concurrent_blob_count,
            default_prefetch_concurrent_blob_count()
        );
        assert_eq!(prefetch.timeout, default_prefetch_timeout());
        assert_eq!(prefetch.scope, PrefetchScope::Ondemand);
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
        assert_eq!(config.prefetch.scope, PrefetchScope::Ondemand);
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
}

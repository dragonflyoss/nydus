use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use nydus_error::{Context, Error, Result};

/// Default number of worker threads used for concurrent blob prefetch.
pub const DEFAULT_PREFETCH_THREADS: usize = 10;

/// Top-level nydus configuration, typically loaded from a YAML file passed to
/// `nydus fuse --config` or constructed by an embedding application before
/// creating a `NydusCore` (in the `nydus-core` crate).
///
/// ```yaml
/// backend:
///   type: local
///   config:
///     dir: /path/to/blobs
/// cache:
///   type: local
///   config:
///     dir: /path/to/cache
/// prefetch:
///   enable: true
///   threads: 10
/// ```
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub backend: BackendConfig,
    pub(crate) cache: CacheConfig,
    #[serde(default)]
    pub prefetch: PrefetchConfig,
}

pub use nydus_backend::config::{BackendConfig, LocalDirConfig};

/// Cache configuration. `type` selects the cache implementation and the opaque
/// `config` map is interpreted by that cache (currently only `local`).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CacheConfig {
    #[serde(rename = "type")]
    pub kind: String,
    /// Serialized as `config` — the YAML key predates the rename.
    #[serde(default, rename = "config")]
    pub options: serde_yaml::Value,
}

/// Prefetch configuration controlling background blob prefetch.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PrefetchConfig {
    pub enable: bool,
    pub threads: usize,
    /// Whether to also prefetch every remaining blob in full (phase 2) after
    /// the priority blobs. When false (the default), only the priority blobs
    /// listed in the root prefetch xattr are prefetched — for an optimized
    /// image that is just the "ondemand" redirect blob, which warms the hot
    /// working set without pulling the whole image and keeps the backend
    /// bandwidth focused on the access-ordered groups.
    pub full: bool,
}

impl Default for PrefetchConfig {
    fn default() -> Self {
        Self {
            enable: true,
            threads: DEFAULT_PREFETCH_THREADS,
            full: false,
        }
    }
}

impl Config {
    /// Load and parse a nydus configuration from a YAML file.
    pub fn from_file(path: &Path) -> Result<Self> {
        let contents = fs::read_to_string(path)
            .with_context(|| format!("failed to read config {}", path.display()))?;
        Self::from_yaml(&contents)
    }

    /// Parse a nydus configuration from a YAML string.
    pub fn from_yaml(contents: &str) -> Result<Self> {
        serde_yaml::from_str(contents).context("failed to parse nydus config")
    }

    /// Directory used by the local cache to store decoded chunks.
    pub fn cache_dir(&self) -> Result<PathBuf> {
        if self.cache.kind != "local" {
            return Err(Error::InvalidConfig(format!(
                "unsupported cache type: {}",
                self.cache.kind
            )));
        }
        let cfg: LocalDirConfig = serde_yaml::from_value(self.cache.options.clone())
            .context("invalid local cache config")?;
        Ok(cfg.dir)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_full_config() {
        let yaml = "
backend:
  type: local
  config:
    dir: /var/lib/nydus/blobs
cache:
  type: local
  config:
    dir: /var/lib/nydus/cache
prefetch:
  enable: true
  threads: 8
";
        let config = Config::from_yaml(yaml).unwrap();
        assert_eq!(config.backend.kind, "local");
        let backend_dir: PathBuf =
            serde_yaml::from_value(config.backend.options["dir"].clone()).unwrap();
        assert_eq!(backend_dir, Path::new("/var/lib/nydus/blobs"));
        assert_eq!(
            config.cache_dir().unwrap(),
            Path::new("/var/lib/nydus/cache")
        );
        assert!(config.prefetch.enable);
        assert_eq!(config.prefetch.threads, 8);
    }

    #[test]
    fn prefetch_defaults_when_omitted() {
        let yaml = "
backend:
  type: local
  config:
    dir: /blobs
cache:
  type: local
  config:
    dir: /cache
";
        let config = Config::from_yaml(yaml).unwrap();
        assert!(config.prefetch.enable);
        assert_eq!(config.prefetch.threads, DEFAULT_PREFETCH_THREADS);
    }

    #[test]
    fn prefetch_partial_fields_fall_back_to_defaults() {
        let yaml = "
backend:
  type: local
  config:
    dir: /blobs
cache:
  type: local
  config:
    dir: /cache
prefetch:
  enable: false
";
        let config = Config::from_yaml(yaml).unwrap();
        assert!(!config.prefetch.enable);
        assert_eq!(config.prefetch.threads, DEFAULT_PREFETCH_THREADS);
    }

    #[test]
    fn parses_registry_backend_with_nested_config() {
        let yaml = "
backend:
  type: registry
  config:
    host: registry.example.com
    repo: library/ubuntu
    auth:
      username: alice
      password: secret
cache:
  type: local
  config:
    dir: /cache
";
        let config = Config::from_yaml(yaml).unwrap();
        assert_eq!(config.backend.kind, "registry");
        assert_eq!(
            config.backend.options["host"].as_str(),
            Some("registry.example.com")
        );
        assert_eq!(config.cache_dir().unwrap(), Path::new("/cache"));
    }
}

use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::storage::prefetch::DEFAULT_PREFETCH_THREADS;

/// Top-level lepton configuration, typically loaded from a YAML file passed to
/// `lepton fuse --config` or constructed by an embedding application before
/// creating a [`LeptonAccessor`](crate::accessor::LeptonAccessor).
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
pub struct Config {
    pub backend: BackendConfig,
    pub cache: CacheConfig,
    #[serde(default)]
    pub prefetch: PrefetchConfig,
}

/// Backend configuration. `type` selects the backend implementation and the
/// opaque `config` map is interpreted by that backend (e.g. `local`, `registry`).
#[derive(Debug, Clone, Deserialize)]
pub struct BackendConfig {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub config: serde_yaml::Value,
}

/// Cache configuration. `type` selects the cache implementation and the opaque
/// `config` map is interpreted by that cache (currently only `local`).
#[derive(Debug, Clone, Deserialize)]
pub struct CacheConfig {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub config: serde_yaml::Value,
}

/// Settings for the local cache: a single directory path.
#[derive(Debug, Clone, Deserialize)]
pub struct LocalDirConfig {
    pub dir: PathBuf,
}

/// Prefetch configuration controlling background blob prefetch.
#[derive(Debug, Clone, Deserialize)]
pub struct PrefetchConfig {
    #[serde(default = "default_prefetch_enable")]
    pub enable: bool,
    #[serde(default = "default_prefetch_threads")]
    pub threads: usize,
}

fn default_prefetch_enable() -> bool {
    true
}

fn default_prefetch_threads() -> usize {
    DEFAULT_PREFETCH_THREADS
}

impl Default for PrefetchConfig {
    fn default() -> Self {
        Self {
            enable: default_prefetch_enable(),
            threads: default_prefetch_threads(),
        }
    }
}

impl Config {
    /// Load and parse a lepton configuration from a YAML file.
    pub fn from_file(path: &Path) -> anyhow::Result<Self> {
        let contents = fs::read_to_string(path)
            .map_err(|err| anyhow::anyhow!("failed to read config {}: {}", path.display(), err))?;
        Self::from_yaml(&contents)
    }

    /// Parse a lepton configuration from a YAML string.
    pub fn from_yaml(contents: &str) -> anyhow::Result<Self> {
        serde_yaml::from_str(contents)
            .map_err(|err| anyhow::anyhow!("failed to parse lepton config: {err}"))
    }

    /// Directory used by the local cache to store decoded chunks.
    pub fn cache_dir(&self) -> anyhow::Result<PathBuf> {
        if self.cache.kind != "local" {
            anyhow::bail!("unsupported cache type: {}", self.cache.kind);
        }
        let cfg: LocalDirConfig = serde_yaml::from_value(self.cache.config.clone())
            .map_err(|err| anyhow::anyhow!("invalid local cache config: {err}"))?;
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
    dir: /var/lib/lepton/blobs
cache:
  type: local
  config:
    dir: /var/lib/lepton/cache
prefetch:
  enable: true
  threads: 8
";
        let config = Config::from_yaml(yaml).unwrap();
        assert_eq!(config.backend.kind, "local");
        let backend_dir: PathBuf =
            serde_yaml::from_value(config.backend.config["dir"].clone()).unwrap();
        assert_eq!(backend_dir, Path::new("/var/lib/lepton/blobs"));
        assert_eq!(
            config.cache_dir().unwrap(),
            Path::new("/var/lib/lepton/cache")
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
            config.backend.config["host"].as_str(),
            Some("registry.example.com")
        );
        assert_eq!(config.cache_dir().unwrap(), Path::new("/cache"));
    }
}

use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use super::prefetch::DEFAULT_PREFETCH_THREADS;

/// Top-level storage configuration, typically loaded from a YAML file passed to
/// `lepton fuse --config`.
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
pub struct StorageConfig {
    pub backend: BackendConfig,
    pub cache: CacheConfig,
    #[serde(default)]
    pub prefetch: PrefetchConfig,
}

/// Backend configuration, tagged by `type` with the inner settings under `config`.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", content = "config", rename_all = "snake_case")]
pub enum BackendConfig {
    Local(LocalDirConfig),
}

/// Cache configuration, tagged by `type` with the inner settings under `config`.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", content = "config", rename_all = "snake_case")]
pub enum CacheConfig {
    Local(LocalDirConfig),
}

/// Settings shared by local backend and local cache: a single directory path.
#[derive(Debug, Clone, Deserialize)]
pub struct LocalDirConfig {
    pub dir: PathBuf,
}

/// Prefetch configuration controlling background blob prefetch after mount.
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

impl StorageConfig {
    /// Load and parse a storage configuration from a YAML file.
    pub fn from_file(path: &Path) -> anyhow::Result<Self> {
        let contents = fs::read_to_string(path)
            .map_err(|err| anyhow::anyhow!("failed to read config {}: {}", path.display(), err))?;
        Self::from_yaml(&contents)
    }

    /// Parse a storage configuration from a YAML string.
    pub fn from_yaml(contents: &str) -> anyhow::Result<Self> {
        serde_yaml::from_str(contents)
            .map_err(|err| anyhow::anyhow!("failed to parse storage config: {}", err))
    }

    /// Directory used by the local backend to locate blobs.
    pub fn backend_dir(&self) -> &Path {
        match &self.backend {
            BackendConfig::Local(config) => &config.dir,
        }
    }

    /// Directory used by the local cache to store decoded chunks.
    pub fn cache_dir(&self) -> &Path {
        match &self.cache {
            CacheConfig::Local(config) => &config.dir,
        }
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
        let config = StorageConfig::from_yaml(yaml).unwrap();
        assert_eq!(config.backend_dir(), Path::new("/var/lib/lepton/blobs"));
        assert_eq!(config.cache_dir(), Path::new("/var/lib/lepton/cache"));
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
        let config = StorageConfig::from_yaml(yaml).unwrap();
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
        let config = StorageConfig::from_yaml(yaml).unwrap();
        assert!(!config.prefetch.enable);
        assert_eq!(config.prefetch.threads, DEFAULT_PREFETCH_THREADS);
    }

    #[test]
    fn rejects_unknown_backend_type() {
        let yaml = "
backend:
  type: s3
  config:
    dir: /blobs
cache:
  type: local
  config:
    dir: /cache
";
        assert!(StorageConfig::from_yaml(yaml).is_err());
    }
}

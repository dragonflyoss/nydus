use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::storage::prefetch::DEFAULT_PREFETCH_THREADS;

/// Maximum number of entries accepted by `/proc/<pid>/{uid,gid}_map`.
pub const MAX_ID_MAP_ENTRIES: usize = 340;

/// Top-level nydus configuration, typically loaded from a YAML file passed to
/// `nydus fuse --config` or constructed by an embedding application before
/// creating a [`NydusCore`](crate::core::NydusCore).
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
    #[serde(default)]
    pub id_mapping: Option<IdMappingConfig>,
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

/// ID mapping used to create an idmapped FUSE mount.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IdMappingConfig {
    #[serde(default)]
    pub mapping: Vec<IdMapTriple>,
}

/// One extent in a Linux user namespace uid/gid map.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IdMapTriple {
    pub internal: u32,
    pub external: u32,
    pub range: u32,
}

/// Prefetch configuration controlling background blob prefetch.
#[derive(Debug, Clone, Deserialize)]
pub struct PrefetchConfig {
    #[serde(default = "default_prefetch_enable")]
    pub enable: bool,
    #[serde(default = "default_prefetch_threads")]
    pub threads: usize,
    /// Whether to also prefetch every remaining blob in full (phase 2) after
    /// the priority blobs. When false (the default), only the priority blobs
    /// listed in the root prefetch xattr are prefetched — for an optimized
    /// image that is just the "ondemand" redirect blob, which warms the hot
    /// working set without pulling the whole image and keeps the backend
    /// bandwidth focused on the access-ordered groups.
    #[serde(default = "default_prefetch_full")]
    pub full: bool,
}

fn default_prefetch_enable() -> bool {
    true
}

fn default_prefetch_threads() -> usize {
    DEFAULT_PREFETCH_THREADS
}

fn default_prefetch_full() -> bool {
    false
}

impl Default for PrefetchConfig {
    fn default() -> Self {
        Self {
            enable: default_prefetch_enable(),
            threads: default_prefetch_threads(),
            full: default_prefetch_full(),
        }
    }
}

impl Config {
    /// Load and parse a nydus configuration from a YAML file.
    pub fn from_file(path: &Path) -> anyhow::Result<Self> {
        let contents = fs::read_to_string(path)
            .map_err(|err| anyhow::anyhow!("failed to read config {}: {}", path.display(), err))?;
        Self::from_yaml(&contents)
    }

    /// Parse a nydus configuration from a YAML string.
    pub fn from_yaml(contents: &str) -> anyhow::Result<Self> {
        let config: Self = serde_yaml::from_str(contents)
            .map_err(|err| anyhow::anyhow!("failed to parse nydus config: {err}"))?;
        config.validate()?;
        Ok(config)
    }

    /// Validate configuration that has cross-field or kernel constraints.
    pub fn validate(&self) -> anyhow::Result<()> {
        if let Some(id_mapping) = &self.id_mapping {
            validate_id_mappings(&id_mapping.mapping)?;
        }
        Ok(())
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

/// Serialize entries in the format accepted by `/proc/<pid>/{uid,gid}_map`.
pub fn serialize_id_mappings(mappings: &[IdMapTriple]) -> String {
    let mut output = String::new();
    for mapping in mappings {
        use std::fmt::Write as _;
        writeln!(
            output,
            "{} {} {}",
            mapping.internal, mapping.external, mapping.range
        )
        .expect("writing to String cannot fail");
    }
    output
}

/// Validate mapping constraints imposed by Linux user namespaces.
pub fn validate_id_mappings(mappings: &[IdMapTriple]) -> anyhow::Result<()> {
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if page_size <= 0 {
        anyhow::bail!("failed to query system page size");
    }
    validate_id_mappings_with_page_size(mappings, page_size as usize)
}

fn validate_id_mappings_with_page_size(
    mappings: &[IdMapTriple],
    page_size: usize,
) -> anyhow::Result<()> {
    if mappings.is_empty() {
        anyhow::bail!("id_mapping.mapping must contain at least one entry");
    }
    if mappings.len() > MAX_ID_MAP_ENTRIES {
        anyhow::bail!(
            "id_mapping.mapping contains {} entries, exceeding the kernel limit of {}",
            mappings.len(),
            MAX_ID_MAP_ENTRIES
        );
    }

    let mut internal_ranges = Vec::with_capacity(mappings.len());
    let mut external_ranges = Vec::with_capacity(mappings.len());
    for (index, mapping) in mappings.iter().enumerate() {
        if mapping.range == 0 {
            anyhow::bail!("id_mapping.mapping[{index}].range must be greater than zero");
        }
        let internal_end = mapping.internal.checked_add(mapping.range).ok_or_else(|| {
            anyhow::anyhow!("id_mapping.mapping[{index}] internal range overflows u32")
        })?;
        let external_end = mapping.external.checked_add(mapping.range).ok_or_else(|| {
            anyhow::anyhow!("id_mapping.mapping[{index}] external range overflows u32")
        })?;
        internal_ranges.push((mapping.internal, internal_end, index));
        external_ranges.push((mapping.external, external_end, index));
    }

    validate_non_overlapping_ranges("internal", &mut internal_ranges)?;
    validate_non_overlapping_ranges("external", &mut external_ranges)?;

    let serialized = serialize_id_mappings(mappings);
    if serialized.len() >= page_size {
        anyhow::bail!(
            "serialized id_mapping is {} bytes, but must be smaller than the {} byte system page",
            serialized.len(),
            page_size
        );
    }

    Ok(())
}

fn validate_non_overlapping_ranges(
    side: &str,
    ranges: &mut [(u32, u32, usize)],
) -> anyhow::Result<()> {
    ranges.sort_unstable_by_key(|range| range.0);
    for pair in ranges.windows(2) {
        let (left_start, left_end, left_index) = pair[0];
        let (right_start, _, right_index) = pair[1];
        if right_start < left_end {
            anyhow::bail!(
                "id_mapping.mapping[{left_index}] and id_mapping.mapping[{right_index}] have overlapping {side} ranges [{left_start}, {left_end})"
            );
        }
    }
    Ok(())
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
            serde_yaml::from_value(config.backend.config["dir"].clone()).unwrap();
        assert_eq!(backend_dir, Path::new("/var/lib/nydus/blobs"));
        assert_eq!(
            config.cache_dir().unwrap(),
            Path::new("/var/lib/nydus/cache")
        );
        assert!(config.prefetch.enable);
        assert_eq!(config.prefetch.threads, 8);
        assert!(config.id_mapping.is_none());
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

    fn config_with_mapping(mapping: &str) -> String {
        format!(
            r#"backend:
  type: local
  config:
    dir: /blobs
cache:
  type: local
  config:
    dir: /cache
id_mapping:
  mapping:
{mapping}"#
        )
    }

    #[test]
    fn parses_id_mapping() {
        let yaml = config_with_mapping(
            r#"    - internal: 0
      external: 100000
      range: 65536
"#,
        );
        let config = Config::from_yaml(&yaml).unwrap();
        assert_eq!(
            config.id_mapping.unwrap().mapping,
            vec![IdMapTriple {
                internal: 0,
                external: 100000,
                range: 65536,
            }]
        );
    }

    #[test]
    fn rejects_unknown_id_mapping_fields_only() {
        let yaml = config_with_mapping(
            r#"    - internal: 0
      external: 100000
      range: 1
      typo: true
"#,
        );
        assert!(Config::from_yaml(&yaml).is_err());

        let yaml = format!(
            "{}legacy_top_level: true\n",
            config_with_mapping(
                r#"    - internal: 0
      external: 100000
      range: 1
"#
            )
        );
        assert!(Config::from_yaml(&yaml).is_ok());
    }

    #[test]
    fn rejects_empty_or_zero_length_id_mapping() {
        let empty = config_with_mapping("");
        assert!(Config::from_yaml(&empty)
            .unwrap_err()
            .to_string()
            .contains("at least one"));

        let zero = config_with_mapping(
            r#"    - internal: 0
      external: 100000
      range: 0
"#,
        );
        assert!(Config::from_yaml(&zero)
            .unwrap_err()
            .to_string()
            .contains("greater than zero"));
    }

    #[test]
    fn rejects_overflowing_id_mapping() {
        for yaml in [
            config_with_mapping(
                r#"    - internal: 4294967295
      external: 0
      range: 1
"#,
            ),
            config_with_mapping(
                r#"    - internal: 0
      external: 4294967295
      range: 1
"#,
            ),
        ] {
            assert!(Config::from_yaml(&yaml)
                .unwrap_err()
                .to_string()
                .contains("overflows"));
        }
    }

    #[test]
    fn rejects_overlapping_id_mapping_ranges() {
        let internal = config_with_mapping(
            r#"    - internal: 0
      external: 100000
      range: 10
    - internal: 9
      external: 200000
      range: 10
"#,
        );
        assert!(Config::from_yaml(&internal)
            .unwrap_err()
            .to_string()
            .contains("overlapping internal"));

        let external = config_with_mapping(
            r#"    - internal: 0
      external: 100000
      range: 10
    - internal: 20
      external: 100009
      range: 10
"#,
        );
        assert!(Config::from_yaml(&external)
            .unwrap_err()
            .to_string()
            .contains("overlapping external"));
    }

    #[test]
    fn rejects_too_many_id_mapping_entries() {
        let mappings = (0..=MAX_ID_MAP_ENTRIES)
            .map(|index| IdMapTriple {
                internal: index as u32,
                external: 100000 + index as u32,
                range: 1,
            })
            .collect::<Vec<_>>();
        assert!(validate_id_mappings(&mappings)
            .unwrap_err()
            .to_string()
            .contains("kernel limit"));
    }

    #[test]
    fn rejects_page_sized_serialized_mapping() {
        let mappings = (0..10)
            .map(|index| IdMapTriple {
                internal: (index as u32) * 2,
                external: 1_000_000_000 + (index as u32) * 2,
                range: 1,
            })
            .collect::<Vec<_>>();
        let serialized = serialize_id_mappings(&mappings);
        assert!(
            validate_id_mappings_with_page_size(&mappings, serialized.len())
                .unwrap_err()
                .to_string()
                .contains("system page")
        );
    }
}

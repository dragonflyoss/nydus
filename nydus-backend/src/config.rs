//! Backend configuration structures.
//!
//! These are pure data: the YAML file that produces them is parsed and
//! validated by the control plane, which converts into these structs. Owning
//! them here keeps this crate free of the control-plane error type.

use serde::Deserialize;

/// Backend configuration. `type` selects the backend implementation and the
/// opaque `config` map is interpreted by that backend (e.g. `local`, `registry`).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackendConfig {
    #[serde(rename = "type")]
    pub kind: String,
    /// Serialized as `config` — the YAML key predates the rename.
    #[serde(default, rename = "config")]
    pub options: serde_yaml::Value,
}

/// Settings for a directory-backed component: a single directory path. Shared
/// by the local backend here and the local cache in the storage layer.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalDirConfig {
    pub dir: std::path::PathBuf,
}

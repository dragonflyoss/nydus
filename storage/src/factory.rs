// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::fs::File;
use std::io::Result as IOResult;
use std::sync::Arc;

use anyhow::{Context, Result};
use serde::Deserialize;
use serde_json::value::Value;

use crate::backend::*;
use crate::cache::*;
use crate::compress;

use nydus_utils::{digest, einval};

// storage backend config
#[derive(Default, Clone, Deserialize)]
pub struct Config {
    pub backend: BackendConfig,
    #[serde(default)]
    pub cache: CacheConfig,
}

#[derive(Default, Clone, Deserialize)]
pub struct BackendConfig {
    #[serde(rename = "type")]
    pub backend_type: String,
    #[serde(rename = "config")]
    pub backend_config: Value,
}

impl BackendConfig {
    pub fn from_str(backend_type: &str, json_str: &str) -> Result<BackendConfig> {
        let backend_config = serde_json::from_str(json_str)
            .context("failed to parse backend config in JSON string")?;
        Ok(Self {
            backend_type: backend_type.to_string(),
            backend_config,
        })
    }
    pub fn from_file(backend_type: &str, file_path: &str) -> Result<BackendConfig> {
        let file = File::open(file_path)
            .with_context(|| format!("failed to open backend config file {}", file_path))?;
        let backend_config = serde_json::from_reader(file)
            .with_context(|| format!("failed to parse backend config file {}", file_path))?;
        Ok(Self {
            backend_type: backend_type.to_string(),
            backend_config,
        })
    }
}

#[derive(Default, Clone, Deserialize)]
pub struct CacheConfig {
    #[serde(default, rename = "validate")]
    pub cache_validate: bool,
    #[serde(default, rename = "compressed")]
    pub cache_compressed: bool,
    #[serde(default, rename = "type")]
    pub cache_type: String,
    #[serde(default, rename = "config")]
    pub cache_config: Value,
    #[serde(skip_serializing, skip_deserializing)]
    pub prefetch_worker: PrefetchWorker,
}

pub fn new_backend(
    config: BackendConfig,
    id: &str,
) -> IOResult<Arc<dyn BlobBackend + Send + Sync>> {
    match config.backend_type.as_str() {
        #[cfg(feature = "backend-oss")]
        "oss" => Ok(Arc::new(oss::new(config.backend_config, Some(id))?)),
        #[cfg(feature = "backend-registry")]
        "registry" => Ok(Arc::new(registry::new(config.backend_config, Some(id))?)),
        #[cfg(feature = "backend-localfs")]
        "localfs" => Ok(Arc::new(localfs::new(config.backend_config, Some(id))?)),
        _ => Err(einval!(format!(
            "unsupported backend type '{}'",
            config.backend_type
        ))),
    }
}

pub fn new_uploader(mut config: BackendConfig) -> IOResult<Arc<dyn BlobBackendUploader>> {
    // Disable http timeout for upload request
    config.backend_config["connect_timeout"] = 0.into();
    config.backend_config["timeout"] = 0.into();
    match config.backend_type.as_str() {
        #[cfg(feature = "backend-oss")]
        "oss" => {
            let backend = oss::new(config.backend_config, None)?;
            Ok(Arc::new(backend) as Arc<dyn BlobBackendUploader>)
        }
        #[cfg(feature = "backend-registry")]
        "registry" => {
            let backend = registry::new(config.backend_config, None)?;
            Ok(Arc::new(backend) as Arc<dyn BlobBackendUploader>)
        }
        #[cfg(feature = "backend-localfs")]
        "localfs" => {
            let backend = localfs::new(config.backend_config, None)?;
            Ok(Arc::new(backend) as Arc<dyn BlobBackendUploader>)
        }
        _ => Err(einval!(format!(
            "unsupported backend type '{}'",
            config.backend_type
        ))),
    }
}

pub fn new_rw_layer(
    config: Config,
    compressor: compress::Algorithm,
    digester: digest::Algorithm,
    id: &str,
) -> IOResult<Arc<dyn RafsCache + Send + Sync>> {
    let backend = new_backend(config.backend, id)?;
    match config.cache.cache_type.as_str() {
        "blobcache" => Ok(blobcache::new(
            config.cache,
            backend,
            compressor,
            digester,
            id,
        )?),
        _ => Ok(Arc::new(dummycache::new(
            config.cache,
            backend,
            compressor,
            digester,
        )?)),
    }
}

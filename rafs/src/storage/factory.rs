// Copyright 2020 Ant Financial. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::io::Result;
use std::sync::Arc;

use serde::Deserialize;
use serde_json::value::Value;

use crate::metadata::digest;
use crate::storage::backend::*;
use crate::storage::cache::*;

use crate::storage::compress;

use nydus_utils::einval;

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

#[derive(Default, Clone, Deserialize)]
pub struct CacheConfig {
    #[serde(default, rename = "validate")]
    pub cache_validate: bool,
    #[serde(default, rename = "type")]
    pub cache_type: String,
    #[serde(default, rename = "config")]
    pub cache_config: Value,
    #[serde(skip_serializing, skip_deserializing)]
    pub prefetch_worker: PrefetchWorker,
}

pub fn new_backend(config: BackendConfig) -> Result<Arc<dyn BlobBackend + Send + Sync>> {
    match config.backend_type.as_str() {
        #[cfg(feature = "backend-oss")]
        "oss" => {
            Ok(Arc::new(oss::new(config.backend_config)?) as Arc<dyn BlobBackend + Send + Sync>)
        }
        #[cfg(feature = "backend-registry")]
        "registry" => {
            Ok(Arc::new(registry::new(config.backend_config)?)
                as Arc<dyn BlobBackend + Send + Sync>)
        }
        #[cfg(feature = "backend-localfs")]
        "localfs" => {
            Ok(Arc::new(localfs::new(config.backend_config)?)
                as Arc<dyn BlobBackend + Send + Sync>)
        }
        _ => Err(einval!(format!(
            "unsupported backend type '{}'",
            config.backend_type
        ))),
    }
}

pub fn new_uploader(mut config: BackendConfig) -> Result<Arc<dyn BlobBackendUploader>> {
    // Disable http timeout for upload request
    config.backend_config["connect_timeout"] = 0.into();
    config.backend_config["timeout"] = 0.into();
    match config.backend_type.as_str() {
        #[cfg(feature = "backend-oss")]
        "oss" => {
            let backend = oss::new(config.backend_config)?;
            Ok(Arc::new(backend) as Arc<dyn BlobBackendUploader>)
        }
        #[cfg(feature = "backend-registry")]
        "registry" => {
            let backend = registry::new(config.backend_config)?;
            Ok(Arc::new(backend) as Arc<dyn BlobBackendUploader>)
        }
        #[cfg(feature = "backend-localfs")]
        "localfs" => {
            let backend = localfs::new(config.backend_config)?;
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
) -> Result<Box<dyn RafsCache + Send + Sync>> {
    let backend = new_backend(config.backend)?;
    match config.cache.cache_type.as_str() {
        "blobcache" => Ok(
            Box::new(blobcache::new(config.cache, backend, compressor, digester)?)
                as Box<dyn RafsCache + Send + Sync>,
        ),
        _ => Ok(Box::new(dummycache::new(
            config.cache,
            backend,
            compressor,
            digester,
        )?) as Box<dyn RafsCache + Send + Sync>),
    }
}

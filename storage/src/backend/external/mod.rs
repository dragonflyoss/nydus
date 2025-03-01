// Copyright 2024 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::fs::File;
use std::path::PathBuf;
use std::result::Result;
use std::sync::Arc;

use crate::device::BlobChunkInfo;
use nydus_api::config::ExternalBackendConfig;

use serde::{Deserialize, Serialize};

pub mod local;
pub mod meta;

pub trait ExternalBlobReader: Send + Sync {
    fn read(&self, buf: &mut [u8], chunks: &[&dyn BlobChunkInfo]) -> Result<usize, String>;
}

#[derive(Debug, PartialEq, Deserialize, Serialize)]
struct BackendConfig {
    #[serde(rename = "type")]
    kind: String,
    config: HashMap<String, String>,
}

impl BackendConfig {
    pub fn try_merge(&mut self, additional_backends_config: Arc<Vec<ExternalBackendConfig>>) {
        for config in additional_backends_config.iter() {
            if config.kind != self.kind {
                return;
            }
            for key in config.patch.keys() {
                if !self.config.contains_key(key) {
                    return;
                }
            }
            let mut found = false;
            for (key, value) in config.config.iter() {
                found = true;
                self.config.insert(key.clone(), value.clone());
            }
            if found {
                info!("merged external backend config: {:?}", self.kind);
                return;
            }
        }
    }
}

#[derive(Default)]
pub struct NoopBackend {}

impl ExternalBlobReader for NoopBackend {
    fn read(&self, _buf: &mut [u8], _chunks: &[&dyn BlobChunkInfo]) -> Result<usize, String> {
        unimplemented!();
    }
}

#[derive(Default)]
pub struct ExternalBackendFactory {}

impl ExternalBackendFactory {
    pub fn create(
        additional_backends_config: Arc<Vec<ExternalBackendConfig>>,
        meta_path: PathBuf,
        backend_config_path: PathBuf,
    ) -> Result<Arc<dyn ExternalBlobReader>, String> {
        let mut backend_config: BackendConfig =
            serde_json::from_reader(File::open(backend_config_path).map_err(|e| e.to_string())?)
                .map_err(|e| e.to_string())?;
        backend_config.try_merge(additional_backends_config);
        match backend_config.kind.as_str() {
            "local" => {
                let backend = local::LocalBackend::new(meta_path, &backend_config.config)?;
                Ok(Arc::new(backend) as Arc<dyn ExternalBlobReader>)
            }
            _ => Err(format!("unsupported backend type: {}", backend_config.kind)),
        }
    }

    pub fn create_noop() -> Arc<dyn ExternalBlobReader> {
        let backend = NoopBackend::default();
        Arc::new(backend) as Arc<dyn ExternalBlobReader>
    }
}

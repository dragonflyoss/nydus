// Copyright 2024 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::fs::File;
use std::io::Result;
use std::path::PathBuf;
use std::sync::Arc;

use crate::device::BlobChunkInfo;
use serde::{Deserialize, Serialize};

pub mod local;
pub mod meta;

pub trait ExternalBlobReader: Send + Sync {
    fn read(&self, buf: &mut [u8], chunks: &[&dyn BlobChunkInfo]) -> Result<usize>;
}

#[derive(Debug, PartialEq, Deserialize, Serialize)]
struct BackendConfig {
    #[serde(rename = "type")]
    kind: String,
    config: HashMap<String, String>,
}

pub struct ExternalBackendFactory {}

impl ExternalBackendFactory {
    pub fn new(
        meta_path: PathBuf,
        backend_config_path: PathBuf,
    ) -> Result<Arc<dyn ExternalBlobReader>> {
        let backend_config: BackendConfig =
            serde_json::from_reader(File::open(backend_config_path)?)?;
        match backend_config.kind.as_str() {
            "local" => {
                let backend = local::LocalBackend::new(meta_path, &backend_config.config)?;
                Ok(Arc::new(backend) as Arc<dyn ExternalBlobReader>)
            }
            _ => {
                return Err(einval!(format!(
                    "unsupported backend type: {}",
                    backend_config.kind
                )))
            }
        }
    }
}

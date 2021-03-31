// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

extern crate serde;

use std::fs::rename;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use vmm_sys_util::tempfile::TempFile;

use storage::{backend, factory};

#[derive(PartialEq)]
enum Behavior {
    None,
    Upload,
    Rename,
}

pub struct Uploader {
    behavior: Behavior,
    // Do not remove the field, TempFile will remove the temp
    // file after instance dropping.
    #[allow(dead_code)]
    temp_file: Option<TempFile>,
    backend: Arc<dyn backend::BlobBackendUploader>,
    pub blob_path: PathBuf,
}

impl Uploader {
    pub fn from_config_str(backend_type: &str, backend_config_str: &str) -> Result<Self> {
        Self::new(
            factory::BackendConfig::from_str(backend_type, backend_config_str)
                .context("failed to parse backend config from JSON string")?,
        )
    }

    pub fn from_config_file(backend_type: &str, backend_config_file: &str) -> Result<Self> {
        Self::new(
            factory::BackendConfig::from_file(backend_type, backend_config_file)
                .context("failed to parse backend config from JSON file")?,
        )
    }

    fn new(config: factory::BackendConfig) -> Result<Self> {
        let mut blob_path = PathBuf::from("");
        let mut temp_file = None;
        let mut behavior = Behavior::None;

        // Special optimization: Avoid unnecessary blob upload in localfs backend,
        // builder just dumps blob file to target path (`blob_file/dir` in backend config)
        // of localfs backend.
        if config.backend_type == "localfs" {
            if let Some(blob_file) = config.backend_config["blob_file"].as_str() {
                blob_path = PathBuf::from(blob_file);
            } else if let Some(dir) = config.backend_config["dir"].as_str() {
                temp_file = Some(
                    TempFile::new_in(Path::new(dir))
                        .with_context(|| format!("failed to create temp file in {}", dir))?,
                );
                // Just rename blob file from `/path/to/dir/{temp_file}` to
                // `/path/to/dir/{blob_id}` after blob dumping, instead of upload.
                behavior = Behavior::Rename;
            }
        } else {
            temp_file =
                Some(TempFile::new().context("failed to create temp file in current directory")?);
            behavior = Behavior::Upload;
        }

        if let Some(temp_file) = &temp_file {
            blob_path = temp_file.as_path().to_path_buf();
        }

        let backend = factory::new_uploader(config).context("failed to init uploader")?;

        Ok(Self {
            behavior,
            temp_file,
            backend,
            blob_path,
        })
    }

    pub fn upload(&self, blob_id: &str) -> Result<Option<PathBuf>> {
        match self.behavior {
            Behavior::Upload => {
                self.backend
                    .upload(blob_id, &self.blob_path, |(current, total)| {
                        io::stdout().flush().unwrap_or_default();
                        print!("\r");
                        print!(
                            "Backend blob uploading: {}/{} bytes ({}%)",
                            current,
                            total,
                            current * 100 / total,
                        );
                    })
                    .context("failed to upload blob")?;

                print!("\r");
                io::stdout().flush().unwrap_or_default();
            }
            Behavior::Rename => {
                let dir = &self.blob_path.parent();
                if let Some(dir) = dir {
                    let target = dir.join(blob_id);
                    trace!("rename {:?} to {:?}", self.blob_path, target);
                    rename(&self.blob_path, &target).context(format!(
                        "failed to rename blob from {:?} to {:?}",
                        self.blob_path, target,
                    ))?;
                    return Ok(Some(target));
                }
            }
            Behavior::None => {}
        }

        if self.behavior != Behavior::Upload {
            return Ok(Some(self.blob_path.clone()));
        }

        Ok(None)
    }
}

// Copyright (C) 2020-2021 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Storage backend driver to access blobs on local filesystems.

use std::io::Result;
use std::sync::Arc;

use fuse_backend_rs::file_buf::FileVolatileSlice;
use nydus_utils::metrics::BackendMetrics;

use crate::backend::{BackendError, BackendResult, BlobBackend, BlobReader};

#[derive(Debug)]
pub enum NoopError {
    Noop,
}

/// a Noop backend, do nothing
#[derive(Default)]
pub struct Noop {
    metrics: Arc<BackendMetrics>,
}

impl Noop {
    pub fn new(id: Option<&str>) -> Result<Self> {
        let id = id.ok_or_else(|| einval!("noop requires blob_id"))?;
        Ok(Noop {
            metrics: BackendMetrics::new(id, "noop"),
        })
    }
}

struct NoopEntry {
    blob_id: String,
    metrics: Arc<BackendMetrics>,
}

impl BlobReader for NoopEntry {
    fn blob_size(&self) -> BackendResult<u64> {
        Err(BackendError::Unsupported(format!(
            "unsupport blob_size operation for {}",
            self.blob_id,
        )))
    }

    fn try_read(&self, _buf: &mut [u8], _offset: u64) -> BackendResult<usize> {
        Err(BackendError::Unsupported(format!(
            "unsupport try_read operation for {}",
            self.blob_id,
        )))
    }

    fn readv(
        &self,
        _bufs: &[FileVolatileSlice],
        _offset: u64,
        _max_size: usize,
    ) -> BackendResult<usize> {
        Err(BackendError::Unsupported(format!(
            "unsupport readv operation for {}",
            self.blob_id,
        )))
    }

    fn metrics(&self) -> &BackendMetrics {
        &self.metrics
    }
}

impl BlobBackend for Noop {
    fn shutdown(&self) {}

    fn metrics(&self) -> &BackendMetrics {
        &self.metrics
    }

    fn get_reader(&self, blob_id: &str) -> BackendResult<Arc<dyn BlobReader>> {
        Ok(Arc::new(NoopEntry {
            blob_id: blob_id.to_owned(),
            metrics: self.metrics.clone(),
        }))
    }
}

impl Drop for Noop {
    fn drop(&mut self) {
        self.metrics.release().unwrap_or_else(|e| error!("{:?}", e));
    }
}

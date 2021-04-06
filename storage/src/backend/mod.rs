// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::io::Error;

use vm_memory::VolatileSlice;

use nydus_utils::metrics::{BackendMetrics, ERROR_HOLDER};

#[cfg(feature = "backend-localfs")]
use crate::backend::localfs::LocalFsError;
#[cfg(feature = "backend-oss")]
use crate::backend::oss::OssError;
#[cfg(feature = "backend-registry")]
use crate::backend::registry::RegistryError;
use crate::utils::copyv;

#[cfg(feature = "backend-localfs")]
pub mod localfs;
#[cfg(feature = "backend-oss")]
pub mod oss;
#[cfg(feature = "backend-registry")]
pub mod registry;
#[cfg(any(feature = "backend-oss", feature = "backend-registry"))]
pub mod request;

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ProxyConfig {
    url: String,
    ping_url: String,
    fallback: bool,
    check_interval: u64,
}

#[derive(Debug)]
pub enum BackendError {
    Unsupported(String),
    CopyData(Error),
    #[cfg(feature = "backend-registry")]
    Registry(RegistryError),
    #[cfg(feature = "backend-localfs")]
    LocalFs(LocalFsError),
    #[cfg(feature = "backend-oss")]
    Oss(OssError),
}

pub type BackendResult<T> = std::result::Result<T, BackendError>;

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            ping_url: String::new(),
            fallback: true,
            check_interval: 5,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct CommonConfig {
    proxy: ProxyConfig,
    timeout: u64,
    connect_timeout: u64,
    retry_limit: u8,
}

impl Default for CommonConfig {
    fn default() -> Self {
        Self {
            proxy: ProxyConfig::default(),
            timeout: 5,
            connect_timeout: 5,
            retry_limit: 0,
        }
    }
}

/// Rafs blob backend API
pub trait BlobBackend {
    /// prefetch blob if supported
    fn prefetch_blob(
        &self,
        blob_id: &str,
        blob_readahead_offset: u32,
        blob_readahead_size: u32,
    ) -> BackendResult<()>;

    fn release(&self);

    #[inline]
    fn retry_limit(&self) -> u8 {
        0
    }

    fn metrics(&self) -> &BackendMetrics;

    /// Get whole blob size
    fn blob_size(&self, blob_id: &str) -> BackendResult<u64>;

    /// Read a range of data from blob into the provided slice
    fn read(&self, blob_id: &str, buf: &mut [u8], offset: u64) -> BackendResult<usize> {
        let mut retry_count = self.retry_limit();
        let begin_time = self.metrics().begin();
        loop {
            let ret = self.try_read(blob_id, buf, offset);
            match ret {
                Ok(size) => {
                    self.metrics().end(&begin_time, buf.len(), false);
                    return Ok(size);
                }
                Err(err) => {
                    if retry_count > 0 {
                        warn!(
                            "Read from backend failed: {:?}, retry count {}",
                            err, retry_count
                        );
                        retry_count -= 1;
                    } else {
                        self.metrics().end(&begin_time, buf.len(), true);
                        ERROR_HOLDER
                            .lock()
                            .unwrap()
                            .push(&format!("{:?}", err))
                            .unwrap_or_else(|_| error!("Failed when try to hold error"));
                        break Err(err);
                    }
                }
            }
        }
    }

    /// Read a range of data from blob into the provided slice
    fn try_read(&self, blob_id: &str, buf: &mut [u8], offset: u64) -> BackendResult<usize>;

    /// Read multiple range of data from blob into the provided slices
    fn readv(
        &self,
        blob_id: &str,
        bufs: &[VolatileSlice],
        offset: u64,
        max_size: usize,
    ) -> BackendResult<usize> {
        if bufs.len() == 1 && max_size >= bufs[0].len() {
            let buf = unsafe { std::slice::from_raw_parts_mut(bufs[0].as_ptr(), bufs[0].len()) };
            self.read(blob_id, buf, offset)
        } else {
            // Use std::alloc to avoid zeroing the allocated buffer.
            let size = bufs.iter().fold(0usize, move |size, s| size + s.len());
            let layout = std::alloc::Layout::from_size_align(size, 8).unwrap();
            let ptr = unsafe { std::alloc::alloc(layout) };
            let data = unsafe { std::slice::from_raw_parts_mut(ptr, size) };

            self.read(blob_id, data, offset)?;
            let result = copyv(&data, bufs, offset, max_size).map_err(BackendError::CopyData);

            unsafe { std::alloc::dealloc(ptr, layout) };

            result
        }
    }

    /// Write a range of data to blob from the provided slice
    fn write(&self, blob_id: &str, buf: &[u8], offset: u64) -> BackendResult<usize>;
}

#[cfg(any(feature = "backend-oss", feature = "backend-registry"))]
fn default_http_scheme() -> String {
    "https".to_string()
}

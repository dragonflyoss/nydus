// Copyright 2020 Ant Group. All rights reserved.
// Copyright (C) 2021 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Storage backends to read blob data from Registry, OSS, disk, file system etc.
//!
//! There are several types of storage backend drivers implemented:
//! - [Registry](registry/struct.Registry.html): backend driver to access blobs on container image
//!   registry.
//! - [Oss](oss/struct.Oss.html): backend driver to access blobs on Oss(Object Storage System).
//! - [LocalFs](localfs/struct.LocalFs.html): backend driver to access blobs on local file system.
//!   The [LocalFs](localfs/struct.LocalFs.html) storage backend supports backend level data
//!   prefetching, which is to load data into page cache.

use std::sync::Arc;

use fuse_backend_rs::transport::FileVolatileSlice;
use nydus_utils::metrics::{BackendMetrics, ERROR_HOLDER};

use crate::utils::copyv;
use crate::StorageError;

#[cfg(any(feature = "backend-oss", feature = "backend-registry"))]
pub mod connection;
#[cfg(feature = "backend-localfs")]
pub mod localfs;
#[cfg(feature = "backend-oss")]
pub mod oss;
#[cfg(feature = "backend-registry")]
pub mod registry;

/// Error codes related to storage backend operations.
#[derive(Debug)]
pub enum BackendError {
    /// Unsupported operation.
    Unsupported(String),
    /// Failed to copy data from/into blob.
    CopyData(StorageError),
    #[cfg(feature = "backend-registry")]
    /// Error from Registry storage backend.
    Registry(self::registry::RegistryError),
    #[cfg(feature = "backend-localfs")]
    /// Error from LocalFs storage backend.
    LocalFs(self::localfs::LocalFsError),
    #[cfg(feature = "backend-oss")]
    /// Error from OSS storage backend.
    Oss(self::oss::OssError),
}

/// Specialized `Result` for storage backends.
pub type BackendResult<T> = std::result::Result<T, BackendError>;

/// Configuration information for network proxy.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct ProxyConfig {
    /// Access remote storage backend via P2P proxy, e.g. Dragonfly dfdaemon server URL.
    url: String,
    /// Endpoint of P2P proxy health checking.
    ping_url: String,
    /// Fallback to remote storage backend if P2P proxy ping failed.
    fallback: bool,
    /// Interval of P2P proxy health checking, in seconds.
    check_interval: u64,
}

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

/// Generic configuration for storage backends.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct CommonConfig {
    /// Enable HTTP proxy for the read request.
    proxy: ProxyConfig,
    /// Skip SSL certificate validation for HTTPS scheme.
    skip_verify: bool,
    /// Drop the read request once http request timeout, in seconds.
    timeout: u64,
    /// Drop the read request once http connection timeout, in seconds.
    connect_timeout: u64,
    /// Retry count when read request failed.
    retry_limit: u8,
}

impl Default for CommonConfig {
    fn default() -> Self {
        Self {
            proxy: ProxyConfig::default(),
            skip_verify: false,
            timeout: 5,
            connect_timeout: 5,
            retry_limit: 0,
        }
    }
}

/// Trait to read data from a on storage backend.
pub trait BlobReader: Send + Sync {
    /// Get size of the blob file.
    fn blob_size(&self) -> BackendResult<u64>;

    /// Try to read a range of data from the blob file into the provided buffer.
    ///
    /// Try to read data of range [offset, offset + buf.len()) from the blob file, and returns:
    /// - bytes of data read, which may be smaller than buf.len()
    /// - error code if error happens
    fn try_read(&self, buf: &mut [u8], offset: u64) -> BackendResult<usize>;

    /// Read a range of data from the blob file into the provided buffer.
    ///
    /// Read data of range [offset, offset + buf.len()) from the blob file, and returns:
    /// - bytes of data read, which may be smaller than buf.len()
    /// - error code if error happens
    ///
    /// It will try `BlobBackend::retry_limit()` times at most and return the first successfully
    /// read data.
    fn read(&self, buf: &mut [u8], offset: u64) -> BackendResult<usize> {
        let mut retry_count = self.retry_limit();
        let begin_time = self.metrics().begin();

        loop {
            match self.try_read(buf, offset) {
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
                        return Err(err);
                    }
                }
            }
        }
    }

    /// Read a range of data from the blob file into the provided buffers.
    ///
    /// Read data of range [offset, offset + max_size) from the blob file, and returns:
    /// - bytes of data read, which may be smaller than max_size
    /// - error code if error happens
    ///
    /// It will try `BlobBackend::retry_limit()` times at most and return the first successfully
    /// read data.
    fn readv(
        &self,
        bufs: &[FileVolatileSlice],
        offset: u64,
        max_size: usize,
    ) -> BackendResult<usize> {
        if bufs.len() == 1 && max_size >= bufs[0].len() {
            let buf = unsafe { std::slice::from_raw_parts_mut(bufs[0].as_ptr(), bufs[0].len()) };
            self.read(buf, offset)
        } else {
            // Use std::alloc to avoid zeroing the allocated buffer.
            let size = bufs.iter().fold(0usize, move |size, s| size + s.len());
            let size = std::cmp::min(size, max_size);
            let mut data = Vec::with_capacity(size);
            unsafe { data.set_len(size) };

            let result = self.read(&mut data, offset)?;
            copyv(&[&data], bufs, 0, result, 0, 0)
                .map(|r| r.0)
                .map_err(BackendError::CopyData)
        }
    }

    /// Give hints to prefetch blob data range.
    ///
    /// This method only prefetch blob data from storage backends, it doesn't cache data in the
    /// blob cache subsystem. So it's useful for disk and file system based storage backends, but
    /// it may not help for Registry/OSS based storage backends.
    fn prefetch_blob_data_range(&self, ra_offset: u64, ra_size: u64) -> BackendResult<()>;

    /// Stop the background data prefetching tasks.
    fn stop_data_prefetch(&self) -> BackendResult<()>;

    /// Get metrics object.
    fn metrics(&self) -> &BackendMetrics;

    /// Get maximum number of times to retry when encountering IO errors.
    fn retry_limit(&self) -> u8 {
        0
    }
}

/// Trait to access blob files on backend storages, such as OSS, registry, local fs etc.
pub trait BlobBackend: Send + Sync {
    /// Destroy the `BlobBackend` storage object.
    fn shutdown(&self);

    /// Get metrics object.
    fn metrics(&self) -> &BackendMetrics;

    /// Get a blob reader object to access blod `blob_id`.
    fn get_reader(&self, blob_id: &str) -> BackendResult<Arc<dyn BlobReader>>;
}

#[cfg(any(feature = "backend-oss", feature = "backend-registry"))]
/// Get default http scheme for network connection.
fn default_http_scheme() -> String {
    "https".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(any(feature = "backend-oss", feature = "backend-registry"))]
    #[test]
    fn test_default_http_scheme() {
        assert_eq!(default_http_scheme(), "https");
    }

    #[test]
    fn test_common_config() {
        let config = CommonConfig::default();

        assert_eq!(config.timeout, 5);
        assert_eq!(config.connect_timeout, 5);
        assert_eq!(config.retry_limit, 0);
        assert_eq!(config.proxy.check_interval, 5);
        assert_eq!(config.proxy.fallback, true);
        assert_eq!(config.proxy.ping_url, "");
        assert_eq!(config.proxy.url, "");
    }
}

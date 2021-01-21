// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::io::Result;
use std::path::Path;

use vm_memory::VolatileSlice;

use crate::storage::utils::copyv;
use nydus_utils::eio;

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
    force_upload: bool,
    retry_limit: u8,
}

impl Default for CommonConfig {
    fn default() -> Self {
        Self {
            proxy: ProxyConfig::default(),
            timeout: 5,
            connect_timeout: 5,
            force_upload: false,
            retry_limit: 0,
        }
    }
}

/// Rafs blob backend API
pub trait BlobBackend {
    /// prefetch blob if supported
    /// TODO: Now `blob_readahead_offset` is type of `u32`. Better that we can change
    /// it to u64 someday.
    fn prefetch_blob(
        &self,
        _blob_id: &str,
        _blob_readahead_offset: u32,
        _blob_readahead_size: u32,
    ) -> Result<()> {
        Ok(())
    }

    #[inline]
    fn retry_limit(&self) -> u8 {
        0
    }

    /// Get whole blob size
    fn blob_size(&self, blob_id: &str) -> Result<u64>;

    /// Read a range of data from blob into the provided slice
    fn read(&self, blob_id: &str, buf: &mut [u8], offset: u64) -> Result<usize> {
        let mut retry_count = self.retry_limit();
        loop {
            let ret = self.try_read(blob_id, buf, offset);
            match ret {
                Ok(size) => {
                    return Ok(size);
                }
                Err(err) => {
                    if retry_count > 0 {
                        warn!(
                            "Read from backend failed: {}, retry count {}",
                            err, retry_count
                        );
                        retry_count -= 1;
                    } else {
                        break Err(eio!(format!("Read from backend failed: {}", err)));
                    }
                }
            }
        }
    }

    /// Read a range of data from blob into the provided slice
    fn try_read(&self, blob_id: &str, buf: &mut [u8], offset: u64) -> Result<usize>;

    /// Read multiple range of data from blob into the provided slices
    fn readv(
        &self,
        blob_id: &str,
        bufs: &[VolatileSlice],
        offset: u64,
        max_size: usize,
    ) -> Result<usize> {
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
            let result = copyv(&data, bufs, offset, max_size);

            unsafe { std::alloc::dealloc(ptr, layout) };

            result
        }
    }

    /// Write a range of data to blob from the provided slice
    fn write(&self, blob_id: &str, buf: &[u8], offset: u64) -> Result<usize>;
}

// Rafs blob backend upload API
pub trait BlobBackendUploader {
    fn upload(
        &self,
        blob_id: &str,
        blob_path: &Path,
        callback: fn((usize, usize)),
    ) -> Result<usize>;
}

fn default_http_scheme() -> String {
    "https".to_string()
}

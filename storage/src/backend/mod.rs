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
//! - [LocalDisk](localdisk/struct.LocalDisk.html): backend driver to access blobs on local disk.

use std::fmt;
use std::io::Read;
use std::{sync::Arc, time::Duration};

use fuse_backend_rs::file_buf::FileVolatileSlice;
use nydus_utils::{
    metrics::{BackendMetrics, ERROR_HOLDER},
    DelayType, Delayer,
};

use crate::utils::{alloc_buf, copyv};
use crate::StorageError;

#[cfg(any(
    feature = "backend-oss",
    feature = "backend-registry",
    feature = "backend-s3",
    feature = "backend-http-proxy",
))]
pub mod connection;
#[cfg(feature = "backend-http-proxy")]
pub mod http_proxy;
#[cfg(feature = "backend-localdisk")]
pub mod localdisk;
#[cfg(feature = "backend-localfs")]
pub mod localfs;
#[cfg(any(feature = "backend-oss", feature = "backend-s3"))]
pub mod object_storage;
#[cfg(feature = "backend-oss")]
pub mod oss;
#[cfg(feature = "backend-registry")]
pub mod registry;
#[cfg(feature = "backend-s3")]
pub mod s3;

/// Error codes related to storage backend operations.
#[derive(Debug)]
pub enum BackendError {
    /// Unsupported operation.
    Unsupported(String),
    /// Failed to copy data from/into blob.
    CopyData(StorageError),
    #[cfg(feature = "backend-localdisk")]
    /// Error from LocalDisk storage backend.
    LocalDisk(self::localdisk::LocalDiskError),
    #[cfg(feature = "backend-registry")]
    /// Error from Registry storage backend.
    Registry(self::registry::RegistryError),
    #[cfg(feature = "backend-localfs")]
    /// Error from LocalFs storage backend.
    LocalFs(self::localfs::LocalFsError),
    #[cfg(any(feature = "backend-oss", feature = "backend-s3"))]
    /// Error from object storage backend.
    ObjectStorage(self::object_storage::ObjectStorageError),
    #[cfg(feature = "backend-http-proxy")]
    /// Error from local http proxy backend.
    HttpProxy(self::http_proxy::HttpProxyError),
}

impl fmt::Display for BackendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BackendError::Unsupported(s) => write!(f, "{}", s),
            BackendError::CopyData(e) => write!(f, "failed to copy data, {}", e),
            #[cfg(feature = "backend-registry")]
            BackendError::Registry(e) => write!(f, "{:?}", e),
            #[cfg(feature = "backend-localfs")]
            BackendError::LocalFs(e) => write!(f, "{}", e),
            #[cfg(any(feature = "backend-oss", feature = "backend-s3"))]
            BackendError::ObjectStorage(e) => write!(f, "{}", e),
            #[cfg(feature = "backend-localdisk")]
            BackendError::LocalDisk(e) => write!(f, "{:?}", e),
            #[cfg(feature = "backend-http-proxy")]
            BackendError::HttpProxy(e) => write!(f, "{}", e),
        }
    }
}

/// Specialized `Result` for storage backends.
pub type BackendResult<T> = std::result::Result<T, BackendError>;

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

        let mut delayer = Delayer::new(DelayType::BackOff, Duration::from_millis(500));

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
                        delayer.delay();
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

    /// Read as much as possible data into buffer.
    fn read_all(&self, buf: &mut [u8], offset: u64) -> BackendResult<usize> {
        let mut off = 0usize;
        let mut left = buf.len();

        while left > 0 {
            let cnt = self.read(&mut buf[off..], offset + off as u64)?;
            if cnt == 0 {
                break;
            }
            off += cnt;
            left -= cnt;
        }

        Ok(off as usize)
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
            let mut data = alloc_buf(size);

            let result = self.read(&mut data, offset)?;
            copyv(&[&data], bufs, 0, result, 0, 0)
                .map(|r| r.0)
                .map_err(BackendError::CopyData)
        }
    }

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

/// A buffered reader for `BlobReader` object.
pub struct BlobBufReader {
    buf: Vec<u8>,
    pos: usize,
    len: usize,
    start: u64,
    size: u64,
    reader: Arc<dyn BlobReader>,
}

impl BlobBufReader {
    /// Create a new instance of `BlobBufReader`.
    pub fn new(buf_size: usize, reader: Arc<dyn BlobReader>, start: u64, size: u64) -> Self {
        Self {
            buf: alloc_buf(buf_size),
            pos: 0,
            len: 0,
            start,
            size,
            reader,
        }
    }
}

impl Read for BlobBufReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut sz = self.len;
        if sz == 0 && self.size == 0 {
            // No more data.
            return Ok(0);
        }

        // Refill the buffer.
        if sz == 0 && self.size > 0 {
            let cnt = std::cmp::min(self.buf.len() as u64, self.size) as usize;
            let ret = self
                .reader
                .read(&mut self.buf[..cnt], self.start)
                .map_err(|e| eio!(format!("failed to read data from backend, {:?}", e)))?;
            self.start += ret as u64;
            self.size -= ret as u64;
            self.pos = 0;
            self.len = ret;
            sz = ret;
        }
        if self.size != 0 && sz == 0 {
            return Err(eio!("unexpected EOF when reading data from backend"));
        }

        let sz = std::cmp::min(sz, buf.len());
        buf[..sz].copy_from_slice(&self.buf[self.pos..self.pos + sz]);
        self.pos += sz;
        self.len -= sz;

        Ok(sz)
    }
}

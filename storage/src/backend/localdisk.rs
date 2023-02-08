// Copyright (C) 2022 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Storage backend driver to access blobs on local disks.

use std::collections::HashMap;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::Result;
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::sync::{Arc, RwLock};

use fuse_backend_rs::file_buf::FileVolatileSlice;
use gpt;
use nix::sys::uio;

use nydus_api::LocalDiskConfig;
use nydus_utils::metrics::BackendMetrics;

use crate::backend::{BackendError, BackendResult, BlobBackend, BlobReader};
use crate::utils::{readv, MemSliceCursor};

type LocalDiskResult<T> = std::result::Result<T, LocalDiskError>;

const LOCALDISK_BLOB_ID_LEN: usize = 32;

/// Error codes related to localdisk storage backend.
#[derive(Debug)]
pub enum LocalDiskError {
    BlobFile(String),
    ReadBlob(String),
}

impl fmt::Display for LocalDiskError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LocalDiskError::BlobFile(s) => write!(f, "{}", s),
            LocalDiskError::ReadBlob(s) => write!(f, "{}", s),
        }
    }
}

impl From<LocalDiskError> for BackendError {
    fn from(error: LocalDiskError) -> Self {
        BackendError::LocalDisk(error)
    }
}

/// Each LocalDiskPartition corresponds to a partition on the disk
#[derive(Debug)]
struct LocalDiskPartition {
    // The blob id corresponding to the partition
    blob_id: String,
    // The file descriptor of the disk
    device_fd: i32,
    // Start offset of the partition
    base_offset: u64,
    // Last offset of the partition
    last_offset: u64,
    // Length of the partition
    length: u64,
    // Metrics collector.
    metrics: Arc<BackendMetrics>,
}

impl BlobReader for LocalDiskPartition {
    fn blob_size(&self) -> BackendResult<u64> {
        Ok(self.length)
    }

    fn try_read(&self, buf: &mut [u8], offset: u64) -> BackendResult<usize> {
        let actual_offset = self.base_offset + offset;

        debug!(
            "localdisk blob reading: offset={}, size={}, from={}",
            actual_offset,
            buf.len(),
            self.blob_id,
        );

        uio::pread(self.device_fd, buf, actual_offset as i64).map_err(|e| {
            let msg = format!("failed to read data from blob {}, {}", self.blob_id, e);
            LocalDiskError::ReadBlob(msg).into()
        })
    }

    fn readv(
        &self,
        bufs: &[FileVolatileSlice],
        offset: u64,
        max_size: usize,
    ) -> BackendResult<usize> {
        let mut c = MemSliceCursor::new(bufs);
        let mut iovec = c.consume(max_size);

        let actual_offset = self.base_offset + offset;

        let mut len = 0;
        for buf in bufs {
            len += buf.len();
        }

        // Guarantees that reads do not exceed the size of the blob
        if len as u64 > self.length {
            let msg = format!(
                "failed to read data from blob {}, this read exceeds the blob size",
                self.blob_id
            );
            return Err(LocalDiskError::ReadBlob(msg).into());
        }

        readv(self.device_fd, &mut iovec, actual_offset).map_err(|e| {
            let msg = format!("failed to read data from blob {}, {}", self.blob_id, e);
            LocalDiskError::ReadBlob(msg).into()
        })
    }

    fn metrics(&self) -> &BackendMetrics {
        &self.metrics
    }
}

/// Storage backend based on local disk.
pub struct LocalDisk {
    // A reference to an open device
    device_file: File,
    // The disk device path specified by the user
    device_path: String,
    // Metrics collector.
    metrics: Arc<BackendMetrics>,
    // Hashmap to map blob id to disk entry.
    entries: RwLock<HashMap<String, Arc<LocalDiskPartition>>>,
}

impl LocalDisk {
    pub fn new(config: &LocalDiskConfig, id: Option<&str>) -> Result<LocalDisk> {
        let id = id.ok_or_else(|| einval!("LocalDisk requires blob_id"))?;
        let path = config.device_path.clone();

        if path.is_empty() {
            error!("device path is required");
            return Err(einval!("device path is required"));
        }

        let path_buf = Path::new(&path).to_path_buf().canonicalize().map_err(|e| {
            error!("failed to parse path {}: {:?}", path, e);
            LocalDiskError::BlobFile(format!("invalid file path {}, {}", path, e));
            e
        })?;

        let file = OpenOptions::new().read(true).open(&path_buf).map_err(|e| {
            error!("failed to open localdisk image at {}: {:?}", path, e);
            LocalDiskError::BlobFile(format!("failed to open localdisk image at {}, {}", path, e));
            e
        })?;

        let local_disk = LocalDisk {
            device_file: file,
            device_path: path.clone(),
            metrics: BackendMetrics::new(id, "localdisk"),
            entries: RwLock::new(HashMap::new()),
        };

        local_disk.init().map_err(|e| {
            error!("load localdisk image failed at {}: {:?}", path, e);
            LocalDiskError::BlobFile(format!("load localdisk image failed at {}: {}", path, e));
            e
        })?;

        Ok(local_disk)
    }

    pub fn init(&self) -> Result<()> {
        let mut table_guard = self.entries.write().unwrap();

        // Open disk image.
        let cfg = gpt::GptConfig::new().writable(false);
        let disk = cfg.open(self.device_path.clone())?;
        let partitions = disk.partitions();
        let sector_size = gpt::disk::DEFAULT_SECTOR_SIZE;
        info!(
            "Localdisk backend initialized at {}, has {} patitions, GUID: {}",
            self.device_path,
            partitions.len(),
            disk.guid()
        );

        for (k, v) in partitions {
            let length = v.bytes_len(sector_size)?;
            let base_offset = v.bytes_start(sector_size)?;
            if base_offset.checked_add(length).is_none() {
                let msg = format!("partition {} ends with an invalid offset", v.part_guid);
                return Err(eio!(msg));
            };
            let last_offset = base_offset + length;
            let guid = v.part_guid;
            let name = if v.part_type_guid == gpt::partition_types::BASIC {
                v.name.clone() // Compatible with old versions of localdisk image
            } else {
                v.name.clone() + guid.to_simple().to_string().as_str() // The 64-byte blob_id is stored in two parts
            };

            if name.is_empty() {
                let msg = format!("partition {} does not record an blob id", v.part_guid);
                return Err(eio!(msg));
            }

            let partition = Arc::new(LocalDiskPartition {
                blob_id: name.clone(),
                device_fd: self.device_file.as_raw_fd(),
                base_offset,
                last_offset,
                length,
                metrics: self.metrics.clone(),
            });

            debug!(
                "Localdisk partition {} initialized, blob id: {}, offset from {} to {}, length {}",
                k,
                partition.blob_id,
                partition.base_offset,
                partition.last_offset,
                partition.length
            );
            table_guard.insert(name, partition);
        }

        Ok(())
    }

    // Disk names in GPT tables cannot store full 64-byte blob ids, so we should truncate them to 32 bytes.
    fn truncate_blob_id(blob_id: &str) -> LocalDiskResult<&str> {
        if blob_id.len() >= LOCALDISK_BLOB_ID_LEN {
            let new_blob_id = &blob_id[0..LOCALDISK_BLOB_ID_LEN];
            Ok(new_blob_id)
        } else {
            let msg = format!("invalid blob_id: {}", blob_id);
            Err(LocalDiskError::BlobFile(msg))
        }
    }

    #[allow(clippy::mutex_atomic)]
    fn get_blob(&self, blob_id: &str) -> LocalDiskResult<Arc<dyn BlobReader>> {
        // Try to read the full length blob_id from the hashMap, if that doesn't work, read the older version's truncated blob_id.
        let localdisk_blob_id = if self.entries.read().unwrap().contains_key(blob_id) {
            blob_id
        } else {
            LocalDisk::truncate_blob_id(blob_id)?
        };

        // Don't expect poisoned lock here.
        if let Some(entry) = self.entries.read().unwrap().get(localdisk_blob_id) {
            Ok(entry.clone())
        } else {
            let msg = format!(
                "can not find such blob: {}, this image might be corrupted",
                blob_id
            );
            Err(LocalDiskError::ReadBlob(msg))
        }
    }
}

impl BlobBackend for LocalDisk {
    fn shutdown(&self) {}

    fn metrics(&self) -> &BackendMetrics {
        &self.metrics
    }

    fn get_reader(&self, blob_id: &str) -> BackendResult<Arc<dyn BlobReader>> {
        self.get_blob(blob_id).map_err(|e| e.into())
    }
}

impl Drop for LocalDisk {
    fn drop(&mut self) {
        self.metrics.release().unwrap_or_else(|e| error!("{:?}", e));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_invalid_localdisk_new() {
        let config = LocalDiskConfig {
            device_path: "".to_string(),
        };
        assert!(LocalDisk::new(&config, Some("test")).is_err());

        let config = LocalDiskConfig {
            device_path: "/a/b/c".to_string(),
        };
        assert!(LocalDisk::new(&config, None).is_err());
    }

    #[test]
    fn test_truncate_blob_id() {
        let guid = "50ad3c8243e0a08ecdebde0ef8afcc6f2abca44498ad15491acbe58c83acb66f";
        let guid_truncated = "50ad3c8243e0a08ecdebde0ef8afcc6f";

        let result = LocalDisk::truncate_blob_id(guid).unwrap();
        assert_eq!(result, guid_truncated)
    }
}

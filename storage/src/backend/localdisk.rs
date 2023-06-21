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
use nix::sys::uio;
use nydus_api::LocalDiskConfig;
use nydus_utils::metrics::BackendMetrics;

use crate::backend::{BackendError, BackendResult, BlobBackend, BlobReader};
use crate::utils::{readv, MemSliceCursor};

type LocalDiskResult<T> = std::result::Result<T, LocalDiskError>;

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

#[derive(Debug)]
struct LocalDiskBlob {
    // The file descriptor of the disk
    device_file: File,
    // Start offset of the partition
    blob_offset: u64,
    // Length of the partition
    blob_length: u64,
    // The identifier for the corresponding blob.
    blob_id: String,
    // Metrics collector.
    metrics: Arc<BackendMetrics>,
}

impl BlobReader for LocalDiskBlob {
    fn blob_size(&self) -> BackendResult<u64> {
        Ok(self.blob_length)
    }

    fn try_read(&self, buf: &mut [u8], offset: u64) -> BackendResult<usize> {
        let msg = format!(
            "localdisk: invalid offset 0x{:x}, base 0x{:x}, length 0x{:x}",
            offset, self.blob_offset, self.blob_length
        );
        if offset > self.blob_length {
            return Err(LocalDiskError::ReadBlob(msg).into());
        }
        let actual_offset = self
            .blob_offset
            .checked_add(offset)
            .ok_or(LocalDiskError::ReadBlob(msg))?;
        let sz = std::cmp::min(self.blob_length - offset, buf.len() as u64) as usize;

        uio::pread(
            self.device_file.as_raw_fd(),
            &mut buf[..sz],
            actual_offset as i64,
        )
        .map_err(|e| {
            let msg = format!(
                "localdisk: failed to read data from blob {}, {}",
                self.blob_id, e
            );
            LocalDiskError::ReadBlob(msg).into()
        })
    }

    fn readv(
        &self,
        bufs: &[FileVolatileSlice],
        offset: u64,
        max_size: usize,
    ) -> BackendResult<usize> {
        let msg = format!(
            "localdisk: invalid offset 0x{:x}, base 0x{:x}, length 0x{:x}",
            offset, self.blob_offset, self.blob_length
        );
        if offset > self.blob_length {
            return Err(LocalDiskError::ReadBlob(msg).into());
        }
        let actual_offset = self
            .blob_offset
            .checked_add(offset)
            .ok_or(LocalDiskError::ReadBlob(msg))?;

        let mut c = MemSliceCursor::new(bufs);
        let mut iovec = c.consume(max_size);
        let mut len = 0;
        for buf in bufs {
            len += buf.len();
        }

        // Guarantees that reads do not exceed the size of the blob
        if offset.checked_add(len as u64).is_none() || offset + len as u64 > self.blob_length {
            let msg = format!(
                "localdisk: invalid offset 0x{:x}, base 0x{:x}, length 0x{:x}",
                offset, self.blob_offset, self.blob_length
            );
            return Err(LocalDiskError::ReadBlob(msg).into());
        }

        readv(self.device_file.as_raw_fd(), &mut iovec, actual_offset).map_err(|e| {
            let msg = format!(
                "localdisk: failed to read data from blob {}, {}",
                self.blob_id, e
            );
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
    // Blobs are discovered by scanning GPT or not.
    is_gpt_mode: bool,
    // Metrics collector.
    metrics: Arc<BackendMetrics>,
    // Hashmap to map blob id to disk entry.
    entries: RwLock<HashMap<String, Arc<LocalDiskBlob>>>,
}

impl LocalDisk {
    pub fn new(config: &LocalDiskConfig, id: Option<&str>) -> Result<LocalDisk> {
        let id = id.ok_or_else(|| einval!("localDisk: argument `id` is empty"))?;
        let path = &config.device_path;
        let path_buf = Path::new(path).to_path_buf().canonicalize().map_err(|e| {
            einval!(format!(
                "localdisk: invalid disk device path {}, {}",
                path, e
            ))
        })?;
        let device_file = OpenOptions::new().read(true).open(&path_buf).map_err(|e| {
            einval!(format!(
                "localdisk: can not open disk device at {}, {}",
                path, e
            ))
        })?;
        let mut local_disk = LocalDisk {
            device_file,
            device_path: path.clone(),
            is_gpt_mode: false,
            metrics: BackendMetrics::new(id, "localdisk"),
            entries: RwLock::new(HashMap::new()),
        };

        local_disk.scan_blobs_by_gpt()?;

        Ok(local_disk)
    }

    fn get_blob(&self, blob_id: &str) -> LocalDiskResult<Arc<dyn BlobReader>> {
        // Don't expect poisoned lock here.
        if let Some(entry) = self.entries.read().unwrap().get(blob_id) {
            Ok(entry.clone())
        } else {
            self.search_blob_from_gpt(blob_id)
        }
    }
}

#[cfg(feature = "backend-localdisk-gpt")]
impl LocalDisk {
    // Disk names in GPT tables cannot store full 64-byte blob ids, so we should truncate them to 32 bytes.
    fn truncate_blob_id(blob_id: &str) -> Option<&str> {
        const LOCALDISK_BLOB_ID_LEN: usize = 32;
        if blob_id.len() >= LOCALDISK_BLOB_ID_LEN {
            let new_blob_id = &blob_id[0..LOCALDISK_BLOB_ID_LEN];
            Some(new_blob_id)
        } else {
            None
        }
    }

    fn search_blob_from_gpt(&self, blob_id: &str) -> LocalDiskResult<Arc<dyn BlobReader>> {
        if self.is_gpt_mode {
            if let Some(localdisk_blob_id) = LocalDisk::truncate_blob_id(blob_id) {
                // Don't expect poisoned lock here.
                if let Some(entry) = self.entries.read().unwrap().get(localdisk_blob_id) {
                    return Ok(entry.clone());
                }
            }
        }

        let msg = format!("localdisk: can not find such blob: {}", blob_id);
        Err(LocalDiskError::ReadBlob(msg))
    }

    fn scan_blobs_by_gpt(&mut self) -> Result<()> {
        // Open disk image.
        let cfg = gpt::GptConfig::new().writable(false);
        let disk = cfg.open(&self.device_path)?;
        let partitions = disk.partitions();
        let sector_size = gpt::disk::DEFAULT_SECTOR_SIZE;
        info!(
            "Localdisk initializing storage backend for device {} with {} partitions, GUID: {}",
            self.device_path,
            partitions.len(),
            disk.guid()
        );

        let mut table_guard = self.entries.write().unwrap();
        for (k, v) in partitions {
            let length = v.bytes_len(sector_size)?;
            let base_offset = v.bytes_start(sector_size)?;
            if base_offset.checked_add(length).is_none() {
                let msg = format!(
                    "localdisk: partition {} with invalid offset and length",
                    v.part_guid
                );
                return Err(einval!(msg));
            };
            let guid = v.part_guid;
            let mut is_gpt_mode = false;
            let name = if v.part_type_guid == gpt::partition_types::BASIC {
                is_gpt_mode = true;
                // Compatible with old versions of localdisk image
                v.name.clone()
            } else {
                // The 64-byte blob_id is stored in two parts
                v.name.clone() + guid.to_simple().to_string().as_str()
            };

            if name.is_empty() {
                let msg = format!("localdisk: partition {} has empty blob id", v.part_guid);
                return Err(einval!(msg));
            }

            let device_file = self.device_file.try_clone()?;
            let partition = Arc::new(LocalDiskBlob {
                blob_id: name.clone(),
                device_file,
                blob_offset: base_offset,
                blob_length: length,
                metrics: self.metrics.clone(),
            });

            debug!(
                "Localdisk partition {} initialized, blob id: {}, offset {}, length {}",
                k, partition.blob_id, partition.blob_offset, partition.blob_length
            );
            table_guard.insert(name, partition);
            if is_gpt_mode {
                self.is_gpt_mode = true;
            }
        }

        Ok(())
    }
}

#[cfg(not(feature = "backend-localdisk-gpt"))]
impl LocalDisk {
    fn search_blob_from_gpt(&self, blob_id: &str) -> LocalDiskResult<Arc<dyn BlobReader>> {
        Err(LocalDiskError::ReadBlob(format!(
            "can not find such blob: {}, this image might be corrupted",
            blob_id
        )))
    }

    fn scan_blobs_by_gpt(&mut self) -> Result<()> {
        Ok(())
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

    #[cfg(feature = "backend-localdisk-gpt")]
    #[test]
    fn test_truncate_blob_id() {
        let guid = "50ad3c8243e0a08ecdebde0ef8afcc6f2abca44498ad15491acbe58c83acb66f";
        let guid_truncated = "50ad3c8243e0a08ecdebde0ef8afcc6f";

        let result = LocalDisk::truncate_blob_id(guid).unwrap();
        assert_eq!(result, guid_truncated)
    }
}

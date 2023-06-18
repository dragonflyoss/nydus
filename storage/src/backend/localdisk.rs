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
        if offset >= self.blob_length {
            return Ok(0);
        }
        let actual_offset = self
            .blob_offset
            .checked_add(offset)
            .ok_or(LocalDiskError::ReadBlob(msg))?;
        let len = std::cmp::min(self.blob_length - offset, buf.len() as u64) as usize;

        uio::pread(
            self.device_file.as_raw_fd(),
            &mut buf[..len],
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
        if offset >= self.blob_length {
            return Ok(0);
        }
        let actual_offset = self
            .blob_offset
            .checked_add(offset)
            .ok_or(LocalDiskError::ReadBlob(msg.clone()))?;

        let mut c = MemSliceCursor::new(bufs);
        let mut iovec = c.consume(max_size);
        let mut len = 0;
        for buf in bufs {
            len += buf.len();
        }

        // Guarantees that reads do not exceed the size of the blob
        if offset.checked_add(len as u64).is_none() || offset + len as u64 > self.blob_length {
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
    // Size of the block device.
    device_capacity: u64,
    // Blobs are discovered by scanning GPT or not.
    is_gpt_mode: bool,
    // Metrics collector.
    metrics: Arc<BackendMetrics>,
    // Hashmap to map blob id to disk entry.
    entries: RwLock<HashMap<String, Arc<LocalDiskBlob>>>,
}

impl LocalDisk {
    pub fn new(config: &LocalDiskConfig, id: Option<&str>) -> Result<LocalDisk> {
        let id = id.ok_or_else(|| einval!("localdisk: argument `id` is empty"))?;
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
        let md = device_file.metadata().map_err(|e| {
            eio!(format!(
                "localdisk: can not get file meta data about disk device {}, {}",
                path, e
            ))
        })?;
        let mut local_disk = LocalDisk {
            device_file,
            device_path: path.clone(),
            device_capacity: md.len(),
            is_gpt_mode: false,
            metrics: BackendMetrics::new(id, "localdisk"),
            entries: RwLock::new(HashMap::new()),
        };

        if !config.disable_gpt {
            local_disk.scan_blobs_by_gpt()?;
        }

        Ok(local_disk)
    }

    pub fn add_blob(&self, blob_id: &str, offset: u64, length: u64) -> LocalDiskResult<()> {
        if self.is_gpt_mode {
            let msg = format!(
                "localdisk: device {} is in legacy gpt mode",
                self.device_path
            );
            return Err(LocalDiskError::BlobFile(msg));
        }
        if offset.checked_add(length).is_none() || offset + length > self.device_capacity {
            let msg = format!(
                "localdisk: add blob {} with invalid offset 0x{:x} and length 0x{:x}, device size 0x{:x}",
                blob_id, offset, length, self.device_capacity
            );
            return Err(LocalDiskError::BlobFile(msg));
        };

        let device_file = self.device_file.try_clone().map_err(|e| {
            LocalDiskError::BlobFile(format!("localdisk: can not duplicate file, {}", e))
        })?;
        let blob = Arc::new(LocalDiskBlob {
            blob_id: blob_id.to_string(),
            device_file,
            blob_offset: offset,
            blob_length: length,
            metrics: self.metrics.clone(),
        });

        let mut table_guard = self.entries.write().unwrap();
        if table_guard.contains_key(blob_id) {
            let msg = format!("localdisk: blob {} already exists", blob_id);
            return Err(LocalDiskError::BlobFile(msg));
        }
        table_guard.insert(blob_id.to_string(), blob);

        Ok(())
    }

    fn get_blob(&self, blob_id: &str) -> LocalDiskResult<Arc<dyn BlobReader>> {
        // Don't expect poisoned lock here.
        if let Some(entry) = self.entries.read().unwrap().get(blob_id) {
            Ok(entry.clone())
        } else {
            self.get_blob_from_gpt(blob_id)
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

    fn get_blob_from_gpt(&self, blob_id: &str) -> LocalDiskResult<Arc<dyn BlobReader>> {
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
            if base_offset.checked_add(length).is_none()
                || base_offset + length > self.device_capacity
            {
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
            if table_guard.contains_key(&name) {
                let msg = format!("localdisk: blob {} already exists", name);
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
    fn get_blob_from_gpt(&self, blob_id: &str) -> LocalDiskResult<Arc<dyn BlobReader>> {
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
            disable_gpt: true,
        };
        assert!(LocalDisk::new(&config, Some("test")).is_err());

        let config = LocalDiskConfig {
            device_path: "/a/b/c".to_string(),
            disable_gpt: true,
        };
        assert!(LocalDisk::new(&config, None).is_err());
    }

    #[test]
    fn test_add_disk_blob() {
        let root_dir = &std::env::var("CARGO_MANIFEST_DIR").expect("$CARGO_MANIFEST_DIR");
        let root_dir = Path::new(root_dir).join("../tests/texture/blobs/");

        let config = LocalDiskConfig {
            device_path: root_dir.join("nonexist_blob_file").display().to_string(),
            disable_gpt: true,
        };
        assert!(LocalDisk::new(&config, Some("test")).is_err());

        let blob_id = "be7d77eeb719f70884758d1aa800ed0fb09d701aaec469964e9d54325f0d5fef";
        let config = LocalDiskConfig {
            device_path: root_dir.join(blob_id).display().to_string(),
            disable_gpt: true,
        };
        let disk = LocalDisk::new(&config, Some("test")).unwrap();

        assert!(disk.add_blob(blob_id, u64::MAX, 1).is_err());
        assert!(disk.add_blob(blob_id, 14553, 2).is_err());
        assert!(disk.add_blob(blob_id, 14554, 1).is_err());
        assert!(disk.add_blob(blob_id, 0, 4096).is_ok());
        assert!(disk.add_blob(blob_id, 0, 4096).is_err());
        let blob = disk.get_blob(blob_id).unwrap();
        assert_eq!(blob.blob_size().unwrap(), 4096);

        let mut buf = vec![0u8; 4096];
        let sz = blob.read(&mut buf, 0).unwrap();
        assert_eq!(sz, 4096);
        let sz = blob.read(&mut buf, 4095).unwrap();
        assert_eq!(sz, 1);
        let sz = blob.read(&mut buf, 4096).unwrap();
        assert_eq!(sz, 0);
        let sz = blob.read(&mut buf, 4097).unwrap();
        assert_eq!(sz, 0);
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

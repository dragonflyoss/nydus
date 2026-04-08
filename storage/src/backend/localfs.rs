// Copyright (C) 2020-2021 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Storage backend driver to access blobs on local filesystems.

use std::collections::HashMap;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::Result;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use fuse_backend_rs::file_buf::FileVolatileSlice;
use nix::sys::uio;

use nydus_api::LocalFsConfig;
use nydus_utils::metrics::BackendMetrics;

use crate::backend::{BackendError, BackendResult, BlobBackend, BlobReader};
use crate::utils::{readv, MemSliceCursor};

type LocalFsResult<T> = std::result::Result<T, LocalFsError>;

/// Error codes related to localfs storage backend.
#[derive(Debug)]
pub enum LocalFsError {
    BlobFile(String),
    ReadBlob(String),
}

impl fmt::Display for LocalFsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LocalFsError::BlobFile(s) => write!(f, "{}", s),
            LocalFsError::ReadBlob(s) => write!(f, "{}", s),
        }
    }
}

impl From<LocalFsError> for BackendError {
    fn from(error: LocalFsError) -> Self {
        BackendError::LocalFs(error)
    }
}

struct LocalFsEntry {
    id: String,
    file: File,
    metrics: Arc<BackendMetrics>,
}

impl BlobReader for LocalFsEntry {
    fn blob_size(&self) -> BackendResult<u64> {
        self.file.metadata().map(|v| v.len()).map_err(|e| {
            let msg = format!("failed to get size of localfs blob {}, {}", self.id, e);
            LocalFsError::BlobFile(msg).into()
        })
    }

    fn expect_exact_read(&self) -> bool {
        false
    }

    fn try_read(&self, buf: &mut [u8], offset: u64) -> BackendResult<usize> {
        uio::pread(self.file.as_raw_fd(), buf, offset as i64).map_err(|e| {
            let msg = format!("failed to read data from blob {}, {}", self.id, e);
            LocalFsError::ReadBlob(msg).into()
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

        readv(self.file.as_raw_fd(), &mut iovec, offset).map_err(|e| {
            let msg = format!("failed to read data from blob {}, {}", self.id, e);
            LocalFsError::ReadBlob(msg).into()
        })
    }

    fn metrics(&self) -> &BackendMetrics {
        &self.metrics
    }
}

/// Storage backend based on local filesystem.
#[derive(Default)]
pub struct LocalFs {
    // The blob file specified by the user.
    blob_file: String,
    // Directory to store blob files. If `blob_file` is not specified, `dir`/`blob_id` will be used
    // as the blob file name.
    dir: String,
    // Alternative directories to store blob files
    alt_dirs: Vec<String>,
    // Metrics collector.
    metrics: Arc<BackendMetrics>,
    // Hashmap to map blob id to blob file.
    entries: RwLock<HashMap<String, Arc<LocalFsEntry>>>,
}

impl LocalFs {
    pub fn new(config: &LocalFsConfig, id: Option<&str>) -> Result<LocalFs> {
        let id = id.ok_or_else(|| einval!("LocalFs requires blob_id"))?;

        if config.blob_file.is_empty() && config.dir.is_empty() {
            return Err(einval!("blob file or dir is required"));
        }

        Ok(LocalFs {
            blob_file: config.blob_file.clone(),
            dir: config.dir.clone(),
            alt_dirs: config.alt_dirs.clone(),
            metrics: BackendMetrics::new(id, "localfs"),
            entries: RwLock::new(HashMap::new()),
        })
    }

    // Use the user specified blob file name if available, otherwise generate the file name by
    // concatenating `dir` and `blob_id`.
    fn get_blob_path(&self, blob_id: &str) -> LocalFsResult<PathBuf> {
        let path = if !self.blob_file.is_empty() {
            Path::new(&self.blob_file).to_path_buf()
        } else {
            // Search blob file in dir and additionally in alt_dirs
            let is_valid = |dir: &PathBuf| -> bool {
                let blob = Path::new(&dir).join(blob_id);
                if let Ok(meta) = std::fs::metadata(blob) {
                    meta.len() != 0
                } else {
                    false
                }
            };

            let blob = Path::new(&self.dir).join(blob_id);
            if is_valid(&blob) || self.alt_dirs.is_empty() {
                blob
            } else {
                let mut file = PathBuf::new();
                for dir in &self.alt_dirs {
                    file = Path::new(dir).join(blob_id);
                    if is_valid(&file) {
                        break;
                    }
                }
                file
            }
        };

        path.canonicalize().map_err(|e| {
            LocalFsError::BlobFile(format!("invalid file path {}, {}", path.display(), e))
        })
    }

    #[allow(clippy::mutex_atomic)]
    fn get_blob(&self, blob_id: &str) -> LocalFsResult<Arc<dyn BlobReader>> {
        // Don't expect poisoned lock here.
        if let Some(entry) = self.entries.read().unwrap().get(blob_id) {
            return Ok(entry.clone());
        }

        let blob_file_path = self.get_blob_path(blob_id)?;
        let file = OpenOptions::new()
            .read(true)
            .open(&blob_file_path)
            .map_err(|e| {
                let msg = format!(
                    "failed to open blob file {}, {}",
                    blob_file_path.display(),
                    e
                );
                LocalFsError::BlobFile(msg)
            })?;
        // Don't expect poisoned lock here.
        let mut table_guard = self.entries.write().unwrap();
        if let Some(entry) = table_guard.get(blob_id) {
            Ok(entry.clone())
        } else {
            let entry = Arc::new(LocalFsEntry {
                id: blob_id.to_owned(),
                file,
                metrics: self.metrics.clone(),
            });
            table_guard.insert(blob_id.to_string(), entry.clone());
            Ok(entry)
        }
    }
}

impl BlobBackend for LocalFs {
    fn shutdown(&self) {}

    fn metrics(&self) -> &BackendMetrics {
        &self.metrics
    }

    fn get_reader(&self, blob_id: &str) -> BackendResult<Arc<dyn BlobReader>> {
        self.get_blob(blob_id).map_err(|e| e.into())
    }
}

impl Drop for LocalFs {
    fn drop(&mut self) {
        self.metrics.release().unwrap_or_else(|e| error!("{:?}", e));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;
    use std::os::unix::io::{FromRawFd, IntoRawFd};
    use vmm_sys_util::{tempdir::TempDir, tempfile::TempFile};

    fn new_localfs(
        dir: &Path,
        blob_file: Option<&Path>,
        alt_dirs: Vec<&Path>,
        id: &str,
    ) -> LocalFs {
        let config = LocalFsConfig {
            blob_file: blob_file
                .map(|path| path.to_str().unwrap().to_owned())
                .unwrap_or_default(),
            dir: dir.to_str().unwrap().to_owned(),
            alt_dirs: alt_dirs
                .into_iter()
                .map(|path| path.to_str().unwrap().to_owned())
                .collect(),
        };

        LocalFs::new(&config, Some(id)).unwrap()
    }

    fn write_blob(path: &Path, data: &[u8]) {
        fs::write(path, data).unwrap();
    }

    #[test]
    fn test_invalid_localfs_new() {
        let config = LocalFsConfig {
            blob_file: "".to_string(),
            dir: "".to_string(),
            alt_dirs: Vec::new(),
        };
        assert!(LocalFs::new(&config, Some("test")).is_err());

        let config = LocalFsConfig {
            blob_file: "/a/b/c".to_string(),
            dir: "/a/b".to_string(),
            alt_dirs: Vec::new(),
        };
        assert!(LocalFs::new(&config, None).is_err());
    }

    #[test]
    fn test_localfs_get_blob_path() {
        let config = LocalFsConfig {
            blob_file: "/a/b/cxxxxxxxxxxxxxxxxxxxxxxx".to_string(),
            dir: "/a/b".to_string(),
            alt_dirs: Vec::new(),
        };
        let fs = LocalFs::new(&config, Some("test")).unwrap();
        assert!(fs.get_blob_path("test").is_err());

        let tempfile = TempFile::new().unwrap();
        let path = tempfile.as_path();
        let filename = path.file_name().unwrap().to_str().unwrap();

        let config = LocalFsConfig {
            blob_file: path.to_str().unwrap().to_owned(),
            dir: path.parent().unwrap().to_str().unwrap().to_owned(),
            alt_dirs: Vec::new(),
        };
        let fs = LocalFs::new(&config, Some("test")).unwrap();
        assert_eq!(fs.get_blob_path("test").unwrap().to_str(), path.to_str());

        let config = LocalFsConfig {
            blob_file: "".to_string(),
            dir: path.parent().unwrap().to_str().unwrap().to_owned(),
            alt_dirs: Vec::new(),
        };
        let fs = LocalFs::new(&config, Some(filename)).unwrap();
        assert_eq!(fs.get_blob_path(filename).unwrap().to_str(), path.to_str());

        let config = LocalFsConfig {
            blob_file: "".to_string(),
            dir: "/a/b".to_string(),
            alt_dirs: vec![
                "/test".to_string(),
                path.parent().unwrap().to_str().unwrap().to_owned(),
            ],
        };
        let fs = LocalFs::new(&config, Some(filename)).unwrap();
        assert_eq!(fs.get_blob_path(filename).unwrap().to_str(), path.to_str());
    }

    #[test]
    fn test_localfs_get_blob_path_skips_zero_byte_alt_dirs() {
        let main_dir = TempDir::new().unwrap();
        let zero_alt_dir = TempDir::new().unwrap();
        let valid_alt_dir = TempDir::new().unwrap();
        let blob_id = "blob-alt-skip";

        write_blob(&main_dir.as_path().join(blob_id), &[]);
        write_blob(&zero_alt_dir.as_path().join(blob_id), &[]);
        write_blob(&valid_alt_dir.as_path().join(blob_id), b"nydus");

        let fs = new_localfs(
            main_dir.as_path(),
            None,
            vec![zero_alt_dir.as_path(), valid_alt_dir.as_path()],
            blob_id,
        );

        assert_eq!(
            fs.get_blob_path(blob_id).unwrap(),
            valid_alt_dir
                .as_path()
                .join(blob_id)
                .canonicalize()
                .unwrap()
        );
    }

    #[test]
    fn test_localfs_get_blob_path_prefers_blob_file_over_dirs() {
        let dir = TempDir::new().unwrap();
        let blob_file = TempFile::new().unwrap();
        let blob_id = "blob-priority";
        let dir_blob = dir.as_path().join(blob_id);

        write_blob(blob_file.as_path(), b"blob-file");
        write_blob(&dir_blob, b"dir-file");

        let fs = new_localfs(
            dir.as_path(),
            Some(blob_file.as_path()),
            Vec::new(),
            blob_id,
        );

        assert_eq!(
            fs.get_blob_path(blob_id).unwrap(),
            blob_file.as_path().canonicalize().unwrap()
        );

        let blob = fs.get_reader(blob_id).unwrap();
        let mut buf = [0u8; 9];
        assert_eq!(blob.read(&mut buf, 0).unwrap(), 9);
        assert_eq!(&buf, b"blob-file");
    }

    #[test]
    fn test_localfs_get_blob_path_errors_when_all_dirs_miss() {
        let main_dir = TempDir::new().unwrap();
        let alt_dir_1 = TempDir::new().unwrap();
        let alt_dir_2 = TempDir::new().unwrap();
        let blob_id = "blob-miss";

        let fs = new_localfs(
            main_dir.as_path(),
            None,
            vec![alt_dir_1.as_path(), alt_dir_2.as_path()],
            blob_id,
        );

        assert!(fs.get_blob_path(blob_id).is_err());
        assert!(fs.get_blob(blob_id).is_err());
    }

    #[test]
    fn test_localfs_get_blob() {
        let tempfile = TempFile::new().unwrap();
        let path = tempfile.as_path();
        let filename = path.file_name().unwrap().to_str().unwrap();
        let config = LocalFsConfig {
            blob_file: "".to_string(),
            dir: path.parent().unwrap().to_str().unwrap().to_owned(),
            alt_dirs: Vec::new(),
        };
        let fs = LocalFs::new(&config, Some(filename)).unwrap();
        let blob1 = fs.get_blob(filename).unwrap();
        let blob2 = fs.get_blob(filename).unwrap();
        assert_eq!(Arc::strong_count(&blob1), 3);
        assert_eq!(Arc::strong_count(&blob2), 3);
    }

    #[test]
    fn test_localfs_get_reader() {
        let tempfile = TempFile::new().unwrap();
        let path = tempfile.as_path();
        let filename = path.file_name().unwrap().to_str().unwrap();

        {
            let mut file = unsafe { File::from_raw_fd(tempfile.as_file().as_raw_fd()) };
            file.write_all(&[0x1u8, 0x2, 0x3, 0x4]).unwrap();
            let _ = file.into_raw_fd();
        }

        let config = LocalFsConfig {
            blob_file: "".to_string(),
            dir: path.parent().unwrap().to_str().unwrap().to_owned(),
            alt_dirs: Vec::new(),
        };
        let fs = LocalFs::new(&config, Some(filename)).unwrap();
        let blob1 = fs.get_reader(filename).unwrap();
        let blob2 = fs.get_reader(filename).unwrap();
        assert_eq!(Arc::strong_count(&blob1), 3);

        let mut buf1 = [0x0u8];
        blob1.read(&mut buf1, 0x0).unwrap();
        assert_eq!(buf1[0], 0x1);

        let mut buf2 = [0x0u8];
        let mut buf3 = [0x0u8];
        let bufs = [
            unsafe { FileVolatileSlice::from_raw_ptr(buf2.as_mut_ptr(), buf2.len()) },
            unsafe { FileVolatileSlice::from_raw_ptr(buf3.as_mut_ptr(), buf3.len()) },
        ];

        assert_eq!(blob2.readv(&bufs, 0x1, 2).unwrap(), 2);
        assert_eq!(buf2[0], 0x2);
        assert_eq!(buf3[0], 0x3);

        assert_eq!(blob2.readv(&bufs, 0x3, 3).unwrap(), 1);
        assert_eq!(buf2[0], 0x4);
        assert_eq!(buf3[0], 0x3);

        assert_eq!(blob2.blob_size().unwrap(), 4);
        let blob4 = fs.get_blob(filename).unwrap();
        assert_eq!(blob4.blob_size().unwrap(), 4);
    }

    #[test]
    fn test_localfs_reader_handles_empty_requests_and_eof() {
        let tempfile = TempFile::new().unwrap();
        let path = tempfile.as_path();
        let filename = path.file_name().unwrap().to_str().unwrap();

        write_blob(path, b"data");

        let fs = new_localfs(path.parent().unwrap(), None, Vec::new(), filename);
        let blob = fs.get_reader(filename).unwrap();

        let mut empty = [];
        assert_eq!(blob.read(&mut empty, 0).unwrap(), 0);

        let mut eof_buf = [0u8; 2];
        assert_eq!(blob.read(&mut eof_buf, 4).unwrap(), 0);
        assert_eq!(eof_buf, [0u8; 2]);

        let mut readv_buf = [0xabu8; 2];
        let bufs =
            [unsafe { FileVolatileSlice::from_raw_ptr(readv_buf.as_mut_ptr(), readv_buf.len()) }];
        assert_eq!(blob.readv(&bufs, 0, 0).unwrap(), 0);
        assert_eq!(readv_buf, [0xab, 0xab]);
    }
}

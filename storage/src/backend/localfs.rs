// Copyright (C) 2020-2021 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Storage backend driver to access blobs on local filesystems.

#[cfg(target_os = "macos")]
use libc::{fcntl, radvisory};
use std::collections::HashMap;
use std::fs::{remove_file, File, OpenOptions};
use std::io::{Error, Result};
use std::mem::{size_of, ManuallyDrop};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, RwLock};
use std::thread;
use std::time::Duration;

use fuse_backend_rs::transport::FileVolatileSlice;
use nix::sys::uio;
use nydus_utils::{metrics::BackendMetrics, round_down_4k, try_round_up_4k};

use crate::backend::{BackendError, BackendResult, BlobBackend, BlobReader};
use crate::utils::{readahead, readv, MemSliceCursor};

const BLOB_ACCESSED_SUFFIX: &str = ".access";
const BLOB_ACCESS_RECORD_SECOND: u32 = 10;

// Each access record takes 16 bytes: u64 + u32 + u32
// So we allow 2048 entries at most to avoid hurting backend upon flush
const ACCESS_RECORD_ENTRY_SIZE: usize = size_of::<u64>() + size_of::<u32>() + size_of::<u32>();
const MAX_ACCESS_RECORD_FILE_SIZE: usize = 32768;
const MAX_ACCESS_RECORD: usize = MAX_ACCESS_RECORD_FILE_SIZE / ACCESS_RECORD_ENTRY_SIZE;

type LocalFsResult<T> = std::result::Result<T, LocalFsError>;
type AccessLogEntry = (u64, u32, u32);

/// Error codes related to localfs storage backend.
#[derive(Debug)]
pub enum LocalFsError {
    BlobFile(Error),
    ReadVecBlob(Error),
    ReadBlob(nix::Error),
    CopyData(Error),
    Readahead(Error),
    AccessLog(Error),
}

impl From<LocalFsError> for BackendError {
    fn from(error: LocalFsError) -> Self {
        BackendError::LocalFs(error)
    }
}

fn default_readahead_sec() -> u32 {
    BLOB_ACCESS_RECORD_SECOND
}

/// Configuration information for localfs storage backend.
#[derive(Clone, Deserialize, Serialize)]
struct LocalFsConfig {
    #[serde(default)]
    readahead: bool,
    #[serde(default = "default_readahead_sec")]
    readahead_sec: u32,
    #[serde(default)]
    blob_file: String,
    #[serde(default)]
    dir: String,
    #[serde(default)]
    alt_dirs: Vec<String>,
}

struct LocalFsEntry {
    id: String,
    path: PathBuf,
    file: File,
    metrics: Arc<BackendMetrics>,
    readahead: bool,
    trace: Arc<LocalFsTracer>,
    trace_sec: u32,
    trace_condvar: Arc<(Mutex<bool>, Condvar)>,
}

impl BlobReader for LocalFsEntry {
    fn blob_size(&self) -> BackendResult<u64> {
        self.file
            .metadata()
            .map(|v| v.len())
            .map_err(|e| LocalFsError::BlobFile(e).into())
    }

    fn try_read(&self, buf: &mut [u8], offset: u64) -> BackendResult<usize> {
        debug!(
            "local blob file reading: offset={}, size={} from={}",
            offset,
            buf.len(),
            self.id,
        );

        uio::pread(self.file.as_raw_fd(), buf, offset as i64)
            .map(|v| {
                debug!("local blob file read {} bytes", v);
                self.trace.record(offset, v as u32);
                v
            })
            .map_err(|e| LocalFsError::ReadBlob(e).into())
    }

    fn readv(
        &self,
        bufs: &[FileVolatileSlice],
        offset: u64,
        max_size: usize,
    ) -> BackendResult<usize> {
        let mut c = MemSliceCursor::new(bufs);
        let iovec = c.consume(max_size);

        readv(self.file.as_raw_fd(), &iovec, offset)
            .map(|v| {
                debug!("local blob file read {} bytes", v);
                self.trace.record(offset, v as u32);
                v
            })
            .map_err(|e| LocalFsError::ReadVecBlob(e).into())
    }

    fn prefetch_blob_data_range(&self, ra_offset: u64, ra_size: u64) -> BackendResult<()> {
        if !self.readahead {
            return Ok(());
        }

        let blob_size = self.blob_size()?;
        let prefix = self
            .path
            .to_str()
            .ok_or_else(|| LocalFsError::BlobFile(einval!("invalid blob path")))?;
        let log_path = prefix.to_owned() + BLOB_ACCESSED_SUFFIX;

        // Prefetch according to the trace file if it's ready.
        if let Ok(log_file) = OpenOptions::new().read(true).open(Path::new(&log_path)) {
            // Found access log, kick off readahead
            if log_file.metadata().map_err(LocalFsError::AccessLog)?.len() > 0 {
                // Don't expect poisoned lock here.
                let prefetcher = Prefetcher::new(log_file, log_path, &self.file, blob_size)
                    .map_err(LocalFsError::AccessLog)?;
                let _ = thread::Builder::new()
                    .name("nydus-localfs-readahead".to_string())
                    .spawn(move || {
                        let _ = prefetcher.do_readahead();
                    });
                return Ok(());
            }
        }

        // Prefetch data according to the hint if it's valid.
        let end = ra_offset + ra_size;
        if ra_size != 0 && end <= blob_size {
            info!(
                "kick off hinted blob readahead offset {} len {}",
                ra_offset, ra_size
            );
            readahead(self.file.as_raw_fd(), ra_offset, end);
        }

        // start access logging
        if let Ok(log_file) = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(Path::new(&log_path))
        {
            let tracer = self.trace.clone();
            let trace_sec = self.trace_sec;
            let trace_to = Duration::from_secs(trace_sec as u64);
            let trace_cond = self.trace_condvar.clone();

            tracer.active.store(true, Ordering::Release);

            // Spawn a working thread to flush access trace records.
            let _ = thread::Builder::new()
                .name("nydus-localfs-access-recorder".to_string())
                .spawn(move || {
                    let &(ref lock, ref cvar) = &*trace_cond;
                    let guard = lock.lock().unwrap();
                    if !*guard {
                        let _guard = cvar.wait_timeout(guard, trace_to);
                    }
                    LocalFsTracer::flush(log_file, log_path, tracer);
                });
        }

        Ok(())
    }

    fn stop_data_prefetch(&self) -> BackendResult<()> {
        let &(ref lock, ref cvar) = &*self.trace_condvar;
        *lock.lock().unwrap() = true;
        cvar.notify_all();

        Ok(())
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
    // Whether to prefetch data from the blob file
    readahead: bool,
    // Number of seconds to collect blob access logs
    readahead_sec: u32,
    // Metrics collector.
    metrics: Arc<BackendMetrics>,
    // Hashmap to map blob id to blob file.
    entries: RwLock<HashMap<String, Arc<LocalFsEntry>>>,
}

impl LocalFs {
    pub fn new(config: serde_json::value::Value, id: Option<&str>) -> Result<LocalFs> {
        let config: LocalFsConfig = serde_json::from_value(config).map_err(|e| einval!(e))?;
        let id = id.ok_or_else(|| einval!("LocalFs requires blob_id"))?;

        if config.blob_file.is_empty() && config.dir.is_empty() {
            return Err(einval!("blob file or dir is required"));
        }

        Ok(LocalFs {
            blob_file: config.blob_file,
            dir: config.dir,
            alt_dirs: config.alt_dirs,
            readahead: config.readahead,
            readahead_sec: config.readahead_sec,
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
                if let Ok(meta) = std::fs::metadata(&blob) {
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

        path.canonicalize().map_err(LocalFsError::BlobFile)
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
            .map_err(LocalFsError::BlobFile)?;
        // Don't expect poisoned lock here.
        let mut table_guard = self.entries.write().unwrap();
        if let Some(entry) = table_guard.get(blob_id) {
            Ok(entry.clone())
        } else {
            let entry = Arc::new(LocalFsEntry {
                id: blob_id.to_owned(),
                path: blob_file_path,
                file,
                metrics: self.metrics.clone(),
                readahead: self.readahead,
                trace: Arc::new(LocalFsTracer::new()),
                trace_sec: self.readahead_sec,
                trace_condvar: Arc::new((Mutex::new(false), Condvar::new())),
            });
            table_guard.insert(blob_id.to_string(), entry.clone());
            Ok(entry)
        }
    }
}

impl BlobBackend for LocalFs {
    fn shutdown(&self) {
        for entry in self.entries.read().unwrap().values() {
            let &(ref lock, ref cvar) = &*entry.trace_condvar;
            *lock.lock().unwrap() = true;
            cvar.notify_all();
        }
    }

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

struct LocalFsTracer {
    active: AtomicBool,
    records: Mutex<Vec<AccessLogEntry>>,
}

impl LocalFsTracer {
    fn new() -> Self {
        LocalFsTracer {
            active: AtomicBool::new(false),
            records: Mutex::new(Vec::new()),
        }
    }

    fn record(&self, offset: u64, len: u32) {
        // TODO: avoid rounding
        if self.active.load(Ordering::Acquire) {
            if let Some(rounded_len) = try_round_up_4k(len) {
                let mut r = self.records.lock().unwrap();
                if r.len() < MAX_ACCESS_RECORD {
                    if self.active.load(Ordering::Acquire) {
                        r.push((round_down_4k(offset), rounded_len, 0));
                    }
                } else {
                    self.active.store(false, Ordering::Release);
                }
            }
        }
    }

    fn flush(file: File, path: String, tracer: Arc<LocalFsTracer>) {
        info!("flushing access log to {}", &path);

        // Disable tracer and the underlying vector won't change anymore once we acquired the lock.
        tracer.active.store(false, Ordering::Release);
        // Do not expected poisoned lock here.
        let mut r = tracer.records.lock().unwrap();

        if r.len() == 0 {
            drop(r);
            info!("No read access is recorded. Drop access file {}", &path);
            let _ = remove_file(Path::new(&path)).map_err(|e| {
                warn!("failed to remove access file {}: {}", &path, e);
            });
        } else {
            r.sort_unstable();
            r.dedup();
            // Safe because `records` is valid and never changes anymore.
            let buf = unsafe {
                std::slice::from_raw_parts(
                    r.as_ptr() as *const u8,
                    r.len() * std::mem::size_of::<AccessLogEntry>(),
                )
            };
            drop(r);

            let _ = nix::unistd::write(file.as_raw_fd(), buf).map_err(|e| {
                warn!("fail to write access log: {}", e);
            });

            // Do not expected poisoned lock here.
            tracer.records.lock().unwrap().resize(0, Default::default());
        }
    }
}

/// Struct to prefetch blob data according to access trace.
#[derive(Debug)]
struct Prefetcher {
    blob_file: File,     // blob file for readahead
    blob_size: u64,      // blob file size
    log_path: String,    // log file path
    log_file: File,      // file for access logging
    log_base: *const u8, // mmapped access log base
    log_size: u64,       // size of mmapped area
    records: ManuallyDrop<Vec<AccessLogEntry>>,
}

unsafe impl Send for Prefetcher {}

unsafe impl Sync for Prefetcher {}

impl Prefetcher {
    fn new(log_file: File, log_path: String, blob_file: &File, blob_size: u64) -> Result<Self> {
        let blob_file = blob_file.try_clone()?;
        let size = log_file.metadata()?.len();
        if size == 0 || size % (ACCESS_RECORD_ENTRY_SIZE as u64) != 0 || size > usize::MAX as u64 {
            warn!("ignoring unaligned log file");
            return Err(einval!("access trace log file is invalid"));
        }

        let count = size / (ACCESS_RECORD_ENTRY_SIZE as u64);
        let base = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                size as usize,
                libc::PROT_READ,
                libc::MAP_NORESERVE | libc::MAP_SHARED,
                log_file.as_raw_fd(),
                0,
            )
        };
        if base == libc::MAP_FAILED {
            return Err(last_error!("failed to mmap access log file"));
        } else if base.is_null() {
            return Err(ebadf!("failed to mmap access log file"));
        }

        // safe because we have validated size
        let records = unsafe {
            ManuallyDrop::new(Vec::from_raw_parts(
                base as *mut AccessLogEntry,
                count as usize,
                count as usize,
            ))
        };

        Ok(Prefetcher {
            blob_file,
            blob_size,
            log_path,
            log_file,
            log_base: base as *const u8,
            log_size: size,
            records,
        })
    }

    #[cfg(target_os = "macos")]
    fn do_readahead(&self) -> Result<()> {
        info!("starting localfs blob readahead");

        for &(offset, len, zero) in self.records.iter() {
            let end: u64 = offset
                .checked_add(len as u64)
                .ok_or_else(|| einval!("invalid length"))?;
            if offset > self.blob_size || end > self.blob_size || zero != 0 {
                return Err(einval!(format!(
                    "invalid readahead entry ({}, {}), blob size {}",
                    offset, len, self.blob_size
                )));
            }

            unsafe {
                fcntl(
                    self.blob_file.as_raw_fd(),
                    libc::F_RDADVISE,
                    radvisory {
                        ra_offset: offset as i64,
                        ra_count: len as i32,
                    },
                );
            };
        }

        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn do_readahead(&self) -> Result<()> {
        info!("starting localfs blob readahead");

        for &(offset, len, zero) in self.records.iter() {
            let end: u64 = offset
                .checked_add(len as u64)
                .ok_or_else(|| einval!("invalid length"))?;
            if offset > self.blob_size || end > self.blob_size || zero != 0 {
                return Err(einval!(format!(
                    "invalid readahead entry ({}, {}), blob size {}",
                    offset, len, self.blob_size
                )));
            }

            unsafe { libc::readahead(self.blob_file.as_raw_fd(), offset as i64, len as usize) };
        }

        Ok(())
    }
}

impl Drop for Prefetcher {
    fn drop(&mut self) {
        if !self.log_base.is_null() {
            let ptr = self.log_base as *mut u8 as *mut libc::c_void;
            unsafe { libc::munmap(ptr, self.log_size as usize) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::os::unix::fs::FileExt;
    use std::os::unix::io::{FromRawFd, IntoRawFd};
    use vmm_sys_util::tempfile::TempFile;

    #[test]
    fn test_invalid_localfs_new() {
        let config = LocalFsConfig {
            readahead: true,
            readahead_sec: 20,
            blob_file: "".to_string(),
            dir: "".to_string(),
            alt_dirs: Vec::new(),
        };
        let json = serde_json::to_value(&config).unwrap();
        assert!(LocalFs::new(json, Some("test")).is_err());

        let config = LocalFsConfig {
            readahead: true,
            readahead_sec: 20,
            blob_file: "/a/b/c".to_string(),
            dir: "/a/b".to_string(),
            alt_dirs: Vec::new(),
        };
        let json = serde_json::to_value(&config).unwrap();
        assert!(LocalFs::new(json, None).is_err());
    }

    #[test]
    fn test_localfs_get_blob_path() {
        let config = LocalFsConfig {
            readahead: true,
            readahead_sec: 20,
            blob_file: "/a/b/cxxxxxxxxxxxxxxxxxxxxxxx".to_string(),
            dir: "/a/b".to_string(),
            alt_dirs: Vec::new(),
        };
        let json = serde_json::to_value(&config).unwrap();
        let fs = LocalFs::new(json, Some("test")).unwrap();
        assert!(fs.get_blob_path("test").is_err());

        let tempfile = TempFile::new().unwrap();
        let path = tempfile.as_path();
        let filename = path.file_name().unwrap().to_str().unwrap();

        let config = LocalFsConfig {
            readahead: true,
            readahead_sec: 20,
            blob_file: path.to_str().unwrap().to_owned(),
            dir: path.parent().unwrap().to_str().unwrap().to_owned(),
            alt_dirs: Vec::new(),
        };
        let json = serde_json::to_value(&config).unwrap();
        let fs = LocalFs::new(json, Some("test")).unwrap();
        assert_eq!(fs.get_blob_path("test").unwrap().to_str(), path.to_str());

        let config = LocalFsConfig {
            readahead: true,
            readahead_sec: 20,
            blob_file: "".to_string(),
            dir: path.parent().unwrap().to_str().unwrap().to_owned(),
            alt_dirs: Vec::new(),
        };
        let json = serde_json::to_value(&config).unwrap();
        let fs = LocalFs::new(json, Some(filename)).unwrap();
        assert_eq!(fs.get_blob_path(filename).unwrap().to_str(), path.to_str());

        let config = LocalFsConfig {
            readahead: true,
            readahead_sec: 20,
            blob_file: "".to_string(),
            dir: "/a/b".to_string(),
            alt_dirs: vec![
                "/test".to_string(),
                path.parent().unwrap().to_str().unwrap().to_owned(),
            ],
        };
        let json = serde_json::to_value(&config).unwrap();
        let fs = LocalFs::new(json, Some(filename)).unwrap();
        assert_eq!(fs.get_blob_path(filename).unwrap().to_str(), path.to_str());
    }

    #[test]
    fn test_localfs_get_blob() {
        let tempfile = TempFile::new().unwrap();
        let path = tempfile.as_path();
        let filename = path.file_name().unwrap().to_str().unwrap();
        let config = LocalFsConfig {
            readahead: true,
            readahead_sec: 20,
            blob_file: "".to_string(),
            dir: path.parent().unwrap().to_str().unwrap().to_owned(),
            alt_dirs: Vec::new(),
        };
        let json = serde_json::to_value(&config).unwrap();
        let fs = LocalFs::new(json, Some(filename)).unwrap();
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
            readahead: true,
            readahead_sec: 20,
            blob_file: "".to_string(),
            dir: path.parent().unwrap().to_str().unwrap().to_owned(),
            alt_dirs: Vec::new(),
        };
        let json = serde_json::to_value(&config).unwrap();
        let fs = LocalFs::new(json, Some(filename)).unwrap();
        let blob1 = fs.get_reader(filename).unwrap();
        let blob2 = fs.get_reader(filename).unwrap();
        assert_eq!(Arc::strong_count(&blob1), 3);

        let mut buf1 = [0x0u8];
        blob1.read(&mut buf1, 0x0).unwrap();
        assert_eq!(buf1[0], 0x1);

        let mut buf2 = [0x0u8];
        let mut buf3 = [0x0u8];
        let bufs = [
            unsafe { FileVolatileSlice::new(buf2.as_mut_ptr(), 1) },
            unsafe { FileVolatileSlice::new(buf3.as_mut_ptr(), 1) },
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
    fn test_localfs_trace_and_prefetch() {
        let tempfile = TempFile::new().unwrap();
        let path = tempfile.as_path();
        let filename = path.file_name().unwrap().to_str().unwrap();

        {
            let mut file = unsafe { File::from_raw_fd(tempfile.as_file().as_raw_fd()) };
            file.write_all(&[0x1u8, 0x2, 0x3, 0x4]).unwrap();
            file.write_all_at(&[0x1u8, 0x2, 0x3, 0x4], 0x1000).unwrap();
            let _ = file.into_raw_fd();
        }

        let config = LocalFsConfig {
            readahead: true,
            readahead_sec: 10,
            blob_file: "".to_string(),
            dir: path.parent().unwrap().to_str().unwrap().to_owned(),
            alt_dirs: Vec::new(),
        };
        let json = serde_json::to_value(&config).unwrap();
        let fs = LocalFs::new(json, Some(filename)).unwrap();

        fs.get_reader(filename)
            .unwrap()
            .prefetch_blob_data_range(0x0, 0x1)
            .unwrap();

        let blob1 = fs.get_reader(filename).unwrap();
        let blob2 = fs.get_reader(filename).unwrap();
        assert_eq!(Arc::strong_count(&blob1), 3);

        let mut buf1 = [0x0u8];
        blob1.read(&mut buf1, 0x0).unwrap();
        assert_eq!(buf1[0], 0x1);

        let mut buf2 = [0x0u8];
        let mut buf3 = [0x0u8];
        let bufs = [
            unsafe { FileVolatileSlice::new(buf2.as_mut_ptr(), 1) },
            unsafe { FileVolatileSlice::new(buf3.as_mut_ptr(), 1) },
        ];
        assert_eq!(blob2.readv(&bufs, 0x1001, 3).unwrap(), 2);
        assert_eq!(buf2[0], 0x2);
        assert_eq!(buf3[0], 0x3);

        fs.shutdown();
        thread::sleep(Duration::from_secs(1));

        let mut trace: Vec<AccessLogEntry> = vec![Default::default(); 4];
        let log_path = path.to_str().unwrap().to_owned() + BLOB_ACCESSED_SUFFIX;
        let mut log_file = File::open(&log_path).unwrap();
        let mut buf = unsafe { std::slice::from_raw_parts_mut(trace.as_mut_ptr() as *mut u8, 64) };
        assert_eq!(log_file.read(&mut buf).unwrap(), 32);

        assert_eq!(trace[0].0, 0x0);
        assert_eq!(trace[0].1, 0x1000);
        assert_eq!(trace[0].2, 0);
        assert_eq!(trace[1].0, 0x1000);
        assert_eq!(trace[1].1, 0x1000);
        assert_eq!(trace[1].2, 0);
    }
}

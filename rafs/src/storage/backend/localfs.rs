// Copyright 2020 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::fs::{self, remove_file, File, OpenOptions};
use std::io::{self, Result};
use std::mem::{size_of, ManuallyDrop};
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::{thread, time};

use nix::sys::uio;
use vm_memory::VolatileSlice;

use crate::storage::backend::{BlobBackend, BlobBackendUploader};
use crate::storage::utils::{readahead, readv};

use nydus_utils::{ebadf, einval, eio, enoent, last_error};
use nydus_utils::{round_down_4k, round_up_4k};

const BLOB_ACCESSED_SUFFIX: &str = ".access";
const BLOB_ACCESS_RECORD_SECOND: u32 = 10;

// Each access record takes 16 bytes: u64 + u32 + u32
// So we allow 2048 entries at most to avoid hurting backend upon flush
const ACCESS_RECORD_ENTRY_SIZE: usize = size_of::<u64>() + size_of::<u32>() + size_of::<u32>();
const MAX_ACCESS_RECORD_FILE_SIZE: usize = 32768;
const MAX_ACCESS_RECORD: usize = MAX_ACCESS_RECORD_FILE_SIZE / ACCESS_RECORD_ENTRY_SIZE;

type FileTableEntry = (File, Option<Arc<LocalFsAccessLog>>);

#[derive(Default)]
pub struct LocalFs {
    // the specified blob file
    blob_file: String,
    // directory to blob files
    dir: String,
    // readahead blob file
    readahead: bool,
    // number of seconds to record blob access logs
    readahead_sec: u32,
    // blobid-File map
    file_table: RwLock<HashMap<String, FileTableEntry>>,
}

#[derive(Clone, Deserialize)]
struct LocalFsConfig {
    #[serde(default)]
    readahead: bool,
    #[serde(default = "default_readahead_sec")]
    readahead_sec: u32,
    #[serde(default)]
    blob_file: String,
    #[serde(default)]
    dir: String,
}

fn default_readahead_sec() -> u32 {
    BLOB_ACCESS_RECORD_SECOND
}

pub fn new(config: serde_json::value::Value) -> Result<LocalFs> {
    let config: LocalFsConfig = serde_json::from_value(config).map_err(|e| einval!(e))?;

    if config.blob_file.is_empty() && config.dir.is_empty() {
        return Err(einval!("blob file or dir is required"));
    }

    if !config.blob_file.is_empty() {
        return Ok(LocalFs {
            blob_file: config.blob_file,
            readahead: config.readahead,
            readahead_sec: config.readahead_sec,
            file_table: RwLock::new(HashMap::new()),
            ..Default::default()
        });
    }

    Ok(LocalFs {
        dir: config.dir,
        readahead: config.readahead,
        readahead_sec: config.readahead_sec,
        file_table: RwLock::new(HashMap::new()),
        ..Default::default()
    })
}

type AccessLogEntry = (u64, u32, u32);

// Access entries can be either mmapped or Vec-allocated.
// Use mmap for read case and Vec-allocated for write case.
struct LocalFsAccessLog {
    log_path: String,                                  // log file path
    log_fd: RawFd,                                     // log file fd
    log_base: *const u8,                               // mmaped access log base
    log_size: usize,                                   // log file size
    blob_fd: RawFd,                                    // blob fd for readahead
    blob_size: usize,                                  // blob file size
    records: ManuallyDrop<Mutex<Vec<AccessLogEntry>>>, // access records
}

unsafe impl Send for LocalFsAccessLog {}

unsafe impl Sync for LocalFsAccessLog {}

impl LocalFsAccessLog {
    fn new() -> LocalFsAccessLog {
        LocalFsAccessLog {
            log_path: "".to_string(),
            log_fd: -1,
            log_base: std::ptr::null(),
            log_size: 0,
            blob_fd: -1,
            blob_size: 0,
            records: ManuallyDrop::new(Mutex::new(Vec::new())),
        }
    }

    fn init(
        &mut self,
        log_file: File,
        log_path: String,
        blob_fd: RawFd,
        blob_size: usize,
        load_entries: bool,
    ) -> Result<()> {
        if self.log_fd > 0
            || !self.log_path.is_empty()
            || self.blob_fd > 0
            || self.records.lock().unwrap().len() > 0
        {
            return Err(einval!("invalid access log info"));
        }

        self.log_fd = unsafe { libc::dup(log_file.as_raw_fd()) };
        if self.log_fd < 0 {
            return Err(last_error!("failed to dup log fd"));
        }
        self.blob_fd = unsafe { libc::dup(blob_fd) };
        if self.blob_fd < 0 {
            return Err(last_error!("failed to dup blob fd"));
        }
        self.log_path = log_path;
        self.blob_size = blob_size;

        if !load_entries {
            return Ok(());
        }

        // load exiting entries
        let size = log_file.metadata()?.len() as usize;
        if size == 0 || size % ACCESS_RECORD_ENTRY_SIZE != 0 {
            warn!("ignoring unaligned log file");
            return Ok(());
        }
        let count = size / ACCESS_RECORD_ENTRY_SIZE;
        let base = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                size as usize,
                libc::PROT_READ,
                libc::MAP_NORESERVE | libc::MAP_PRIVATE,
                self.log_fd,
                0,
            )
        } as *const AccessLogEntry;
        if base as *mut core::ffi::c_void == libc::MAP_FAILED {
            return Err(last_error!("failed to mmap access log file"));
        }
        if base.is_null() {
            return Err(ebadf!("failed to mmap access log file"));
        }
        // safe because we have validated size
        self.records = unsafe {
            ManuallyDrop::new(Mutex::new(Vec::from_raw_parts(
                base as *mut AccessLogEntry,
                count as usize,
                count as usize,
            )))
        };
        self.log_base = base as *const u8;
        self.log_size = size;
        Ok(())
    }

    fn do_readahead(&self) -> Result<()> {
        info!("starting localfs blob readahead");
        let blob_end = round_up_4k(self.blob_size as u64).unwrap();
        for &(offset, len, zero) in self.records.lock().unwrap().iter() {
            let end: u64 = offset
                .checked_add(len as u64)
                .ok_or_else(|| einval!("invalid length"))?;
            if offset > blob_end as u64 || end > blob_end as u64 || zero != 0 {
                return Err(einval!(format!(
                    "invalid readahead entry ({}, {}), blob size {}",
                    offset, len, blob_end
                )));
            }
            unsafe { libc::readahead(self.blob_fd, offset as i64, len as usize) };
        }
        Ok(())
    }

    fn record(&self, offset: u64, len: u32) -> bool {
        // Never modify mmaped records
        if !self.log_base.is_null() {
            return false;
        }

        let mut r = self.records.lock().unwrap();
        if r.len() < MAX_ACCESS_RECORD {
            r.push((
                round_down_4k(offset),
                // Safe to unwrap because len is u32
                round_up_4k(len as u64).unwrap() as u32,
                0,
            ));
            return true;
        }
        false
    }

    fn flush(&self) {
        info!("flushing access log to {}", &self.log_path);
        let mut r = self.records.lock().unwrap();
        if r.len() == 0 {
            info!(
                "No read access is recorded. Drop access file {}",
                &self.log_path
            );
            // set record length to max to no new record is saved
            // safe because we have locked records
            unsafe { r.set_len(MAX_ACCESS_RECORD) };
            drop(r);
            if let Err(e) = remove_file(Path::new(&self.log_path)) {
                warn!("failed to remove access file {}: {}", &self.log_path, e);
            }
            return;
        }
        r.sort_unstable();
        r.dedup();

        // record is valid as long as LocalFsAccessLog is not dropped
        // which means it must be valid within flush()
        let record = unsafe {
            std::slice::from_raw_parts(
                r.as_ptr() as *const u8,
                r.len() * std::mem::size_of::<AccessLogEntry>(),
            )
        };

        // set record length to max to no new record is saved
        // safe because we have locked records
        unsafe { r.set_len(MAX_ACCESS_RECORD) };
        drop(r);

        let _ = nix::unistd::write(self.log_fd, record).map_err(|e| {
            warn!("fail to write access log: {}", e);
            eio!(e)
        });
    }
}

impl Drop for LocalFsAccessLog {
    fn drop(&mut self) {
        if !self.log_base.is_null() {
            unsafe {
                libc::munmap(
                    self.log_base as *mut u8 as *mut libc::c_void,
                    self.log_size as usize,
                )
            };
            self.log_base = std::ptr::null();
            self.log_size = 0;
        } else {
            // Drop records if it is not mmapped
            unsafe {
                ManuallyDrop::drop(&mut self.records);
            }
        }
        if self.blob_fd > 0 {
            let _ = nix::unistd::close(self.blob_fd);
            self.blob_fd = -1;
        }
        if self.log_fd > 0 {
            let _ = nix::unistd::close(self.log_fd);
            self.log_fd = -1;
        }
    }
}

impl LocalFs {
    fn get_blob_path(&self, blob_id: &str) -> PathBuf {
        if self.use_blob_file() {
            Path::new(&self.blob_file).to_path_buf()
        } else {
            Path::new(&self.dir).join(blob_id)
        }
    }

    fn get_blob_fd(&self, blob_id: &str, offset: u64, len: usize) -> Result<RawFd> {
        let blob_file_path = self.get_blob_path(blob_id);

        let mut drop_access_log = false;
        let blob_file;
        // Don't expect poisoned lock here.
        let table_guard = self.file_table.read().unwrap();
        if let Some((file, access_log)) = table_guard.get(blob_id) {
            if let Some(access_log) = access_log {
                if len != 0 {
                    drop_access_log = !access_log.record(offset, len as u32);
                }
            }
            if !drop_access_log {
                return Ok(file.as_raw_fd());
            }
            // need to drop access log file, clone the blob file first
            blob_file = file.try_clone()?;
            drop(table_guard);

            let fd = blob_file.as_raw_fd();
            self.file_table
                .write()
                .unwrap()
                .insert(blob_id.to_owned(), (blob_file, None));
            return Ok(fd);
        }
        drop(table_guard);

        let file = OpenOptions::new()
            .read(true)
            .open(&blob_file_path)
            .map_err(|e| last_error!(format!("failed to open blob {}: {}", blob_id, e)))?;
        let fd = file.as_raw_fd();

        // Don't expect poisoned lock here.
        let mut table_guard = self.file_table.write().unwrap();
        // Double check whether someone else inserted the file concurrently.
        if let Some((other, access_log)) = table_guard.get(blob_id) {
            if let Some(access_log) = access_log {
                if len != 0 {
                    let _ = access_log.record(offset, len as u32);
                }
            }
            return Ok(other.as_raw_fd());
        }

        table_guard.insert(blob_id.to_string(), (file, None));
        Ok(fd)
    }

    fn use_blob_file(&self) -> bool {
        !self.blob_file.is_empty()
    }
}

impl BlobBackend for LocalFs {
    fn prefetch_blob(
        &self,
        blob_id: &str,
        blob_readahead_offset: u32,
        blob_readahead_size: u32,
    ) -> Result<()> {
        if !self.readahead {
            return Ok(());
        }

        let _ = self
            .get_blob_fd(blob_id, 0, 0)
            .map_err(|e| enoent!(format!("failed to find blob {}: {}", blob_id, e)))?;
        // Do not expect get failure as we just added it above in get_blob_fd
        let blob_file = self
            .file_table
            .read()
            .unwrap()
            .get(blob_id)
            .unwrap()
            .0
            .try_clone()?;
        let blob_size = blob_file.metadata()?.len() as usize;
        let blob_fd = blob_file.as_raw_fd();
        let blob_path = self.get_blob_path(blob_id);

        // try to kick off readahead
        let access_file_path = blob_path.to_str().unwrap().to_owned() + BLOB_ACCESSED_SUFFIX;
        if let Ok(access_file) = OpenOptions::new()
            .read(true)
            .open(Path::new(&access_file_path))
        {
            // Found access log, kick off readahead
            if access_file.metadata()?.len() > 0 {
                // Don't expect poisoned lock here.
                let mut access_log = LocalFsAccessLog::new();
                access_log.init(access_file, access_file_path, blob_fd, blob_size, true)?;
                let _ = thread::Builder::new()
                    .name("nydus-localfs-readahead".to_string())
                    .spawn(move || {
                        let _ = access_log.do_readahead();
                    });
                return Ok(());
            }
        }

        // kick off hinted blob readahead
        if blob_readahead_size != 0
            && ((blob_readahead_offset + blob_readahead_size) as usize) <= blob_size
        {
            info!(
                "kick off hinted blob readahead offset {} len {}",
                blob_readahead_offset, blob_readahead_size
            );
            readahead(
                blob_file.as_raw_fd(),
                blob_readahead_offset as u64,
                (blob_readahead_offset + blob_readahead_size) as u64,
            );
        }

        // start access logging
        if let Ok(access_file) = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(Path::new(&access_file_path))
        {
            let mut access_log = LocalFsAccessLog::new();
            access_log.init(access_file, access_file_path, blob_fd, blob_size, false)?;
            let access_log = Arc::new(access_log);
            // Do not expect poisoned lock here
            self.file_table
                .write()
                .unwrap()
                .insert(blob_id.to_owned(), (blob_file, Some(access_log.clone())));

            // Split a thread to flush access record
            let wait_sec = self.readahead_sec;
            let _ = thread::Builder::new()
                .name("nydus-localfs-access-recorder".to_string())
                .spawn(move || {
                    thread::sleep(time::Duration::from_secs(wait_sec as u64));
                    access_log.flush();
                });
        }

        Ok(())
    }

    fn try_read(&self, blob_id: &str, buf: &mut [u8], offset: u64) -> Result<usize> {
        let fd = self.get_blob_fd(blob_id, offset, buf.len())?;

        debug!(
            "local blob file reading: offset={}, size={} from={}",
            offset,
            buf.len(),
            blob_id,
        );
        let len = uio::pread(fd, buf, offset as i64)
            .map_err(|_| last_error!("failed to read blob file"))?;
        debug!("local blob file read {} bytes", len);

        Ok(len)
    }

    fn readv(
        &self,
        blob_id: &str,
        bufs: &[VolatileSlice],
        offset: u64,
        max_size: usize,
    ) -> Result<usize> {
        let fd = self.get_blob_fd(blob_id, offset, max_size)?;
        readv(fd, bufs, offset, max_size)
    }

    fn write(&self, _blob_id: &str, _buf: &[u8], _offset: u64) -> Result<usize> {
        unimplemented!("write operation not supported with localfs");
    }
}

impl BlobBackendUploader for LocalFs {
    fn upload(
        &self,
        blob_id: &str,
        blob_path: &Path,
        _callback: fn((usize, usize)),
    ) -> Result<usize> {
        let target_path = if self.use_blob_file() {
            Path::new(&self.blob_file).to_path_buf()
        } else {
            Path::new(&self.dir).join(blob_id)
        };

        if let Some(parent) = target_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let size = fs::metadata(blob_path)?.len() as usize;

        if let Err(err) = fs::rename(blob_path, &target_path) {
            warn!(
                "localfs blob upload: file rename failed {:?}, fallback to copy",
                err
            );
            let mut blob_file = OpenOptions::new().read(true).open(blob_path).map_err(|e| {
                error!("localfs blob upload: open blob file failed {:?}", e);
                e
            })?;
            let mut target_file = OpenOptions::new()
                .create(true)
                .write(true)
                .open(target_path)
                .map_err(|e| {
                    error!("localfs blob upload: open target file failed {:?}", e);
                    e
                })?;
            io::copy(&mut blob_file, &mut target_file)?;
        }

        Ok(size)
    }
}

// Copyright (C) 2022 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! Handler to expose RAFSv6 image through EROFS/fscache.
//!
//! The [`FsCacheHandler`] is the inter-connection between in kernel EROFS/fscache drivers
//! and the user space [BlobCacheMgr](https://docs.rs/nydus-service/latest/nydus_service/blob_cache/struct.BlobCacheMgr.html).
//! The workflow is as below:
//! - EROFS presents a filesystem structure by parsing a RAFS image metadata blob.
//! - EROFS sends requests to the fscache subsystem when user reads data from files.
//! - Fscache subsystem send requests to [FsCacheHandler] if the requested data has been cached yet.
//! - [FsCacheHandler] reads blob data from the [BlobCacheMgr] and sends back reply messages.

use std::collections::hash_map::Entry::Vacant;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::fs::{self, File, OpenOptions};
use std::io::{copy, Error, ErrorKind, Result, Write};
use std::ops::Deref;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::ptr::read_unaligned;
use std::string::String;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier, Condvar, Mutex, MutexGuard, RwLock};
use std::{cmp, env, thread, time};

use mio::unix::SourceFd;
use mio::{Events, Interest, Poll, Token, Waker};
use nydus_storage::cache::BlobCache;
use nydus_storage::device::BlobPrefetchRequest;
use nydus_storage::factory::{ASYNC_RUNTIME, BLOB_FACTORY};

use crate::blob_cache::{
    generate_blob_key, BlobCacheMgr, BlobConfig, DataBlobConfig, MetaBlobConfig,
};

nix::ioctl_write_int!(fscache_cread, 0x98, 1);

/// Maximum size of fscache request message from kernel.
const MIN_DATA_BUF_SIZE: usize = 1024;
const MSG_HEADER_SIZE: usize = 16;
const MSG_OPEN_SIZE: usize = 16;
const MSG_READ_SIZE: usize = 16;

const TOKEN_EVENT_WAKER: usize = 1;
const TOKEN_EVENT_FSCACHE: usize = 2;

const BLOB_CACHE_INIT_RETRY: u8 = 5;
const BLOB_CACHE_INIT_INTERVAL_MS: u64 = 300;

/// Command code in requests from fscache driver.
#[repr(u32)]
#[derive(Debug, Eq, PartialEq)]
enum FsCacheOpCode {
    Open = 0,
    Close = 1,
    Read = 2,
}

impl TryFrom<u32> for FsCacheOpCode {
    type Error = Error;

    fn try_from(value: u32) -> std::result::Result<Self, Self::Error> {
        match value {
            0 => Ok(FsCacheOpCode::Open),
            1 => Ok(FsCacheOpCode::Close),
            2 => Ok(FsCacheOpCode::Read),
            _ => Err(einval!(format!(
                "fscache: invalid operation code {}",
                value
            ))),
        }
    }
}

/// Common header for request messages.
#[repr(C)]
#[derive(Debug, Eq, PartialEq)]
struct FsCacheMsgHeader {
    /// Message identifier to associate reply with request by the fscache driver.
    msg_id: u32,
    /// Message operation code.
    opcode: FsCacheOpCode,
    /// Message length, including message header and message body.
    len: u32,
    /// A unique ID identifying the cache file operated on.
    object_id: u32,
}

impl TryFrom<&[u8]> for FsCacheMsgHeader {
    type Error = Error;

    fn try_from(value: &[u8]) -> std::result::Result<Self, Self::Error> {
        if value.len() < MSG_HEADER_SIZE {
            return Err(einval!(format!(
                "fscache: request message size is too small, {}",
                value.len()
            )));
        }

        // Safe because we have verified buffer size.
        let msg_id = unsafe { read_unaligned(value[0..4].as_ptr() as *const u32) };
        let opcode = unsafe { read_unaligned(value[4..8].as_ptr() as *const u32) };
        let len = unsafe { read_unaligned(value[8..12].as_ptr() as *const u32) };
        let opcode = FsCacheOpCode::try_from(opcode)?;
        let object_id = unsafe { read_unaligned(value[12..16].as_ptr() as *const u32) };
        if len as usize != value.len() {
            return Err(einval!(format!(
                "fscache: message length {} does not match length from message header {}",
                value.len(),
                len
            )));
        }

        Ok(FsCacheMsgHeader {
            msg_id,
            opcode,
            len,
            object_id,
        })
    }
}

/// Request message to open a file.
///
/// The opened file should be kept valid until corresponding `CLOSE` message has been received
/// from the fscache driver.
#[derive(Default, Debug, Eq, PartialEq)]
struct FsCacheMsgOpen {
    volume_key: String,
    cookie_key: String,
    fd: u32,
    flags: u32,
}

impl TryFrom<&[u8]> for FsCacheMsgOpen {
    type Error = Error;

    fn try_from(value: &[u8]) -> std::result::Result<Self, Self::Error> {
        if value.len() < MSG_OPEN_SIZE {
            return Err(einval!(format!(
                "fscache: request message size is too small, {}",
                value.len()
            )));
        }

        // Safe because we have verified buffer size.
        let volume_key_size = unsafe { read_unaligned(value[0..4].as_ptr() as *const u32) };
        let cookie_key_size = unsafe { read_unaligned(value[4..8].as_ptr() as *const u32) };
        let fd = unsafe { read_unaligned(value[8..12].as_ptr() as *const u32) };
        let flags = unsafe { read_unaligned(value[12..16].as_ptr() as *const u32) };
        if volume_key_size.checked_add(cookie_key_size).is_none()
            || (volume_key_size + cookie_key_size)
                .checked_add(MSG_OPEN_SIZE as u32)
                .is_none()
        {
            return Err(einval!(
                "fscache: invalid volume/cookie key length in OPEN request"
            ));
        }
        let total_sz = (volume_key_size + cookie_key_size) as usize + MSG_OPEN_SIZE;
        if value.len() < total_sz {
            return Err(einval!("fscache: invalid message length for OPEN request"));
        }
        let pos = MSG_OPEN_SIZE + volume_key_size as usize;
        let volume_key = String::from_utf8(value[MSG_OPEN_SIZE..pos].to_vec())
            .map_err(|_e| einval!("fscache: invalid volume key in OPEN request"))?
            .trim_end_matches('\0')
            .to_string();
        let cookie_key = String::from_utf8(value[pos..pos + cookie_key_size as usize].to_vec())
            .map_err(|_e| einval!("fscache: invalid cookie key in OPEN request"))?;

        Ok(FsCacheMsgOpen {
            volume_key,
            cookie_key,
            fd,
            flags,
        })
    }
}

/// Request message to feed requested data into the cache file.
#[repr(C)]
#[derive(Default, Debug, Eq, PartialEq)]
struct FsCacheMsgRead {
    off: u64,
    len: u64,
}

impl TryFrom<&[u8]> for FsCacheMsgRead {
    type Error = Error;

    fn try_from(value: &[u8]) -> std::result::Result<Self, Self::Error> {
        if value.len() < MSG_READ_SIZE {
            return Err(einval!(format!(
                "fscache: request message size is too small, {}",
                value.len()
            )));
        }

        // Safe because we have verified buffer size.
        let off = unsafe { read_unaligned(value[0..8].as_ptr() as *const u64) };
        let len = unsafe { read_unaligned(value[8..16].as_ptr() as *const u64) };

        Ok(FsCacheMsgRead { off, len })
    }
}

struct FsCacheBootstrap {
    bootstrap_file: File,
    cache_file: File,
}

struct FsCacheBlobCache {
    cache: Option<Arc<dyn BlobCache>>,
    config: Arc<DataBlobConfig>,
    file: Arc<File>,
}

impl FsCacheBlobCache {
    fn set_blob_cache(&mut self, cache: Option<Arc<dyn BlobCache>>) {
        self.cache = cache;
    }

    fn get_blob_cache(&self) -> Option<Arc<dyn BlobCache>> {
        self.cache.clone()
    }
}

#[derive(Clone)]
enum FsCacheObject {
    Bootstrap(Arc<FsCacheBootstrap>),
    DataBlob(Arc<RwLock<FsCacheBlobCache>>),
}

/// Struct to maintain cached file objects.
#[derive(Default)]
struct FsCacheState {
    id_to_object_map: HashMap<u32, (FsCacheObject, u32)>,
    id_to_config_map: HashMap<u32, Arc<DataBlobConfig>>,
    blob_cache_mgr: Arc<BlobCacheMgr>,
}

/// Handler to cooperate with Linux fscache driver to manage cached blob objects.
///
/// The `FsCacheHandler` create a communication channel with the Linux fscache driver, configure
/// the communication session and serves all requests from the fscache driver.
pub struct FsCacheHandler {
    active: AtomicBool,
    barrier: Barrier,
    threads: usize,
    file: File,
    state: Arc<Mutex<FsCacheState>>,
    poller: Mutex<Poll>,
    waker: Arc<Waker>,
    cache_dir: PathBuf,
}

impl FsCacheHandler {
    /// Create a new instance of [FsCacheHandler].
    pub fn new(
        path: &str,
        dir: &str,
        tag: Option<&str>,
        blob_cache_mgr: Arc<BlobCacheMgr>,
        threads: usize,
    ) -> Result<Self> {
        info!(
            "fscache: create FsCacheHandler with dir {}, tag {}",
            dir,
            tag.unwrap_or("<None>")
        );

        let mut file = OpenOptions::new()
            .write(true)
            .read(true)
            .create(false)
            .open(path)
            .map_err(|e| {
                error!("Failed to open cachefiles device {}. {}", path, e);
                e
            })?;

        let poller =
            Poll::new().map_err(|_e| eother!("fscache: failed to create poller for service"))?;
        let waker = Waker::new(poller.registry(), Token(TOKEN_EVENT_WAKER))
            .map_err(|_e| eother!("fscache: failed to create waker for service"))?;
        poller
            .registry()
            .register(
                &mut SourceFd(&file.as_raw_fd()),
                Token(TOKEN_EVENT_FSCACHE),
                Interest::READABLE,
            )
            .map_err(|_e| eother!("fscache: failed to register fd for service"))?;

        // Initialize the fscache session
        file.write_all(format!("dir {}", dir).as_bytes())?;
        file.flush()?;
        if let Some(tag) = tag {
            file.write_all(format!("tag {}", tag).as_bytes())?;
            file.flush()?;
        }
        file.write_all(b"bind ondemand")?;
        file.flush()?;

        let state = FsCacheState {
            id_to_object_map: Default::default(),
            id_to_config_map: Default::default(),
            blob_cache_mgr,
        };
        let cache_dir = PathBuf::new().join(dir).join("cache");

        Ok(FsCacheHandler {
            active: AtomicBool::new(true),
            barrier: Barrier::new(threads + 1),
            threads,
            file,
            state: Arc::new(Mutex::new(state)),
            poller: Mutex::new(poller),
            waker: Arc::new(waker),
            cache_dir,
        })
    }

    /// Get number of working threads to service fscache requests.
    pub fn working_threads(&self) -> usize {
        self.threads
    }

    /// Stop worker threads for the fscache service.
    pub fn stop(&self) {
        self.active.store(false, Ordering::Release);
        if let Err(e) = self.waker.wake() {
            error!("fscache: failed to signal worker thread to exit, {}", e);
        }
        self.barrier.wait();
    }

    /// Run the event loop to handle all requests from kernel fscache driver.
    ///
    /// This method should only be invoked by a single thread, which will poll the fscache fd
    /// and dispatch requests from fscache fd to other working threads.
    pub fn run_loop(&self) -> Result<()> {
        let mut events = Events::with_capacity(64);
        let mut buf = vec![0u8; MIN_DATA_BUF_SIZE];

        loop {
            match self.poller.lock().unwrap().poll(&mut events, None) {
                Ok(_) => {}
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) => {
                    warn!("fscache: failed to poll events");
                    return Err(e);
                }
            }

            for event in events.iter() {
                if event.is_error() {
                    error!("fscache: got error event from poller");
                    continue;
                }
                if event.token() == Token(TOKEN_EVENT_FSCACHE) {
                    if event.is_readable() {
                        self.handle_requests(&mut buf)?;
                    }
                } else if event.is_readable()
                    && event.token() == Token(TOKEN_EVENT_WAKER)
                    && !self.active.load(Ordering::Acquire)
                {
                    // Notify next worker to exit.
                    let _ = self.waker.wake();
                    self.barrier.wait();
                    return Ok(());
                }
            }
        }
    }

    /// Read and process all requests from fscache driver until no data available.
    fn handle_requests(&self, buf: &mut [u8]) -> Result<()> {
        loop {
            let ret = unsafe {
                libc::read(
                    self.file.as_raw_fd(),
                    buf.as_ptr() as *mut u8 as *mut libc::c_void,
                    buf.len(),
                )
            };
            match ret {
                // A special behavior of old cachefile driver which returns zero if there's no
                // pending requests instead of `ErrorKind::WouldBlock`.
                0 => return Ok(()),
                _i if _i > 0 => self.handle_one_request(&buf[0..ret as usize])?,
                _ => {
                    let err = Error::last_os_error();
                    match err.kind() {
                        ErrorKind::Interrupted => continue,
                        ErrorKind::WouldBlock => return Ok(()),
                        _ => return Err(err),
                    }
                }
            }
        }
    }

    fn handle_one_request(&self, buf: &[u8]) -> Result<()> {
        let hdr = FsCacheMsgHeader::try_from(buf)?;
        let buf = &buf[MSG_HEADER_SIZE..];

        match hdr.opcode {
            FsCacheOpCode::Open => {
                let msg = FsCacheMsgOpen::try_from(buf)?;
                self.handle_open_request(&hdr, &msg);
            }
            FsCacheOpCode::Close => {
                self.handle_close_request(&hdr);
            }
            FsCacheOpCode::Read => {
                let msg = FsCacheMsgRead::try_from(buf)?;
                self.handle_read_request(&hdr, &msg);
            }
        }

        Ok(())
    }

    fn handle_open_request(&self, hdr: &FsCacheMsgHeader, msg: &FsCacheMsgOpen) {
        // Drop the 'erofs,' prefix if any
        let domain_id = msg
            .volume_key
            .strip_prefix("erofs,")
            .unwrap_or(msg.volume_key.as_str());

        let key = generate_blob_key(domain_id, &msg.cookie_key);
        match self.get_config(&key) {
            None => {
                unsafe { libc::close(msg.fd as i32) };
                self.reply(&format!("copen {},{}", hdr.msg_id, -libc::ENOENT));
            }
            Some(cfg) => match cfg {
                BlobConfig::DataBlob(config) => {
                    let reply = self.handle_open_data_blob(hdr, msg, config);
                    self.reply(&reply);
                }
                BlobConfig::MetaBlob(config) => {
                    self.handle_open_bootstrap(hdr, msg, config);
                }
            },
        }
    }

    fn handle_open_data_blob(
        &self,
        hdr: &FsCacheMsgHeader,
        msg: &FsCacheMsgOpen,
        config: Arc<DataBlobConfig>,
    ) -> String {
        let mut state = self.state.lock().unwrap();
        if let Vacant(e) = state.id_to_object_map.entry(hdr.object_id) {
            let fsblob = Arc::new(RwLock::new(FsCacheBlobCache {
                cache: None,
                config: config.clone(),
                file: Arc::new(unsafe { File::from_raw_fd(msg.fd as RawFd) }),
            }));
            e.insert((FsCacheObject::DataBlob(fsblob.clone()), msg.fd));
            state.id_to_config_map.insert(hdr.object_id, config.clone());
            let blob_size = config.blob_info().deref().uncompressed_size();
            let barrier = Arc::new(Barrier::new(2));
            Self::init_blob_cache(fsblob, barrier.clone());
            // make sure that the blobcache init thread have gotten writer lock before user daemon
            // receives first request.
            barrier.wait();
            format!("copen {},{}", hdr.msg_id, blob_size)
        } else {
            unsafe { libc::close(msg.fd as i32) };
            format!("copen {},{}", hdr.msg_id, -libc::EALREADY)
        }
    }

    fn init_blob_cache(fsblob: Arc<RwLock<FsCacheBlobCache>>, barrier: Arc<Barrier>) {
        thread::spawn(move || {
            let mut guard = fsblob.write().unwrap();
            barrier.wait();
            //for now FsCacheBlobCache only init once, should not have blobcache associated with it
            assert!(guard.get_blob_cache().is_none());
            for _ in 0..BLOB_CACHE_INIT_RETRY {
                match Self::create_data_blob_object(&guard.config, guard.file.clone()) {
                    Err(e) => {
                        warn!("fscache: create_data_blob_object failed {}", e);
                        thread::sleep(time::Duration::from_millis(BLOB_CACHE_INIT_INTERVAL_MS));
                    }
                    Ok(blob) => {
                        guard.set_blob_cache(Some(blob.clone()));
                        if let Err(e) = Self::do_prefetch(&guard.config, blob.clone()) {
                            warn!(
                                "fscache: failed to prefetch data for blob {}, {}",
                                blob.blob_id(),
                                e
                            );
                        }
                        break;
                    }
                }
            }
        });
    }

    fn do_prefetch(cfg: &DataBlobConfig, blob: Arc<dyn BlobCache>) -> Result<()> {
        let blob_info = cfg.blob_info().deref();
        let cache_cfg = cfg.config_v2().get_cache_config()?;
        if !cache_cfg.prefetch.enable {
            return Ok(());
        }
        blob.start_prefetch()
            .map_err(|e| eother!(format!("failed to start prefetch worker, {}", e)))?;

        let size = match cache_cfg.prefetch.batch_size.checked_next_power_of_two() {
            None => nydus_api::default_batch_size() as u64,
            Some(1) => nydus_api::default_batch_size() as u64,
            Some(s) => s as u64,
        };
        let size = std::cmp::max(0x4_0000u64, size);
        let blob_size = blob_info.compressed_data_size();
        let count = (blob_size + size - 1) / size;
        let mut blob_req = Vec::with_capacity(count as usize);
        let mut pre_offset = 0u64;
        for _i in 0..count {
            blob_req.push(BlobPrefetchRequest {
                blob_id: blob_info.blob_id().to_owned(),
                offset: pre_offset,
                len: cmp::min(size, blob_size - pre_offset),
            });
            pre_offset += size;
            if pre_offset >= blob_size {
                break;
            }
        }

        let id = blob.blob_id();
        info!("fscache: start to prefetch data for blob {}", id);
        if let Err(e) = blob.prefetch(blob.clone(), &blob_req, &[]) {
            warn!("fscache: failed to prefetch data for blob {}, {}", id, e);
        }

        Ok(())
    }

    /// The `fscache` factory essentially creates a namespace for blob objects cached by the
    /// fscache subsystem. The data blob files will be managed the in kernel fscache driver,
    /// the chunk map file will be managed by the userspace daemon. We need to figure out the
    /// way to share blob/chunkamp files with filecache manager.
    fn create_data_blob_object(
        config: &DataBlobConfig,
        file: Arc<File>,
    ) -> Result<Arc<dyn BlobCache>> {
        let mut blob_info = config.blob_info().deref().clone();
        blob_info.set_fscache_file(Some(file));
        let blob_ref = Arc::new(blob_info);
        BLOB_FACTORY.new_blob_cache(config.config_v2(), &blob_ref)
    }

    fn fill_bootstrap_cache(bootstrap: Arc<FsCacheBootstrap>) -> Result<u64> {
        // Safe because bootstrap.bootstrap_file/cache_file are valid.
        let mut src = unsafe { File::from_raw_fd(bootstrap.bootstrap_file.as_raw_fd()) };
        let mut dst = unsafe { File::from_raw_fd(bootstrap.cache_file.as_raw_fd()) };
        let ret = copy(&mut src, &mut dst);
        std::mem::forget(src);
        std::mem::forget(dst);
        ret.map_err(|e| {
            warn!("failed to copy content from bootstap into cache fd, {}", e);
            e
        })
    }

    fn handle_open_bootstrap(
        &self,
        hdr: &FsCacheMsgHeader,
        msg: &FsCacheMsgOpen,
        config: Arc<MetaBlobConfig>,
    ) {
        let path = config.path().display();
        let condvar = Arc::new((Mutex::new(false), Condvar::new()));
        let condvar2 = condvar.clone();
        let mut state = self.get_state();

        let ret: i64 = if let Vacant(e) = state.id_to_object_map.entry(hdr.object_id) {
            match OpenOptions::new().read(true).open(config.path()) {
                Err(e) => {
                    warn!("fscache: failed to open bootstrap file {}, {}", path, e);
                    -libc::ENOENT as i64
                }
                Ok(f) => match f.metadata() {
                    Err(e) => {
                        warn!("fscache: failed to open bootstrap file {}, {}", path, e);
                        -libc::ENOENT as i64
                    }
                    Ok(md) => {
                        let cache_file = unsafe { File::from_raw_fd(msg.fd as RawFd) };
                        let bootstrap = Arc::new(FsCacheBootstrap {
                            bootstrap_file: f,
                            cache_file,
                        });
                        let object = FsCacheObject::Bootstrap(bootstrap.clone());
                        e.insert((object, msg.fd));
                        ASYNC_RUNTIME.spawn_blocking(|| async move {
                            // Ensure copen reply message has been sent to kernel.
                            {
                                let (m, c) = condvar.as_ref();
                                let mut g = m.lock().unwrap();
                                while !*g {
                                    g = c.wait(g).unwrap();
                                }
                            }

                            for _i in 0..3 {
                                if Self::fill_bootstrap_cache(bootstrap.clone()).is_ok() {
                                    break;
                                }
                                tokio::time::sleep(time::Duration::from_secs(2)).await;
                            }
                        });
                        md.len() as i64
                    }
                },
            }
        } else {
            -libc::EALREADY as i64
        };

        if ret < 0 {
            unsafe { libc::close(msg.fd as i32) };
        }
        self.reply(&format!("copen {},{}", hdr.msg_id, ret));
        if ret >= 0 {
            let (m, c) = condvar2.as_ref();
            *m.lock().unwrap() = true;
            c.notify_one();
        }
    }

    fn handle_close_request(&self, hdr: &FsCacheMsgHeader) {
        let mut state = self.get_state();

        if let Some((FsCacheObject::DataBlob(fsblob), _)) =
            state.id_to_object_map.remove(&hdr.object_id)
        {
            // Safe to unwrap() because `id_to_config_map` and `id_to_object_map` is kept
            // in consistence.
            let config = state.id_to_config_map.remove(&hdr.object_id).unwrap();
            let factory_config = config.config_v2();
            let guard = fsblob.read().unwrap();
            match guard.get_blob_cache() {
                Some(blob) => {
                    if let Ok(cache_cfg) = factory_config.get_cache_config() {
                        if cache_cfg.prefetch.enable {
                            let _ = blob.stop_prefetch();
                        }
                    }
                    let id = blob.blob_id().to_string();
                    drop(blob);
                    BLOB_FACTORY.gc(Some((factory_config, &id)));
                }
                _ => warn!("fscache: blob object not ready {}", hdr.object_id),
            }
        }
    }

    fn handle_read_request(&self, hdr: &FsCacheMsgHeader, msg: &FsCacheMsgRead) {
        let fd: u32;

        match self.get_object(hdr.object_id) {
            None => {
                warn!(
                    "fscache: no cached file object found for obj_id {}",
                    hdr.object_id
                );
                return;
            }
            Some((FsCacheObject::DataBlob(fsblob), u)) => {
                fd = u;
                let guard = fsblob.read().unwrap();
                match guard.get_blob_cache() {
                    Some(blob) => match blob.get_blob_object() {
                        None => {
                            warn!("fscache: internal error: cached object is not BlobCache objects")
                        }
                        Some(obj) => {
                            if let Err(e) = obj.fetch_range_uncompressed(msg.off, msg.len) {
                                error!("fscache: failed to read data from blob object: {}", e,);
                            }
                        }
                    },
                    _ => {
                        //TODO: maybe we should retry init blob object here
                        warn!("fscache: blob object not ready");
                    }
                }
            }
            Some((FsCacheObject::Bootstrap(bs), u)) => {
                // TODO: should we feed the bootstrap at together to improve performance?
                fd = u;
                let base = unsafe {
                    libc::mmap(
                        std::ptr::null_mut(),
                        msg.len as usize,
                        libc::PROT_READ,
                        libc::MAP_SHARED,
                        bs.bootstrap_file.as_raw_fd(),
                        msg.off as libc::off_t,
                    )
                };
                if base == libc::MAP_FAILED {
                    warn!(
                        "fscache: failed to mmap bootstrap file, {}",
                        std::io::Error::last_os_error()
                    );
                } else {
                    let ret = unsafe {
                        libc::pwrite(
                            bs.cache_file.as_raw_fd(),
                            base,
                            msg.len as usize,
                            msg.off as libc::off_t,
                        )
                    };
                    let _ = unsafe { libc::munmap(base, msg.len as usize) };
                    if ret < 0 {
                        warn!(
                            "fscache: failed to write bootstrap blob data to cached file, {}",
                            std::io::Error::last_os_error()
                        );
                    }
                }
            }
        }

        if let Err(e) = unsafe { fscache_cread(fd as i32, hdr.msg_id as u64) } {
            warn!("failed to send reply for cread request, {}", e);
        }
    }

    /// Reclaim unused facache objects.
    pub fn cull_cache(&self, blob_id: String) -> Result<()> {
        let children = fs::read_dir(self.cache_dir.clone())?;
        let mut res = true;
        // This is safe, because only api server which is a single thread server will call this func,
        // and no other func will change cwd.
        let cwd_old = env::current_dir()?;

        info!("try to cull blob {}", blob_id);

        // calc blob path in all volumes then try to cull them
        for child in children {
            let child = child?;
            let path = child.path();
            let file_name = match child.file_name().to_str() {
                Some(n) => n.to_string(),
                None => {
                    warn!("failed to get file name of {}", child.path().display());
                    continue;
                }
            };
            if !path.is_dir() || !file_name.starts_with("Ierofs,") {
                continue;
            }

            // get volume_key form volume dir name e.g. Ierofs,SharedDomain
            let volume_key = &file_name[1..];
            let (cookie_dir, cookie_name) = self.generate_cookie_path(&path, volume_key, &blob_id);
            let cookie_path = cookie_dir.join(&cookie_name);
            if !cookie_path.is_file() {
                continue;
            }
            let cookie_path = cookie_path.display();

            match self.inuse(&cookie_dir, &cookie_name) {
                Err(e) => {
                    warn!("blob {} call inuse err {}, cull failed!", cookie_path, e);
                    res = false;
                }
                Ok(true) => {
                    warn!("blob {} in use, skip!", cookie_path);
                    res = false;
                }
                Ok(false) => {
                    if let Err(e) = self.cull(&cookie_dir, &cookie_name) {
                        warn!("blob {} call cull err {}, cull failed!", cookie_path, e);
                        res = false;
                    }
                }
            }
        }

        env::set_current_dir(&cwd_old)?;
        if res {
            Ok(())
        } else {
            Err(eother!("failed to cull blob objects from fscache"))
        }
    }

    #[inline]
    fn hash_32(&self, val: u32) -> u32 {
        val * 0x61C88647
    }

    #[inline]
    fn rol32(&self, word: u32, shift: i32) -> u32 {
        word << (shift & 31) | (word >> ((-shift) & 31))
    }

    #[inline]
    fn round_up_u32(&self, size: usize) -> usize {
        (size + 3) / 4 * 4
    }

    //address from kernel fscache_hash()
    fn fscache_hash(&self, salt: u32, data: &[u8]) -> u32 {
        assert_eq!(data.len() % 4, 0);

        let mut x = 0;
        let mut y = salt;
        let mut buf_le32: [u8; 4] = [0; 4];
        let n = data.len() / 4;

        for i in 0..n {
            buf_le32.clone_from_slice(&data[i * 4..i * 4 + 4]);
            let a = unsafe { std::mem::transmute::<[u8; 4], u32>(buf_le32) }.to_le();
            x ^= a;
            y ^= x;
            x = self.rol32(x, 7);
            x += y;
            y = self.rol32(y, 20);
            y *= 9;
        }
        self.hash_32(y ^ self.hash_32(x))
    }

    fn generate_cookie_path(
        &self,
        volume_path: &Path,
        volume_key: &str,
        cookie_key: &str,
    ) -> (PathBuf, String) {
        //calc volume hash
        let mut volume_hash_key: Vec<u8> =
            Vec::with_capacity(self.round_up_u32(volume_key.len() + 2));
        volume_hash_key.push(volume_key.len() as u8);
        volume_hash_key.append(&mut volume_key.as_bytes().to_vec());
        volume_hash_key.resize(volume_hash_key.capacity(), 0);
        let volume_hash = self.fscache_hash(0, volume_hash_key.as_slice());

        //calc cookie hash
        let mut cookie_hash_key: Vec<u8> = Vec::with_capacity(self.round_up_u32(cookie_key.len()));
        cookie_hash_key.append(&mut cookie_key.as_bytes().to_vec());
        cookie_hash_key.resize(cookie_hash_key.capacity(), 0);
        let dir_hash = self.fscache_hash(volume_hash, cookie_hash_key.as_slice());

        let dir = format!("@{:02x}", dir_hash as u8);
        let cookie = format!("D{}", cookie_key);
        (volume_path.join(dir), cookie)
    }

    fn inuse(&self, cookie_dir: &Path, cookie_name: &str) -> Result<bool> {
        env::set_current_dir(&cookie_dir)?;
        let msg = format!("inuse {}", cookie_name);
        let ret = unsafe {
            libc::write(
                self.file.as_raw_fd(),
                msg.as_bytes().as_ptr() as *const u8 as *const libc::c_void,
                msg.len(),
            )
        };
        if ret < 0 {
            let err = Error::last_os_error();
            if let Some(e) = err.raw_os_error() {
                if e == libc::EBUSY {
                    return Ok(true);
                }
            }
            Err(err)
        } else {
            Ok(false)
        }
    }

    fn cull(&self, cookie_dir: &Path, cookie_name: &str) -> Result<()> {
        env::set_current_dir(&cookie_dir)?;
        let msg = format!("cull {}", cookie_name);
        let ret = unsafe {
            libc::write(
                self.file.as_raw_fd(),
                msg.as_bytes().as_ptr() as *const u8 as *const libc::c_void,
                msg.len(),
            )
        };
        if ret as usize != msg.len() {
            Err(Error::last_os_error())
        } else {
            Ok(())
        }
    }

    #[inline]
    fn reply(&self, result: &str) {
        // Safe because the fd and data buffer are valid. And we trust the fscache driver which
        // will never return error for write operations.
        let ret = unsafe {
            libc::write(
                self.file.as_raw_fd(),
                result.as_bytes().as_ptr() as *const u8 as *const libc::c_void,
                result.len(),
            )
        };
        if ret as usize != result.len() {
            warn!(
                "fscache: failed to send reply \"{}\", {}",
                result,
                std::io::Error::last_os_error()
            );
        }
    }

    #[inline]
    fn get_state(&self) -> MutexGuard<FsCacheState> {
        self.state.lock().unwrap()
    }

    #[inline]
    fn get_object(&self, object_id: u32) -> Option<(FsCacheObject, u32)> {
        self.get_state().id_to_object_map.get(&object_id).cloned()
    }

    #[inline]
    fn get_config(&self, key: &str) -> Option<BlobConfig> {
        self.get_state().blob_cache_mgr.get_config(key)
    }
}

impl AsRawFd for FsCacheHandler {
    fn as_raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_op_code() {
        assert_eq!(FsCacheOpCode::try_from(0).unwrap(), FsCacheOpCode::Open);
        assert_eq!(FsCacheOpCode::try_from(1).unwrap(), FsCacheOpCode::Close);
        assert_eq!(FsCacheOpCode::try_from(2).unwrap(), FsCacheOpCode::Read);
        FsCacheOpCode::try_from(3).unwrap_err();
    }

    #[test]
    fn test_msg_header() {
        let hdr = FsCacheMsgHeader::try_from(
            vec![1u8, 0, 0, 0, 2, 0, 0, 0, 17, 0, 0, 0, 2u8, 0, 0, 0, 0].as_slice(),
        )
        .unwrap();
        assert_eq!(hdr.msg_id, 0x1);
        assert_eq!(hdr.opcode, FsCacheOpCode::Read);
        assert_eq!(hdr.len, 17);
        assert_eq!(hdr.object_id, 0x2);

        FsCacheMsgHeader::try_from(vec![0u8, 0, 0, 1, 0, 0, 0, 3, 0, 0, 0, 13, 0].as_slice())
            .unwrap_err();
        FsCacheMsgHeader::try_from(vec![0u8, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 13].as_slice())
            .unwrap_err();
        FsCacheMsgHeader::try_from(vec![0u8, 0, 0, 1, 0, 0, 0, 2, 0, 0].as_slice()).unwrap_err();
        FsCacheMsgHeader::try_from(vec![].as_slice()).unwrap_err();
    }
}

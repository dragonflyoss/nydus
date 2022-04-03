// Copyright (C) 2022 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! Handler to cooperate with Linux fscache subsystem for blob cache.

use std::collections::HashMap;
use std::convert::TryFrom;
use std::fs::{File, OpenOptions};
use std::io::{Error, ErrorKind, Result, Write};
use std::ops::Deref;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::ptr::read_unaligned;
use std::string::String;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier, Mutex, MutexGuard};

use mio::unix::SourceFd;
use mio::{Events, Interest, Poll, Token, Waker};
use storage::cache::BlobCache;
use storage::factory::BLOB_FACTORY;

use crate::blob_cache::{
    BlobCacheMgr, FsCacheBootstrapConfig, FsCacheDataBlobConfig, FsCacheObjectConfig,
};

ioctl_write_int!(fscache_cread, 0x98, 1);

/// Maximum size of fscache request message from kernel.
const MIN_DATA_BUF_SIZE: usize = 1024;
const MSG_HEADER_SIZE: usize = 12;
const MSG_OPEN_SIZE: usize = 16;
const MSG_CLOSE_SIZE: usize = 4;
const MSG_READ_SIZE: usize = 20;

const TOKEN_EVENT_WAKER: usize = 1;
const TOKEN_EVENT_FSCACHE: usize = 2;

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
            _ => Err(einval!(format!("invalid fscache operation code {}", value))),
        }
    }
}

/// Common header for request messages.
#[repr(C)]
#[derive(Debug, Eq, PartialEq)]
struct FsCacheMsgHeader {
    /// Message identifier to associate reply with request by the fscache driver.
    id: u32,
    /// Message operation code.
    opcode: FsCacheOpCode,
    /// Message length, including message header and message body.
    len: u32,
}

impl TryFrom<&[u8]> for FsCacheMsgHeader {
    type Error = Error;

    fn try_from(value: &[u8]) -> std::result::Result<Self, Self::Error> {
        if value.len() < MSG_HEADER_SIZE {
            return Err(einval!(format!(
                "fscache request message size is too small, {}",
                value.len()
            )));
        }

        // Safe because we have verified buffer size.
        let id = unsafe { read_unaligned(value[0..4].as_ptr() as *const u32) };
        let opcode = unsafe { read_unaligned(value[4..8].as_ptr() as *const u32) };
        let len = unsafe { read_unaligned(value[8..12].as_ptr() as *const u32) };
        let opcode = FsCacheOpCode::try_from(opcode)?;
        if len as usize != value.len() {
            return Err(einval!(format!(
                "message length {} does not match length from message header {}",
                value.len(),
                len
            )));
        }

        Ok(FsCacheMsgHeader { id, opcode, len })
    }
}

/// Request message to open a file.
///
/// The opened file should be kept valid until corresponding `CLOSE` message has been received
/// from the fscache driver.
#[derive(Default, Debug, Eq, PartialEq)]
struct FsCacheMsgOpen {
    fd: u32,
    flags: u32,
    volume_key: String,
    cookie_key: String,
}

impl TryFrom<&[u8]> for FsCacheMsgOpen {
    type Error = Error;

    fn try_from(value: &[u8]) -> std::result::Result<Self, Self::Error> {
        if value.len() < MSG_OPEN_SIZE {
            return Err(einval!(format!(
                "fscache request message size is too small, {}",
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
                "invalid volume/cookie key length in fscache OPEN request"
            ));
        }
        let total_sz = (volume_key_size + cookie_key_size) as usize + MSG_OPEN_SIZE;
        if value.len() < total_sz {
            return Err(einval!("invalid message length for fscache OPEN request"));
        }
        let pos = MSG_OPEN_SIZE + volume_key_size as usize;
        let volume_key = String::from_utf8(value[MSG_OPEN_SIZE..pos].to_vec())
            .map_err(|_e| einval!("invalid volume key in fscache OPEN request"))?
            .trim_end_matches('\0')
            .to_string();
        let cookie_key = String::from_utf8(value[pos..pos + cookie_key_size as usize].to_vec())
            .map_err(|_e| einval!("invalid cookie key in fscache OPEN request"))?;

        Ok(FsCacheMsgOpen {
            fd,
            flags,
            volume_key,
            cookie_key,
        })
    }
}

/// Request message to close a file.
///
/// Once replied a `CLOSE` message, a following `READ` requests against the same file should be
/// rejected. The corresponding file descriptor may be actually closed after sending the reply
/// message. But it should be close in limited delay to avoid conflicting when re-opening the
/// same file again.
#[repr(C)]
#[derive(Default, Debug, Eq, PartialEq)]
struct FsCacheMsgClose {
    fd: u32,
}

impl TryFrom<&[u8]> for FsCacheMsgClose {
    type Error = Error;

    fn try_from(value: &[u8]) -> std::result::Result<Self, Self::Error> {
        if value.len() < MSG_CLOSE_SIZE {
            return Err(einval!(format!(
                "fscache request message size is too small, {}",
                value.len()
            )));
        }

        // Safe because we have verified buffer size.
        let fd = unsafe { read_unaligned(value[0..4].as_ptr() as *const u32) };

        Ok(FsCacheMsgClose { fd })
    }
}

/// Request message to feed requested data into the cache file.
#[repr(C)]
#[derive(Default, Debug, Eq, PartialEq)]
struct FsCacheMsgRead {
    off: u64,
    len: u64,
    fd: u32,
}

impl TryFrom<&[u8]> for FsCacheMsgRead {
    type Error = Error;

    fn try_from(value: &[u8]) -> std::result::Result<Self, Self::Error> {
        if value.len() < MSG_READ_SIZE {
            return Err(einval!(format!(
                "fscache request message size is too small, {}",
                value.len()
            )));
        }

        // Safe because we have verified buffer size.
        let off = unsafe { read_unaligned(value[0..8].as_ptr() as *const u64) };
        let len = unsafe { read_unaligned(value[8..16].as_ptr() as *const u64) };
        let fd = unsafe { read_unaligned(value[16..20].as_ptr() as *const u32) };

        Ok(FsCacheMsgRead { off, len, fd })
    }
}

struct FsCacheBootStrap {
    bootstrap_file: File,
    cache_file: File,
}

#[derive(Clone)]
enum FsCacheObject {
    DataBlob(Arc<dyn BlobCache>),
    Bootstrap(Arc<FsCacheBootStrap>),
}

/// Struct to maintain cached file objects.
#[derive(Default)]
struct FsCacheState {
    fd_to_object_map: HashMap<u32, FsCacheObject>,
    fd_to_config_map: HashMap<u32, Arc<FsCacheDataBlobConfig>>,
    blob_cache_mgr: Arc<BlobCacheMgr>,
}

/// Handler to cooperate with Linux fscache driver to manage cached blob objects.
///
/// The `FsCacheHandler` create a communication channel with the Linux fscache driver, configure
/// the communication session and serves all requests from the fscache driver.
pub struct FsCacheHandler {
    active: AtomicBool,
    barrier: Barrier,
    file: File,
    state: Arc<Mutex<FsCacheState>>,
    poller: Mutex<Poll>,
    waker: Arc<Waker>,
}

impl FsCacheHandler {
    /// Create a new instance of `FsCacheService`.
    pub fn new(
        path: &str,
        dir: &str,
        tag: Option<&str>,
        blob_cache_mgr: Arc<BlobCacheMgr>,
    ) -> Result<Self> {
        info!(
            "create FsCacheHandler with dir {}, tag {}",
            dir,
            tag.unwrap_or("<None>")
        );

        let mut file = OpenOptions::new()
            .write(true)
            .read(true)
            .create(false)
            .open(path)?;
        let poller =
            Poll::new().map_err(|_e| eother!("Failed to create poller for fscache service"))?;
        let waker = Waker::new(poller.registry(), Token(TOKEN_EVENT_WAKER))
            .map_err(|_e| eother!("Failed to create waker for fscache service"))?;
        poller
            .registry()
            .register(
                &mut SourceFd(&file.as_raw_fd()),
                Token(TOKEN_EVENT_FSCACHE),
                Interest::READABLE,
            )
            .map_err(|_e| eother!("Failed to register fd for fscache service"))?;

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
            fd_to_object_map: Default::default(),
            fd_to_config_map: Default::default(),
            blob_cache_mgr,
        };

        Ok(FsCacheHandler {
            active: AtomicBool::new(true),
            barrier: Barrier::new(2),
            file,
            state: Arc::new(Mutex::new(state)),
            poller: Mutex::new(poller),
            waker: Arc::new(waker),
        })
    }

    /// Stop the fscache event loop.
    pub fn stop(&self) {
        self.active.store(false, Ordering::Release);
        if let Err(e) = self.waker.wake() {
            error!("Failed to signal fscache worker thread to exit, {}", e);
        }
        self.barrier.wait();
    }

    /// Run the event loop to handle all requests from kernel fscache driver.
    ///
    /// This method should only be invoked by a single thread, which will poll the fscache fd
    /// and dispatch requests from fscache fd to other working threads.
    pub fn run_loop(&self) -> Result<()> {
        let mut events = Events::with_capacity(64);
        let mut buf = [0u8; MIN_DATA_BUF_SIZE];

        loop {
            match self.poller.lock().unwrap().poll(&mut events, None) {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    warn!("Failed to poll events for fscache service");
                    return Err(e);
                }
            }

            for event in events.iter() {
                if event.is_error() {
                    error!("Got error event for fscache poller");
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
                let msg = FsCacheMsgClose::try_from(buf)?;
                self.handle_close_request(&hdr, &msg);
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
        let domain_id = match msg.volume_key.clone().strip_prefix("erofs,") {
            None => msg.volume_key.clone(),
            Some(str) => str.to_string(),
        };
        let key = domain_id + "-" + &msg.cookie_key;
        let config = self.get_config(&key);
        let msg = match config {
            None => format!("cinit {},{}", hdr.id, -libc::ENOENT),
            Some(info) => match info {
                FsCacheObjectConfig::DataBlob(config) => {
                    self.handle_open_data_blob(hdr, msg, config)
                }
                FsCacheObjectConfig::Bootstrap(config) => {
                    self.handle_open_bootstrap(hdr, msg, config)
                }
            },
        };
        self.reply(&msg);
    }

    fn handle_open_data_blob(
        &self,
        hdr: &FsCacheMsgHeader,
        msg: &FsCacheMsgOpen,
        config: Arc<FsCacheDataBlobConfig>,
    ) -> String {
        match self.create_data_blob_object(&config, hdr.id, msg.fd) {
            Err(s) => s,
            Ok((blob, blob_size)) => {
                let mut state = self.state.lock().unwrap();
                if state.fd_to_object_map.contains_key(&msg.fd) {
                    format!("cinit {},{}", hdr.id, -libc::EALREADY)
                } else {
                    state
                        .fd_to_object_map
                        .insert(msg.fd, FsCacheObject::DataBlob(blob));
                    state.fd_to_config_map.insert(msg.fd, config.clone());
                    format!("cinit {},{}", hdr.id, blob_size)
                }
            }
        }
    }

    /// The `fscache` factory essentially creates a namespace for blob objects cached by the
    /// fscache subsystem. The data blob files will be managed the in kernel fscache driver,
    /// the chunk map file will be managed by the userspace daemon. We need to figure out the
    /// way to share blob/chunkamp files with filecache manager.
    fn create_data_blob_object(
        &self,
        config: &FsCacheDataBlobConfig,
        id: u32,
        fd: u32,
    ) -> std::result::Result<(Arc<dyn BlobCache>, u64), String> {
        let mut blob_info = config.blob_info().deref().clone();
        // `BlobInfo` from the configuration cache should not have fscache file associated with it.
        assert!(blob_info.get_fscache_file().is_none());

        // Safe because we trust the kernel fscache driver.
        let file = unsafe { File::from_raw_fd(fd as RawFd) };
        blob_info.set_fscache_file(Some(Arc::new(file)));
        let blob_ref = Arc::new(blob_info);

        match BLOB_FACTORY.new_blob_cache(config.factory_config(), &blob_ref) {
            Err(_e) => Err(format!("cinit {},{}", id, -libc::ENOENT)),
            Ok(blob) => {
                let blob_size = match blob.blob_size() {
                    Err(_e) => return Err(format!("cinit {},{}", id, -libc::EIO)),
                    Ok(v) => v,
                };
                Ok((blob, blob_size))
            }
        }
    }

    fn handle_open_bootstrap(
        &self,
        hdr: &FsCacheMsgHeader,
        msg: &FsCacheMsgOpen,
        config: Arc<FsCacheBootstrapConfig>,
    ) -> String {
        let mut state = self.get_state();
        if state.fd_to_object_map.contains_key(&msg.fd) {
            return format!("copen {},{}", hdr.id, -libc::EALREADY);
        }

        match OpenOptions::new().read(true).open(config.path()) {
            Err(e) => {
                warn!("Failed to open bootstrap file {}, {}", config.path(), e);
                format!("copen {},{}", hdr.id, -libc::ENOENT)
            }
            Ok(f) => match f.metadata() {
                Err(e) => {
                    warn!("Failed to open bootstrap file {}, {}", config.path(), e);
                    format!("copen {},{}", hdr.id, -libc::ENOENT)
                }
                Ok(md) => {
                    let cache_file = unsafe { File::from_raw_fd(msg.fd as RawFd) };
                    let object = FsCacheObject::Bootstrap(Arc::new(FsCacheBootStrap {
                        bootstrap_file: f,
                        cache_file,
                    }));
                    state.fd_to_object_map.insert(msg.fd, object);
                    format!("copen {},{}", hdr.id, md.len())
                }
            },
        }
    }

    fn handle_close_request(&self, _hdr: &FsCacheMsgHeader, msg: &FsCacheMsgClose) {
        let mut state = self.get_state();

        if let Some(FsCacheObject::DataBlob(blob)) = state.fd_to_object_map.remove(&msg.fd) {
            let config = state.fd_to_config_map.remove(&msg.fd).unwrap();
            BLOB_FACTORY.gc(Some((config.factory_config(), blob.blob_id())));
        }
    }

    fn handle_read_request(&self, hdr: &FsCacheMsgHeader, msg: &FsCacheMsgRead) {
        match self.get_object(msg.fd) {
            None => warn!("No cached file object found for fd {}", msg.fd),
            Some(FsCacheObject::DataBlob(blob)) => match blob.get_blob_object() {
                None => {
                    warn!("Internal error: blob object used by fscache is not BlobCache objects")
                }
                Some(obj) => match obj.fetch_range_uncompressed(msg.off, msg.len) {
                    Ok(v) if v == msg.len as usize => {}
                    _ => debug!("Failed to read data from blob object"),
                },
            },
            Some(FsCacheObject::Bootstrap(bs)) => {
                // TODO: should we feed the bootstrap at together to improve performance?
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
                        "Failed to mmap bootstrap file, {}",
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
                            "Failed to write bootstrap blob data to cached file, {}",
                            std::io::Error::last_os_error()
                        );
                    }
                }
            }
        }

        unsafe { fscache_cread(msg.fd as i32, hdr.id as u64).unwrap() };
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
                "Failed to reply \"{}\", {}",
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
    fn get_object(&self, fd: u32) -> Option<FsCacheObject> {
        self.get_state().fd_to_object_map.get(&fd).cloned()
    }

    #[inline]
    fn get_config(&self, key: &str) -> Option<FsCacheObjectConfig> {
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
        let hdr =
            FsCacheMsgHeader::try_from(vec![1u8, 0, 0, 0, 2, 0, 0, 0, 13, 0, 0, 0, 0].as_slice())
                .unwrap();
        assert_eq!(hdr.id, 0x1);
        assert_eq!(hdr.opcode, FsCacheOpCode::Read);
        assert_eq!(hdr.len, 0xd);

        FsCacheMsgHeader::try_from(vec![0u8, 0, 0, 1, 0, 0, 0, 3, 0, 0, 0, 13, 0].as_slice())
            .unwrap_err();
        FsCacheMsgHeader::try_from(vec![0u8, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 13].as_slice())
            .unwrap_err();
        FsCacheMsgHeader::try_from(vec![0u8, 0, 0, 1, 0, 0, 0, 2, 0, 0].as_slice()).unwrap_err();
        FsCacheMsgHeader::try_from(vec![].as_slice()).unwrap_err();
    }
}

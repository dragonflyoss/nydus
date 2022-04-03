// Copyright (C) 2022 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! Handler to cooperate with Linux fscache subsystem for blob cache.

use std::collections::HashMap;
use std::convert::TryFrom;
use std::fs::{File, OpenOptions};
use std::io::{Error, ErrorKind, Result};
use std::mem::size_of;
use std::ops::Deref;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::ptr::read_unaligned;
use std::string::String;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier, Mutex, MutexGuard};

use mio::unix::SourceFd;
use mio::{Events, Interest, Poll, Token, Waker};
use rafs::metadata::{RafsMode, RafsSuper};
use storage::cache::BlobCache;
use storage::device::BlobInfo;
use storage::factory::{FactoryConfig, BLOB_FACTORY};

/// Maximum size of fscache request message from kernel.
const MIN_DATA_BUF_SIZE: usize = 1024;
const MSG_HEADER_SIZE: usize = size_of::<FsCacheMsgHeader>();
const MSG_OPEN_SIZE: usize = 16;
const MSG_CLOSE_SIZE: usize = size_of::<FsCacheMsgClose>();
const MSG_READ_SIZE: usize = size_of::<FsCacheMsgRead>();
const CACHEFILES_OPEN_WANT_CACHE_SIZE: u32 = 0x1;

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
    volume_key_len: u32,
    cookie_key_len: u32,
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
        let volume_key_len = unsafe { read_unaligned(value[0..4].as_ptr() as *const u32) };
        let cookie_key_len = unsafe { read_unaligned(value[4..8].as_ptr() as *const u32) };
        let fd = unsafe { read_unaligned(value[8..12].as_ptr() as *const u32) };
        let flags = unsafe { read_unaligned(value[12..16].as_ptr() as *const u32) };
        if volume_key_len.checked_add(cookie_key_len).is_none()
            || (volume_key_len + cookie_key_len)
                .checked_add(MSG_OPEN_SIZE as u32)
                .is_none()
        {
            return Err(einval!(
                "invalid volume/cookie key length in fscache OPEN request"
            ));
        }
        let total_sz = (volume_key_len + cookie_key_len) as usize + MSG_OPEN_SIZE;
        if value.len() < total_sz {
            return Err(einval!("invalid message length for fscache OPEN request"));
        }
        let pos = MSG_OPEN_SIZE + volume_key_len as usize;
        let volume_key = String::from_utf8(value[MSG_OPEN_SIZE..pos].to_vec())
            .map_err(|_e| einval!("invalid volume key in fscache OPEN request"))?;
        let cookie_key = String::from_utf8(value[pos..pos + cookie_key_len as usize].to_vec())
            .map_err(|_e| einval!("invalid cookie key in fscache OPEN request"))?;

        Ok(FsCacheMsgOpen {
            volume_key_len,
            cookie_key_len,
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

#[derive(Clone)]
struct FsCacheBootstrapConfig {
    blob_id: String,
    scoped_blob_id: String,
    path: String,
    factory_config: Arc<FactoryConfig>,
}

#[derive(Clone)]
struct FsCacheDataBlobConfig {
    blob_info: Arc<BlobInfo>,
    scoped_blob_id: String,
    factory_config: Arc<FactoryConfig>,
}

#[derive(Clone)]
enum FsCacheObjectConfig {
    DataBlob(Arc<FsCacheDataBlobConfig>),
    Bootstrap(Arc<FsCacheBootstrapConfig>),
}

impl FsCacheObjectConfig {
    fn new_data_blob(
        domain_id: String,
        blob_info: Arc<BlobInfo>,
        factory_config: Arc<FactoryConfig>,
    ) -> Self {
        let scoped_blob_id = domain_id + "-" + blob_info.blob_id();
        FsCacheObjectConfig::DataBlob(Arc::new(FsCacheDataBlobConfig {
            blob_info,
            scoped_blob_id,
            factory_config,
        }))
    }

    fn new_bootstrap_blob(
        domain_id: String,
        blob_id: String,
        path: String,
        factory_config: Arc<FactoryConfig>,
    ) -> Self {
        let scoped_blob_id = domain_id + "-" + &blob_id;
        FsCacheObjectConfig::Bootstrap(Arc::new(FsCacheBootstrapConfig {
            blob_id,
            scoped_blob_id,
            path,
            factory_config,
        }))
    }

    fn get_key(&self) -> &str {
        match self {
            FsCacheObjectConfig::Bootstrap(o) => &o.scoped_blob_id,
            FsCacheObjectConfig::DataBlob(o) => &o.scoped_blob_id,
        }
    }
}

struct FsCacheBootStrap {
    bootstrap_file: File,
    cache_file: File,
}

#[derive(Clone)]
#[allow(unused)]
enum FsCacheObject {
    DataBlob(Arc<dyn BlobCache>),
    Bootstrap(Arc<FsCacheBootStrap>),
}

/// Struct to maintain cached file objects.
#[derive(Default)]
struct FsCacheState {
    fd_to_object_map: HashMap<u32, FsCacheObject>,
    id_to_config_map: HashMap<String, FsCacheObjectConfig>,
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
    pub fn new(path: &str, dir: &str, tag: Option<&str>) -> Result<Self> {
        let poller =
            Poll::new().map_err(|_e| eother!("Failed to create poller for fscache service"))?;
        let waker = Waker::new(poller.registry(), Token(TOKEN_EVENT_WAKER))
            .map_err(|_e| eother!("Failed to create waker for fscache service"))?;
        let file = OpenOptions::new()
            .write(true)
            .read(true)
            .create(false)
            .custom_flags(libc::O_NONBLOCK)
            .open(path)?;
        poller
            .registry()
            .register(
                &mut SourceFd(&file.as_raw_fd()),
                Token(TOKEN_EVENT_FSCACHE),
                Interest::READABLE,
            )
            .map_err(|_e| eother!("Failed to register fd for fscache service"))?;

        println!("{} {}", dir, tag.unwrap_or_default());
        /*
        let msg = format!("dir {}", dir);
        file.write_all(msg.as_bytes())?;
        if let Some(tag) = tag {
            let msg = format!("tag {}", tag);
            file.write_all(msg.as_bytes())?;
        }
        file.write_all("bind ondemand".as_bytes())?;
         */

        Ok(FsCacheHandler {
            active: AtomicBool::new(true),
            barrier: Barrier::new(2),
            file,
            poller: Mutex::new(poller),
            waker: Arc::new(waker),
            state: Arc::new(Mutex::new(FsCacheState::default())),
        })
    }

    /// Add a blob object to be managed by the `FsCacheHandler`.
    ///
    /// The `domain_id` and `blob_id` forms a unique identifier to identify cached objects.
    /// That means `domain_id` is used to divide cached objects into groups and blobs with the same
    /// `blob_id` may exist in different groups.
    pub fn add_blob_object(
        &self,
        domain_id: String,
        blob_info: Arc<BlobInfo>,
        factory_config: Arc<FactoryConfig>,
    ) -> Result<()> {
        let config = FsCacheObjectConfig::new_data_blob(domain_id, blob_info, factory_config);
        let mut state = self.get_state();
        if state.id_to_config_map.contains_key(config.get_key()) {
            Err(Error::new(
                ErrorKind::AlreadyExists,
                "blob configuration information already exists",
            ))
        } else {
            state
                .id_to_config_map
                .insert(config.get_key().to_string(), config);
            Ok(())
        }
    }

    /// Add a metadata blob object to be managed by the `FsCacheHandler`.
    ///
    /// When adding a rafs metadata blob to the manager, all data blobs referenced by it will
    /// also be added to the manager. It's convenient to support rafs image filesystem.
    ///
    /// The `domain_id` and `id` forms a unique identifier to identify cached bootstrap objects.
    /// That means `domain_id` is used to divide cached objects into groups and blobs with the
    /// same `id` may exist in different groups.
    #[allow(unused)]
    pub fn add_bootstrap_object(
        &self,
        domain_id: String,
        id: &str,
        path: &str,
        factory_config: Arc<FactoryConfig>,
    ) -> Result<()> {
        let rs = RafsSuper::load_from_metadata(path, RafsMode::Direct, true)?;
        let config = FsCacheObjectConfig::new_bootstrap_blob(
            domain_id.clone(),
            id.to_string(),
            factory_config.clone(),
        );
        let mut state = self.get_state();

        if state.id_to_config_map.contains_key(config.get_key()) {
            Err(Error::new(
                ErrorKind::AlreadyExists,
                "blob configuration information already exists",
            ))
        } else {
            // Try to add the referenced data blob object if it doesn't exist yet.
            for bi in rs.superblock.get_blob_infos() {
                let data_blob = FsCacheObjectConfig::new_data_blob(
                    domain_id.clone(),
                    bi,
                    factory_config.clone(),
                );
                if !state.id_to_config_map.contains_key(data_blob.get_key()) {
                    state
                        .id_to_config_map
                        .insert(data_blob.get_key().to_string(), data_blob);
                }
            }
            state
                .id_to_config_map
                .insert(config.get_key().to_string(), config);
            Ok(())
        }
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
            self.poller
                .lock()
                .unwrap()
                .poll(&mut events, None)
                .map_err(|_e| eother!("Failed to poll events for fscache service"))?;

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
            // TODO: confirm how to handle ret == 0?
            if ret > 0 {
                self.handle_one_request(&buf[0..ret as usize])?;
            } else {
                let err = Error::last_os_error();
                match err.kind() {
                    ErrorKind::Interrupted => continue,
                    ErrorKind::WouldBlock => return Ok(()),
                    _ => return Err(err),
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
        let info = self.get_config(&msg.volume_key);
        let msg = match info {
            None => format!("cinit {},{}", hdr.id, -libc::ENOENT),
            Some(info) => {
                let need_size = msg.flags & CACHEFILES_OPEN_WANT_CACHE_SIZE != 0;
                match self.create_data_blob_object(info, hdr.id, msg.fd, need_size) {
                    Err(s) => s,
                    Ok((blob, blob_size)) => {
                        let mut state = self.get_state();
                        if state.fd_to_object_map.contains_key(&msg.fd) {
                            format!("cinit {},{}", hdr.id, -libc::EALREADY)
                        } else {
                            state
                                .fd_to_object_map
                                .insert(msg.fd, FsCacheObject::DataBlob(blob));
                            if need_size {
                                format!("cinit {},{}", hdr.id, blob_size)
                            } else {
                                format!("cinit {}", hdr.id)
                            }
                        }
                    }
                }
            }
        };
        self.reply(&msg);
    }

    // TODO: extend the kernel ABI to return result, otherwise kernel does not when it's safe to
    // close the fd. Assume the fscache driver will get notified when we close the fd, but there
    // is no way to return error still.
    fn handle_close_request(&self, hdr: &FsCacheMsgHeader, msg: &FsCacheMsgClose) {
        let blob = self.get_object(msg.fd);
        let msg = match blob {
            None => format!("cfini {},{}", hdr.id, -libc::ENOENT),
            Some(_blob) => {
                todo!()
            }
        };
        self.reply(&msg);
    }

    // TODO: extend the kernel ABI to return error code.
    fn handle_read_request(&self, hdr: &FsCacheMsgHeader, msg: &FsCacheMsgRead) {
        let object = self.get_object(msg.fd);
        let msg = match object {
            None => format!("cread {},{}", hdr.id, -libc::ENOENT),
            Some(FsCacheObject::DataBlob(blob)) => match blob.get_blob_object() {
                None => {
                    //panic!("All blob used by fscache should support BlobObject interface")
                    format!("cread {},{}", hdr.id, -libc::ENOSYS)
                }
                Some(obj) => match obj.fetch_range_uncompressed(msg.off, msg.len) {
                    Ok(v) if v == msg.len as usize => format!("cread {}", hdr.id),
                    Ok(_v) => format!("cread {},{}", hdr.id, -libc::EIO),
                    Err(_e) => format!("cread {},{}", hdr.id, -libc::EIO),
                },
            },
            Some(FsCacheObject::Bootstrap(_bs)) => {
                todo!();
            }
        };
        self.reply(&msg);
    }

    /// The `fscache` factory essentially creates a namespace for blob objects cached by the
    /// fscache subsystem. The data blob files will be managed the in kernel fscache driver,
    /// the chunk map file will be managed by the userspace daemon. We need to figure out the
    /// way to share blob/chunkamp files with filecache manager.
    fn create_data_blob_object(
        &self,
        info: FsCacheObjectConfig,
        id: u32,
        fd: u32,
        need_size: bool,
    ) -> std::result::Result<(Arc<dyn BlobCache>, u64), String> {
        let blob_info = info.get_blob_info().expect("info is not a data blob");
        let mut blob_info = blob_info.deref().clone();
        assert!(blob_info.get_fscache_file().is_none());
        // Safe because we trust the kernel fscache driver.
        let file = unsafe { File::from_raw_fd(fd as RawFd) };
        blob_info.set_fscache_file(Some(Arc::new(file)));
        let blob_ref = Arc::new(blob_info);

        match BLOB_FACTORY.new_blob_cache(&info.get_factory_config(), &blob_ref) {
            Err(_e) => Err(format!("cinit {},{}", id, -libc::ENOENT)),
            Ok(blob) => {
                let blob_size = if need_size {
                    match blob.blob_size() {
                        Err(_e) => return Err(format!("cinit {},{}", id, -libc::EIO)),
                        Ok(v) => v,
                    }
                } else {
                    0
                };
                Ok((blob, blob_size))
            }
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
        assert_eq!(ret, result.len() as isize);
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
        self.get_state().id_to_config_map.get(key).cloned()
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
    fn test_msg_size() {
        assert_eq!(MSG_HEADER_SIZE, 12);
        assert_eq!(MSG_READ_SIZE, 20);
        assert_eq!(MSG_CLOSE_SIZE, 4);
    }

    #[test]
    fn test_msg_header() {
        let hdr = FsCacheMsgHeader::try_from(&[0u8, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 13, 0]).unwrap();
        assert_eq!(hdr.id, 0x1);
        assert_eq!(hdr.opcode, FsCacheOpCode::Read);
        assert_eq!(hdr.len, 0xd);

        FsCacheMsgHeader::try_from(&[0u8, 0, 0, 1, 0, 0, 0, 3, 0, 0, 0, 13, 0]).unwrap_err();
        FsCacheMsgHeader::try_from(&[0u8, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 13]).unwrap_err();
        FsCacheMsgHeader::try_from(&[0u8, 0, 0, 1, 0, 0, 0, 2, 0, 0]).unwrap_err();
        FsCacheMsgHeader::try_from(&[]).unwrap_err();
    }
}

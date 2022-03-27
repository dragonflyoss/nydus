// Copyright (C) 2022 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! Handler to cooperate with Linux fscache subsystem for blob cache.

use std::collections::HashMap;
use std::convert::TryFrom;
use std::fs::{File, OpenOptions};
use std::io::{Error, ErrorKind, Result, Write};
use std::mem::size_of;
use std::ops::Deref;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::ptr::read_unaligned;
use std::string::String;
use std::sync::{Arc, Mutex};

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

#[repr(C)]
#[derive(Debug, Eq, PartialEq)]
struct FsCacheMsgHeader {
    /// Message id to identifying position of this message in the fscache internal radix tree.
    id: u32,
    /// message type, CACHEFILE_OP_*
    opcode: FsCacheOpCode,
    /// message length, including message header and following data.
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
            return Err(einval!("invalid volume/cookie key length"));
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
struct FsCacheBlobInfo {
    blob_info: Arc<BlobInfo>,
    factory_config: Arc<FactoryConfig>,
}

#[derive(Default)]
struct FsCacheState {
    fd_to_blob_map: HashMap<u32, Arc<dyn BlobCache>>,
    id_to_fd_map: HashMap<String, u32>,
    id_to_info_map: HashMap<String, Arc<FsCacheBlobInfo>>,
}

/// Handler to cooperate with Linux fscache driver to manage cached blob objects.
///
/// The `FsCacheHandler` create a communication channel with the Linux fscache driver, configure
/// the communication session and serves all requests from the fscache driver.
pub struct FsCacheHandler {
    path: String,
    file: File,
    state: Arc<Mutex<FsCacheState>>,
}

impl FsCacheHandler {
    /// Create a new instance of `FsCacheService`.
    pub fn new(path: &str, dir: &str, tag: Option<&str>) -> Result<Self> {
        let mut file = OpenOptions::new()
            .write(true)
            .read(true)
            .create(false)
            .custom_flags(libc::O_NONBLOCK)
            .open(path)?;

        let msg = format!("dir {}", dir);
        file.write_all(msg.as_bytes())?;
        if let Some(tag) = tag {
            let msg = format!("tag {}", tag);
            file.write_all(msg.as_bytes())?;
        }
        file.write_all("bind ondemand".as_bytes())?;

        Ok(FsCacheHandler {
            path: path.to_string(),
            file,
            state: Arc::new(Mutex::new(FsCacheState::default())),
        })
    }

    /// Add a blob object to be managed by the `FsCacheHandler`.
    pub fn add_blob_object(
        &self,
        blob_info: Arc<BlobInfo>,
        factory_config: Arc<FactoryConfig>,
    ) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        if state.id_to_info_map.contains_key(blob_info.blob_id()) {
            Err(Error::new(
                ErrorKind::AlreadyExists,
                "blob configuration information already exists",
            ))
        } else {
            let blob_id = blob_info.blob_id().to_string();
            let info = Arc::new(FsCacheBlobInfo {
                blob_info,
                factory_config,
            });
            state.id_to_info_map.insert(blob_id, info);
            Ok(())
        }
    }

    /// Run the event loop to handle all requests from kernel fscache driver.
    pub fn run_loop(&self) -> Result<()> {
        let mut buf = [0u8; MIN_DATA_BUF_SIZE];
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

    // TODO: extend the kernel ABI to return error code.
    // TODO: confirm that once the fd is passed to userspace, the userspace has ownership of the
    // fd, and should close the fd when needed.
    fn handle_open_request(&self, hdr: &FsCacheMsgHeader, msg: &FsCacheMsgOpen) {
        let info = self.get_blob_info(&msg.volume_key);
        let msg = match info {
            None => format!("cinit {},{}", hdr.id, -libc::ENOENT),
            Some(info) => {
                let need_size = msg.flags & CACHEFILES_OPEN_WANT_CACHE_SIZE != 0;
                match self.create_blob_object(info, hdr.id, msg.fd, need_size) {
                    Err(s) => s,
                    Ok((blob, blob_size)) => {
                        let mut state = self.state.lock().unwrap();
                        if state.fd_to_blob_map.contains_key(&msg.fd)
                            || state.id_to_fd_map.contains_key(blob.blob_id())
                        {
                            format!("cinit {},{}", hdr.id, -libc::EALREADY)
                        } else {
                            state.fd_to_blob_map.insert(msg.fd, blob);
                            state
                                .id_to_fd_map
                                .insert(blob.blob_id().to_string(), msg.fd);
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

    fn handle_close_request(&self, hdr: &FsCacheMsgHeader, msg: &FsCacheMsgClose) {
        todo!()
    }

    // TODO: extend the kernel ABI to return error code.
    fn handle_read_request(&self, hdr: &FsCacheMsgHeader, msg: &FsCacheMsgRead) {
        let blob = self.get_blob_from_fd(msg.fd);
        let msg = match blob {
            None => format!("cread {},{}", hdr.id, -libc::ENOENT),
            Some(blob) => match blob.get_blob_object() {
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
        };
        self.reply(&msg);
    }

    /// The `fscache` factory essentially creates a namespace for blob objects cached by the
    /// fscache subsystem. The data blob files will be managed the in kernel fscache driver,
    /// the chunk map file will be managed by the userspace daemon. We need to figure out the
    /// way to share blob/chunkamp files with filecache manager.
    fn create_blob_object(
        &self,
        info: Arc<FsCacheBlobInfo>,
        id: u32,
        fd: u32,
        need_size: bool,
    ) -> std::result::Result<(Arc<dyn BlobCache>, u64), String> {
        let mut blob_info = info.blob_info.deref().clone();
        assert!(blob_info.get_fscache_file().is_none());
        // Safe because we trust the kernel fscache driver.
        let file = unsafe { File::from_raw_fd(fd as RawFd) };
        blob_info.set_fscache_file(Some(Arc::new(file)));
        let blob_ref = Arc::new(blob_info);

        match BLOB_FACTORY.new_blob_cache(&info.factory_config, &blob_ref) {
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
    fn get_blob_from_fd(&self, fd: u32) -> Option<Arc<dyn BlobCache>> {
        self.state.lock().unwrap().fd_to_blob_map.get(&fd).cloned()
    }

    #[inline]
    fn get_blob_info(&self, key: &str) -> Option<Arc<FsCacheBlobInfo>> {
        self.state.lock().unwrap().id_to_info_map.get(key).cloned()
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

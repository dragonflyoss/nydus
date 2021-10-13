// Copyright (C) 2021 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::fs::File;
use std::io::Result;
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::{Arc, Mutex};

use self::client::Client;
use crate::cache::state::{BlobRangeMap, RangeMap};
use crate::device::{BlobInfo, BlobIoRange, BlobObject};

pub use server::Server;

mod client;
mod connection;
mod message;
mod server;

const REQUEST_TIMEOUT_SEC: u64 = 4;
const RANGE_MAP_SHIFT: u64 = 18;
const RANGE_MAP_MASK: u64 = (1 << RANGE_MAP_SHIFT) - 1;

/// Manager to access and cache blob objects managed by remote blob manager.
///
/// A `RemoteBlobMgr` object may be used to access services from a remote blob manager, and cache
/// blob information to improve performance.
pub struct RemoteBlobMgr {
    blobs: Mutex<HashMap<String, Arc<RemoteBlob>>>,
    conn: Arc<Client>,
    workdir: String,
}

impl RemoteBlobMgr {
    /// Create a new instance of `RemoteBlobMgr`.
    pub fn new(workdir: String, sock: &str) -> Result<Self> {
        let conn = Client::new(sock);

        Ok(RemoteBlobMgr {
            blobs: Mutex::new(HashMap::new()),
            conn: Arc::new(conn),
            workdir,
        })
    }

    /// Connect to remote blob manager.
    pub fn connect(&self) -> Result<()> {
        self.conn.connect().map(|_| ())
    }

    /// Start to handle communication messages.
    pub fn start(&self) -> Result<()> {
        Client::start(self.conn.clone())
    }

    /// Shutdown the `RemoteblogMgr` instance.
    pub fn shudown(&self) {
        self.conn.close();
        self.blobs.lock().unwrap().clear();
    }

    /// Get an `BlobObject` trait object to access the specified blob.
    pub fn get_blob_object(&self, blob_info: &Arc<BlobInfo>) -> Result<Arc<dyn BlobObject>> {
        let guard = self.blobs.lock().unwrap();
        if let Some(v) = guard.get(blob_info.blob_id()) {
            return Ok(v.clone());
        }
        drop(guard);

        let (file, base, token) = self.conn.call_get_blob(blob_info)?;
        let file = Arc::new(file);
        let blob = RemoteBlob::new(
            blob_info,
            self.conn.clone(),
            file,
            base,
            token,
            &self.workdir,
        )?;
        let blob = Arc::new(blob);

        let mut guard = self.blobs.lock().unwrap();
        if let Some(v) = guard.get(blob_info.blob_id()) {
            Ok(v.clone())
        } else {
            guard.insert(blob_info.blob_id().to_owned(), blob.clone());
            Ok(blob)
        }
    }
}

/// Struct to access and cache blob object managed by remote blob manager.
///
/// The `RemoteBlob` structure acts as a proxy to access a blob managed by remote blob manager.
/// It has a separate data plane and control plane. A file descriptor will be received from the
/// remote blob manager, so all data access requests will be served by directly access the file
/// descriptor. And a communication channel will be used to communicate control message between
/// the client and the remote blob manager. To improve control plane performance, it may cache
/// blob metadata and chunk map to avoid unnecessary control messages.
struct RemoteBlob {
    conn: Arc<Client>,
    map: Arc<BlobRangeMap>,
    file: Arc<File>,
    base: u64,
    token: u64,
}

impl RemoteBlob {
    /// Create a new instance of `RemoteBlob`.
    fn new(
        blob_info: &Arc<BlobInfo>,
        conn: Arc<Client>,
        file: Arc<File>,
        base: u64,
        token: u64,
        work_dir: &str,
    ) -> Result<Self> {
        let blob_path = format!("{}/{}", work_dir, blob_info.blob_id());
        let count = (blob_info.uncompressed_size() + RANGE_MAP_MASK) >> RANGE_MAP_SHIFT;
        let map = BlobRangeMap::new(&blob_path, count as u32, RANGE_MAP_SHIFT as u32)?;
        debug_assert!(count <= u32::MAX as u64);

        Ok(RemoteBlob {
            map: Arc::new(map),
            conn,
            file,
            base,
            token,
        })
    }
}

impl AsRawFd for RemoteBlob {
    fn as_raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }
}

impl BlobObject for RemoteBlob {
    fn base_offset(&self) -> u64 {
        self.base
    }

    fn is_all_data_ready(&self) -> bool {
        self.map.is_range_all_ready()
    }

    fn fetch_range_compressed(&self, _offset: u64, _size: u64) -> Result<usize> {
        Err(enosys!())
        /*
        if let Ok(v) = self.meta.get_chunks_compressed(offset, size) {
            if v.is_empty() {
                Ok(0)
            } else if let Ok(true) = self.chunk_map.is_range_ready(v[0].id(), v.len() as u32) {
                Ok(0)
            } else {
                self.conn.call_fetch_chunks(v[0].id(), v.len() as u32)
            }
        } else {
            Err(enoent!("failed to get chunks for compressed range"))
        }
         */
    }

    fn fetch_range_uncompressed(&self, offset: u64, size: u64) -> Result<usize> {
        match self.map.is_range_ready(offset, size) {
            Ok(true) => Ok(0),
            _ => self.conn.call_fetch_range(self.token, offset, size),
        }
    }

    fn fetch_chunks(&self, _range: &BlobIoRange) -> Result<usize> {
        Err(enosys!())
        /*
        debug_assert!(range.validate());
        if range.chunks.is_empty() {
            Ok(0)
        } else {
            self.conn
                .call_fetch_chunks(range.chunks[0].id(), range.chunks.len() as u32)
        }
         */
    }
}

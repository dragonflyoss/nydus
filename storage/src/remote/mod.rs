// Copyright (C) 2021 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::fs::File;
use std::io::Result;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, WaitTimeoutResult};
use std::time::Duration;

use crate::cache::chunkmap::{ChunkBitmap, IndexedChunkMap};
use crate::device::{BlobChunkInfo, BlobInfo, BlobIoRange, BlobObject};
use crate::meta::BlobMetaInfo;

const REQUEST_TIMEOUT_SEC: u64 = 4;

#[derive(Eq, PartialEq)]
enum RequestStatus {
    Waiting,
    Timeout,
    Finished,
}

#[allow(dead_code)]
#[derive(Clone)]
enum RequestResult {
    None,
    GetBlob(RawFd, u64),
    FetchChunks(u64),
}

struct Request {
    tag: u64,
    condvar: Condvar,
    state: Mutex<(RequestStatus, RequestResult)>,
}

impl Request {
    fn wait_for_result(&self) {
        let mut tor: WaitTimeoutResult;
        let mut guard = self.state.lock().unwrap();

        while guard.0 == RequestStatus::Waiting {
            let res = self
                .condvar
                .wait_timeout(guard, Duration::from_secs(REQUEST_TIMEOUT_SEC))
                .unwrap();

            tor = res.1;
            guard = res.0;
            if guard.0 == RequestStatus::Finished {
                return;
            } else if tor.timed_out() {
                guard.0 = RequestStatus::Timeout;
            }
        }
    }

    fn set_result(&self, result: RequestResult) {
        let mut guard = self.state.lock().unwrap();

        match guard.0 {
            RequestStatus::Waiting | RequestStatus::Timeout => {
                guard.1 = result;
                guard.0 = RequestStatus::Finished;
                self.condvar.notify_all();
            }
            RequestStatus::Finished => {
                debug!("received duplicated reply");
            }
        }
    }
}

/// Struct to maintain state for a connection to remote blob manager.
pub struct RemoteConnection {
    tag: AtomicU64,
    requests: Mutex<HashMap<u64, Arc<Request>>>,
}

impl RemoteConnection {
    fn call_fetch_chunks(&self, _start: u32, _count: u32) -> Result<usize> {
        let req = self.create_request();

        // TODO: send message to remote server

        match self.wait_for_result(req)? {
            RequestResult::FetchChunks(size) => Ok(size as usize),
            _ => Err(eother!()),
        }
    }

    fn call_get_blob(&self, _blob_info: &Arc<BlobInfo>) -> Result<(File, u64)> {
        let req = self.create_request();

        // TODO: send message to remote server

        match self.wait_for_result(req)? {
            RequestResult::GetBlob(fd, base) => {
                let file = unsafe { File::from_raw_fd(fd) };
                Ok((file, base))
            }
            _ => Err(eother!()),
        }
    }

    fn create_request(&self) -> Arc<Request> {
        let tag = self.get_next_tag();
        let request = Arc::new(Request {
            tag,
            condvar: Condvar::new(),
            state: Mutex::new((RequestStatus::Waiting, RequestResult::None)),
        });

        self.requests.lock().unwrap().insert(tag, request.clone());

        request
    }

    fn wait_for_result(&self, request: Arc<Request>) -> Result<RequestResult> {
        request.wait_for_result();

        match self.requests.lock().unwrap().remove(&request.tag) {
            None => Err(enoent!()),
            Some(entry) => {
                let guard = entry.state.lock().unwrap();
                match guard.0 {
                    RequestStatus::Waiting => panic!("should not happen"),
                    RequestStatus::Timeout => Err(enoent!()),
                    RequestStatus::Finished => Ok(guard.1.clone()),
                }
            }
        }
    }

    #[allow(dead_code)]
    fn handle_result(&self, tag: u64, result: RequestResult) {
        let requests = self.requests.lock().unwrap();

        match requests.get(&tag) {
            None => debug!("no request for tag {} found, may have timed out", tag),
            Some(request) => request.set_result(result),
        }
    }

    fn get_next_tag(&self) -> u64 {
        self.tag.fetch_add(1, Ordering::AcqRel)
    }
}

/// Manager to create and cache remote blob object.
pub struct RemoteBlobMgr {
    blobs: Mutex<HashMap<String, Arc<RemoteBlob>>>,
    conn: Arc<RemoteConnection>,
    workdir: String,
}

impl RemoteBlobMgr {
    /// Create a new instance of `RemoteBlobMgr`.
    pub fn new(conn: Arc<RemoteConnection>, workdir: String) -> Result<Self> {
        Ok(RemoteBlobMgr {
            blobs: Mutex::new(HashMap::new()),
            conn,
            workdir,
        })
    }

    /// Get an `BlobObject` trait object to access the specified blob.
    pub fn get_blob_object(&self, blob_info: &Arc<BlobInfo>) -> Result<Arc<dyn BlobObject>> {
        let guard = self.blobs.lock().unwrap();
        if let Some(v) = guard.get(blob_info.blob_id()) {
            return Ok(v.clone());
        }
        drop(guard);

        let (file, base) = self.conn.call_get_blob(blob_info)?;
        let file = Arc::new(file);
        let blob = RemoteBlob::new(blob_info, self.conn.clone(), file, base, &self.workdir)?;
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

/// Struct to cache and access blob object managed by remote blob manager.
///
/// The `RemoteBlob` structure acts as a proxy to access a blob managed by remote blob manager.
/// It has a separate data plane and control plane. A file descriptor will be sent from the remote
/// blob manager, so all data access requests will be served by directly access the file descriptor.
/// And a communication channel will be used to communicate control message between the client and
/// the remote blob manager. To improve control plane performance, it caches blob metadata and chunk
/// map to avoid unnecessary control messages.
struct RemoteBlob {
    chunk_map: Arc<IndexedChunkMap>,
    conn: Arc<RemoteConnection>,
    meta: Arc<BlobMetaInfo>,
    file: Arc<File>,
    base: u64,
}

impl RemoteBlob {
    /// Create a new instance of `RemoteBlob`.
    fn new(
        blob_info: &Arc<BlobInfo>,
        conn: Arc<RemoteConnection>,
        file: Arc<File>,
        base: u64,
        work_dir: &str,
    ) -> Result<Self> {
        let meta = BlobMetaInfo::new(work_dir, blob_info, None)?;
        let chunk_map = IndexedChunkMap::open(blob_info, work_dir)?;

        Ok(RemoteBlob {
            chunk_map: Arc::new(chunk_map),
            conn,
            meta: Arc::new(meta),
            file,
            base,
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
        self.chunk_map.is_bitmap_all_ready()
    }

    fn fetch_range_compressed(&self, offset: u64, size: u64) -> Result<usize> {
        if let Ok(v) = self.meta.get_chunks_compressed(offset, size) {
            if v.is_empty() {
                Ok(0)
            } else if let Ok(true) = self.chunk_map.is_bitmap_ready(v[0].id(), v.len() as u32) {
                Ok(0)
            } else {
                self.conn.call_fetch_chunks(v[0].id(), v.len() as u32)
            }
        } else {
            Err(enoent!("failed to get chunks for compressed range"))
        }
    }

    fn fetch_range_uncompressed(&self, offset: u64, size: u64) -> Result<usize> {
        if let Ok(v) = self.meta.get_chunks_uncompressed(offset, size) {
            if v.is_empty() {
                Ok(0)
            } else if let Ok(true) = self.chunk_map.is_bitmap_ready(v[0].id(), v.len() as u32) {
                Ok(0)
            } else {
                self.conn.call_fetch_chunks(v[0].id(), v.len() as u32)
            }
        } else {
            Err(enoent!("failed to get chunks for uncompressed range"))
        }
    }

    fn fetch_chunks(&self, range: &BlobIoRange) -> Result<usize> {
        debug_assert!(range.validate());
        if range.chunks.is_empty() {
            Ok(0)
        } else if let Ok(true) = self
            .chunk_map
            .is_bitmap_ready(range.chunks[0].id(), range.chunks.len() as u32)
        {
            Ok(0)
        } else {
            self.conn
                .call_fetch_chunks(range.chunks[0].id(), range.chunks.len() as u32)
        }
    }
}

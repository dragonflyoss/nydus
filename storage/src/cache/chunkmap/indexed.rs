// Copyright 2021 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Result;
use std::os::unix::io::AsRawFd;
use std::sync::{
    atomic::{AtomicU8, Ordering},
    Arc, Condvar, Mutex, WaitTimeoutResult,
};
use std::time::Duration;

use nydus_utils::div_round_up;

use super::ChunkMap;
use crate::device::RafsChunkInfo;
use crate::utils::readahead;
use crate::{StorageError, StorageResult};

use crate::cache::blobcache::SINGLE_INFLIGHT_WAIT_TIMEOUT;

/// The magic number of blob chunk_map file, it's ASCII hex of string "BMAP".
const MAGIC: u32 = 0x424D_4150;
/// The name suffix of blob chunk_map file, named $blob_id.chunk_map.
const FILE_SUFFIX: &str = "chunk_map";
/// The header of blob chunk_map file.
const HEADER_SIZE: usize = 4096;
const HEADER_RESERVED_SIZE: usize = HEADER_SIZE - 4;

/// The blob chunk map file header, 4096 bytes.
#[repr(C)]
struct Header {
    /// IndexedChunkMap magic number
    magic: u32,
    reserved: [u8; HEADER_RESERVED_SIZE],
}

/// The IndexedChunkMap is an implementation that uses a file as bitmap
/// (like HashMap<chunk_index, has_ready>). It creates or opens a file with
/// the name $blob_id.chunk_map which records whether a chunk has been cached
/// by the blobcache. This approach can be used to share chunk ready state
/// between multiple nydusd instances, which was not possible with the previous
/// implementation using in-memory hashmap.
///
/// For example: the bitmap file layout is [0b00000000, 0b00000000],
/// when blobcache calls set_ready(3), the layout should be changed
/// to [0b00010000, 0b00000000].
pub struct IndexedChunkMap {
    chunk_count: u32,
    size: usize,
    base: *const u8,
    inflight_tracer: Arc<Mutex<HashMap<u32, Arc<ChunkSlot>>>>,
}

#[derive(PartialEq)]
enum Status {
    Inflight,
    Complete,
}

struct ChunkSlot {
    on_trip: Mutex<Status>,
    condvar: Condvar,
}

impl ChunkSlot {
    fn new() -> Self {
        ChunkSlot {
            on_trip: Mutex::new(Status::Inflight),
            condvar: Condvar::new(),
        }
    }

    fn notify(&self) {
        self.condvar.notify_all();
    }

    fn done(&self) {
        // Not expect poisoned lock here
        *self.on_trip.lock().unwrap() = Status::Complete;
        self.notify();
    }

    fn wait_for_inflight(&self, timeout: Duration) -> StorageResult<()> {
        let mut inflight = self.on_trip.lock().unwrap();
        let mut tor: WaitTimeoutResult;
        while *inflight == Status::Inflight {
            // Do not expect poisoned lock, so unwrap here.
            let r = self.condvar.wait_timeout(inflight, timeout).unwrap();
            inflight = r.0;
            tor = r.1;
            if tor.timed_out() {
                return Err(StorageError::Timeout);
            }
        }

        Ok(())
    }
}

unsafe impl Send for IndexedChunkMap {}
unsafe impl Sync for IndexedChunkMap {}

impl IndexedChunkMap {
    pub fn new(blob_path: &str, chunk_count: u32) -> Result<Self> {
        if chunk_count == 0 {
            return Err(einval!("chunk count should be greater than 0"));
        }

        let cache_path = format!("{}.{}", blob_path, FILE_SUFFIX);

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&cache_path)
            .map_err(|err| {
                einval!(format!(
                    "failed to open/create blob chunk_map file {:?}: {:?}",
                    cache_path, err
                ))
            })?;

        let file_size = file.metadata()?.len();
        let bitmap_size = div_round_up(chunk_count as u64, 8u64);
        let expected_size = HEADER_SIZE as u64 + bitmap_size;

        if file_size != expected_size {
            if file_size > 0 {
                warn!("blob chunk_map file may be corrupted: {:?}", cache_path);
            }
            file.set_len(expected_size)?;
        }

        let fd = file.as_raw_fd();
        let base = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                expected_size as usize,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            )
        };
        if base == libc::MAP_FAILED {
            return Err(last_error!("failed to mmap blob chunk_map"));
        }
        if base.is_null() {
            return Err(ebadf!("failed to mmap blob chunk_map"));
        }

        // Make clippy of 1.45 happy. Higher version of clippy won't complain about this
        #[allow(clippy::cast_ptr_alignment)]
        let header = unsafe { &mut *(base as *mut Header) };
        if file_size == 0 {
            header.magic = MAGIC
        } else if header.magic != MAGIC {
            return Err(einval!(format!(
                "invalid blob chunk_map file header: {:?}",
                cache_path
            )));
        }

        readahead(fd, 0, expected_size);

        Ok(Self {
            chunk_count,
            size: expected_size as usize,
            base: base as *const u8,
            inflight_tracer: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    fn validate_index(&self, idx: u32) -> Result<()> {
        if idx > self.chunk_count - 1 {
            return Err(einval!(format!(
                "chunk index {} exceeds chunk count {}",
                idx, self.chunk_count
            )));
        }
        Ok(())
    }

    fn read_u8(&self, idx: u32) -> u8 {
        let start = HEADER_SIZE + (idx as usize >> 3);
        let current = unsafe { self.base.add(start) as *const AtomicU8 };
        unsafe { (*current).load(Ordering::Acquire) }
    }

    fn write_u8(&self, idx: u32, current: u8) -> bool {
        let mask = Self::index_to_mask(idx);
        let expected = current | mask;
        let start = HEADER_SIZE + (idx as usize >> 3);
        let atomic_value = unsafe { &*{ self.base.add(start) as *const AtomicU8 } };
        atomic_value
            .compare_exchange(current, expected, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
    }

    #[inline]
    fn index_to_mask(index: u32) -> u8 {
        let pos = 8 - ((index & 0b111) + 1);
        1 << pos
    }

    fn is_chunk_ready(&self, index: u32) -> (bool, u8) {
        let mask = Self::index_to_mask(index);
        let current = self.read_u8(index);
        let ready = current & mask == mask;
        (ready, current)
    }
}

impl Drop for IndexedChunkMap {
    fn drop(&mut self) {
        if !self.base.is_null() {
            unsafe { libc::munmap(self.base as *mut libc::c_void, self.size) };
            self.base = std::ptr::null();
        }
    }
}

impl ChunkMap for IndexedChunkMap {
    fn has_ready(&self, chunk: &dyn RafsChunkInfo, wait: bool) -> Result<bool> {
        let index = chunk.index();
        let _ = self.validate_index(index)?;
        let (ready, _) = self.is_chunk_ready(index);
        if !ready {
            let mut guard = self.inflight_tracer.lock().unwrap();
            trace!(
                "chunk index {}, tracer scale {}",
                chunk.index(),
                guard.len()
            );
            if let Some(i) = guard.get(&index).cloned() {
                if wait {
                    drop(guard);
                    match i.wait_for_inflight(Duration::from_millis(SINGLE_INFLIGHT_WAIT_TIMEOUT)) {
                        Err(StorageError::Timeout) => {
                            // Notice that lock of tracer is already dropped.
                            let mut t = self.inflight_tracer.lock().unwrap();
                            t.remove(&index);
                            i.notify();
                            warn!("Waiting for another backend IO expires. chunk index {}, tracer scale {}", chunk.index(), t.len());
                            return Ok(self.is_chunk_ready(chunk.index()).0);
                        }
                        _ => {
                            return Ok(self.is_chunk_ready(chunk.index()).0);
                        }
                    };
                }
            } else {
                // Double check to close the window where prior slot was just
                // removed after backend IO returned.
                if self.is_chunk_ready(index).0 {
                    return Ok(true);
                }
                guard.insert(index, Arc::new(ChunkSlot::new()));
            }
        }
        Ok(ready)
    }

    fn set_ready(&self, chunk: &dyn RafsChunkInfo) -> Result<()> {
        // Loop to write one byte (a bitmap with 8 bits capacity) to
        // blob chunk_map file until success.
        let index = chunk.index();
        let _ = self.validate_index(index)?;
        loop {
            let (ready, current) = self.is_chunk_ready(index);
            if ready {
                break;
            }

            if self.write_u8(index, current) {
                break;
            }
        }

        self.finish(chunk);

        Ok(())
    }

    fn finish(&self, chunk: &dyn RafsChunkInfo) {
        let index = chunk.index();
        let mut guard = self.inflight_tracer.lock().unwrap();
        if let Some(i) = guard.remove(&index) {
            i.done();
        }
    }
}

#[cfg(test)]
mod this_test {
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    use vmm_sys_util::tempfile::TempFile;

    use super::IndexedChunkMap;
    use crate::cache::blobcache::blob_cache_tests::MockChunkInfo;
    use crate::cache::chunkmap::ChunkMap;
    use crate::device::RafsChunkInfo;

    #[test]
    fn test_inflight_tracer_race() {
        let tmp_file = TempFile::new().unwrap();
        let map = Arc::new(IndexedChunkMap::new(tmp_file.as_path().to_str().unwrap(), 10).unwrap());

        let chunk_4: Arc<dyn RafsChunkInfo> = Arc::new({
            let mut c = MockChunkInfo::new();
            c.index = 4;
            c
        });

        map.as_ref().has_ready(chunk_4.as_ref(), false).unwrap();
        let map_cloned = map.clone();

        assert_eq!(map.inflight_tracer.lock().unwrap().len(), 1);

        let chunk_4_cloned = chunk_4.clone();
        let t1 = thread::Builder::new()
            .spawn(move || {
                for _ in 0..4 {
                    let ready = map_cloned.has_ready(chunk_4_cloned.as_ref(), true).unwrap();
                    assert_eq!(ready, true);
                }
            })
            .unwrap();

        let map_cloned_2 = map.clone();
        let chunk_4_cloned_2 = chunk_4.clone();
        let t2 = thread::Builder::new()
            .spawn(move || {
                for _ in 0..2 {
                    let ready = map_cloned_2
                        .has_ready(chunk_4_cloned_2.as_ref(), true)
                        .unwrap();
                    assert_eq!(ready, true);
                }
            })
            .unwrap();

        thread::sleep(Duration::from_secs(1));

        map.set_ready(chunk_4.as_ref()).unwrap();

        // Fuzz
        map.set_ready(chunk_4.as_ref()).unwrap();
        map.set_ready(chunk_4.as_ref()).unwrap();

        assert_eq!(map.inflight_tracer.lock().unwrap().len(), 0);

        t1.join().unwrap();
        t2.join().unwrap();
    }

    #[test]
    /// Case description:
    ///     Never invoke `set_ready` method, thus to let each caller of `has_ready` reach
    ///     a point of timeout.
    /// Expect:
    ///     The chunk of index 4 is never marked as ready/downloaded.
    ///     Each caller of `has_ready` can escape from where it is blocked.
    ///     After timeout, no slot is left in inflight tracer.
    fn test_inflight_tracer_timeout() {
        let tmp_file = TempFile::new().unwrap();
        let map = Arc::new(IndexedChunkMap::new(tmp_file.as_path().to_str().unwrap(), 10).unwrap());

        let chunk_4: Arc<dyn RafsChunkInfo> = Arc::new({
            let mut c = MockChunkInfo::new();
            c.index = 4;
            c
        });

        map.as_ref().has_ready(chunk_4.as_ref(), false).unwrap();
        let map_cloned = map.clone();

        assert_eq!(map.inflight_tracer.lock().unwrap().len(), 1);

        let chunk_4_cloned = chunk_4.clone();
        let t1 = thread::Builder::new()
            .spawn(move || {
                for _ in 0..4 {
                    map_cloned.has_ready(chunk_4_cloned.as_ref(), true).unwrap();
                }
            })
            .unwrap();

        t1.join().unwrap();

        assert_eq!(map.inflight_tracer.lock().unwrap().len(), 1);

        let ready = map.as_ref().has_ready(chunk_4.as_ref(), false).unwrap();
        assert_eq!(ready, false);

        map.finish(chunk_4.as_ref());
        assert_eq!(map.inflight_tracer.lock().unwrap().len(), 0);
    }
}

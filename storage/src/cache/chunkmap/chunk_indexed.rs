// Copyright 2021 Ant Group. All rights reserved.
// Copyright (C) 2021 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::fs::{File, OpenOptions};
use std::io::{Result, Write};
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use nydus_utils::div_round_up;

use super::ChunkMap;
use crate::cache::chunkmap::{ChunkIndexGetter, NoWaitSupport};
use crate::device::BlobChunkInfo;
use crate::utils::readahead;

/// The magic number of blob chunk_map file, it's ASCII hex of string "BMAP".
const MAGIC1: u32 = 0x424D_4150;
const MAGIC2: u32 = 0x434D_4150;
const MAGIC_ALL_READY: u32 = 0x4D4D_4150;
/// The name suffix of blob chunk_map file, named $blob_id.chunk_map.
const FILE_SUFFIX: &str = "chunk_map";
/// The header of blob chunk_map file.
const HEADER_SIZE: usize = 4096;
const HEADER_RESERVED_SIZE: usize = HEADER_SIZE - 16;

/// The blob chunk map file header, 4096 bytes.
#[repr(C)]
struct Header {
    /// IndexedChunkMap magic number
    magic: u32,
    version: u32,
    magic2: u32,
    all_ready: u32,
    reserved: [u8; HEADER_RESERVED_SIZE],
}

impl Header {
    fn as_slice(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(
                self as *const Header as *const u8,
                std::mem::size_of::<Header>(),
            )
        }
    }
}

/// A `ChunkMap` implementation based on atomic bitmap.
///
/// The `IndexedChunkMap` is an implementation of `ChunkMap` which uses a file and atomic bitmap
/// operations to track chunk data readiness. It creates or opens a file with the name
/// `$blob_id.chunk_map` to record whether a chunk has been cached by the blob cache, and atomic
/// bitmap operations are used to manipulate the state bit.
///
/// This approach can be used to share chunk ready state between multiple nydusd instances.
/// For example: the bitmap file layout is [0b00000000, 0b00000000], when blobcache calls
/// set_ready(3), the layout should be changed to [0b00010000, 0b00000000].
pub struct IndexedChunkMap {
    chunk_count: u32,
    size: usize,
    base: *const u8,
    all_ready: AtomicBool,
}

impl IndexedChunkMap {
    /// Create a new instance of `IndexedChunkMap`.
    pub fn new(blob_path: &str, chunk_count: u32) -> Result<Self> {
        if chunk_count == 0 {
            return Err(einval!("chunk count should be greater than 0"));
        }

        let cache_path = format!("{}.{}", blob_path, FILE_SUFFIX);
        let mut file = OpenOptions::new()
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

        if file_size == 0 {
            Self::write_header(&mut file, expected_size)?;
        } else if file_size != expected_size {
            // File size doesn't match, it's too risky to accept the chunk state file. Fallback to
            // always mark chunk data as not ready.
            warn!("blob chunk_map file may be corrupted: {:?}", cache_path);
            return Err(einval!(format!(
                "chunk_map file {:?} is invalid",
                cache_path
            )));
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
        } else if base.is_null() {
            return Err(ebadf!("failed to mmap blob chunk_map"));
        }

        let mut all_ready = false;
        let header = unsafe { &mut *(base as *mut Header) };
        if header.magic != MAGIC1 {
            // There's race window between "file.set_len()" and "file.write(&header)". If that
            // happens, all file content should be zero. Detect the race window and write out
            // header again to fix it.
            let content =
                unsafe { std::slice::from_raw_parts(base as *const u8, expected_size as usize) };
            for c in content {
                if *c != 0 {
                    return Err(einval!(format!(
                        "invalid blob chunk_map file header: {:?}",
                        cache_path
                    )));
                }
            }
            Self::write_header(&mut file, expected_size)?;
        } else if header.version >= 1 {
            if header.magic2 != MAGIC2 {
                return Err(einval!(format!(
                    "invalid blob chunk_map file header: {:?}",
                    cache_path
                )));
            }
            if header.all_ready == MAGIC_ALL_READY {
                all_ready = true;
            }
        }

        readahead(fd, 0, expected_size);

        Ok(Self {
            chunk_count,
            size: expected_size as usize,
            base: base as *const u8,
            all_ready: AtomicBool::new(all_ready),
        })
    }

    fn write_header(file: &mut File, size: u64) -> Result<()> {
        let header = Header {
            magic: MAGIC1,
            version: 1,
            magic2: MAGIC2,
            all_ready: 0,
            reserved: [0x0u8; HEADER_RESERVED_SIZE],
        };

        // Set file size to expected value and sync to disk.
        file.set_len(size)?;
        file.sync_all()?;
        // write file header and sync to disk.
        file.write_all(header.as_slice())?;
        file.sync_all()?;

        Ok(())
    }

    fn validate_index(&self, idx: u32) -> Result<u32> {
        if idx < self.chunk_count {
            Ok(idx)
        } else {
            Err(einval!(format!(
                "chunk index {} exceeds chunk count {}",
                idx, self.chunk_count
            )))
        }
    }

    fn read_u8(&self, idx: u32) -> u8 {
        let start = HEADER_SIZE + (idx as usize >> 3);
        let current = unsafe { &*(self.base.add(start) as *const AtomicU8) };

        current.load(Ordering::Acquire)
    }

    fn write_u8(&self, idx: u32, current: u8) -> bool {
        let mask = Self::index_to_mask(idx);
        let expected = current | mask;
        let start = HEADER_SIZE + (idx as usize >> 3);
        let atomic_value = unsafe { &*(self.base.add(start) as *const AtomicU8) };

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

unsafe impl Send for IndexedChunkMap {}

unsafe impl Sync for IndexedChunkMap {}

impl NoWaitSupport for IndexedChunkMap {}

impl ChunkMap for IndexedChunkMap {
    fn is_ready(&self, chunk: &dyn BlobChunkInfo, _wait: bool) -> Result<bool> {
        if self.all_ready.load(Ordering::Acquire) {
            Ok(true)
        } else {
            let index = self.validate_index(chunk.id())?;
            Ok(self.is_chunk_ready(index).0)
        }
    }

    fn set_ready(&self, chunk: &dyn BlobChunkInfo) -> Result<()> {
        let index = self.validate_index(chunk.id())?;

        // Loop to atomically update the state bit corresponding to the chunk index.
        loop {
            let (ready, current) = self.is_chunk_ready(index);
            if ready || self.write_u8(index, current) {
                break;
            }
        }

        Ok(())
    }
}

impl ChunkIndexGetter for IndexedChunkMap {
    type Index = u32;

    fn get_index(chunk: &dyn BlobChunkInfo) -> Self::Index {
        chunk.id()
    }
}

#[cfg(test)]
mod tests {
    use vmm_sys_util::tempdir::TempDir;

    use super::*;
    use crate::cache::blobcache::blob_cache_tests::MockChunkInfo;
    use crate::device::v5::BlobV5ChunkInfo;

    #[test]
    fn test_indexed_new_invalid_file_size() {
        let dir = TempDir::new().unwrap();
        let blob_path = dir.as_path().join("blob-1");
        let blob_path = blob_path.as_os_str().to_str().unwrap().to_string();

        assert!(IndexedChunkMap::new(&blob_path, 0).is_err());

        let cache_path = format!("{}.{}", blob_path, FILE_SUFFIX);
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&cache_path)
            .map_err(|err| {
                einval!(format!(
                    "failed to open/create blob chunk_map file {:?}: {:?}",
                    cache_path, err
                ))
            })
            .unwrap();
        file.write_all(&[0x0u8]).unwrap();

        let chunk = MockChunkInfo::new();
        assert_eq!(chunk.id(), 0);

        assert!(IndexedChunkMap::new(&blob_path, 1).is_err());
    }

    #[test]
    fn test_indexed_new_zero_file_size() {
        let dir = TempDir::new().unwrap();
        let blob_path = dir.as_path().join("blob-1");
        let blob_path = blob_path.as_os_str().to_str().unwrap().to_string();

        assert!(IndexedChunkMap::new(&blob_path, 0).is_err());

        let cache_path = format!("{}.{}", blob_path, FILE_SUFFIX);
        let _file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&cache_path)
            .map_err(|err| {
                einval!(format!(
                    "failed to open/create blob chunk_map file {:?}: {:?}",
                    cache_path, err
                ))
            })
            .unwrap();

        let chunk = MockChunkInfo::new();
        assert_eq!(chunk.id(), 0);

        let map = IndexedChunkMap::new(&blob_path, 1).unwrap();
        assert_eq!(map.all_ready.load(Ordering::Acquire), false);
        assert_eq!(map.chunk_count, 1);
        assert_eq!(map.size, 0x1001);
        assert_eq!(map.is_ready_nowait(chunk.as_base()).unwrap(), false);
        map.set_ready(chunk.as_base()).unwrap();
        assert_eq!(map.is_ready_nowait(chunk.as_base()).unwrap(), true);
    }

    #[test]
    fn test_indexed_new_header_not_ready() {
        let dir = TempDir::new().unwrap();
        let blob_path = dir.as_path().join("blob-1");
        let blob_path = blob_path.as_os_str().to_str().unwrap().to_string();

        assert!(IndexedChunkMap::new(&blob_path, 0).is_err());

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
            })
            .unwrap();
        file.set_len(0x1001).unwrap();

        let chunk = MockChunkInfo::new();
        assert_eq!(chunk.id(), 0);

        let map = IndexedChunkMap::new(&blob_path, 1).unwrap();
        assert_eq!(map.all_ready.load(Ordering::Acquire), false);
        assert_eq!(map.chunk_count, 1);
        assert_eq!(map.size, 0x1001);
        assert_eq!(map.is_ready_nowait(chunk.as_base()).unwrap(), false);
        map.set_ready(chunk.as_base()).unwrap();
        assert_eq!(map.is_ready_nowait(chunk.as_base()).unwrap(), true);
    }

    #[test]
    fn test_indexed_new_all_ready() {
        let dir = TempDir::new().unwrap();
        let blob_path = dir.as_path().join("blob-1");
        let blob_path = blob_path.as_os_str().to_str().unwrap().to_string();

        assert!(IndexedChunkMap::new(&blob_path, 0).is_err());

        let cache_path = format!("{}.{}", blob_path, FILE_SUFFIX);
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&cache_path)
            .map_err(|err| {
                einval!(format!(
                    "failed to open/create blob chunk_map file {:?}: {:?}",
                    cache_path, err
                ))
            })
            .unwrap();
        let header = Header {
            magic: MAGIC1,
            version: 1,
            magic2: MAGIC2,
            all_ready: MAGIC_ALL_READY,
            reserved: [0x0u8; HEADER_RESERVED_SIZE],
        };

        // write file header and sync to disk.
        file.write_all(header.as_slice()).unwrap();
        file.write_all(&[0x0u8]).unwrap();

        let chunk = MockChunkInfo::new();
        assert_eq!(chunk.id(), 0);

        let map = IndexedChunkMap::new(&blob_path, 1).unwrap();
        assert_eq!(map.all_ready.load(Ordering::Acquire), true);
        assert_eq!(map.chunk_count, 1);
        assert_eq!(map.size, 0x1001);
        assert_eq!(map.is_ready_nowait(chunk.as_base()).unwrap(), true);
        map.set_ready(chunk.as_base()).unwrap();
        assert_eq!(map.is_ready_nowait(chunk.as_base()).unwrap(), true);
    }

    #[test]
    fn test_indexed_new_load_v0() {
        let dir = TempDir::new().unwrap();
        let blob_path = dir.as_path().join("blob-1");
        let blob_path = blob_path.as_os_str().to_str().unwrap().to_string();

        assert!(IndexedChunkMap::new(&blob_path, 0).is_err());

        let cache_path = format!("{}.{}", blob_path, FILE_SUFFIX);
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&cache_path)
            .map_err(|err| {
                einval!(format!(
                    "failed to open/create blob chunk_map file {:?}: {:?}",
                    cache_path, err
                ))
            })
            .unwrap();
        let header = Header {
            magic: MAGIC1,
            version: 0,
            magic2: 0,
            all_ready: 0,
            reserved: [0x0u8; HEADER_RESERVED_SIZE],
        };

        // write file header and sync to disk.
        file.write_all(header.as_slice()).unwrap();
        file.write_all(&[0x0u8]).unwrap();

        let chunk = MockChunkInfo::new();
        assert_eq!(chunk.id(), 0);

        let map = IndexedChunkMap::new(&blob_path, 1).unwrap();
        assert_eq!(map.all_ready.load(Ordering::Acquire), false);
        assert_eq!(map.chunk_count, 1);
        assert_eq!(map.size, 0x1001);
        assert_eq!(map.is_ready_nowait(chunk.as_base()).unwrap(), false);
        map.set_ready(chunk.as_base()).unwrap();
        assert_eq!(map.is_ready_nowait(chunk.as_base()).unwrap(), true);
    }
}

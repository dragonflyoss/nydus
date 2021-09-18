// Copyright 2021 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::fs::OpenOptions;
use std::io::Result;
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicU8, Ordering};

use nydus_utils::div_round_up;

use super::ChunkMap;
use crate::cache::chunkmap::{ChunkIndexGetter, NoWaitSupport};
use crate::device::BlobChunkInfo;
use crate::utils::readahead;

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
}

impl IndexedChunkMap {
    /// Create a new instance of `IndexedChunkMap`.
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
        } else if base.is_null() {
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
        })
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
        let index = self.validate_index(chunk.id())?;

        Ok(self.is_chunk_ready(index).0)
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

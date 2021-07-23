// Copyright 2021 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::fs::OpenOptions;
use std::io::Result;
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicU8, Ordering};

use nydus_utils::div_round_up;

use super::ChunkMap;
use crate::device::RafsChunkInfo;
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
        })
    }

    fn check_index(&self, idx: u32) -> Result<()> {
        if idx > self.chunk_count - 1 {
            return Err(einval!(format!(
                "chunk index {} exceeds chunk count {}",
                idx, self.chunk_count
            )));
        }
        Ok(())
    }

    fn read_u8(&self, idx: u32) -> Result<(u8, u8)> {
        self.check_index(idx)?;
        let start = HEADER_SIZE + (idx as usize >> 3);
        let current = unsafe { self.base.add(start) as *const AtomicU8 };
        let pos = 8 - ((idx & 0b111) + 1);
        let mask = 1 << pos;
        Ok((unsafe { (*current).load(Ordering::Acquire) }, mask))
    }

    fn write_u8(&self, idx: u32, current: u8, expected: u8) -> Result<bool> {
        self.check_index(idx)?;
        let start = HEADER_SIZE + (idx as usize >> 3);
        let atomic_value = unsafe { &*{ self.base.add(start) as *const AtomicU8 } };
        Ok(atomic_value
            .compare_exchange(current, expected, Ordering::Acquire, Ordering::Relaxed)
            .is_ok())
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
    fn has_ready(&self, chunk: &dyn RafsChunkInfo) -> Result<bool> {
        let (current, mask) = self.read_u8(chunk.index())?;
        Ok((current & mask) == mask)
    }

    fn set_ready(&self, chunk: &dyn RafsChunkInfo) -> Result<()> {
        // Loop to write one byte (a bitmap with 8 bits capacity) to
        // blob chunk_map file until success.
        loop {
            let index = chunk.index();
            let (current, mask) = self.read_u8(index)?;
            let ready = (current & mask) == mask;
            if ready {
                break;
            }
            let expected = current | mask;
            if self.write_u8(index, current, expected)? {
                break;
            }
        }
        Ok(())
    }
}

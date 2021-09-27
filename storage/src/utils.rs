// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::cmp::{self, min, Ordering};
use std::io::{ErrorKind, Result};
use std::os::unix::io::RawFd;
use std::slice::from_raw_parts_mut;

use libc::off64_t;
use nix::sys::uio::{preadv, IoVec};
use vm_memory::{Bytes, VolatileSlice};

use nydus_utils::{
    digest::{self, RafsDigest},
    round_down_4k,
};

use crate::{StorageError, StorageResult};

/// Just a simple wrapper for posix `preadv`. Provide a slice of `IoVec` as input.
pub fn readv(fd: RawFd, iovec: &[IoVec<&mut [u8]>], offset: u64) -> Result<usize> {
    loop {
        let ret = preadv(fd, iovec, offset as off64_t).map_err(|_| last_error!());
        match ret {
            Ok(ret) => {
                return Ok(ret);
            }
            Err(err) => {
                // Retry if the IO is interrupted by signal.
                if err.kind() != ErrorKind::Interrupted {
                    return Err(err);
                }
            }
        }
    }
}

/// Copy from buffer slice to another buffer slice.
/// `offset` is where to start copy in the first buffer of source slice.
/// Up to bytes of `length` is wanted in `src`.
/// `dst_index` and `dst_slice_offset` indicate from where to start write destination.
/// Return (Total copied bytes, (Final written destination index, Final written destination offset))
pub fn copyv(
    src: &[&[u8]],
    dst: &[VolatileSlice],
    offset: usize,
    length: usize,
    mut dst_index: usize,
    mut dst_offset: usize,
) -> StorageResult<(usize, (usize, usize))> {
    let mut copied = 0;
    let mut src_offset = offset;

    'next_source: for s in src {
        let mut buffer_len = min(s.len() - src_offset, length - copied);
        'next_slice: loop {
            if dst_index >= dst.len() {
                return Err(StorageError::MemOverflow);
            }
            let dst_slice = &dst[dst_index];
            if dst_offset >= dst_slice.len() {
                return Err(StorageError::MemOverflow);
            }

            let buffer = &s[src_offset..src_offset + buffer_len];

            let written = dst_slice
                .write(buffer, dst_offset)
                .map_err(StorageError::VolatileSlice)?;

            copied += written;

            match written.cmp(&buffer_len) {
                Ordering::Equal => {
                    src_offset = 0;
                    if dst_slice.len() - dst_offset == written {
                        dst_offset = 0;
                        dst_index += 1;
                    } else {
                        dst_offset += written;
                    }
                    continue 'next_source;
                }
                Ordering::Less => {
                    if dst_slice.len() - dst_offset == written {
                        dst_index += 1;
                        dst_offset = 0;
                    } else {
                        dst_offset += written
                    }
                    src_offset += written;
                    buffer_len -= written;
                    assert!(src_offset < s.len());
                    if dst_index >= dst.len() {
                        return Err(StorageError::MemOverflow);
                    }
                    continue 'next_slice;
                }
                _ => {
                    panic!("Written length can't exceed length of source");
                }
            }
        }
    }

    Ok((copied, (dst_index, dst_offset)))
}

pub struct MemSliceCursor<'a> {
    pub mem_slice: &'a [VolatileSlice<'a>],
    pub index: usize,
    pub offset: usize,
}

impl<'a, 'b> MemSliceCursor<'b> {
    pub fn new(slice: &'a [VolatileSlice]) -> Self
    where
        'a: 'b,
    {
        Self {
            mem_slice: slice,
            index: 0,
            offset: 0,
        }
    }

    pub fn move_cursor(&mut self, mut size: usize) {
        loop {
            let slice = self.mem_slice[self.index];
            let this_left = slice.len() - self.offset;

            match this_left.cmp(&size) {
                cmp::Ordering::Equal => {
                    self.index += 1;
                    self.offset = 0;
                    break;
                }
                cmp::Ordering::Greater => {
                    self.offset += size;
                    break;
                }
                cmp::Ordering::Less => {
                    self.index += 1;
                    self.offset = 0;
                    size -= this_left;
                    continue;
                }
            }
        }
    }

    pub fn consume(&mut self, mut size: usize) -> Vec<IoVec<&mut [u8]>> {
        // FIXME: What if `size` is 0?
        let mut vectors: Vec<IoVec<&mut [u8]>> = Vec::new();
        loop {
            let slice = self.mem_slice[self.index];
            let this_left = slice.len() - self.offset;
            match this_left.cmp(&size) {
                cmp::Ordering::Greater | cmp::Ordering::Equal => {
                    let p = unsafe { slice.as_ptr().add(self.offset) };
                    let s = unsafe { from_raw_parts_mut(p, size) };
                    let iov = IoVec::from_mut_slice(s);
                    self.offset += size;
                    vectors.push(iov);
                    break;
                }
                cmp::Ordering::Less => {
                    let p = unsafe { slice.as_ptr().add(self.offset) };
                    let s = unsafe { from_raw_parts_mut(p, this_left) };
                    let iov = IoVec::from_mut_slice(s);
                    self.offset = 0;
                    self.index += 1;
                    size -= this_left;
                    vectors.push(iov);
                }
            }
        }
        vectors
    }

    pub fn inner_slice(&self) -> &[VolatileSlice] {
        self.mem_slice
    }
}

/// A customized readahead function to ask kernel to fault in all pages from offset to end.
///
/// Call libc::readahead on every 128KB range because otherwise readahead stops at kernel bdi
/// readahead size which is 128KB by default.
pub fn readahead(fd: libc::c_int, mut offset: u64, end: u64) {
    let mut count;
    offset = round_down_4k(offset);
    loop {
        if offset >= end {
            break;
        }
        // Kernel default 128KB readahead size
        count = std::cmp::min(128 << 10, end - offset);
        unsafe { libc::readahead(fd, offset as i64, count as usize) };
        offset += count;
    }
}

/// A customized buf allocator that avoids zeroing
pub fn alloc_buf(size: usize) -> Vec<u8> {
    let mut buf = Vec::with_capacity(size);
    unsafe { buf.set_len(size) };
    buf
}

/// Check hash of data matches provided one
pub fn digest_check(data: &[u8], digest: &RafsDigest, digester: digest::Algorithm) -> bool {
    digest == &RafsDigest::from_buf(data, digester)
}

#[cfg(test)]
mod tests {
    use vm_memory::VolatileSlice;

    use crate::StorageError;

    use super::alloc_buf;
    use super::copyv;

    #[test]
    fn test_copyv() {
        let mem_size: usize = 4;
        let mut _mem_1 = alloc_buf(mem_size);
        let volatile_slice_1 = unsafe { VolatileSlice::new(_mem_1.as_mut_ptr(), mem_size) };
        let mut _mem_2 = alloc_buf(mem_size);
        let volatile_slice_2 = unsafe { VolatileSlice::new(_mem_2.as_mut_ptr(), mem_size) };

        let src_buf_1 = vec![1u8, 2u8, 3u8];
        let src_buf_2 = vec![4u8, 5u8, 6u8];

        let src_bufs = vec![src_buf_1.as_slice(), src_buf_2.as_slice()];

        copyv(
            src_bufs.as_slice(),
            &[volatile_slice_1, volatile_slice_2],
            1,
            5,
            0,
            0,
        )
        .unwrap();

        assert_eq!(_mem_1[0], 2);
        assert_eq!(_mem_1[1], 3);
        assert_eq!(_mem_1[2], 4);
        assert_eq!(_mem_1[3], 5);
        assert_eq!(_mem_2[0], 6);

        copyv(
            src_bufs.as_slice(),
            &[volatile_slice_1, volatile_slice_2],
            1,
            3,
            1,
            0,
        )
        .unwrap();

        assert_eq!(_mem_2[0], 2);
        assert_eq!(_mem_2[1], 3);
        assert_eq!(_mem_2[2], 4);

        let r = copyv(
            src_bufs.as_slice(),
            &[volatile_slice_1, volatile_slice_2],
            1,
            3,
            1,
            4,
        );

        match r {
            Err(StorageError::MemOverflow) => (),
            _ => panic!("should overflow"),
        }

        // Specified slice index is greater than real one.
        let r = copyv(
            src_bufs.as_slice(),
            &[volatile_slice_1, volatile_slice_2],
            1,
            3,
            3,
            4,
        );

        match r {
            Err(StorageError::MemOverflow) => (),
            _ => panic!("should overflow"),
        }
    }
}

// Copyright 2020 Ant Financial. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::io::{ErrorKind, Result};
use std::os::unix::io::RawFd;
use std::slice::from_raw_parts_mut;

use libc::off64_t;
use nix::sys::uio::{preadv, IoVec};
use vm_memory::{Bytes, VolatileSlice};

use nydus_utils::{einval, last_error, round_down_4k};

use crate::metadata::digest::{self, RafsDigest};

pub fn readv(fd: RawFd, bufs: &[VolatileSlice], offset: u64, max_size: usize) -> Result<usize> {
    if bufs.is_empty() {
        return Ok(0);
    }

    let mut size: usize = 0;
    let mut iovecs: Vec<IoVec<&mut [u8]>> = Vec::new();

    for buf in bufs {
        let mut exceed = false;
        let len = if size + buf.len() > max_size {
            exceed = true;
            max_size - size
        } else {
            buf.len()
        };
        size += len;
        let iov = IoVec::from_mut_slice(unsafe { from_raw_parts_mut(buf.as_ptr(), len) });
        iovecs.push(iov);
        if exceed {
            break;
        }
    }

    loop {
        let ret = preadv(fd, &iovecs, offset as off64_t).map_err(|_| last_error!());
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

pub fn copyv(src: &[u8], dst: &[VolatileSlice], offset: u64, mut max_size: usize) -> Result<usize> {
    let mut offset = offset as usize;
    let mut size: usize = 0;
    if max_size > src.len() {
        max_size = src.len()
    }

    for s in dst.iter() {
        if offset >= src.len() || size >= src.len() {
            break;
        }
        let mut len = max_size - size;
        if offset + len > src.len() {
            len = src.len() - offset;
        }

        s.write_slice(&src[offset..offset + len], 0)
            .map_err(|e| einval!(e))?;
        offset += len;
        size += len;
    }

    Ok(size)
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

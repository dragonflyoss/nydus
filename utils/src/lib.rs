// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

#[macro_use]
extern crate log;
#[macro_use]
extern crate nydus_error;
#[macro_use]
extern crate serde;
#[macro_use]
extern crate lazy_static;

use std::convert::{Into, TryFrom, TryInto};
use std::fs::File;
use std::io::Read;
use std::marker::PhantomData;
use std::os::unix::io::{AsRawFd, RawFd};

pub use self::exec::*;
pub use self::inode_bitmap::InodeBitmap;
pub use self::types::*;

pub mod async_helper;
pub mod compact;
pub mod compress;
pub mod digest;
pub mod exec;
pub mod filemap;
pub mod inode_bitmap;
pub mod metrics;
pub mod mpmc;
pub mod types;

/// Round up and divide the value `n` by `d`.
pub fn div_round_up(n: u64, d: u64) -> u64 {
    debug_assert!(d != 0);
    debug_assert!(d.is_power_of_two());
    (n + d - 1) / d
}

/// Round up the value `n` to by `d`.
pub fn round_up(n: u64, d: u64) -> u64 {
    debug_assert!(d != 0);
    debug_assert!(d.is_power_of_two());
    (n + d - 1) / d * d
}

/// Overflow can fail this rounder if the base value is large enough with 4095 added.
pub fn try_round_up_4k<U: TryFrom<u64>, T: Into<u64>>(x: T) -> Option<U> {
    let t = 4095u64;
    if let Some(v) = x.into().checked_add(t) {
        let z = v & (!t);
        z.try_into().ok()
    } else {
        None
    }
}

pub fn round_down_4k(x: u64) -> u64 {
    x & (!4095u64)
}

/// A wrapper reader to read a range of data from a file.
pub struct FileRangeReader<'a> {
    fd: RawFd,
    offset: u64,
    size: u64,
    r: PhantomData<&'a u8>,
}

impl<'a> FileRangeReader<'a> {
    /// Create a wrapper reader to read a range of data from the file.
    pub fn new(f: &File, offset: u64, size: u64) -> Self {
        Self {
            fd: f.as_raw_fd(),
            offset,
            size,
            r: PhantomData,
        }
    }
}

impl<'a> Read for FileRangeReader<'a> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let size = std::cmp::min(self.size as usize, buf.len());
        let nr_read = nix::sys::uio::pread(self.fd, &mut buf[0..size], self.offset as i64)
            .map_err(|_| last_error!())?;
        self.offset += nr_read as u64;
        self.size -= nr_read as u64;
        Ok(nr_read)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vmm_sys_util::tempfile::TempFile;

    #[test]
    fn test_rounders() {
        assert_eq!(round_down_4k(0), 0);
        assert_eq!(round_down_4k(100), 0);
        assert_eq!(round_down_4k(4300), 4096);
        assert_eq!(round_down_4k(4096), 4096);
        assert_eq!(round_down_4k(4095), 0);
        assert_eq!(round_down_4k(4097), 4096);
        assert_eq!(round_down_4k(u64::MAX - 1), u64::MAX - 4095);
        assert_eq!(round_down_4k(u64::MAX - 4095), u64::MAX - 4095);
        // zero is rounded up to zero
        assert_eq!(try_round_up_4k::<i32, _>(0u32), Some(0i32));
        assert_eq!(try_round_up_4k::<u32, _>(0u32), Some(0u32));
        assert_eq!(try_round_up_4k::<u32, _>(1u32), Some(4096u32));
        assert_eq!(try_round_up_4k::<u32, _>(100u32), Some(4096u32));
        assert_eq!(try_round_up_4k::<u32, _>(4100u32), Some(8192u32));
        assert_eq!(try_round_up_4k::<u32, _>(4096u32), Some(4096u32));
        assert_eq!(try_round_up_4k::<u32, _>(4095u32), Some(4096u32));
        assert_eq!(try_round_up_4k::<u32, _>(4097u32), Some(8192u32));
        assert_eq!(try_round_up_4k::<u32, _>(u32::MAX), None);
        assert_eq!(try_round_up_4k::<u64, _>(u32::MAX), Some(0x1_0000_0000u64));
        assert_eq!(try_round_up_4k::<u32, _>(u64::MAX - 1), None);
        assert_eq!(try_round_up_4k::<u32, _>(u64::MAX), None);
        assert_eq!(try_round_up_4k::<u32, _>(u64::MAX - 4097), None);
        // success
        assert_eq!(
            try_round_up_4k::<u64, _>(u64::MAX - 4096),
            Some(u64::MAX - 4095)
        );
        // overflow
        assert_eq!(try_round_up_4k::<u64, _>(u64::MAX - 1), None);
        // fail to convert u64 to u32
        assert_eq!(try_round_up_4k::<u32, _>(u64::MAX - 4096), None);
    }

    #[test]
    fn test_file_range_reader() {
        let file = TempFile::new().unwrap();
        std::fs::write(file.as_path(), b"This is a test").unwrap();
        let mut reader = FileRangeReader::new(file.as_file(), 4, 6);
        let mut buf = vec![0u8; 128];
        let res = reader.read(&mut buf).unwrap();
        assert_eq!(res, 6);
        assert_eq!(&buf[..6], b" is a ".as_slice());
        let res = reader.read(&mut buf).unwrap();
        assert_eq!(res, 0);
    }
}

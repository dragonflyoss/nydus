// Copyright (C) 2022 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::marker::PhantomData;
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::{Arc, Mutex};

use sha2::Sha256;

use crate::digest::DigestHasher;

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

struct BufReaderState<R: Read> {
    reader: BufReader<R>,
    pos: u64,
    hash: Sha256,
}

/// A wrapper over `BufReader` to track current position.
pub struct BufReaderInfo<R: Read> {
    calc_digest: bool,
    state: Arc<Mutex<BufReaderState<R>>>,
}

impl<R: Read> BufReaderInfo<R> {
    /// Create a new instance of `BufReaderPos` from a `BufReader`.
    pub fn from_buf_reader(buf_reader: BufReader<R>) -> Self {
        let state = BufReaderState {
            reader: buf_reader,
            pos: 0,
            hash: Sha256::default(),
        };
        Self {
            calc_digest: true,
            state: Arc::new(Mutex::new(state)),
        }
    }

    /// Get current position of the reader.
    pub fn position(&self) -> u64 {
        self.state.lock().unwrap().pos
    }

    /// Get the hash object.
    pub fn get_hash_object(&self) -> Sha256 {
        self.state.lock().unwrap().hash.clone()
    }

    /// Enable or disable blob digest calculation.
    pub fn enable_digest_calculation(&mut self, enable: bool) {
        self.calc_digest = enable;
    }
}

impl<R: Read> Read for BufReaderInfo<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut state = self.state.lock().unwrap();
        state.reader.read(buf).map(|v| {
            state.pos += v as u64;
            if v > 0 && self.calc_digest {
                state.hash.digest_update(&buf[..v]);
            }
            v
        })
    }
}

impl<R: Read + Seek> Seek for BufReaderInfo<R> {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        let mut state = self.state.lock().unwrap();
        let pos = state.reader.seek(pos)?;
        state.pos = pos;
        Ok(pos)
    }
}

impl<R: Read> Clone for BufReaderInfo<R> {
    fn clone(&self) -> Self {
        Self {
            calc_digest: self.calc_digest,
            state: self.state.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vmm_sys_util::tempfile::TempFile;

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

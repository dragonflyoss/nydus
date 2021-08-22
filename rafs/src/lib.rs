// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! RAFS: an on-demand loading, chunk dedup, readonly fuse filesystem.
//!
//! A RAFS filesystem image includes two types of components:
//! - metadata blob: containing filesystem, directory and file metadata. There's only one metadata
//!   blob for an RAFS filesystem.
//! - data blob: containing actual file data. There may be 0, 1 or multiple data blobs for an RAFS
//!   filesystem. And several RAFS filesystems may share one data blob.
//!
//! The metadata blob are pre-loaded when mounting the filesystem, and data blobs may be loaded
//! on demand when the data is actually accessed.

#[macro_use]
extern crate log;
#[macro_use]
extern crate bitflags;
#[macro_use]
extern crate nydus_error;
#[macro_use]
extern crate storage;

use std::any::Any;
use std::fs::File;
use std::io::{BufWriter, Error, Read, Result, Seek, SeekFrom, Write};
use std::os::unix::io::AsRawFd;
use std::path::Path;

use crate::metadata::layout::v5::align_to_rafs;

pub mod fs;
pub mod metadata;

#[derive(Debug)]
pub enum RafsError {
    Unsupported,
    Uninitialized,
    AlreadyMounted,
    ReadMetadata(Error, String),
    LoadConfig(Error),
    ParseConfig(serde_json::Error),
    SwapBackend(Error),
    FillSuperblock(Error),
    CreateDevice(Error),
    Prefetch(String),
    Configure(String),
}

pub type RafsResult<T> = std::result::Result<T, RafsError>;

/// Handler to read file system bootstrap.
pub type RafsIoReader = Box<dyn RafsIoRead>;

/// A helper trait for RafsIoReader.
pub trait RafsIoRead: Read + AsRawFd + Seek + Send {}

impl RafsIoRead for File {}

/// Handler to write file system bootstrap.
pub type RafsIoWriter = Box<dyn RafsIoWrite>;

/// A helper trait for RafsIoWriter.
pub trait RafsIoWrite: Write + Seek {
    fn as_any(&self) -> &dyn Any;

    fn validate_alignment(&mut self, size: usize, alignment: usize) -> Result<usize> {
        if alignment != 0 {
            let cur = self.seek(SeekFrom::Current(0))?;

            if (size & (alignment - 1) != 0) || (cur & (alignment as u64 - 1) != 0) {
                return Err(einval!("unaligned data"));
            }
        }

        Ok(size)
    }
}

impl RafsIoWrite for File {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

// Rust file I/O is un-buffered by default. If we have many small write calls
// to a file, should use BufWriter. BufWriter maintains an in-memory buffer
// for writing, minimizing the number of system calls required.
impl RafsIoWrite for BufWriter<File> {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

const WRITE_PADDING_DATA: [u8; 64] = [0u8; 64];

impl dyn RafsIoWrite {
    /// write padding to align to RAFS_ALIGNMENT.
    pub fn write_padding(&mut self, size: usize) -> Result<()> {
        if size > WRITE_PADDING_DATA.len() {
            return Err(einval!("invalid padding size"));
        }
        self.write_all(&WRITE_PADDING_DATA[0..size])
    }
}

impl dyn RafsIoRead {
    pub fn seek_to_next_aligned(&mut self, last_read_len: usize) -> Result<u64> {
        // Seek should not fail otherwise rafs goes insane.
        let offset = (align_to_rafs(last_read_len) - last_read_len) as i64;
        self.seek(SeekFrom::Current(offset)).map_err(|e| {
            error!("Seeking to offset {} from current fails, {}", offset, e);
            e
        })
    }

    pub fn seek_plus_offset(&mut self, plus_offset: i64) -> Result<u64> {
        // Seek should not fail otherwise rafs goes insane.
        self.seek(SeekFrom::Current(plus_offset)).map_err(|e| {
            error!(
                "Seeking to offset {} from current fails, {}",
                plus_offset, e
            );
            e
        })
    }

    pub fn seek_to_offset(&mut self, offset: u64) -> Result<u64> {
        self.seek(SeekFrom::Start(offset)).map_err(|e| {
            error!("Seeking to offset {} from start fails, {}", offset, e);
            e
        })
    }

    pub fn from_file(path: impl AsRef<Path>) -> RafsResult<RafsIoReader> {
        let f = File::open(&path).map_err(|e| {
            RafsError::ReadMetadata(e, path.as_ref().to_string_lossy().into_owned())
        })?;

        Ok(Box::new(f))
    }
}

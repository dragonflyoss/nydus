// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! A readonly filesystem with separated bootstrap and data, to support on-demand loading.

#[macro_use]
extern crate log;
#[macro_use]
extern crate bitflags;
#[macro_use]
extern crate nydus_utils;

use std::any::Any;
use std::fs::File;
use std::io::{BufWriter, Error, Read, Result, Seek, SeekFrom, Write};
use std::os::unix::io::AsRawFd;
use std::path::Path;

use crate::metadata::layout::{align_to_rafs, RAFS_ALIGNMENT};

pub mod fs;
pub mod metadata;
#[macro_use]
extern crate storage;

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

/// A helper trait for RafsIoReader.
pub trait RafsIoRead: Read + AsRawFd + Seek + Send {}

/// A helper trait for RafsIoWriter.
pub trait RafsIoWrite: Write + Seek {
    fn as_any(&self) -> &dyn Any;
}

impl RafsIoRead for File {}
impl RafsIoWrite for File {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Handler to read file system bootstrap.
pub type RafsIoReader = Box<dyn RafsIoRead>;

/// Handler to write file system bootstrap.
pub type RafsIoWriter = Box<dyn RafsIoWrite>;

// Rust file I/O is un-buffered by default. If we have many small write calls
// to a file, should use BufWriter. BufWriter maintains an in-memory buffer
// for writing, minimizing the number of system calls required.
impl RafsIoWrite for BufWriter<File> {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl dyn RafsIoWrite {
    /// write padding to align to RAFS_ALIGNMENT.
    pub fn write_padding(&mut self, size: usize) -> Result<()> {
        if size > RAFS_ALIGNMENT {
            return Err(einval!("invalid padding size"));
        }
        let padding = [0u8; RAFS_ALIGNMENT];
        self.write_all(&padding[0..size])
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

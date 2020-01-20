// Copyright 2020 Ant Financial. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! A readonly filesystem with separated bootstrap and data, to support on-demand loading.

#[macro_use]
extern crate log;
#[macro_use]
extern crate serde;
#[macro_use]
extern crate bitflags;

use std::any::Any;
use std::fs::File;
use std::io::Result;
use std::io::{Read, Seek, Write};
use std::os::unix::io::AsRawFd;

use crate::metadata::layout::{align_to_rafs, RAFS_ALIGNMENT};
use nydus_utils::einval;

#[macro_use]
mod error;
pub mod fs;
pub mod metadata;
pub mod storage;
use std::io::SeekFrom;

#[macro_use]
extern crate lazy_static;
#[allow(dead_code)]
pub mod io_stats;

/// A helper trait for RafsIoReader.
pub trait RafsIoRead: Read + AsRawFd + Seek {}

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
    pub fn try_seek_aligned(&mut self, last_read_len: usize) {
        // Seek should not fail otherwise rafs goes insane.
        self.seek(SeekFrom::Current(
            (align_to_rafs(last_read_len) - last_read_len) as i64,
        ))
        .unwrap();
    }
}

/// Handler to read file system bootstrap.
pub type RafsIoReader = Box<dyn RafsIoRead>;

/// Handler to write file system bootstrap.
pub type RafsIoWriter = Box<dyn RafsIoWrite>;

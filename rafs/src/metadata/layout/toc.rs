// Copyright 2022 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Rafs filesystem TOC entry layout and data structures.

use anyhow::{bail, Result};

use nydus_utils::digest::RafsDigest;

pub const ENTRY_BLOB_RAW: &str = "image.blob";
pub const ENTRY_BOOTSTRAP: &str = "image.boot";
pub const ENTRY_BLOB_META: &str = "blob.meta";
pub const ENTRY_TOC: &str = "toc";

/// RAFS TOC entry on-disk format, 128 bytes.
///
/// The structure is designed to seek TOC data with the `name` field.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Entry {
    /// Possible values: COMPRESSOR
    flags: u32,
    reserved1: u32,
    /// Name of entry file,
    name: [u8; 16],
    /// Sha256 of data
    digest: [u8; 32],
    /// Offset of data
    offset: u64,
    /// Size of data
    size: u64,
    reserved2: [u8; 52],
}

pub struct EntryList {
    entries: Vec<Entry>,
}

impl EntryList {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub fn add(&mut self, name: &str, digest: RafsDigest, offset: u64, size: u64) -> Result<()> {
        let name_size = name.as_bytes().len();
        if name_size > 16 {
            bail!("invalid entry name length {}", name_size);
        }
        let target = &mut [0u8; 16];
        target[..name_size].clone_from_slice(name.as_bytes());
        self.entries.push(Entry {
            flags: 0,
            reserved1: 0,
            name: *target,
            digest: digest.data,
            offset,
            size,
            reserved2: [0u8; 52],
        });
        Ok(())
    }

    pub fn as_bytes(&self) -> &[u8] {
        let (_, data, _) = unsafe { self.entries.align_to::<u8>() };
        data
    }
}

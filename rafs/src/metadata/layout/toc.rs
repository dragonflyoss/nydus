// Copyright 2022 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Rafs filesystem TOC entry layout and data structures.

use std::convert::TryFrom;
use std::convert::TryInto;

use anyhow::{bail, Result};
use serde::Serialize;

use nydus_utils::compress;
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
    /// Name of entry file
    name: [u8; 16],
    /// Sha256 of uncompressed data
    uncompressed_digest: [u8; 32],
    /// Offset of compressed data
    compressed_offset: u64,
    /// Size of compressed data
    compressed_size: u64,
    /// Size of uncompressed data
    uncompressed_size: u64,
    reserved2: [u8; 44],
}

bitflags! {
    #[derive(Serialize)]
    pub struct EntryFlags: u32 {
        /// Entry data is not compressed.
        const COMPRESSION_NONE = 0x0001;
        /// Entry data is compressed with zstd.
        const COMPRESSION_ZSTD = 0x0002;
        /// Entry data is compressed with lz4.
        const COMPRESSION_LZ4_BLOCK = 0x0004;
    }
}

impl TryFrom<compress::Algorithm> for EntryFlags {
    type Error = anyhow::Error;

    fn try_from(c: compress::Algorithm) -> std::result::Result<Self, Self::Error> {
        match c {
            compress::Algorithm::None => Ok(Self::COMPRESSION_NONE),
            compress::Algorithm::Zstd => Ok(Self::COMPRESSION_ZSTD),
            compress::Algorithm::Lz4Block => Ok(Self::COMPRESSION_LZ4_BLOCK),
            _ => bail!("unsupported compressor {}", c,),
        }
    }
}

impl Entry {
    pub fn set_compressor(&mut self, compressor: compress::Algorithm) -> Result<()> {
        let c: EntryFlags = compressor.try_into()?;

        self.flags &= !EntryFlags::COMPRESSION_NONE.bits();
        self.flags &= !EntryFlags::COMPRESSION_ZSTD.bits();
        self.flags &= !EntryFlags::COMPRESSION_LZ4_BLOCK.bits();
        self.flags |= c.bits();

        Ok(())
    }
}

pub struct EntryList {
    entries: Vec<Entry>,
}

impl Default for EntryList {
    fn default() -> Self {
        Self::new()
    }
}

impl EntryList {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub fn add(
        &mut self,
        name: &str,
        compressor: compress::Algorithm,
        uncompressed_digest: RafsDigest,
        compressed_offset: u64,
        compressed_size: u64,
        uncompressed_size: u64,
    ) -> Result<()> {
        let name_size = name.as_bytes().len();
        if name_size > 16 {
            bail!("invalid entry name length {}", name_size);
        }
        let target = &mut [0u8; 16];
        target[..name_size].clone_from_slice(name.as_bytes());
        let mut entry = Entry {
            flags: 0,
            reserved1: 0,
            name: *target,
            uncompressed_digest: uncompressed_digest.data,
            compressed_offset,
            compressed_size,
            uncompressed_size,
            reserved2: [0u8; 44],
        };
        entry.set_compressor(compressor)?;
        self.entries.push(entry);
        Ok(())
    }

    pub fn as_bytes(&self) -> &[u8] {
        let (_, data, _) = unsafe { self.entries.align_to::<u8>() };
        data
    }
}

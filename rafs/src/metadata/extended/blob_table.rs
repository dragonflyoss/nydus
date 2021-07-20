// Copyright 2021 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::fmt::Debug;
use std::io::Result;
use std::mem::size_of;
use std::sync::Arc;

use crate::metadata::RafsStore;
use crate::{align_to_rafs, RafsIoReader, RafsIoWriter};

pub const EXTENDED_BLOB_TABLE_ENTRY_SIZE: usize = 64;
const RESERVED_SIZE: usize = EXTENDED_BLOB_TABLE_ENTRY_SIZE - 24;

/// ExtendedDBlobTableEntry is appended to the tail of bootstrap,
/// can be used as an extended table for the original blob table.
// This disk structure is well defined and rafs aligned.
#[repr(C)]
#[derive(Clone)]
pub struct ExtendedBlobTableEntry {
    /// Number of chunks in a blob file.
    pub chunk_count: u32,
    pub reserved1: [u8; 4], //   --  8 Bytes
    /// The expected decompress size of blob cache file.
    pub blob_cache_size: u64, // -- 16 Bytes
    pub compressed_blob_size: u64, // -- 24 Bytes
    pub reserved2: [u8; RESERVED_SIZE],
}

// Implement Debug trait ourselves, as rust prior to 1.47 doesn't impl Debug for array with size
// larger than 32
impl Debug for ExtendedBlobTableEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("ExtendedBlobTableEntry")
            .field("chunk_count", &self.chunk_count)
            .field("blob_cache_size", &self.blob_cache_size)
            .field("compressed_blob_size", &self.compressed_blob_size)
            .finish()
    }
}

impl Default for ExtendedBlobTableEntry {
    fn default() -> Self {
        ExtendedBlobTableEntry {
            chunk_count: 0,
            reserved1: [0; 4],
            blob_cache_size: 0,
            compressed_blob_size: 0,
            reserved2: [0; RESERVED_SIZE],
        }
    }
}

impl ExtendedBlobTableEntry {
    pub fn new(chunk_count: u32, blob_cache_size: u64, compressed_blob_size: u64) -> Self {
        Self {
            chunk_count,
            reserved1: [0; 4],
            blob_cache_size,
            compressed_blob_size,
            reserved2: [0; RESERVED_SIZE],
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct ExtendedBlobTable {
    /// The vector index means blob index, every entry represents
    /// extended information of a blob.
    pub entries: Vec<Arc<ExtendedBlobTableEntry>>,
}

impl ExtendedBlobTable {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub fn size(&self) -> usize {
        // `ExtendedBlobTableEntry` is already a well defined disk structure and rafs-aligned
        // So directly use its `size_of()` is reliable.
        align_to_rafs(size_of::<ExtendedBlobTableEntry>() * self.entries.len())
    }

    pub fn entries(&self) -> usize {
        self.entries.len()
    }

    pub fn add(&mut self, chunk_count: u32, blob_cache_size: u64, compressed_blob_size: u64) {
        self.entries.push(Arc::new(ExtendedBlobTableEntry::new(
            chunk_count,
            blob_cache_size,
            compressed_blob_size,
        )));
    }

    pub fn get(&self, blob_index: u32) -> Option<Arc<ExtendedBlobTableEntry>> {
        let len = self.entries.len();
        if len == 0 || blob_index > (len - 1) as u32 {
            return None;
        }
        Some(self.entries[blob_index as usize].clone())
    }

    pub fn load(&mut self, r: &mut RafsIoReader, count: usize) -> Result<()> {
        let mut entries = Vec::<ExtendedBlobTableEntry>::with_capacity(count);
        // Safe because it is already reserved enough space
        unsafe {
            entries.set_len(count);
        }
        let (_, mut data, _) = unsafe { (&mut entries).align_to_mut::<u8>() };
        r.read_exact(&mut data)?;
        self.entries = entries.to_vec().into_iter().map(Arc::new).collect();
        Ok(())
    }
}

impl RafsStore for ExtendedBlobTable {
    fn store_inner(&self, w: &mut RafsIoWriter) -> Result<usize> {
        let mut size = 0;

        // Store the list of entries
        self.entries
            .iter()
            .enumerate()
            .try_for_each::<_, Result<()>>(|(_idx, entry)| {
                w.write_all(&u32::to_le_bytes(entry.chunk_count))?;
                w.write_all(&entry.reserved1)?;
                w.write_all(&u64::to_le_bytes(entry.blob_cache_size))?;
                w.write_all(&u64::to_le_bytes(entry.compressed_blob_size))?;
                w.write_all(&entry.reserved2)?;
                size += size_of::<u32>()
                    + entry.reserved1.len()
                    + size_of::<u64>()
                    + entry.reserved2.len();
                Ok(())
            })?;

        // Append padding for RAFS alignment
        let padding = align_to_rafs(size) - size;
        w.write_padding(padding)?;
        size += padding;

        Ok(size)
    }
}

#[cfg(test)]
mod tests {
    use std::fs::OpenOptions;
    use std::io::BufWriter;
    use vmm_sys_util::tempfile::TempFile;

    use super::ExtendedBlobTable;
    use super::RESERVED_SIZE;
    use crate::metadata::RafsStore;
    use crate::{RafsIoRead, RafsIoWrite};

    #[test]
    fn test_extended_blob_table() {
        let tmp_file = TempFile::new().unwrap();

        // Create extended blob table
        let mut table = ExtendedBlobTable::new();
        for i in 0..5 {
            table.add(i * 3, 100, 100);
        }

        // Store extended blob table
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(tmp_file.as_path())
            .unwrap();
        let mut writer = Box::new(BufWriter::new(file)) as Box<dyn RafsIoWrite>;
        table.store(&mut writer).unwrap();

        // Load extended blob table
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(tmp_file.as_path())
            .unwrap();
        let mut reader = Box::new(file) as Box<dyn RafsIoRead>;
        let mut table = ExtendedBlobTable::new();
        table.load(&mut reader, 5).unwrap();

        // Check expected blob table
        for i in 0..5 {
            assert_eq!(table.get(i).unwrap().chunk_count, i * 3);
            assert_eq!(table.get(i).unwrap().reserved1, [0u8; 4]);
            assert_eq!(table.get(i).unwrap().blob_cache_size, 100);
            assert_eq!(table.get(i).unwrap().reserved2, [0u8; RESERVED_SIZE]);
        }
    }
}

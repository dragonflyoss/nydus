// Copyright 2021 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::io::Result;
use std::mem::size_of;
use std::sync::Arc;

use crate::metadata::RafsStore;
use crate::{align_to_rafs, RafsIoReader, RafsIoWriter};

pub const EXTENDED_BLOB_TABLE_ENTRY_SIZE: usize = 32;

/// ExtendedDBlobTableEntry is appended to the tail of bootstrap,
/// can be used as an extended table for the original blob table.
#[repr(C)]
#[derive(Clone, Debug, Default)]
pub struct ExtendedBlobTableEntry {
    /// Number of chunks in a blob file.
    pub chunk_count: u32,
    pub reserved: [u8; EXTENDED_BLOB_TABLE_ENTRY_SIZE - 4],
}

impl ExtendedBlobTableEntry {
    pub fn new(chunk_count: u32) -> Self {
        Self {
            chunk_count,
            reserved: [0; EXTENDED_BLOB_TABLE_ENTRY_SIZE - 4],
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

    pub fn size(entries_count: u32) -> usize {
        align_to_rafs(size_of::<ExtendedBlobTableEntry>() * entries_count as usize)
    }

    pub fn add(&mut self, chunk_count: u32) {
        self.entries
            .push(Arc::new(ExtendedBlobTableEntry::new(chunk_count)));
    }

    pub fn get(&self, blob_index: u32) -> Option<Arc<ExtendedBlobTableEntry>> {
        let len = self.entries.len();
        if len == 0 || blob_index > (len - 1) as u32 {
            return None;
        }
        Some(self.entries[blob_index as usize].clone())
    }

    pub fn load(&mut self, r: &mut RafsIoReader, entries_count: u32) -> Result<()> {
        let mut entries_data = vec![0u8; ExtendedBlobTable::size(entries_count)];
        r.read_exact(&mut entries_data)?;
        self.load_from_slice(&entries_data, entries_count)
    }

    fn load_from_slice(&mut self, entries_data: &[u8], entries_count: u32) -> Result<()> {
        let entries = unsafe {
            std::slice::from_raw_parts(
                entries_data as *const [u8] as *const u8 as *const ExtendedBlobTableEntry,
                entries_count as usize,
            )
        };
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
                w.write_all(&entry.reserved)?;
                size += size_of::<u32>() + entry.reserved.len();
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
    use crate::metadata::RafsStore;
    use crate::{RafsIoRead, RafsIoWrite};

    #[test]
    fn test_extended_blob_table() {
        let tmp_file = TempFile::new().unwrap();

        // Create extended blob table
        let mut table = ExtendedBlobTable::new();
        for i in 0..5 {
            table.add(i * 3);
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
            assert_eq!(table.get(i).unwrap().reserved, [0u8; 28]);
        }
    }
}

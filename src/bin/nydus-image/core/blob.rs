// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::fs::{remove_file, rename, File, OpenOptions};
use std::io::{BufWriter, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Error, Result};
use sha2::{Digest, Sha256};
use vmm_sys_util::tempfile::TempFile;

use nydus_utils::digest::{self, DigestHasher, RafsDigest};

use super::context::{BuildContext, SourceType, BUF_WRITER_CAPACITY};
use super::node::*;
use crate::core::layout::BlobLayout;

#[derive(Debug, Clone)]
pub enum BlobStorage {
    // Won't rename user's specification
    SingleFile(PathBuf),
    // Will rename it from tmp file as user didn't specify a name.
    BlobsDir(PathBuf),
}

pub struct BlobBufferWriter {
    file: BufWriter<File>,
    blob_stor: BlobStorage,
    // Keep this because tmp file will be removed automatically when it is dropped.
    // But we will rename/link the tmp file before it is removed.
    tmp_file: Option<TempFile>,
}

impl BlobBufferWriter {
    pub fn new(blob_stor: BlobStorage) -> Result<Self> {
        match blob_stor {
            BlobStorage::SingleFile(ref p) => {
                let b = BufWriter::with_capacity(
                    BUF_WRITER_CAPACITY,
                    OpenOptions::new()
                        .write(true)
                        .create(true)
                        .truncate(true)
                        .open(p)?,
                );
                Ok(Self {
                    file: b,
                    blob_stor,
                    tmp_file: None,
                })
            }
            BlobStorage::BlobsDir(ref p) => {
                // Better we can use open(2) O_TMPFILE, but for compatibility sake, we delay this job.
                // TODO: Blob dir existence?
                let tmp = TempFile::new_in(&p)?;
                let tmp2 = tmp.as_file().try_clone()?;
                Ok(Self {
                    file: BufWriter::with_capacity(BUF_WRITER_CAPACITY, tmp2),
                    blob_stor,
                    tmp_file: Some(tmp),
                })
            }
        }
    }

    pub fn write_all(&mut self, buf: &[u8]) -> Result<()> {
        self.file.write_all(buf).map_err(|e| anyhow!(e))
    }

    fn release(self, name: Option<&str>) -> Result<()> {
        let mut f = self.file.into_inner()?;
        f.flush()?;

        if let Some(n) = name {
            if let BlobStorage::BlobsDir(s) = &self.blob_stor {
                // NOTE: File with same name will be deleted ahead of time.
                // So each newly generated blob can be stored.
                let might_exist_path = Path::new(s).join(n);
                if might_exist_path.exists() {
                    remove_file(&might_exist_path)?;
                }

                // Safe to unwrap as `BlobsDir` must have `tmp_file` created.
                rename(self.tmp_file.unwrap().as_path(), might_exist_path)
                    .map_err(|e| anyhow!("Rename blob to {} failed. error: {:?} ", n, e))?;
            }
        } else if let BlobStorage::SingleFile(s) = &self.blob_stor {
            // `new_name` is None means no blob is really built, perhaps due to dedup.
            // We don't want to puzzle user, so delete it from here.
            // In the future, FIFO could be leveraged, don't remove it then.
            remove_file(s)?;
        }

        Ok(())
    }
}

impl Write for BlobBufferWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.file.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}

pub struct BlobInfoEntry {
    chunk_count: u32,
    chunk_ref_count: u64,
}

#[derive(Default)]
pub struct BlobInfoMap {
    /// Store the number of chunks in blob, it's HashMap<blob_index, chunk_count>.
    map: HashMap<u32, BlobInfoEntry>,
}

impl BlobInfoMap {
    /// Allocate a count index sequentially by the index of blob table.
    pub fn alloc_index(&mut self, blob_index: u32) -> Result<u32> {
        match self.map.entry(blob_index) {
            Entry::Occupied(entry) => {
                let info = entry.into_mut();
                let index = info.chunk_count;
                info.chunk_count = index.checked_add(1).ok_or_else(|| {
                    Error::msg("the number of chunks in blob exceeds the u32 limit")
                })?;
                Ok(index)
            }
            Entry::Vacant(entry) => {
                entry.insert(BlobInfoEntry {
                    chunk_count: 1,
                    chunk_ref_count: 0,
                });
                Ok(0)
            }
        }
    }

    /// Increase the chunk reference count of blob.
    pub fn inc_ref_count(&mut self, blob_index: u32) {
        match self.map.entry(blob_index) {
            Entry::Occupied(entry) => {
                let info = entry.into_mut();
                info.chunk_ref_count = info.chunk_ref_count.saturating_add(1);
            }
            Entry::Vacant(entry) => {
                entry.insert(BlobInfoEntry {
                    chunk_count: 0,
                    chunk_ref_count: 1,
                });
            }
        }
    }

    /// Get the number of counts in a blob by the index of blob table.
    pub fn count(&self, blob_index: u32) -> Option<u32> {
        self.map.get(&blob_index).map(|v| v.chunk_count)
    }
}

pub struct BlobCompInfo {
    pub blob_hash: Sha256,
    pub blob_size: u64,
    pub blob_readahead_size: u64,
    pub compressed_blob_size: u64,
    pub compress_offset: u64,
    pub decompressed_blob_size: u64,
    pub decompress_offset: u64,
}

impl BlobCompInfo {
    pub fn new() -> Self {
        BlobCompInfo {
            blob_hash: Sha256::new(),
            blob_size: 0,
            blob_readahead_size: 0,
            compressed_blob_size: 0,
            compress_offset: 0,
            decompressed_blob_size: 0,
            decompress_offset: 0,
        }
    }
}

pub struct Blob {
    writer: BlobBufferWriter,
    /// The size of newly generated blob. It might be ZERO if everything is the same with upper layer.
    blob_size: u64,
}

impl Blob {
    pub fn new(bs: BlobStorage) -> Result<Self> {
        Ok(Self {
            writer: BlobBufferWriter::new(bs)?,
            blob_size: 0,
        })
    }

    /// Dump blob file and generate chunks
    pub fn dump(&mut self, ctx: &mut BuildContext) -> Result<BlobCompInfo> {
        let mut blob_comp_info = BlobCompInfo::new();

        ctx.blob_index = ctx.blob_table.entries.len() as u32;

        match ctx.source_type {
            SourceType::Directory => {
                let (inodes, prefetch_entries) = BlobLayout::layout_blob_simple(ctx)?;
                for (idx, inode) in inodes.iter().enumerate() {
                    let node = &ctx.nodes[*inode];
                    if idx < prefetch_entries {
                        debug!("[{}]\treadahead {}", node.overlay, node);
                    } else {
                        debug!("[{}]\t{}", node.overlay, node);
                    }
                    let size = Node::dump_blob(*inode, ctx, &mut self.writer, &mut blob_comp_info)
                        .context("failed to dump blob chunks")?;
                    blob_comp_info.blob_size += size;
                    if idx < prefetch_entries {
                        blob_comp_info.blob_readahead_size += size;
                    }
                }
            }
            SourceType::StargzIndex => {
                for node in &mut ctx.nodes {
                    if node.overlay.is_lower_layer() {
                        continue;
                    } else if node.is_symlink() {
                        node.inode.i_digest = RafsDigest::from_buf(
                            node.symlink.as_ref().unwrap().as_bytes(),
                            digest::Algorithm::Sha256,
                        );
                    } else {
                        // Set blob index and inode digest for upper nodes
                        let mut inode_hasher = RafsDigest::hasher(digest::Algorithm::Sha256);
                        for chunk in node.chunks.iter_mut() {
                            (*chunk).blob_index = ctx.blob_index;
                            inode_hasher.digest_update(chunk.block_id.as_ref());
                        }
                        node.inode.i_digest = inode_hasher.digest_finalize();
                    }
                }
            }
        }

        self.blob_size = blob_comp_info.blob_size;

        Ok(blob_comp_info)
    }

    pub fn flush(self, ctx: &BuildContext) -> Result<()> {
        let blob_id = if self.blob_size > 0 {
            Some(ctx.blob_id.as_str())
        } else {
            None
        };
        self.writer.release(blob_id)
    }
}

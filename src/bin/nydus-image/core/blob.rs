// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::ffi::CString;
use std::fs::{remove_file, File, OpenOptions};
use std::io::{BufWriter, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use vmm_sys_util::tempfile::TempFile;

use nydus_utils::digest::{self, RafsDigest};

use super::context::{BuildContext, SourceType, BUF_WRITER_CAPACITY};
use super::node::*;

pub struct BlobBufferWriter {
    parent_dir: Option<File>,
    file: BufWriter<File>,
    blob_stor: BlobStorage,
    // Keep this because tmp file will be removed automatically when it is dropped.
    // But we will rename/link the tmp file before it is removed.
    _tmp_file: Option<TempFile>,
}

#[derive(Debug, Clone)]
pub enum BlobStorage {
    // Won't rename user's specification
    SingleFile(PathBuf),
    // Will rename it from tmp file as user didn't specify a
    BlobsDir(PathBuf),
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
                    parent_dir: None,
                    blob_stor,
                    _tmp_file: None,
                })
            }
            BlobStorage::BlobsDir(ref p) => {
                // Better we can use open(2) O_TMPFILE, but for compatibility sake, we delay this job.
                // TODO: Blob dir existence?
                let tmp = TempFile::new_in(&p)?;
                Ok(Self {
                    file: BufWriter::with_capacity(
                        BUF_WRITER_CAPACITY,
                        // Safe to unwrap because it should not be a bad fd.
                        tmp.as_file().try_clone().unwrap(),
                    ),
                    parent_dir: Some(File::open(p)?),
                    blob_stor,
                    _tmp_file: Some(tmp),
                })
            }
        }
    }

    pub fn write_all(&mut self, buf: &[u8]) -> Result<()> {
        self.file.write_all(buf).map_err(|e| anyhow!(e))
    }

    fn release(self, new_name: Option<&str>) -> Result<()> {
        let mut f = self.file.into_inner()?;
        f.flush()?;

        if let Some(name) = new_name {
            if let BlobStorage::BlobsDir(s) = &self.blob_stor {
                let empty = CString::default();

                // NOTE: File with same name will be deleted ahead of time.
                // So each newly generated blob can be stored.
                let might_exist_path = Path::new(s).join(name);
                if might_exist_path.exists() {
                    remove_file(might_exist_path)?;
                }

                // Safe because this doesn't modify any memory and we check the
                // return value. Being used fd never be closed before.
                let res = unsafe {
                    libc::linkat(
                        f.as_raw_fd(),
                        empty.as_ptr(),
                        // Safe because it is using BlobsDir storage.
                        self.parent_dir.unwrap().as_raw_fd(),
                        CString::new(name)?.as_ptr(),
                        libc::AT_EMPTY_PATH,
                    )
                };

                if res < 0 {
                    bail!(
                        "Rename blob to {} failed. error: {:?} ",
                        &name,
                        last_error!()
                    );
                }
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

pub struct Blob {
    writer: BlobBufferWriter,
    /// The size of newly generated blob. It might be ZERO if everything is the same with upper layer.
    blob_size: usize,
}

impl Blob {
    pub fn new(bs: BlobStorage) -> Result<Self> {
        Ok(Self {
            writer: BlobBufferWriter::new(bs)?,
            blob_size: 0,
        })
    }

    /// Dump blob file and generate chunks
    pub fn dump(&mut self, ctx: &mut BuildContext) -> Result<(Sha256, usize, usize)> {
        // NOTE: Don't try to sort readahead files by their sizes,  thus to keep files
        // belonging to the same directory arranged in adjacent in blob file. Together with
        // BFS style collecting descendants inodes, it will have a higher merging possibility.
        let readahead_files = ctx.prefetch.get_file_indexs();

        let blob_index = ctx.blob_table.entries.len() as u32;

        let mut blob_readahead_size = 0usize;
        let mut blob_size = 0usize;
        let mut compress_offset = 0u64;
        let mut decompress_offset = 0u64;
        let mut blob_hash = Sha256::new();

        match ctx.source_type {
            SourceType::Directory => {
                // Dump readahead nodes
                for index in &readahead_files {
                    let node = ctx.nodes.get_mut(**index as usize - 1).unwrap();
                    debug!("[{}]\treadahead {}", node.overlay, node);
                    if node.overlay == Overlay::UpperAddition
                        || node.overlay == Overlay::UpperModification
                    {
                        blob_readahead_size += node
                            .dump_blob(
                                // Safe to unwrap because `Directory source` must have blob
                                &mut self.writer,
                                &mut blob_hash,
                                &mut compress_offset,
                                &mut decompress_offset,
                                &mut ctx.chunk_cache,
                                &mut ctx.chunk_count_map,
                                ctx.compressor,
                                ctx.digester,
                                blob_index,
                                // TODO: Introduce build context to enclose the sparse states?
                                ctx.aligned_chunk,
                            )
                            .context("failed to dump readahead blob chunks")?;
                    }
                }

                blob_size += blob_readahead_size;

                // Dump other nodes
                for node in &mut ctx.nodes {
                    if ctx.prefetch.contains(node) {
                        continue;
                    }
                    // Ignore lower layer node when dump blob
                    debug!("[{}]\t{}", node.overlay, node);
                    if !node.is_dir()
                        && (node.overlay == Overlay::UpperAddition
                            || node.overlay == Overlay::UpperModification)
                    {
                        // Safe to unwrap because `Directory source` must have blob
                        blob_size += node
                            .dump_blob(
                                // Safe to unwrap because `Directory source` must have blob
                                &mut self.writer,
                                &mut blob_hash,
                                &mut compress_offset,
                                &mut decompress_offset,
                                &mut ctx.chunk_cache,
                                &mut ctx.chunk_count_map,
                                ctx.compressor,
                                ctx.digester,
                                blob_index,
                                ctx.aligned_chunk,
                            )
                            .context("failed to dump remaining blob chunks")?;
                    }
                }
            }
            SourceType::StargzIndex => {
                // Set blob index and inode digest for upper nodes
                for node in &mut ctx.nodes {
                    if node.overlay.lower_layer() {
                        continue;
                    }

                    let mut inode_hasher = RafsDigest::hasher(digest::Algorithm::Sha256);

                    for chunk in node.chunks.iter_mut() {
                        (*chunk).blob_index = blob_index;
                        inode_hasher.digest_update(chunk.block_id.as_ref());
                    }

                    if node.is_symlink() {
                        node.inode.i_digest = RafsDigest::from_buf(
                            node.symlink.as_ref().unwrap().as_bytes(),
                            digest::Algorithm::Sha256,
                        );
                    } else {
                        node.inode.i_digest = inode_hasher.digest_finalize();
                    }
                }
            }
        }

        self.blob_size = blob_size;

        Ok((blob_hash, blob_size, blob_readahead_size))
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

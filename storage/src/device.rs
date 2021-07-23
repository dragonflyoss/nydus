// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use arc_swap::ArcSwap;
use std::cmp;
use std::io;
use std::io::Error;
use std::sync::Arc;

use fuse_rs::api::filesystem::{ZeroCopyReader, ZeroCopyWriter};
use fuse_rs::transport::FileReadWriteVolatile;
use vm_memory::{Bytes, VolatileSlice};

use crate::cache::RafsCache;
use crate::{compress, factory, StorageResult};

use nydus_utils::digest::{self, RafsDigest};

static ZEROS: &[u8] = &[0u8; 4096]; // why 4096? volatile slice default size, unfortunately

// A rafs storage device
#[derive(Clone)]
pub struct RafsDevice {
    rw_layer: ArcSwap<Arc<dyn RafsCache + Send + Sync>>,
}

bitflags! {
    pub struct RafsChunkFlags: u32 {
        /// chunk is compressed
        const COMPRESSED = 0x0000_0001;
        const HOLECHUNK = 0x0000_0002;
    }
}

/// Trait to access Rafs Data Chunk Information.
/// Rafs store file contents into blob, which is isolated from the metadata.
/// ChunkInfo describes how a chunk is located and arranged within blob.
/// It is abstracted because Rafs have several ways to load metadata from bootstrap
/// TODO: Better we can put RafsChunkInfo back to rafs, but in order to isolate
/// two components and have a better performance, use RafsChunkInfo as a parameter
/// and keep it in storage trait. Otherwise we have to copy chunk digest everywhere.
/// We didn't make RafsChunkInfo as struct because we don't want to copy from memory mapped region of rafs metadata.
pub trait RafsChunkInfo: Sync + Send {
    fn block_id(&self) -> &RafsDigest;
    fn blob_index(&self) -> u32;
    fn index(&self) -> u32;
    fn compress_offset(&self) -> u64;
    fn compress_size(&self) -> u32;
    fn decompress_offset(&self) -> u64;
    fn decompress_size(&self) -> u32;
    fn file_offset(&self) -> u64;
    fn is_compressed(&self) -> bool;
    fn is_hole(&self) -> bool;
    fn flags(&self) -> RafsChunkFlags;
}

impl Default for RafsChunkFlags {
    fn default() -> Self {
        RafsChunkFlags::empty()
    }
}

/// Backend may be capable to prefetch a range of blob bypass upper file system
/// to blobcache. This should be asynchronous, so filesystem read cache hit
/// should validate data integrity.
pub struct BlobPrefetchControl {
    pub blob_id: String,
    pub offset: u32,
    pub len: u32,
}

impl RafsDevice {
    pub fn new(
        config: factory::Config,
        compressor: compress::Algorithm,
        digester: digest::Algorithm,
        id: &str,
    ) -> io::Result<RafsDevice> {
        Ok(RafsDevice {
            rw_layer: ArcSwap::new(Arc::new(factory::new_rw_layer(
                config, compressor, digester, id,
            )?)),
        })
    }

    pub fn update(
        &self,
        config: factory::Config,
        compressor: compress::Algorithm,
        digester: digest::Algorithm,
        id: &str,
    ) -> io::Result<()> {
        // Stop prefetch if it is running before swapping backend since prefetch
        // threads cloned Arc<Cache>, the swap operation can't drop inner object completely.
        // Otherwise prefetch threads will be leaked.
        self.stop_prefetch().unwrap_or_else(|e| error!("{:?}", e));
        self.rw_layer.store(Arc::new(factory::new_rw_layer(
            config, compressor, digester, id,
        )?));
        Ok(())
    }

    pub fn init(&self, prefetch_vec: &[BlobPrefetchControl]) -> io::Result<()> {
        self.rw_layer.load().init(prefetch_vec)
    }

    pub fn close(&self) -> io::Result<()> {
        self.rw_layer.load().release();
        Ok(())
    }

    /// Read a range of data from blob into the provided writer
    pub fn read_to(&self, w: &mut dyn ZeroCopyWriter, desc: RafsBioDesc) -> io::Result<usize> {
        let mut count: usize = 0;
        for bio in desc.bi_vec.iter() {
            let mut f = RafsBioDevice::new(bio, &self);
            count += w.write_from(&mut f, bio.size, bio.offset as u64)?;
        }
        Ok(count)
    }

    /// Write a range of data to blob from the provided reader
    pub fn write_from(&self, r: &mut dyn ZeroCopyReader, desc: RafsBioDesc) -> io::Result<usize> {
        let mut count: usize = 0;
        for bio in desc.bi_vec.iter() {
            let mut f = RafsBioDevice::new(bio, &self);
            let offset = bio.chunkinfo.compress_offset() + bio.offset as u64;
            count += r.read_to(&mut f, bio.size, offset)?;
        }
        Ok(count)
    }

    pub fn prefetch(&self, desc: &mut RafsBioDesc) -> StorageResult<usize> {
        self.rw_layer.load().prefetch(desc.bi_vec.as_mut_slice())?;

        Ok(desc.bi_size)
    }

    pub fn stop_prefetch(&self) -> StorageResult<()> {
        self.rw_layer.load().stop_prefetch()
    }
}

struct RafsBioDevice<'a> {
    bio: &'a RafsBio,
    dev: &'a RafsDevice,
}

impl<'a> RafsBioDevice<'a> {
    fn new(bio: &'a RafsBio, b: &'a RafsDevice) -> Self {
        // FIXME: make sure bio is valid
        RafsBioDevice { bio, dev: b }
    }
}

impl FileReadWriteVolatile for RafsBioDevice<'_> {
    fn read_volatile(&mut self, _slice: VolatileSlice) -> Result<usize, Error> {
        // Skip because we don't really use it
        unimplemented!();
    }

    fn write_volatile(&mut self, _slice: VolatileSlice) -> Result<usize, Error> {
        // Skip because we don't really use it
        unimplemented!();
    }

    fn read_at_volatile(&mut self, _slice: VolatileSlice, _offset: u64) -> Result<usize, Error> {
        unimplemented!();
    }

    // The default read_vectored_at_volatile only read to the first slice, so we have to overload it.
    fn read_vectored_at_volatile(
        &mut self,
        bufs: &[VolatileSlice],
        offset: u64,
    ) -> Result<usize, Error> {
        if self.bio.chunkinfo.is_hole() {
            return self.fill_hole(bufs);
        }

        self.dev.rw_layer.load().read(&self.bio, bufs, offset)
    }

    fn write_at_volatile(&mut self, slice: VolatileSlice, _offset: u64) -> Result<usize, Error> {
        // It's safe because the virtio buffer shouldn't be accessed concurrently.
        let buf = unsafe { std::slice::from_raw_parts_mut(slice.as_ptr(), slice.len()) };

        self.dev
            .rw_layer
            .load()
            .write(&self.bio.blob.blob_id, self.bio.chunkinfo.as_ref(), buf)
    }
}

impl RafsBioDevice<'_> {
    fn fill_hole(&self, bufs: &[VolatileSlice]) -> Result<usize, Error> {
        let mut count: usize = 0;
        let mut remain: usize = self.bio.size;

        for &buf in bufs.iter() {
            let mut total = cmp::min(remain, buf.len());
            let mut offset = 0;
            while total > 0 {
                let cnt = cmp::min(total, ZEROS.len());
                buf.write_slice(&ZEROS[0..cnt], offset)
                    .map_err(|_| eio!("decompression failed"))?;
                count += cnt;
                remain -= cnt;
                total -= cnt;
                offset += cnt;
            }
        }

        Ok(count)
    }
}

#[derive(Clone, Debug, Default)]
pub struct RafsBlobEntry {
    /// Number of chunks in blob file.
    /// A helper to distinguish bootstrap with extended blob table or not:
    ///     Bootstrap with extended blob table always has non-zero `chunk_count`
    pub chunk_count: u32,
    /// The data range to be prefetched in blob file.
    pub readahead_offset: u32,
    pub readahead_size: u32,
    /// A sha256 hex string generally.
    pub blob_id: String,
    /// The index of blob in RAFS blob table.
    pub blob_index: u32,
    /// The expected decompress size of blob cache file.
    pub blob_cache_size: u64,
}

impl RafsBlobEntry {
    pub fn with_extended_blob_table(&self) -> bool {
        self.chunk_count != 0
    }
}

// Rafs device blob IO descriptor
#[derive(Default)]
pub struct RafsBioDesc {
    // Blob IO flags
    pub bi_flags: u32,
    // Total IO size to be performed
    pub bi_size: usize,
    // Array of blob IO info. Corresponding data should be read from/write to IO stream sequentially
    pub bi_vec: Vec<RafsBio>,
}

impl RafsBioDesc {
    pub fn new() -> Self {
        RafsBioDesc {
            ..Default::default()
        }
    }
}

/// Rafs blob IO info
#[derive(Clone)]
pub struct RafsBio {
    /// reference to the chunk
    pub chunkinfo: Arc<dyn RafsChunkInfo>,
    /// reference to the blob where the chunk is located
    pub blob: Arc<RafsBlobEntry>,
    /// offset within the chunk
    pub offset: u32,
    /// size within the chunk
    pub size: usize,
    /// block size to read in one shot
    pub blksize: u32,
}

impl RafsBio {
    pub fn new(
        chunkinfo: Arc<dyn RafsChunkInfo>,
        blob: Arc<RafsBlobEntry>,
        offset: u32,
        size: usize,
        blksize: u32,
    ) -> Self {
        RafsBio {
            chunkinfo,
            blob,
            offset,
            size,
            blksize,
        }
    }
}

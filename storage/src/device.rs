// Copyright 2020 Ant Group. All rights reserved.
// Copyright (C) 2021 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use nydus_utils::digest::RafsDigest;

use crate::cache::RafsCache;

bitflags! {
    pub struct BlobChunkFlags: u32 {
        /// chunk is compressed
        const COMPRESSED = 0x0000_0001;
        const HOLECHUNK = 0x0000_0002;
    }
}

impl Default for BlobChunkFlags {
    fn default() -> Self {
        BlobChunkFlags::empty()
    }
}

/// Trait to get information about a data chunk.
///
/// The `BlobChunkInfo` object describes how a chunk is located and arranged within compressed and
/// uncompressed data blobs. The blob cache system may convert between compressed and uncompressed
/// forms by using the `BlobChunkInfo` interface.
pub trait BlobChunkInfo: Sync + Send {
    /// Get the message digest of the data chunk.
    fn block_id(&self) -> &RafsDigest;

    /// Get the unique id to identify the chunk within the metadata/data blob.
    ///
    /// The `d()` will be used as HashMap key, so there can't be duplicated ids for different chunks
    /// within a single blob object.
    fn id(&self) -> u32;

    /// Get the offset into the compressed data blob.
    fn compress_offset(&self) -> u64;

    /// Get the size of the compressed data chunk.
    fn compress_size(&self) -> u32;

    /// Get the offset into the decompressed data blob.
    fn decompress_offset(&self) -> u64;

    /// Get the size of the decompressed data chunk.
    fn decompress_size(&self) -> u32;

    /// Check whether the chunk is compressed or not.
    ///
    /// Some data chunk may become bigger after compressing, so plain data is stored in the
    /// compressed data blob for those chunks.
    fn is_compressed(&self) -> bool;

    /// Check whether the chunk is a hole chunk, containing all zeros.
    fn is_hole(&self) -> bool;
}

/// Struct to configure blob prefetch behavior.
///
/// It may help to improve performance for the storage backend to prefetch data in background.
/// The prefetch operation should be asynchronous, and cache hit for filesystem read operations
/// should validate data integrity.
pub struct BlobPrefetchControl {
    /// The ID of the blob to prefetch data for.
    pub blob_id: String,
    /// Offset into the blob to prefetch data.
    pub offset: u32,
    /// Size of data to prefetch.
    pub len: u32,
}

/// Struct representing a blob object.
#[derive(Clone, Debug, Default)]
pub struct BlobEntry {
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
    /// The compressed size of blob file.
    pub compressed_blob_size: u64,
}

/// Traits and Structs to support Rafs V5 image format.
pub mod v5 {
    use arc_swap::ArcSwap;
    use std::cmp;
    use std::fmt::Debug;
    use std::io;
    use std::io::Error;
    use std::sync::Arc;

    use fuse_backend_rs::api::filesystem::{ZeroCopyReader, ZeroCopyWriter};
    use fuse_backend_rs::transport::FileReadWriteVolatile;
    use nydus_utils::digest;
    use vm_memory::{Bytes, VolatileSlice};

    use super::*;
    use crate::device::BlobChunkInfo;
    use crate::{compress, factory, StorageResult};

    static ZEROS: &[u8] = &[0u8; 4096]; // why 4096? volatile slice default size, unfortunately

    /// Trait to get information about a rafs V5 data chunk.
    ///
    /// Rafs store file contents in blobs, which is separated from the metadata blob.
    /// The `Rafsv5ChunkInfo` object describes how a rafs V5 data chunk is located and arranged within
    /// data blobs.
    /// It is abstracted because Rafs have several ways to load metadata from bootstrap
    /// TODO: Better we can put RafsChunkInfo back to rafs, but in order to isolate
    /// two components and have a better performance, use RafsChunkInfo as a parameter
    /// and keep it in storage trait. Otherwise we have to copy chunk digest everywhere.
    /// We didn't make RafsChunkInfo as struct because we don't want to copy from memory mapped region of rafs metadata.
    pub trait BlobV5ChunkInfo: BlobChunkInfo {
        /// Get the blob index into the rafs V5 metadata's blob file array.
        fn blob_index(&self) -> u32;

        /// Get the file offset of the chunk data within the file it belongs to.
        fn file_offset(&self) -> u64;

        /// Get the chunk index in the rafs V5 metadata's chunk info array.
        fn index(&self) -> u32;

        /// Get flags associated with the data chunk.
        fn flags(&self) -> BlobChunkFlags;

        /// Cast to the base `BlobChunkInfo` trait object.
        fn as_base(&self) -> &dyn BlobChunkInfo;
    }

    /// Struct to maintain information for Rafs V5 blob IO operations.
    #[derive(Clone)]
    pub struct BlobV5Bio {
        /// The blob object to which the chunk belongs.
        pub blob: Arc<BlobEntry>,
        /// The associated chunk object for the IO operation.
        pub chunkinfo: Arc<dyn BlobV5ChunkInfo>,
        /// Offset from start of the chunk for the IO operation.
        pub offset: u32,
        /// Size of the IO operation
        pub size: usize,
        /// Block size to read in one shot.
        pub blksize: u32,
        /// Whether it's a user initiated IO, otherwise is a storage system internal IO.
        ///
        /// It might be initiated by user io amplification. With this flag, lower device
        /// layer may choose how to priority the IO operation.
        pub user_io: bool,
    }

    impl Debug for BlobV5Bio {
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.debug_struct("RafsBio")
                .field("blob index", &self.blob.blob_index)
                .field("blob compress offset", &self.chunkinfo.compress_offset())
                .field("chunk index", &self.chunkinfo.index())
                .field("file offset", &self.offset)
                .field("size", &self.size)
                .field("user", &self.user_io)
                .finish()
        }
    }

    impl BlobV5Bio {
        /// Create a new rafs V5 blob IO object.
        pub fn new(
            chunkinfo: Arc<dyn BlobV5ChunkInfo>,
            blob: Arc<BlobEntry>,
            offset: u32,
            size: usize,
            blksize: u32,
            user_io: bool,
        ) -> Self {
            BlobV5Bio {
                chunkinfo,
                blob,
                offset,
                size,
                blksize,
                user_io,
            }
        }
    }

    /// Rafs V5 blob IO descriptor, which may contain multiple blob IO operations.
    #[derive(Default)]
    pub struct BlobV5BioDesc {
        /// Blob IO flags.
        pub bi_flags: u32,
        /// Total size of blb IOs to be performed.
        pub bi_size: usize,
        /// Array of blob IOs, these IOs should executed sequentially.
        pub bi_vec: Vec<BlobV5Bio>,
    }

    impl BlobV5BioDesc {
        /// Create a new rafs V5 blob IO descriptor.
        pub fn new() -> Self {
            BlobV5BioDesc {
                ..Default::default()
            }
        }
    }

    // Rafs V5 storage device to execute blob IO operations.
    #[derive(Clone)]
    pub struct BlobV5Device {
        pub rw_layer: ArcSwap<Arc<dyn RafsCache + Send + Sync>>,
    }

    impl BlobV5Device {
        /// Create a rafs v5 blob device.
        pub fn new(
            config: factory::Config,
            compressor: compress::Algorithm,
            digester: digest::Algorithm,
            id: &str,
        ) -> io::Result<BlobV5Device> {
            Ok(BlobV5Device {
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
            self.rw_layer.load().destroy();
            Ok(())
        }

        /// Read a range of data from blob into the provided writer
        pub fn read_to(
            &self,
            w: &mut dyn ZeroCopyWriter,
            desc: &mut BlobV5BioDesc,
        ) -> io::Result<usize> {
            let offset = desc.bi_vec[0].offset;
            let size = desc.bi_size;
            let mut f = BlobV5BioDevice::new(desc, self);
            let count = w.write_from(&mut f, size, offset as u64)?;

            Ok(count)
        }

        /// Write a range of data to blob from the provided reader
        pub fn write_from(
            &self,
            _r: &mut dyn ZeroCopyReader,
            _desc: BlobV5BioDesc,
        ) -> io::Result<usize> {
            unimplemented!()
        }

        pub fn prefetch(&self, desc: &mut BlobV5BioDesc) -> StorageResult<usize> {
            self.rw_layer.load().prefetch(desc.bi_vec.as_mut_slice())?;

            Ok(desc.bi_size)
        }

        pub fn stop_prefetch(&self) -> StorageResult<()> {
            self.rw_layer.load().stop_prefetch()
        }
    }

    struct BlobV5BioDevice<'a> {
        dev: &'a BlobV5Device,
        desc: &'a mut BlobV5BioDesc,
    }

    impl<'a> BlobV5BioDevice<'a> {
        fn new(desc: &'a mut BlobV5BioDesc, b: &'a BlobV5Device) -> Self {
            BlobV5BioDevice { desc, dev: b }
        }
    }

    #[allow(dead_code)]
    impl BlobV5BioDevice<'_> {
        fn fill_hole(&self, bufs: &[VolatileSlice], size: usize) -> Result<usize, Error> {
            let mut count: usize = 0;
            let mut remain = size;

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

    impl FileReadWriteVolatile for BlobV5BioDevice<'_> {
        fn read_volatile(&mut self, _slice: VolatileSlice) -> Result<usize, Error> {
            // Skip because we don't really use it
            unimplemented!();
        }

        fn write_volatile(&mut self, _slice: VolatileSlice) -> Result<usize, Error> {
            // Skip because we don't really use it
            unimplemented!();
        }

        fn read_at_volatile(
            &mut self,
            _slice: VolatileSlice,
            _offset: u64,
        ) -> Result<usize, Error> {
            unimplemented!();
        }

        // The default read_vectored_at_volatile only read to the first slice, so we have to overload it.
        fn read_vectored_at_volatile(
            &mut self,
            bufs: &[VolatileSlice],
            _offset: u64,
        ) -> Result<usize, Error> {
            self.dev.rw_layer.load().read(&mut self.desc.bi_vec, bufs)
        }

        fn write_at_volatile(
            &mut self,
            _slice: VolatileSlice,
            _offset: u64,
        ) -> Result<usize, Error> {
            unimplemented!()
        }
    }

    impl BlobEntry {
        /// Check whether the rafs V5 metadata blob has extended blob table.
        pub fn with_v5_extended_blob_table(&self) -> bool {
            self.chunk_count != 0
        }
    }
}

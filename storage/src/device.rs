// Copyright 2020 Ant Group. All rights reserved.
// Copyright (C) 2021 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Blob Storage Public Service APIs
//!
//! The core functionality of the nydus-storage crate is to serve blob IO request, mainly read chunk
//! data from blobs. This module provides public APIs and data structures for clients to issue blob
//! IO requests. The main traits and structs provided include:
//! - [BlobChunkInfo](trait.BlobChunkInfo.html): trait to provide basic information for a  chunk.
//! - [BlobDevice](struct.BlobDevice.html): a wrapping object over a group of underlying [BlobCache]
//!   object to serve blob data access requests.
//! - [BlobInfo](struct.BlobInfo.html): configuration information for a metadata/data blob object.
//! - [BlobIoChunk](enum.BlobIoChunk.html): an enumeration to encapsulate different [BlobChunkInfo]
//!   implementations for [BlobIoDesc].
//! - [BlobIoDesc](struct.BlobIoDesc.html): a blob IO descriptor, containing information for a
//!   continuous IO range within a chunk.
//! - [BlobIoVec](struct.BlobIoVec.html): a scatter/gather list for blob IO operation, containing
//!   one or more blob IO descriptors
//! - [BlobPrefetchRequest](struct.BlobPrefetchRequest.html): a blob data prefetching request.
use std::cmp;
use std::fmt::Debug;
use std::io::{self, Error};
use std::sync::Arc;

use arc_swap::ArcSwap;
use fuse_backend_rs::api::filesystem::ZeroCopyWriter;
use fuse_backend_rs::transport::FileReadWriteVolatile;
use nydus_utils::digest::{self, RafsDigest};
use vm_memory::{Bytes, VolatileSlice};

use crate::cache::BlobCache;
use crate::compress;
use crate::factory::{FactoryConfig, BLOB_FACTORY};

static ZEROS: &[u8] = &[0u8; 4096]; // why 4096? volatile slice default size, unfortunately

/// Version number for blob files.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum BlobVersion {
    /// Blob files for Rafs v5 images
    V5 = 5,
}

impl Default for BlobVersion {
    fn default() -> Self {
        BlobVersion::V5
    }
}

/// Configuration information for a metadata/data blob object.
///
/// The `BlobInfo` structure provides information for the storage subsystem to manage a blob file
/// and serve blob IO requests for clients.
#[derive(Clone, Debug, Default)]
pub struct BlobInfo {
    /// Version of the Rafs filesystem.
    blob_version: BlobVersion,
    /// The index of blob in RAFS blob table.
    blob_index: u32,
    /// A sha256 hex string generally.
    blob_id: String,
    /// Size of the compressed blob file.
    compressed_size: u64,
    /// Size of the uncompressed blob file, or the cache file.
    uncompressed_size: u64,
    /// Number of chunks in blob file.
    /// A helper to distinguish bootstrap with extended blob table or not:
    ///     Bootstrap with extended blob table always has non-zero `chunk_count`
    chunk_count: u32,
    /// Compression algorithm to process the blob.
    compressor: compress::Algorithm,
    /// Message digest algorithm to process the blob.
    digester: digest::Algorithm,
    /// Starting offset of the data to prefetch.
    readahead_offset: u32,
    /// Size of blob data to prefetch.
    readahead_size: u32,
    /// Whether to validate blob data.
    validate_data: bool,
}

impl BlobInfo {
    /// Create a new instance of `BlobInfo`.
    pub fn new(
        blob_version: BlobVersion,
        blob_index: u32,
        blob_id: String,
        uncompressed_size: u64,
        compressed_size: u64,
        chunk_count: u32,
    ) -> Self {
        BlobInfo {
            blob_version,
            blob_index,
            blob_id,
            uncompressed_size,
            compressed_size,
            chunk_count,

            compressor: compress::Algorithm::None,
            digester: digest::Algorithm::Blake3,
            readahead_offset: 0,
            readahead_size: 0,
            validate_data: false,
        }
    }

    /// Get the blob version number.
    pub fn blob_version(&self) -> BlobVersion {
        self.blob_version
    }

    /// Check whether it's a blob for Rafs V5 image.
    pub fn is_v5(&self) -> bool {
        self.blob_version == BlobVersion::V5
    }

    /// Get the blob index in the blob array.
    pub fn blob_index(&self) -> u32 {
        self.blob_index
    }

    /// Set the blob index.
    pub fn set_blob_index(&mut self, index: u32) {
        self.blob_index = index;
    }

    /// Get the id of the blob.
    pub fn blob_id(&self) -> &str {
        &self.blob_id
    }

    /// Get size of the compressed blob.
    pub fn compressed_size(&self) -> u64 {
        self.compressed_size
    }

    /// Get size of the uncompressed blob.
    pub fn uncompressed_size(&self) -> u64 {
        self.uncompressed_size
    }

    // Get number of chunks in the blob.
    pub fn chunk_count(&self) -> u32 {
        self.chunk_count
    }

    /// Get the compression algorithm to handle the blob data.
    pub fn compressor(&self) -> compress::Algorithm {
        self.compressor
    }

    /// Set compression algorithm for the blob.
    pub fn set_compressor(&mut self, compressor: compress::Algorithm) {
        self.compressor = compressor;
    }

    /// Get the message digest algorithm for the blob.
    pub fn digester(&self) -> digest::Algorithm {
        self.digester
    }

    /// Set compression algorithm for the blob.
    pub fn set_digester(&mut self, digester: digest::Algorithm) {
        self.digester = digester;
    }

    /// Get blob data prefetching offset.
    pub fn readahead_offset(&self) -> u64 {
        self.readahead_offset as u64
    }

    /// Get blob data prefetching offset.
    pub fn readahead_size(&self) -> u64 {
        self.readahead_size as u64
    }

    /// Set a range for blob data prefetching.
    ///
    /// Only one range could be configured per blob, and zero readahead_size means disabling blob
    /// data prefetching.
    pub fn set_readahead(&mut self, offset: u64, size: u64) {
        self.readahead_offset = offset as u32;
        self.readahead_size = size as u32;
    }

    /// Check blob data validation configuration.
    pub fn validate_data(&self) -> bool {
        self.validate_data
    }

    /// Enable blob data validation
    pub fn enable_data_validation(&mut self, validate: bool) {
        self.validate_data = validate;
    }

    /// Check whether the Rafs v5 metadata blob has extended blob table.
    pub fn with_v5_extended_blob_table(&self) -> bool {
        self.blob_version == BlobVersion::V5 && self.chunk_count != 0
    }
}

bitflags! {
    /// Blob chunk flags.
    pub struct BlobChunkFlags: u32 {
        /// Chunk data is compressed.
        const COMPRESSED = 0x0000_0001;
        /// Chunk is a hole, with all data as zero.
        const HOLECHUNK = 0x0000_0002;
    }
}

impl Default for BlobChunkFlags {
    fn default() -> Self {
        BlobChunkFlags::empty()
    }
}

/// Trait to provide basic information for a chunk.
///
/// A `BlobChunkInfo` object describes how a chunk is located within the compressed and
/// uncompressed data blobs. It's used to help the storage subsystem to:
/// - download chunks from storage backend
/// - maintain chunk readiness state for each chunk
/// - convert from compressed form to uncompressed form
///
/// This trait may be extended to provide additional information for a specific Rafs filesystem
/// version, for example `BlobV5ChunkInfo` provides Rafs v5 filesystem related information about
/// a chunk.
pub trait BlobChunkInfo: Sync + Send {
    /// Get the message digest value of the chunk, which acts as an identifier for the chunk.
    fn chunk_id(&self) -> &RafsDigest;

    /// Get a unique ID to identify the chunk within the metadata/data blob.
    ///
    /// The returned value of `id()` is often been used as HashMap keys, so `id()` method should
    /// return unique identifier for each chunk of a blob file.
    fn id(&self) -> u32;

    /// Get the blob index of the blob file in the Rafs v5 metadata's blob array.
    fn blob_index(&self) -> u32;

    /// Get the chunk offset in the compressed blob.
    fn compress_offset(&self) -> u64;

    /// Get the size of the compressed chunk.
    fn compress_size(&self) -> u32;

    /// Get the chunk offset in the uncompressed blob.
    fn uncompress_offset(&self) -> u64;

    /// Get the size of the uncompressed chunk.
    fn uncompress_size(&self) -> u32;

    /// Check whether the chunk is compressed or not.
    ///
    /// Some chunk may become bigger after compression, so plain data instead of compressed
    /// data may be stored in the compressed data blob for those chunks.
    fn is_compressed(&self) -> bool;

    /// Check whether the chunk is a hole, containing all zeros.
    fn is_hole(&self) -> bool;
}

/// An enumeration to encapsulate different [BlobChunkInfo] implementations for [BlobIoDesc].
#[derive(Clone)]
pub enum BlobIoChunk {
    Base(Arc<dyn BlobChunkInfo>),
    V5(Arc<dyn self::v5::BlobV5ChunkInfo>),
}

impl BlobIoChunk {
    /// Convert a [BlobIoChunk] to a reference to [BlobChunkInfo] trait object.
    pub fn as_base(&self) -> &(dyn BlobChunkInfo) {
        match self {
            BlobIoChunk::Base(v) => &**v,
            BlobIoChunk::V5(v) => v.as_base(),
        }
    }

    /// Convert to an reference of `BlobV5ChunkInfo` trait object.
    pub fn as_v5(&self) -> std::io::Result<&Arc<dyn self::v5::BlobV5ChunkInfo>> {
        match self {
            BlobIoChunk::V5(v) => Ok(v),
            _ => Err(einval!(
                "BlobIoChunk doesn't contain a BlobV5ChunkInfo object."
            )),
        }
    }
}

impl From<Arc<dyn BlobChunkInfo>> for BlobIoChunk {
    fn from(v: Arc<dyn BlobChunkInfo>) -> Self {
        BlobIoChunk::Base(v)
    }
}

impl From<Arc<dyn self::v5::BlobV5ChunkInfo>> for BlobIoChunk {
    fn from(v: Arc<dyn self::v5::BlobV5ChunkInfo>) -> Self {
        BlobIoChunk::V5(v)
    }
}

impl BlobChunkInfo for BlobIoChunk {
    fn chunk_id(&self) -> &RafsDigest {
        self.as_base().chunk_id()
    }

    fn id(&self) -> u32 {
        self.as_base().id()
    }

    fn blob_index(&self) -> u32 {
        self.as_base().blob_index()
    }

    fn compress_offset(&self) -> u64 {
        self.as_base().compress_offset()
    }

    fn compress_size(&self) -> u32 {
        self.as_base().compress_size()
    }

    fn uncompress_offset(&self) -> u64 {
        self.as_base().uncompress_offset()
    }

    fn uncompress_size(&self) -> u32 {
        self.as_base().uncompress_size()
    }

    fn is_compressed(&self) -> bool {
        self.as_base().is_compressed()
    }

    fn is_hole(&self) -> bool {
        self.as_base().is_hole()
    }
}

/// Blob IO descriptor, containing information for a continuous IO range within a chunk.
#[derive(Clone)]
pub struct BlobIoDesc {
    /// The blob associated with the IO operation.
    pub blob: Arc<BlobInfo>,
    /// The chunk associated with the IO operation.
    pub chunkinfo: BlobIoChunk,
    /// Offset from start of the chunk for the IO operation.
    pub offset: u32,
    /// Size of the IO operation
    pub size: usize,
    /// Block size to read in one shot.
    pub chunk_size: u32,
    /// Whether it's a user initiated IO, otherwise is a storage system internal IO.
    ///
    /// It might be initiated by user io amplification. With this flag, lower device
    /// layer may choose how to priority the IO operation.
    pub user_io: bool,
}

impl BlobIoDesc {
    /// Create a new blob IO descriptor.
    pub fn new(
        blob: Arc<BlobInfo>,
        chunkinfo: BlobIoChunk,
        offset: u32,
        size: usize,
        chunk_size: u32,
        user_io: bool,
    ) -> Self {
        BlobIoDesc {
            chunkinfo,
            blob,
            offset,
            size,
            chunk_size,
            user_io,
        }
    }
}

impl Debug for BlobIoDesc {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("RafsBio")
            .field("blob index", &self.blob.blob_index)
            .field("blob compress offset", &self.chunkinfo.compress_offset())
            .field("chunk id", &self.chunkinfo.id())
            .field("file offset", &self.offset)
            .field("size", &self.size)
            .field("user", &self.user_io)
            .finish()
    }
}

/// Scatter/gather list for blob IO operation, containing zero or more blob IO descriptors
#[derive(Default)]
pub struct BlobIoVec {
    /// Blob IO flags.
    pub bi_flags: u32,
    /// Total size of blb IOs to be performed.
    pub bi_size: usize,
    /// Array of blob IOs, these IOs should executed sequentially.
    pub bi_vec: Vec<BlobIoDesc>,
}

impl BlobIoVec {
    /// Create a new blob IO scatter/gather list object.
    pub fn new() -> Self {
        BlobIoVec {
            ..Default::default()
        }
    }

    /// Append another blob io vector to current one.
    pub fn append(&mut self, mut desc: BlobIoVec) {
        self.bi_vec.append(desc.bi_vec.as_mut());
        self.bi_size += desc.bi_size;
        debug_assert!(self.validate());
    }

    /// Reset the blob io vector.
    pub fn reset(&mut self) {
        self.bi_size = 0;
        self.bi_vec.truncate(0);
    }

    /// Get the target blob of the blob io vector.
    pub fn get_target_blob(&self) -> Option<Arc<BlobInfo>> {
        if self.bi_vec.is_empty() {
            None
        } else {
            debug_assert!(self.validate());
            Some(self.bi_vec[0].blob.clone())
        }
    }

    /// Get the target blob index of the blob io vector.
    pub fn get_target_blob_index(&self) -> Option<u32> {
        if self.bi_vec.is_empty() {
            None
        } else {
            debug_assert!(self.validate());
            Some(self.bi_vec[0].blob.blob_index())
        }
    }

    /// Check whether the blob io vector is targeting the blob with `blob_index`
    pub fn is_target_blob(&self, blob_index: u32) -> bool {
        debug_assert!(self.validate());
        !self.bi_vec.is_empty() && self.bi_vec[0].blob.blob_index() == blob_index
    }

    /// Check whether two blob io vector targets the same blob.
    pub fn has_same_blob(&self, desc: &BlobIoVec) -> bool {
        debug_assert!(self.validate());
        debug_assert!(desc.validate());
        !self.bi_vec.is_empty()
            && !desc.bi_vec.is_empty()
            && self.bi_vec[0].blob.blob_index() == desc.bi_vec[0].blob.blob_index()
    }

    #[allow(dead_code)]
    fn validate(&self) -> bool {
        if self.bi_vec.len() > 1 {
            let blob_index = self.bi_vec[0].blob.blob_index();
            for n in &self.bi_vec[1..] {
                if n.blob.blob_index() != blob_index {
                    return false;
                }
            }
        }

        true
    }
}

/// Struct representing a blob data prefetching request.
///
/// It may help to improve performance for the storage backend to prefetch data in background.
/// A `BlobPrefetchControl` object advises to prefetch data range [offset, offset + len) from
/// blob `blob_id`. The prefetch operation should be asynchronous, and cache hit for filesystem
/// read operations should validate data integrity.
pub struct BlobPrefetchRequest {
    /// The ID of the blob to prefetch data for.
    pub blob_id: String,
    /// Offset into the blob to prefetch data.
    pub offset: u32,
    /// Size of data to prefetch.
    pub len: u32,
}

/// A wrapping object over an underlying [BlobCache] object.
///
/// All blob Io requests are actually served by the underlying [BlobCache] object. A new method
/// [update()]() is added to switch the storage backend on demand.
#[derive(Clone)]
pub struct BlobDevice {
    //meta: ArcSwap<Arc<dyn BlobCache>>,
    blobs: ArcSwap<Vec<Arc<dyn BlobCache>>>,
    blob_count: usize,
}

impl BlobDevice {
    /// Create new blob device instance.
    pub fn new(
        config: &Arc<FactoryConfig>,
        blob_infos: &[Arc<BlobInfo>],
    ) -> io::Result<BlobDevice> {
        let mut blobs = Vec::with_capacity(blob_infos.len());
        for blob_info in blob_infos.iter() {
            let blob = BLOB_FACTORY.new_blob_cache(config, blob_info)?;
            blobs.push(blob);
        }

        Ok(BlobDevice {
            blobs: ArcSwap::new(Arc::new(blobs)),
            blob_count: blob_infos.len(),
        })
    }

    /// Update configuration and storage backends of the blob device.
    ///
    /// The `update()` method switch a new storage backend object according to the configuration
    /// information passed in.
    pub fn update(
        &self,
        config: &Arc<FactoryConfig>,
        blob_infos: &[Arc<BlobInfo>],
    ) -> io::Result<()> {
        if self.blobs.load().len() != blob_infos.len() {
            return Err(einval!("number of blobs doesn't match"));
        }
        let mut blobs = Vec::with_capacity(blob_infos.len());
        for blob_info in blob_infos.iter() {
            let blob = BLOB_FACTORY.new_blob_cache(config, blob_info)?;
            blobs.push(blob);
        }

        // Stop prefetch if it is running before swapping backend since prefetch threads cloned
        // Arc<BlobCache>, the swap operation can't drop inner object completely.
        // Otherwise prefetch threads will be leaked.
        for blob in self.blobs.load().iter() {
            blob.stop_prefetch().unwrap_or_else(|e| error!("{:?}", e));
        }

        self.blobs.store(Arc::new(blobs));

        Ok(())
    }

    /// Close the blob device.
    pub fn close(&self) -> io::Result<()> {
        for blob in self.blobs.load().iter() {
            blob.stop_prefetch().unwrap_or_else(|e| error!("{:?}", e));
        }

        Ok(())
    }

    /// Read a range of data from blob into the provided writer
    pub fn read_to(&self, w: &mut dyn ZeroCopyWriter, desc: &mut BlobIoVec) -> io::Result<usize> {
        // Validate that:
        // - bi_vec[0] is valid
        // - bi_vec[0].blob.blob_index() is valid
        // - all IOs are against a single blob.
        if desc.bi_vec.len() == 0 {
            if desc.bi_size == 0 {
                Ok(0)
            } else {
                Err(einval!("BlobIoVec size doesn't match."))
            }
        } else if !desc.validate() {
            Err(einval!("BlobIoVec targets multiple blobs."))
        } else if desc.bi_vec[0].blob.blob_index() as usize >= self.blob_count {
            Err(einval!("BlobIoVec has out of range blob_index."))
        } else {
            let mut f = BlobDeviceIoVec::new(self, desc);
            // The `off` parameter to w.write_from() is actually ignored by
            // BlobV5IoVec::read_vectored_at_volatile()
            w.write_from(&mut f, desc.bi_size, 0)
        }
    }

    /// Try to prefetch specified blob data.
    pub fn prefetch(
        &self,
        io_vecs: &[&BlobIoVec],
        prefetches: &[BlobPrefetchRequest],
    ) -> io::Result<()> {
        for idx in 0..prefetches.len() {
            if let Some(blob) = self.get_blob_by_id(&prefetches[idx].blob_id) {
                let _ = blob
                    .prefetch(&prefetches[idx..idx + 1], &[])
                    .map_err(|_e| eio!("failed to prefetch blob data"));
            }
        }
        for io_vec in io_vecs.iter() {
            if let Some(blob) = self.get_blob_by_iovec(io_vec) {
                let _ = blob
                    .prefetch(&[], &io_vec.bi_vec)
                    .map_err(|_e| eio!("failed to prefetch blob data"));
            }
        }

        Ok(())
    }

    /// Stop the background blob data prefetch task.
    pub fn stop_prefetch(&self) {
        for blob in self.blobs.load().iter() {
            let _ = blob.stop_prefetch();
        }
    }

    /// Check all chunks related to the blob io vector are ready.
    pub fn is_all_chunk_ready(&self, io_vec: &BlobIoVec) -> bool {
        if let Some(blob) = self.get_blob_by_iovec(io_vec) {
            for desc in io_vec.bi_vec.iter() {
                if !blob.is_chunk_ready(&desc.chunkinfo) {
                    return false;
                }
            }
            return true;
        }

        false
    }

    fn get_blob_by_iovec(&self, iovec: &BlobIoVec) -> Option<Arc<dyn BlobCache>> {
        if let Some(blob_index) = iovec.get_target_blob_index() {
            if (blob_index as usize) < self.blob_count {
                return Some(self.blobs.load()[blob_index as usize].clone());
            }
        }

        None
    }

    fn get_blob_by_id(&self, blob_id: &str) -> Option<Arc<dyn BlobCache>> {
        for blob in self.blobs.load().iter() {
            if blob.blob_id() == blob_id {
                return Some(blob.clone());
            }
        }

        None
    }
}

/// Struct to execute Io requests with a single blob.
struct BlobDeviceIoVec<'a> {
    dev: &'a BlobDevice,
    desc: &'a BlobIoVec,
}

impl<'a> BlobDeviceIoVec<'a> {
    fn new(dev: &'a BlobDevice, desc: &'a BlobIoVec) -> Self {
        BlobDeviceIoVec { dev, desc }
    }
}

#[allow(dead_code)]
impl BlobDeviceIoVec<'_> {
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

impl FileReadWriteVolatile for BlobDeviceIoVec<'_> {
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
        _offset: u64,
    ) -> Result<usize, Error> {
        // BlobDevice::read_to() has validated that:
        // - bi_vec[0] is valid
        // - bi_vec[0].blob.blob_index() is valid
        // - all IOs are against a single blob.
        let index = self.desc.bi_vec[0].blob.blob_index();
        let blobs = &self.dev.blobs.load();

        blobs[index as usize].read(&self.desc.bi_vec, bufs)
    }

    fn write_at_volatile(&mut self, _slice: VolatileSlice, _offset: u64) -> Result<usize, Error> {
        unimplemented!()
    }
}

/// Traits and Structs to support Rafs v5 image format.
///
/// The Rafs v5 image format is designed with fused filesystem metadata and blob management
/// metadata, which is simple to implement but also introduces inter-dependency between the
/// filesystem layer and the blob management layer. This circular dependency is hard to maintain
/// and extend. Newer Rafs image format adopts designs with independent blob management layer,
/// which could be easily used to support both fuse and virtio-fs. So Rafs v5 image specific
/// interfaces are isolated into a dedicated sub-module.
pub mod v5 {
    use super::*;

    /// Trait to provide extended information for a Rafs v5 chunk.
    ///
    /// Rafs filesystem stores filesystem metadata in a single metadata blob, and stores file
    /// content in zero or more data blobs, which are separated from the metadata blob.
    /// A `Rafsv5ChunkInfo` object describes how a Rafs v5 chunk is located within a data blob.
    /// It is abstracted because Rafs have several ways to load metadata from metadata blob.
    pub trait BlobV5ChunkInfo: BlobChunkInfo {
        /// Get the chunk index in the Rafs v5 metadata's chunk info array.
        fn index(&self) -> u32;

        /// Get the file offset within the Rafs file it belongs to.
        fn file_offset(&self) -> u64;

        /// Get flags of the chunk.
        fn flags(&self) -> BlobChunkFlags;

        /// Cast to a base [BlobChunkInfo] trait object.
        fn as_base(&self) -> &dyn BlobChunkInfo;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockChunk {
        digest: RafsDigest,
        id: u32,
        compressed_offset: u64,
        compressed_size: u32,
        uncompressed_offset: u64,
        uncompressed_size: u32,
    }

    impl BlobChunkInfo for MockChunk {
        fn chunk_id(&self) -> &RafsDigest {
            &self.digest
        }

        fn id(&self) -> u32 {
            self.id
        }

        fn blob_index(&self) -> u32 {
            0
        }

        fn compress_offset(&self) -> u64 {
            self.compressed_offset
        }

        fn compress_size(&self) -> u32 {
            self.compressed_size
        }

        fn uncompress_offset(&self) -> u64 {
            self.uncompressed_offset
        }

        fn uncompress_size(&self) -> u32 {
            self.uncompressed_size
        }

        fn is_compressed(&self) -> bool {
            true
        }

        fn is_hole(&self) -> bool {
            false
        }
    }

    #[test]
    fn test_blob_io_chunk() {
        let chunk: Arc<dyn BlobChunkInfo> = Arc::new(MockChunk {
            digest: Default::default(),
            id: 3,
            compressed_offset: 0x1000,
            compressed_size: 0x100,
            uncompressed_offset: 0x2000,
            uncompressed_size: 0x200,
        });
        let iochunk: BlobIoChunk = chunk.clone().into();

        assert_eq!(iochunk.id(), 3);
        assert_eq!(iochunk.compress_offset(), 0x1000);
        assert_eq!(iochunk.compress_size(), 0x100);
        assert_eq!(iochunk.uncompress_offset(), 0x2000);
        assert_eq!(iochunk.uncompress_size(), 0x200);
        assert_eq!(iochunk.is_compressed(), true);
        assert_eq!(iochunk.is_hole(), false);
    }
}

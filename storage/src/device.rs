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
use std::any::Any;
use std::collections::hash_map::Drain;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::fmt::{Debug, Formatter};
use std::fs::File;
use std::io::{self, Error};
use std::ops::Deref;
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::sync::{Arc, Mutex};

use arc_swap::ArcSwap;
use fuse_backend_rs::api::filesystem::ZeroCopyWriter;
use fuse_backend_rs::file_buf::FileVolatileSlice;
use fuse_backend_rs::file_traits::FileReadWriteVolatile;

use nydus_api::ConfigV2;
use nydus_utils::compress;
use nydus_utils::crypt::{self, Cipher, CipherContext};
use nydus_utils::digest::{self, RafsDigest};

use crate::cache::BlobCache;
use crate::factory::BLOB_FACTORY;

pub(crate) const BLOB_FEATURE_INCOMPAT_MASK: u32 = 0x0000_ffff;
pub(crate) const BLOB_FEATURE_INCOMPAT_VALUE: u32 = 0x0000_0fff;

bitflags! {
    /// Features bits for blob management.
    pub struct BlobFeatures: u32 {
        /// Uncompressed chunk data is aligned.
        const ALIGNED = 0x0000_0001;
        /// RAFS meta data is inlined in the data blob.
        const INLINED_FS_META = 0x0000_0002;
        /// Blob chunk information format v2.
        const CHUNK_INFO_V2 = 0x0000_0004;
        /// Blob compression information data include context data for zlib random access.
        const ZRAN = 0x0000_0008;
        /// Blob data and blob meta are stored in separate blobs.
        const SEPARATE = 0x0000_0010;
        /// Chunk digest array is inlined in the data blob.
        const INLINED_CHUNK_DIGEST = 0x0000_0020;
        /// Blob is for RAFS filesystems in TARFS mode.
        const TARFS = 0x0000_0040;
        /// Small file chunk are merged into batch chunk.
        const BATCH = 0x0000_0080;
        /// Whether the Blob is encrypted.
        const ENCRYPTED = 0x0000_0100;
        /// Blob has TAR headers to separate contents.
        const HAS_TAR_HEADER = 0x1000_0000;
        /// Blob has Table of Content (ToC) at the tail.
        const HAS_TOC = 0x2000_0000;
        /// Data blob are encoded with Tar header and optionally ToC.
        /// It's also a flag indicating that images are generated with `nydus-image` v2.2 or newer.
        const CAP_TAR_TOC = 0x4000_0000;
        /// Rafs V5 image without extended blob table, this is an internal flag.
        const _V5_NO_EXT_BLOB_TABLE = 0x8000_0000;
    }
}

impl Default for BlobFeatures {
    fn default() -> Self {
        BlobFeatures::empty()
    }
}

impl BlobFeatures {
    /// Check whether the blob is for RAFS filesystems in TARFS mode.
    pub fn is_tarfs(&self) -> bool {
        self.contains(BlobFeatures::CAP_TAR_TOC) && self.contains(BlobFeatures::TARFS)
    }
}

impl TryFrom<u32> for BlobFeatures {
    type Error = Error;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        if value & BLOB_FEATURE_INCOMPAT_MASK & !BLOB_FEATURE_INCOMPAT_VALUE != 0
            || value & BlobFeatures::_V5_NO_EXT_BLOB_TABLE.bits() != 0
        {
            Err(einval!(format!("invalid blob features: 0x{:x}", value)))
        } else {
            // Safe because we have just validated feature flags.
            Ok(unsafe { BlobFeatures::from_bits_unchecked(value) })
        }
    }
}

/// Configuration information for a metadata/data blob object.
///
/// The `BlobInfo` structure provides information for the storage subsystem to manage a blob file
/// and serve blob IO requests for clients.
#[derive(Clone, Debug, Default)]
pub struct BlobInfo {
    /// The index of blob in RAFS blob table.
    blob_index: u32,
    /// A sha256 hex string generally.
    blob_id: String,
    /// Feature bits for blob management.
    blob_features: BlobFeatures,
    /// Size of the compressed blob file.
    compressed_size: u64,
    /// Size of the uncompressed blob file, or the cache file.
    uncompressed_size: u64,
    /// Chunk size.
    chunk_size: u32,
    /// Number of chunks in blob file.
    /// A helper to distinguish bootstrap with extended blob table or not:
    ///     Bootstrap with extended blob table always has non-zero `chunk_count`
    chunk_count: u32,
    /// Compression algorithm to process the blob.
    compressor: compress::Algorithm,
    /// Chunk data encryption algorithm.
    cipher: crypt::Algorithm,
    /// Message digest algorithm to process the blob.
    digester: digest::Algorithm,
    /// Starting offset of the data to prefetch.
    prefetch_offset: u32,
    /// Size of blob data to prefetch.
    prefetch_size: u32,
    /// The blob is for a legacy estargz image.
    is_legacy_stargz: bool,

    /// V6: compressor that is used for compressing chunk info array.
    meta_ci_compressor: u32,
    /// V6: Offset of the chunk information array in the compressed blob.
    meta_ci_offset: u64,
    /// V6: Size of the compressed chunk information array.
    meta_ci_compressed_size: u64,
    /// V6: Size of the uncompressed chunk information array.
    meta_ci_uncompressed_size: u64,

    // SHA256 digest of blob ToC content, including the toc tar header.
    // It's all zero for blobs with inlined-meta.
    blob_toc_digest: [u8; 32],
    // SHA256 digest of RAFS blob for ZRAN, containing `blob.meta`, `blob.digest` `blob.toc` and
    // optionally 'image.boot`. It's all zero for ZRAN blobs with inlined-meta, so need special
    // handling.
    blob_meta_digest: [u8; 32],
    // Size of RAFS blob for ZRAN. It's zero ZRAN blobs with inlined-meta.
    blob_meta_size: u64,
    // Size of blob ToC content, it's zero for blobs with inlined-meta.
    blob_toc_size: u32,

    /// V6: support fs-cache mode
    fs_cache_file: Option<Arc<File>>,
    /// V6: support inlined-meta
    meta_path: Arc<Mutex<String>>,
    /// V6: support data encryption.
    cipher_object: Arc<Cipher>,
    /// Cipher context for encryption.
    cipher_ctx: Option<CipherContext>,
}

impl BlobInfo {
    /// Create a new instance of `BlobInfo`.
    pub fn new(
        blob_index: u32,
        blob_id: String,
        uncompressed_size: u64,
        compressed_size: u64,
        chunk_size: u32,
        chunk_count: u32,
        blob_features: BlobFeatures,
    ) -> Self {
        let blob_id = blob_id.trim_end_matches('\0').to_string();
        let mut blob_info = BlobInfo {
            blob_index,
            blob_id,
            blob_features,
            uncompressed_size,
            compressed_size,
            chunk_size,
            chunk_count,

            compressor: compress::Algorithm::None,
            cipher: crypt::Algorithm::None,
            digester: digest::Algorithm::Blake3,
            prefetch_offset: 0,
            prefetch_size: 0,
            is_legacy_stargz: false,
            meta_ci_compressor: 0,
            meta_ci_offset: 0,
            meta_ci_compressed_size: 0,
            meta_ci_uncompressed_size: 0,

            blob_toc_digest: [0u8; 32],
            blob_meta_digest: [0u8; 32],
            blob_meta_size: 0,
            blob_toc_size: 0,

            fs_cache_file: None,
            meta_path: Arc::new(Mutex::new(String::new())),
            cipher_object: Default::default(),
            cipher_ctx: None,
        };

        blob_info.compute_features();

        blob_info
    }

    /// Get the blob index in the blob array.
    pub fn blob_index(&self) -> u32 {
        self.blob_index
    }

    /// Get the id of the blob, with special handling of `inlined-meta` case.
    pub fn blob_id(&self) -> String {
        if (self.has_feature(BlobFeatures::INLINED_FS_META)
            && !self.has_feature(BlobFeatures::SEPARATE))
            || !self.has_feature(BlobFeatures::CAP_TAR_TOC)
        {
            let guard = self.meta_path.lock().unwrap();
            if !guard.is_empty() {
                return guard.deref().clone();
            }
        }
        self.blob_id.clone()
    }

    /// Get raw blob id, without special handling of `inlined-meta` case.
    pub fn raw_blob_id(&self) -> &str {
        &self.blob_id
    }

    /// Get size of compressed chunk data, not including `blob.meta`, `blob.chunk`, `toc` etc.
    pub fn compressed_data_size(&self) -> u64 {
        if self.has_feature(BlobFeatures::SEPARATE) {
            // It's the size of referenced OCIv1 targz blob.
            self.compressed_size
        } else if self.has_feature(BlobFeatures::CAP_TAR_TOC) {
            // Image built with nydus 2.2 and newer versions.
            if self.meta_ci_is_valid() {
                // For RAFS v6
                if self.has_feature(BlobFeatures::HAS_TAR_HEADER) {
                    // There's a tar header between chunk data and compression information.
                    self.meta_ci_offset - 0x200
                } else {
                    self.meta_ci_offset
                }
            } else {
                // For RAFS v5
                if self.has_feature(BlobFeatures::HAS_TAR_HEADER) {
                    // There's a tar header between chunk data and fs meta data.
                    self.compressed_size - 0x200
                } else {
                    self.compressed_size
                }
            }
        } else {
            // Images built with nydus 2.1 and previous versions.
            self.compressed_size
        }
    }

    /// Get size of the compressed blob, including `blob.meta`, `blob.chunk`, `toc` etc.
    pub fn compressed_size(&self) -> u64 {
        self.compressed_size
    }

    /// Get size of the uncompressed blob.
    pub fn uncompressed_size(&self) -> u64 {
        self.uncompressed_size
    }

    /// Get chunk size.
    pub fn chunk_size(&self) -> u32 {
        self.chunk_size
    }

    /// Get number of chunks in the blob.
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
        self.compute_features();
    }

    /// Get the cipher algorithm to handle chunk data.
    pub fn cipher(&self) -> crypt::Algorithm {
        self.cipher
    }

    /// Set encryption algorithm for the blob.
    pub fn set_cipher(&mut self, cipher: crypt::Algorithm) {
        self.cipher = cipher;
    }

    /// Get the cipher object to encrypt/decrypt chunk data.
    pub fn cipher_object(&self) -> Arc<Cipher> {
        self.cipher_object.clone()
    }

    /// Get the cipher context.
    pub fn cipher_context(&self) -> Option<CipherContext> {
        self.cipher_ctx.clone()
    }

    /// Set the cipher info, including cipher algo, cipher object and cipher context.
    pub fn set_cipher_info(
        &mut self,
        cipher: crypt::Algorithm,
        cipher_object: Arc<Cipher>,
        cipher_ctx: Option<CipherContext>,
    ) {
        self.cipher = cipher;
        self.cipher_object = cipher_object;
        self.cipher_ctx = cipher_ctx;
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
    pub fn prefetch_offset(&self) -> u64 {
        self.prefetch_offset as u64
    }

    /// Get blob data prefetching offset.
    pub fn prefetch_size(&self) -> u64 {
        self.prefetch_size as u64
    }

    /// Set a range for blob data prefetching.
    ///
    /// Only one range could be configured per blob, and zero prefetch_size means disabling blob
    /// data prefetching.
    pub fn set_prefetch_info(&mut self, offset: u64, size: u64) {
        self.prefetch_offset = offset as u32;
        self.prefetch_size = size as u32;
    }

    /// Check whether this blob is for an stargz image.
    pub fn is_legacy_stargz(&self) -> bool {
        self.is_legacy_stargz
    }

    /// Set metadata information for a blob.
    ///
    /// The compressed blobs are laid out as:
    /// `[compressed chunk data], [compressed metadata], [uncompressed header]`.
    pub fn set_blob_meta_info(
        &mut self,
        offset: u64,
        compressed_size: u64,
        uncompressed_size: u64,
        compressor: u32,
    ) {
        self.meta_ci_compressor = compressor;
        self.meta_ci_offset = offset;
        self.meta_ci_compressed_size = compressed_size;
        self.meta_ci_uncompressed_size = uncompressed_size;
    }

    /// Get compression algorithm for chunk information array.
    pub fn meta_ci_compressor(&self) -> compress::Algorithm {
        if self.meta_ci_compressor == compress::Algorithm::Lz4Block as u32 {
            compress::Algorithm::Lz4Block
        } else if self.meta_ci_compressor == compress::Algorithm::GZip as u32 {
            compress::Algorithm::GZip
        } else if self.meta_ci_compressor == compress::Algorithm::Zstd as u32 {
            compress::Algorithm::Zstd
        } else {
            compress::Algorithm::None
        }
    }

    /// Get offset of chunk information array in the compressed blob.
    pub fn meta_ci_offset(&self) -> u64 {
        self.meta_ci_offset
    }

    /// Get size of the compressed chunk information array.
    pub fn meta_ci_compressed_size(&self) -> u64 {
        self.meta_ci_compressed_size
    }

    /// Get the uncompressed size of the chunk information array.
    pub fn meta_ci_uncompressed_size(&self) -> u64 {
        self.meta_ci_uncompressed_size
    }

    /// Check whether compression metadata is available.
    pub fn meta_ci_is_valid(&self) -> bool {
        self.meta_ci_compressed_size != 0 && self.meta_ci_uncompressed_size != 0
    }

    /// Set the associated `File` object provided by Linux fscache subsystem.
    pub fn set_fscache_file(&mut self, file: Option<Arc<File>>) {
        self.fs_cache_file = file;
    }

    #[cfg(target_os = "linux")]
    /// Get the associated `File` object provided by Linux fscache subsystem.
    pub(crate) fn get_fscache_file(&self) -> Option<Arc<File>> {
        self.fs_cache_file.clone()
    }

    /// Get blob features.
    pub fn features(&self) -> BlobFeatures {
        self.blob_features
    }

    /// Check whether the requested features are available.
    pub fn has_feature(&self, features: BlobFeatures) -> bool {
        self.blob_features.bits() & features.bits() == features.bits()
    }

    /// Generate feature flags according to blob configuration.
    fn compute_features(&mut self) {
        if self.chunk_count == 0 {
            self.blob_features |= BlobFeatures::_V5_NO_EXT_BLOB_TABLE;
        }
        if self.compressor == compress::Algorithm::GZip
            && !self.has_feature(BlobFeatures::CHUNK_INFO_V2)
        {
            self.is_legacy_stargz = true;
        }
    }

    /// Get SHA256 digest of the ToC content, including the toc tar header.
    ///
    /// It's all zero for inlined bootstrap.
    pub fn blob_toc_digest(&self) -> &[u8; 32] {
        &self.blob_toc_digest
    }

    /// Set SHA256 digest of the ToC content, including the toc tar header.
    pub fn set_blob_toc_digest(&mut self, digest: [u8; 32]) {
        self.blob_toc_digest = digest;
    }

    /// Get size of the ToC content. It's all zero for inlined bootstrap.
    pub fn blob_toc_size(&self) -> u32 {
        self.blob_toc_size
    }

    /// Set size of the ToC content.
    pub fn set_blob_toc_size(&mut self, sz: u32) {
        self.blob_toc_size = sz;
    }

    /// The RAFS blob contains `blob.meta`, `blob.digest`, `image.boot`, `ToC` etc.
    /// Get SHA256 digest of RAFS blob containing `blob.meta`, `blob.digest` `blob.toc` and
    /// optionally 'image.boot`.
    ///
    /// Default to `self.blob_id` when it's all zero.
    pub fn blob_meta_digest(&self) -> &[u8; 32] {
        &self.blob_meta_digest
    }

    /// Set SHA256 digest of the RAFS blob.
    pub fn set_blob_meta_digest(&mut self, digest: [u8; 32]) {
        self.blob_meta_digest = digest;
    }

    /// Get size of the RAFS blob.
    pub fn blob_meta_size(&self) -> u64 {
        self.blob_meta_size
    }

    /// Set size of the RAFS blob.
    pub fn set_blob_meta_size(&mut self, size: u64) {
        self.blob_meta_size = size;
    }

    /// Set path for meta blob file, which will be used by `get_blob_id()` and `get_blob_meta_id()`.
    pub fn set_blob_id_from_meta_path(&self, path: &Path) -> Result<(), Error> {
        *self.meta_path.lock().unwrap() = Self::get_blob_id_from_meta_path(path)?;
        Ok(())
    }

    pub fn get_blob_id_from_meta_path(path: &Path) -> Result<String, Error> {
        // Manual implementation of Path::file_prefix().
        let mut id = path.file_name().ok_or_else(|| {
            einval!(format!(
                "failed to get blob id from meta file path {}",
                path.display()
            ))
        })?;
        loop {
            let id1 = Path::new(id).file_stem().ok_or_else(|| {
                einval!(format!(
                    "failed to get blob id from meta file path {}",
                    path.display()
                ))
            })?;
            if id1.is_empty() {
                return Err(einval!(format!(
                    "failed to get blob id from meta file path {}",
                    path.display()
                )));
            } else if id == id1 {
                break;
            } else {
                id = id1;
            }
        }
        let id = id.to_str().ok_or_else(|| {
            einval!(format!(
                "failed to get blob id from meta file path {}",
                path.display()
            ))
        })?;

        Ok(id.to_string())
    }

    /// Get RAFS blob id for ZRan.
    pub fn get_blob_meta_id(&self) -> Result<String, Error> {
        assert!(self.has_feature(BlobFeatures::SEPARATE));
        let id = if self.has_feature(BlobFeatures::INLINED_FS_META) {
            let guard = self.meta_path.lock().unwrap();
            if guard.is_empty() {
                return Err(einval!("failed to get blob id from meta file name"));
            }
            guard.deref().clone()
        } else {
            hex::encode(&self.blob_meta_digest)
        };
        Ok(id)
    }

    /// Get the cipher info, including cipher algo, cipher object and cipher context.
    pub fn get_cipher_info(&self) -> (crypt::Algorithm, Arc<Cipher>, Option<CipherContext>) {
        (
            self.cipher,
            self.cipher_object.clone(),
            self.cipher_ctx.clone(),
        )
    }
}

bitflags! {
    /// Blob chunk flags.
    pub struct BlobChunkFlags: u32 {
        /// Chunk data is compressed.
        const COMPRESSED = 0x0000_0001;
        /// Chunk is a hole, with all data as zero.
        const _HOLECHUNK = 0x0000_0002;
        /// Chunk data is encrypted.
        const ENCYPTED = 0x0000_0004;
        /// Chunk data is merged into a batch chunk.
        const BATCH = 0x0000_0008;
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
pub trait BlobChunkInfo: Any + Sync + Send {
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
    fn compressed_offset(&self) -> u64;

    /// Get the size of the compressed chunk.
    fn compressed_size(&self) -> u32;

    /// Get end of the chunk in the compressed blob.
    fn compressed_end(&self) -> u64 {
        self.compressed_offset() + self.compressed_size() as u64
    }

    /// Get the chunk offset in the uncompressed blob.
    fn uncompressed_offset(&self) -> u64;

    /// Get the size of the uncompressed chunk.
    fn uncompressed_size(&self) -> u32;

    /// Get end of the chunk in the compressed blob.
    fn uncompressed_end(&self) -> u64 {
        self.uncompressed_offset() + self.uncompressed_size() as u64
    }

    /// Check whether the chunk is compressed or not.
    ///
    /// Some chunk may become bigger after compression, so plain data instead of compressed
    /// data may be stored in the compressed data blob for those chunks.
    fn is_compressed(&self) -> bool;

    /// Check whether the chunk is encrypted or not.
    fn is_encrypted(&self) -> bool;

    fn as_any(&self) -> &dyn Any;
}

/// An enumeration to encapsulate different [BlobChunkInfo] implementations for [BlobIoDesc].
///
/// This helps to feed unified IO description to storage subsystem from both rafs v6 and v5 since
/// rafs v6 have a different ChunkInfo definition on bootstrap.
#[derive(Clone)]
pub struct BlobIoChunk(Arc<dyn BlobChunkInfo>);

impl From<Arc<dyn BlobChunkInfo>> for BlobIoChunk {
    fn from(v: Arc<dyn BlobChunkInfo>) -> Self {
        BlobIoChunk(v)
    }
}

impl BlobChunkInfo for BlobIoChunk {
    fn chunk_id(&self) -> &RafsDigest {
        self.0.chunk_id()
    }

    fn id(&self) -> u32 {
        self.0.id()
    }

    fn blob_index(&self) -> u32 {
        self.0.blob_index()
    }

    fn compressed_offset(&self) -> u64 {
        self.0.compressed_offset()
    }

    fn compressed_size(&self) -> u32 {
        self.0.compressed_size()
    }

    fn uncompressed_offset(&self) -> u64 {
        self.0.uncompressed_offset()
    }

    fn uncompressed_size(&self) -> u32 {
        self.0.uncompressed_size()
    }

    fn is_compressed(&self) -> bool {
        self.0.is_compressed()
    }

    fn is_encrypted(&self) -> bool {
        self.0.is_encrypted()
    }

    fn as_any(&self) -> &dyn Any {
        self
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
    pub size: u32,
    /// Whether it's a user initiated IO, otherwise is a storage system internal IO.
    ///
    /// It might be initiated by user io amplification. With this flag, lower device
    /// layer may choose how to prioritize the IO operation.
    pub(crate) user_io: bool,
}

impl BlobIoDesc {
    /// Create a new blob IO descriptor.
    pub fn new(
        blob: Arc<BlobInfo>,
        chunkinfo: BlobIoChunk,
        offset: u32,
        size: u32,
        user_io: bool,
    ) -> Self {
        BlobIoDesc {
            blob,
            chunkinfo,
            offset,
            size,
            user_io,
        }
    }

    /// Check whether the `other` BlobIoDesc is continuous to current one.
    pub fn is_continuous(&self, next: &BlobIoDesc, max_gap: u64) -> bool {
        let prev_end = self.chunkinfo.compressed_offset() + self.chunkinfo.compressed_size() as u64;
        let next_offset = next.chunkinfo.compressed_offset();

        if self.chunkinfo.blob_index() == next.chunkinfo.blob_index() && next_offset >= prev_end {
            if next.blob.is_legacy_stargz() {
                next_offset - prev_end <= max_gap * 8
            } else {
                next_offset - prev_end <= max_gap
            }
        } else {
            false
        }
    }
}

impl Debug for BlobIoDesc {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("BlobIoDesc")
            .field("blob_index", &self.blob.blob_index)
            .field("chunk_index", &self.chunkinfo.id())
            .field("compressed_offset", &self.chunkinfo.compressed_offset())
            .field("file_offset", &self.offset)
            .field("size", &self.size)
            .field("user", &self.user_io)
            .finish()
    }
}

/// Scatter/gather list for blob IO operation, containing zero or more blob IO descriptors
pub struct BlobIoVec {
    /// The blob associated with the IO operation.
    bi_blob: Arc<BlobInfo>,
    /// Total size of blob IOs to be performed.
    bi_size: u64,
    /// Array of blob IOs, these IOs should executed sequentially.
    pub(crate) bi_vec: Vec<BlobIoDesc>,
}

impl BlobIoVec {
    /// Create a new blob IO scatter/gather list object.
    pub fn new(bi_blob: Arc<BlobInfo>) -> Self {
        BlobIoVec {
            bi_blob,
            bi_size: 0,
            bi_vec: Vec::with_capacity(128),
        }
    }

    /// Add a new 'BlobIoDesc' to the 'BlobIoVec'.
    pub fn push(&mut self, desc: BlobIoDesc) {
        assert_eq!(self.bi_blob.blob_index(), desc.blob.blob_index());
        assert_eq!(self.bi_blob.blob_id(), desc.blob.blob_id());
        assert!(self.bi_size.checked_add(desc.size as u64).is_some());
        self.bi_size += desc.size as u64;
        self.bi_vec.push(desc);
    }

    /// Append another blob io vector to current one.
    pub fn append(&mut self, mut vec: BlobIoVec) {
        assert_eq!(self.bi_blob.blob_id(), vec.bi_blob.blob_id());
        assert!(self.bi_size.checked_add(vec.bi_size).is_some());
        self.bi_vec.append(vec.bi_vec.as_mut());
        self.bi_size += vec.bi_size;
    }

    /// Reset the blob io vector.
    pub fn reset(&mut self) {
        self.bi_size = 0;
        self.bi_vec.truncate(0);
    }

    /// Get number of 'BlobIoDesc' in the 'BlobIoVec'.
    pub fn len(&self) -> usize {
        self.bi_vec.len()
    }

    /// Check whether there's 'BlobIoDesc' in the'BlobIoVec'.
    pub fn is_empty(&self) -> bool {
        self.bi_vec.is_empty()
    }

    /// Get size of pending IO data.
    pub fn size(&self) -> u64 {
        self.bi_size
    }

    /// Get an immutable reference to a `BlobIoDesc` entry.
    pub fn blob_io_desc(&self, index: usize) -> Option<&BlobIoDesc> {
        if index < self.bi_vec.len() {
            Some(&self.bi_vec[index])
        } else {
            None
        }
    }

    /// Get the target blob index of the blob io vector.
    pub fn blob_index(&self) -> u32 {
        self.bi_blob.blob_index()
    }

    /// Check whether the blob io vector is targeting the blob with `blob_index`
    pub fn is_target_blob(&self, blob_index: u32) -> bool {
        self.bi_blob.blob_index() == blob_index
    }

    /// Check whether two blob io vector targets the same blob.
    pub fn has_same_blob(&self, desc: &BlobIoVec) -> bool {
        self.bi_blob.blob_index() == desc.bi_blob.blob_index()
    }
}

impl Debug for BlobIoVec {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("BlobIoDesc")
            .field("blob_index", &self.bi_blob.blob_index)
            .field("size", &self.bi_size)
            .field("decriptors", &self.bi_vec)
            .finish()
    }
}

/// Helper structure to merge blob IOs to reduce IO requests.
#[derive(Default)]
pub struct BlobIoMerge {
    map: HashMap<String, BlobIoVec>,
    current: String,
}

impl BlobIoMerge {
    /// Append an `BlobIoVec` object to the merge state object.
    pub fn append(&mut self, desc: BlobIoVec) {
        if !desc.is_empty() {
            let id = desc.bi_blob.blob_id.as_str();
            if self.current != id {
                self.current = id.to_string();
            }
            if let Some(prev) = self.map.get_mut(id) {
                prev.append(desc);
            } else {
                self.map.insert(id.to_string(), desc);
            }
        }
    }

    /// Drain elements in the cache.
    pub fn drain(&mut self) -> Drain<'_, String, BlobIoVec> {
        self.map.drain()
    }

    /// Get current element.
    pub fn get_current_element(&mut self) -> Option<&mut BlobIoVec> {
        self.map.get_mut(&self.current)
    }
}

/// A segment representing a continuous range for a blob IO operation.
///
/// It can span multiple chunks while the `offset` is where the user io starts
/// within the first chunk and `len` is the total user io length of these chunks.
#[derive(Clone, Debug, Default)]
pub(crate) struct BlobIoSegment {
    /// Start position of the range within the chunk
    pub offset: u32,
    /// Size of the range within the chunk
    pub len: u32,
}

impl BlobIoSegment {
    /// Create a new instance of `ChunkSegment`.
    pub fn new(offset: u32, len: u32) -> Self {
        Self { offset, len }
    }

    #[inline]
    pub fn append(&mut self, offset: u32, len: u32) {
        assert!(offset.checked_add(len).is_some());
        assert_eq!(offset, 0);

        self.len += len;
    }

    pub fn is_empty(&self) -> bool {
        self.offset == 0 && self.len == 0
    }
}

/// Struct to maintain information about blob IO operation.
#[derive(Clone, Debug)]
pub(crate) enum BlobIoTag {
    /// Io requests to fulfill user requests.
    User(BlobIoSegment),
    /// Io requests to fulfill internal requirements.
    Internal,
}

impl BlobIoTag {
    /// Check whether the tag is a user issued io request.
    pub fn is_user_io(&self) -> bool {
        matches!(self, BlobIoTag::User(_))
    }
}

/// Struct to representing multiple continuous blob IO as one storage backend request.
///
/// For network based remote storage backend, such as Registry/OS, it may have limited IOPs
/// due to high request round-trip time, but have enough network bandwidth. In such cases,
/// it may help to improve performance by merging multiple continuous and small blob IO
/// requests into one big backend request.
///
/// A `BlobIoRange` request targets a continuous range of a single blob.
#[derive(Default, Clone)]
pub struct BlobIoRange {
    pub(crate) blob_info: Arc<BlobInfo>,
    pub(crate) blob_offset: u64,
    pub(crate) blob_size: u64,
    pub(crate) chunks: Vec<Arc<dyn BlobChunkInfo>>,
    pub(crate) tags: Vec<BlobIoTag>,
}

impl Debug for BlobIoRange {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        f.debug_struct("BlobIoRange")
            .field("blob_id", &self.blob_info.blob_id())
            .field("blob_offset", &self.blob_offset)
            .field("blob_size", &self.blob_size)
            .field("tags", &self.tags)
            .finish()
    }
}

impl BlobIoRange {
    /// Create a new instance of `BlobIoRange`.
    pub fn new(bio: &BlobIoDesc, capacity: usize) -> Self {
        let blob_size = bio.chunkinfo.compressed_size() as u64;
        let blob_offset = bio.chunkinfo.compressed_offset();
        assert!(blob_offset.checked_add(blob_size).is_some());

        let mut chunks = Vec::with_capacity(capacity);
        let mut tags = Vec::with_capacity(capacity);
        tags.push(Self::tag_from_desc(bio));
        chunks.push(bio.chunkinfo.0.clone());

        BlobIoRange {
            blob_info: bio.blob.clone(),
            blob_offset,
            blob_size,
            chunks,
            tags,
        }
    }

    /// Merge an `BlobIoDesc` into the `BlobIoRange` object.
    pub fn merge(&mut self, bio: &BlobIoDesc, max_gap: u64) {
        let end = self.blob_offset + self.blob_size;
        let offset = bio.chunkinfo.compressed_offset();
        let size = bio.chunkinfo.compressed_size() as u64;
        let size = if end == offset {
            assert!(offset.checked_add(size).is_some());
            size
        } else {
            assert!((offset > end && offset - end <= max_gap));
            size + (offset - end)
        };
        assert!(end.checked_add(size).is_some());

        self.blob_size += size;
        self.tags.push(Self::tag_from_desc(bio));
        self.chunks.push(bio.chunkinfo.0.clone());
    }

    fn tag_from_desc(bio: &BlobIoDesc) -> BlobIoTag {
        if bio.user_io {
            BlobIoTag::User(BlobIoSegment::new(bio.offset, bio.size as u32))
        } else {
            BlobIoTag::Internal
        }
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
    pub offset: u64,
    /// Size of data to prefetch.
    pub len: u64,
}

/// Trait to provide direct access to underlying uncompressed blob file.
///
/// The suggested flow to make use of an `BlobObject` is as below:
/// - call `is_all_data_ready()` to check all blob data has already been cached. If true, skip
///   next step.
/// - call `fetch()` to ensure blob range [offset, offset + size) has been cached.
/// - call `as_raw_fd()` to get the underlying file descriptor for direct access.
/// - call File::read(buf, offset + `base_offset()`, size) to read data from underlying cache file.
pub trait BlobObject: AsRawFd {
    /// Get base offset to read blob from the fd returned by `as_raw_fd()`.
    fn base_offset(&self) -> u64;

    /// Check whether all data of the blob object is ready.
    fn is_all_data_ready(&self) -> bool;

    /// Fetch data from storage backend covering compressed blob range [offset, offset + size).
    ///
    /// Used by asynchronous prefetch worker to implement blob prefetch.
    fn fetch_range_compressed(&self, offset: u64, size: u64, prefetch: bool) -> io::Result<()>;

    /// Fetch data from storage backend and make sure data range [offset, offset + size) is ready
    /// for use.
    ///
    /// Used by rafs to support blobfs.
    fn fetch_range_uncompressed(&self, offset: u64, size: u64) -> io::Result<()>;

    /// Prefetch data for specified chunks from storage backend.
    ///
    /// Used by asynchronous prefetch worker to implement fs prefetch.
    fn prefetch_chunks(&self, range: &BlobIoRange) -> io::Result<()>;
}

/// A wrapping object over an underlying [BlobCache] object.
///
/// All blob Io requests are actually served by the underlying [BlobCache] object. The wrapper
/// provides an interface to dynamically switch underlying [BlobCache] objects.
#[derive(Clone, Default)]
pub struct BlobDevice {
    blobs: Arc<ArcSwap<Vec<Arc<dyn BlobCache>>>>,
    blob_count: usize,
}

impl BlobDevice {
    /// Create new blob device instance.
    pub fn new(config: &Arc<ConfigV2>, blob_infos: &[Arc<BlobInfo>]) -> io::Result<BlobDevice> {
        let mut blobs = Vec::with_capacity(blob_infos.len());
        for blob_info in blob_infos.iter() {
            let blob = BLOB_FACTORY.new_blob_cache(config, blob_info)?;
            blobs.push(blob);
        }

        Ok(BlobDevice {
            blobs: Arc::new(ArcSwap::new(Arc::new(blobs))),
            blob_count: blob_infos.len(),
        })
    }

    /// Update configuration and storage backends of the blob device.
    ///
    /// The `update()` method switch a new storage backend object according to the configuration
    /// information passed in.
    pub fn update(
        &self,
        config: &Arc<ConfigV2>,
        blob_infos: &[Arc<BlobInfo>],
        fs_prefetch: bool,
    ) -> io::Result<()> {
        if self.blobs.load().len() != blob_infos.len() {
            return Err(einval!(
                "number of blobs doesn't match when update 'BlobDevice' object"
            ));
        }

        let mut blobs = Vec::with_capacity(blob_infos.len());
        for blob_info in blob_infos.iter() {
            let blob = BLOB_FACTORY.new_blob_cache(config, blob_info)?;
            blobs.push(blob);
        }

        if fs_prefetch {
            // Stop prefetch if it is running before swapping backend since prefetch threads cloned
            // Arc<BlobCache>, the swap operation can't drop inner object completely.
            // Otherwise prefetch threads will be leaked.
            self.stop_prefetch();
        }
        self.blobs.store(Arc::new(blobs));
        if fs_prefetch {
            self.start_prefetch();
        }

        Ok(())
    }

    /// Close the blob device.
    pub fn close(&self) -> io::Result<()> {
        Ok(())
    }

    /// Check whether the `BlobDevice` has any blobs.
    pub fn has_device(&self) -> bool {
        self.blob_count > 0
    }

    /// Read a range of data from a data blob into the provided writer
    pub fn read_to(&self, w: &mut dyn ZeroCopyWriter, desc: &mut BlobIoVec) -> io::Result<usize> {
        // Validate that:
        // - bi_vec[0] is valid
        // - bi_vec[0].blob.blob_index() is valid
        // - all IOs are against a single blob.
        if desc.bi_vec.is_empty() {
            if desc.bi_size == 0 {
                Ok(0)
            } else {
                Err(einval!("BlobIoVec size doesn't match."))
            }
        } else if desc.blob_index() as usize >= self.blob_count {
            Err(einval!("BlobIoVec has out of range blob_index."))
        } else {
            let size = desc.bi_size;
            let mut f = BlobDeviceIoVec::new(self, desc);
            // The `off` parameter to w.write_from() is actually ignored by
            // BlobV5IoVec::read_vectored_at_volatile()
            w.write_from(&mut f, size as usize, 0)
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
                let _ = blob.prefetch(blob.clone(), &prefetches[idx..idx + 1], &[]);
            }
        }

        for io_vec in io_vecs.iter() {
            if let Some(blob) = self.get_blob_by_iovec(io_vec) {
                // Prefetch errors are ignored.
                let _ = blob
                    .prefetch(blob.clone(), &[], &io_vec.bi_vec)
                    .map_err(|e| {
                        error!("failed to prefetch blob data, {}", e);
                    });
            }
        }

        Ok(())
    }

    /// Start the background blob data prefetch task.
    pub fn start_prefetch(&self) {
        for blob in self.blobs.load().iter() {
            let _ = blob.start_prefetch();
        }
    }

    /// Stop the background blob data prefetch task.
    pub fn stop_prefetch(&self) {
        for blob in self.blobs.load().iter() {
            let _ = blob.stop_prefetch();
        }
    }

    /// fetch specified blob data in a synchronous way.
    pub fn fetch_range_synchronous(&self, prefetches: &[BlobPrefetchRequest]) -> io::Result<()> {
        for req in prefetches {
            if req.len == 0 {
                continue;
            }
            if let Some(cache) = self.get_blob_by_id(&req.blob_id) {
                trace!(
                    "fetch blob {} offset {} size {}",
                    req.blob_id,
                    req.offset,
                    req.len
                );
                if let Some(obj) = cache.get_blob_object() {
                    obj.fetch_range_uncompressed(req.offset as u64, req.len as u64)
                        .map_err(|e| {
                            warn!(
                                "Failed to prefetch data from blob {}, offset {}, size {}, {}",
                                cache.blob_id(),
                                req.offset,
                                req.len,
                                e
                            );
                            e
                        })?;
                } else {
                    error!("No support for fetching uncompressed blob data");
                    return Err(einval!("No support for fetching uncompressed blob data"));
                }
            }
        }

        Ok(())
    }

    /// Check all chunks related to the blob io vector are ready.
    pub fn all_chunks_ready(&self, io_vecs: &[BlobIoVec]) -> bool {
        for io_vec in io_vecs.iter() {
            if let Some(blob) = self.get_blob_by_iovec(io_vec) {
                let chunk_map = blob.get_chunk_map();
                for desc in io_vec.bi_vec.iter() {
                    if !chunk_map.is_ready(&desc.chunkinfo).unwrap_or(false) {
                        return false;
                    }
                }
            } else {
                return false;
            }
        }

        true
    }

    /// RAFS V6: create a `BlobIoChunk` for chunk with index `chunk_index`.
    pub fn create_io_chunk(&self, blob_index: u32, chunk_index: u32) -> Option<BlobIoChunk> {
        if (blob_index as usize) < self.blob_count {
            let state = self.blobs.load();
            let blob = &state[blob_index as usize];
            blob.get_chunk_info(chunk_index).map(|v| v.into())
        } else {
            None
        }
    }

    /// RAFS V6: get chunk information object for chunks.
    pub fn get_chunk_info(
        &self,
        blob_index: u32,
        chunk_index: u32,
    ) -> Option<Arc<dyn BlobChunkInfo>> {
        if (blob_index as usize) < self.blob_count {
            let state = self.blobs.load();
            let blob = &state[blob_index as usize];
            blob.get_chunk_info(chunk_index)
        } else {
            None
        }
    }

    fn get_blob_by_iovec(&self, iovec: &BlobIoVec) -> Option<Arc<dyn BlobCache>> {
        let blob_index = iovec.blob_index();
        if (blob_index as usize) < self.blob_count {
            return Some(self.blobs.load()[blob_index as usize].clone());
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
///
/// It's used to support `BlobDevice::read_to()` and acts the main entrance to read chunk data
/// from data blobs.
struct BlobDeviceIoVec<'a> {
    dev: &'a BlobDevice,
    iovec: &'a mut BlobIoVec,
}

impl<'a> BlobDeviceIoVec<'a> {
    fn new(dev: &'a BlobDevice, iovec: &'a mut BlobIoVec) -> Self {
        BlobDeviceIoVec { dev, iovec }
    }
}

impl FileReadWriteVolatile for BlobDeviceIoVec<'_> {
    fn read_volatile(&mut self, _slice: FileVolatileSlice) -> Result<usize, Error> {
        // Skip because we don't really use it
        unimplemented!();
    }

    fn write_volatile(&mut self, _slice: FileVolatileSlice) -> Result<usize, Error> {
        // Skip because we don't really use it
        unimplemented!();
    }

    fn read_at_volatile(
        &mut self,
        _slice: FileVolatileSlice,
        _offset: u64,
    ) -> Result<usize, Error> {
        unimplemented!();
    }

    // The default read_vectored_at_volatile only read to the first slice, so we have to overload it.
    fn read_vectored_at_volatile(
        &mut self,
        buffers: &[FileVolatileSlice],
        _offset: u64,
    ) -> Result<usize, Error> {
        // BlobDevice::read_to() has validated that all IOs are against a single blob.
        let index = self.iovec.blob_index();
        let blobs = &self.dev.blobs.load();

        if (index as usize) < blobs.len() {
            blobs[index as usize].read(self.iovec, buffers)
        } else {
            let msg = format!(
                "failed to get blob object for BlobIoVec, index {}, blob array len: {}",
                index,
                blobs.len()
            );
            Err(einval!(msg))
        }
    }

    fn write_at_volatile(
        &mut self,
        _slice: FileVolatileSlice,
        _offset: u64,
    ) -> Result<usize, Error> {
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
    /// A `BlobV5ChunkInfo` object describes how a Rafs v5 chunk is located within a data blob.
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
    use crate::test::MockChunkInfo;

    #[test]
    fn test_blob_io_chunk() {
        let chunk: Arc<dyn BlobChunkInfo> = Arc::new(MockChunkInfo {
            block_id: Default::default(),
            blob_index: 0,
            flags: Default::default(),
            compress_size: 0x100,
            uncompress_size: 0x200,
            compress_offset: 0x1000,
            uncompress_offset: 0x2000,
            file_offset: 0,
            index: 3,
            reserved: 0,
        });
        let iochunk: BlobIoChunk = chunk.clone().into();

        assert_eq!(iochunk.id(), 3);
        assert_eq!(iochunk.compressed_offset(), 0x1000);
        assert_eq!(iochunk.compressed_size(), 0x100);
        assert_eq!(iochunk.uncompressed_offset(), 0x2000);
        assert_eq!(iochunk.uncompressed_size(), 0x200);
        assert!(!iochunk.is_compressed());
    }

    #[test]
    fn test_chunk_is_continuous() {
        let blob_info = Arc::new(BlobInfo::new(
            1,
            "test1".to_owned(),
            0x200000,
            0x100000,
            0x100000,
            512,
            BlobFeatures::_V5_NO_EXT_BLOB_TABLE,
        ));
        let chunk1 = Arc::new(MockChunkInfo {
            block_id: Default::default(),
            blob_index: 1,
            flags: BlobChunkFlags::empty(),
            compress_size: 0x800,
            uncompress_size: 0x1000,
            compress_offset: 0,
            uncompress_offset: 0,
            file_offset: 0,
            index: 0,
            reserved: 0,
        }) as Arc<dyn BlobChunkInfo>;
        let chunk2 = Arc::new(MockChunkInfo {
            block_id: Default::default(),
            blob_index: 1,
            flags: BlobChunkFlags::empty(),
            compress_size: 0x800,
            uncompress_size: 0x1000,
            compress_offset: 0x800,
            uncompress_offset: 0x1000,
            file_offset: 0x1000,
            index: 1,
            reserved: 0,
        }) as Arc<dyn BlobChunkInfo>;
        let chunk3 = Arc::new(MockChunkInfo {
            block_id: Default::default(),
            blob_index: 1,
            flags: BlobChunkFlags::empty(),
            compress_size: 0x800,
            uncompress_size: 0x1000,
            compress_offset: 0x1800,
            uncompress_offset: 0x3000,
            file_offset: 0x3000,
            index: 1,
            reserved: 0,
        }) as Arc<dyn BlobChunkInfo>;

        let desc1 = BlobIoDesc {
            blob: blob_info.clone(),
            chunkinfo: chunk1.into(),
            offset: 0,
            size: 0x1000,
            user_io: true,
        };
        let desc2 = BlobIoDesc {
            blob: blob_info.clone(),
            chunkinfo: chunk2.into(),
            offset: 0,
            size: 0x1000,
            user_io: true,
        };
        let desc3 = BlobIoDesc {
            blob: blob_info,
            chunkinfo: chunk3.into(),
            offset: 0,
            size: 0x1000,
            user_io: true,
        };

        assert!(desc1.is_continuous(&desc2, 0x0));
        assert!(desc1.is_continuous(&desc2, 0x1000));
        assert!(!desc2.is_continuous(&desc1, 0x1000));
        assert!(!desc2.is_continuous(&desc1, 0x0));

        assert!(!desc1.is_continuous(&desc3, 0x0));
        assert!(!desc1.is_continuous(&desc3, 0x400));
        assert!(!desc1.is_continuous(&desc3, 0x800));
        assert!(desc1.is_continuous(&desc3, 0x1000));

        assert!(!desc2.is_continuous(&desc3, 0x0));
        assert!(!desc2.is_continuous(&desc3, 0x400));
        assert!(desc2.is_continuous(&desc3, 0x800));
        assert!(desc2.is_continuous(&desc3, 0x1000));
    }

    #[test]
    fn test_append_same_blob_with_diff_index() {
        let blob1 = Arc::new(BlobInfo::new(
            1,
            "test1".to_owned(),
            0x200000,
            0x100000,
            0x100000,
            512,
            BlobFeatures::_V5_NO_EXT_BLOB_TABLE,
        ));
        let chunk1 = Arc::new(MockChunkInfo {
            block_id: Default::default(),
            blob_index: 1,
            flags: BlobChunkFlags::empty(),
            compress_size: 0x800,
            uncompress_size: 0x1000,
            compress_offset: 0,
            uncompress_offset: 0,
            file_offset: 0,
            index: 0,
            reserved: 0,
        }) as Arc<dyn BlobChunkInfo>;
        let mut iovec = BlobIoVec::new(blob1.clone());
        iovec.push(BlobIoDesc::new(blob1, BlobIoChunk(chunk1), 0, 0x1000, true));

        let blob2 = Arc::new(BlobInfo::new(
            2,                  // different index
            "test1".to_owned(), // same id
            0x200000,
            0x100000,
            0x100000,
            512,
            BlobFeatures::_V5_NO_EXT_BLOB_TABLE,
        ));
        let chunk2 = Arc::new(MockChunkInfo {
            block_id: Default::default(),
            blob_index: 2,
            flags: BlobChunkFlags::empty(),
            compress_size: 0x800,
            uncompress_size: 0x1000,
            compress_offset: 0x800,
            uncompress_offset: 0x1000,
            file_offset: 0x1000,
            index: 1,
            reserved: 0,
        }) as Arc<dyn BlobChunkInfo>;
        let mut iovec2 = BlobIoVec::new(blob2.clone());
        iovec2.push(BlobIoDesc::new(blob2, BlobIoChunk(chunk2), 0, 0x1000, true));

        iovec.append(iovec2);
        assert_eq!(0x2000, iovec.bi_size);
    }

    #[test]
    fn test_extend_large_blob_io_vec() {
        let size = 0x2_0000_0000; // 8G blob
        let chunk_size = 0x10_0000; // 1M chunk
        let chunk_count = (size / chunk_size as u64) as u32;
        let large_blob = Arc::new(BlobInfo::new(
            0,
            "blob_id".to_owned(),
            size,
            size,
            chunk_size,
            chunk_count,
            BlobFeatures::default(),
        ));

        let mut iovec = BlobIoVec::new(large_blob.clone());
        let mut iovec2 = BlobIoVec::new(large_blob.clone());

        // Extend half of blob
        for chunk_idx in 0..chunk_count {
            let chunk = Arc::new(MockChunkInfo {
                block_id: Default::default(),
                blob_index: large_blob.blob_index,
                flags: BlobChunkFlags::empty(),
                compress_size: chunk_size,
                compress_offset: chunk_idx as u64 * chunk_size as u64,
                uncompress_size: 2 * chunk_size,
                uncompress_offset: 2 * chunk_idx as u64 * chunk_size as u64,
                file_offset: 2 * chunk_idx as u64 * chunk_size as u64,
                index: chunk_idx as u32,
                reserved: 0,
            }) as Arc<dyn BlobChunkInfo>;
            let desc = BlobIoDesc::new(large_blob.clone(), BlobIoChunk(chunk), 0, chunk_size, true);
            if chunk_idx < chunk_count / 2 {
                iovec.push(desc);
            } else {
                iovec2.push(desc)
            }
        }

        // Extend other half of blob
        iovec.append(iovec2);

        assert_eq!(size, iovec.size());
        assert_eq!(chunk_count, iovec.len() as u32);
    }
}

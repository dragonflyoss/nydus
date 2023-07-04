// Copyright (C) 2021-2023 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Generate, manage and access blob meta information for RAFS v6 data blobs.
//!
//! RAFS v6 filesystem includes three types of data:
//! - fs meta: contain filesystem meta data including super block, inode table, dirent etc.
//! - blob meta: contain digest and compression context for data chunks.
//! - chunk data: contain chunked file data in compressed or uncompressed form.
//!
//! There are different ways to packing above three types of data into blobs:
//! - meta blob/bootstrap: `fs meta`
//! - native data blob: `chunk data` | `compression context table` | [`chunk digest table`] | [`table of context`]
//! - native data blob with inlined fs meta: `chunk data` | `compression context table` | [`chunk digest table`] | `fs meta` | [`table of content`]
//! - ZRan data blob: `compression context table` | [`chunk digest table`] | [`table of content`]
//! - ZRan data blob with inlined fs meta: `compression context table` | [`chunk digest table`] | `fs meta` | [`table of content`]
//!
//! The blob compression context table contains following information:
//! - chunk compression information table: to locate compressed/uncompressed chunks in the data blob
//! - optional ZRan context table: to support randomly access/decompress gzip file
//! - optional ZRan dictionary table: to support randomly access/decompress gzip file
//!
//! The blob compression context table is laid as below:
//! | `chunk compression info table` | [`ZRan context table`] | [`ZRan dictionary table`]

use std::any::Any;
use std::borrow::Cow;
use std::fs::OpenOptions;
use std::io::Result;
use std::mem::{size_of, ManuallyDrop};
use std::ops::{Add, BitAnd, Not};
use std::path::PathBuf;
use std::sync::Arc;

use nydus_utils::compress::zlib_random::ZranContext;
use nydus_utils::crypt::decrypt_with_context;
use nydus_utils::digest::{DigestData, RafsDigest};
use nydus_utils::filemap::FileMapState;
use nydus_utils::{compress, crypt};

use crate::backend::BlobReader;
use crate::device::v5::BlobV5ChunkInfo;
use crate::device::{BlobChunkFlags, BlobChunkInfo, BlobFeatures, BlobInfo};
use crate::meta::toc::{TocEntryList, TocLocation};
use crate::utils::alloc_buf;
use crate::{RAFS_MAX_CHUNKS_PER_BLOB, RAFS_MAX_CHUNK_SIZE};

mod chunk_info_v1;
pub use chunk_info_v1::BlobChunkInfoV1Ondisk;
mod chunk_info_v2;
pub use chunk_info_v2::BlobChunkInfoV2Ondisk;

pub mod toc;

mod zran;
pub use zran::{ZranContextGenerator, ZranInflateContext};

mod batch;
pub use batch::{BatchContextGenerator, BatchInflateContext};

const BLOB_CCT_MAGIC: u32 = 0xb10bb10bu32;
const BLOB_CCT_HEADER_SIZE: u64 = 0x1000u64;
const BLOB_CCT_CHUNK_SIZE_MASK: u64 = 0xff_ffff;

const BLOB_CCT_V1_MAX_SIZE: u64 = RAFS_MAX_CHUNK_SIZE * 16;
const BLOB_CCT_V2_MAX_SIZE: u64 = RAFS_MAX_CHUNK_SIZE * 24;
//const BLOB_CCT_V1_RESERVED_SIZE: u64 = BLOB_METADATA_HEADER_SIZE - 44;
const BLOB_CCT_V2_RESERVED_SIZE: u64 = BLOB_CCT_HEADER_SIZE - 64;

/// File suffix for blob meta file.
const BLOB_CCT_FILE_SUFFIX: &str = "blob.meta";
/// File suffix for blob chunk digests.
const BLOB_DIGEST_FILE_SUFFIX: &str = "blob.digest";
/// File suffix for blob ToC.
const BLOB_TOC_FILE_SUFFIX: &str = "blob.toc";

/// On disk format for blob compression context table header.
///
/// Blob compression context table contains compression information for all chunks in the blob.
/// The compression context table header will be written into the data blob in plaintext mode,
/// and can be used as marker to locate the compression context table. All fields of compression
/// context table header should be encoded in little-endian format.
///
/// The compression context table and header are arranged in the data blob as follow:
///
/// `chunk data`  |  `compression context table`  |  `[ZRan context table | ZRan dictionary]`  |  `compression context table header`
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct BlobCompressionContextHeader {
    /// Magic number to identify the header.
    s_magic: u32,
    /// Feature flags for the data blob.
    s_features: u32,
    /// Compression algorithm to process the compression context table.
    s_ci_compressor: u32,
    /// Number of entries in compression context table.
    s_ci_entries: u32,
    /// File offset to get the compression context table.
    s_ci_offset: u64,
    /// Size of compressed compression context table.
    s_ci_compressed_size: u64,
    /// Size of uncompressed compression context table.
    s_ci_uncompressed_size: u64,
    /// File offset to get the optional ZRan context data.
    s_ci_zran_offset: u64,
    /// Size of ZRan context data, including the ZRan context table and dictionary table.
    s_ci_zran_size: u64,
    /// Number of entries in the ZRan context table.
    s_ci_zran_count: u32,

    s_reserved: [u8; BLOB_CCT_V2_RESERVED_SIZE as usize],
    /// Second magic number to identify the blob meta data header.
    s_magic2: u32,
}

impl Default for BlobCompressionContextHeader {
    fn default() -> Self {
        BlobCompressionContextHeader {
            s_magic: BLOB_CCT_MAGIC,
            s_features: 0,
            s_ci_compressor: compress::Algorithm::Lz4Block as u32,
            s_ci_entries: 0,
            s_ci_offset: 0,
            s_ci_compressed_size: 0,
            s_ci_uncompressed_size: 0,
            s_ci_zran_offset: 0,
            s_ci_zran_size: 0,
            s_ci_zran_count: 0,
            s_reserved: [0u8; BLOB_CCT_V2_RESERVED_SIZE as usize],
            s_magic2: BLOB_CCT_MAGIC,
        }
    }
}

impl BlobCompressionContextHeader {
    /// Check whether a blob feature is set or not.
    pub fn has_feature(&self, feature: BlobFeatures) -> bool {
        self.s_features & feature.bits() != 0
    }

    /// Get compression algorithm to process chunk compression information array.
    pub fn ci_compressor(&self) -> compress::Algorithm {
        if self.s_ci_compressor == compress::Algorithm::Lz4Block as u32 {
            compress::Algorithm::Lz4Block
        } else if self.s_ci_compressor == compress::Algorithm::GZip as u32 {
            compress::Algorithm::GZip
        } else if self.s_ci_compressor == compress::Algorithm::Zstd as u32 {
            compress::Algorithm::Zstd
        } else {
            compress::Algorithm::None
        }
    }

    /// Set compression algorithm to process chunk compression information array.
    pub fn set_ci_compressor(&mut self, algo: compress::Algorithm) {
        self.s_ci_compressor = algo as u32;
    }

    /// Get number of entries in chunk compression information array.
    pub fn ci_entries(&self) -> u32 {
        self.s_ci_entries
    }

    /// Set number of entries in chunk compression information array.
    pub fn set_ci_entries(&mut self, entries: u32) {
        self.s_ci_entries = entries;
    }

    /// Get offset of compressed chunk compression information array.
    pub fn ci_compressed_offset(&self) -> u64 {
        self.s_ci_offset
    }

    /// Set offset of compressed chunk compression information array.
    pub fn set_ci_compressed_offset(&mut self, offset: u64) {
        self.s_ci_offset = offset;
    }

    /// Get size of compressed chunk compression information array.
    pub fn ci_compressed_size(&self) -> u64 {
        self.s_ci_compressed_size
    }

    /// Set size of compressed chunk compression information array.
    pub fn set_ci_compressed_size(&mut self, size: u64) {
        self.s_ci_compressed_size = size;
    }

    /// Get size of uncompressed chunk compression information array.
    pub fn ci_uncompressed_size(&self) -> u64 {
        self.s_ci_uncompressed_size
    }

    /// Set size of uncompressed chunk compression information array.
    pub fn set_ci_uncompressed_size(&mut self, size: u64) {
        self.s_ci_uncompressed_size = size;
    }

    /// Get ZRan context information entry count.
    pub fn ci_zran_count(&self) -> u32 {
        self.s_ci_zran_count
    }

    /// Set ZRan context information entry count.
    pub fn set_ci_zran_count(&mut self, count: u32) {
        self.s_ci_zran_count = count;
    }

    /// Get offset of ZRan context information table.
    pub fn ci_zran_offset(&self) -> u64 {
        self.s_ci_zran_offset
    }

    /// Set offset of ZRan context information table.
    pub fn set_ci_zran_offset(&mut self, offset: u64) {
        self.s_ci_zran_offset = offset;
    }

    /// Get size of ZRan context information table and dictionary table.
    pub fn ci_zran_size(&self) -> u64 {
        self.s_ci_zran_size
    }

    /// Set size of ZRan context information table and dictionary table.
    pub fn set_ci_zran_size(&mut self, size: u64) {
        self.s_ci_zran_size = size;
    }

    /// Check whether uncompressed chunks are 4k aligned.
    pub fn is_4k_aligned(&self) -> bool {
        self.has_feature(BlobFeatures::ALIGNED)
    }

    /// Set flag indicating whether uncompressed chunks are aligned.
    pub fn set_aligned(&mut self, aligned: bool) {
        if aligned {
            self.s_features |= BlobFeatures::ALIGNED.bits();
        } else {
            self.s_features &= !BlobFeatures::ALIGNED.bits();
        }
    }

    /// Set flag indicating whether RAFS meta is inlined in the data blob.
    pub fn set_inlined_fs_meta(&mut self, inlined: bool) {
        if inlined {
            self.s_features |= BlobFeatures::INLINED_FS_META.bits();
        } else {
            self.s_features &= !BlobFeatures::INLINED_FS_META.bits();
        }
    }

    /// Set flag indicating whether chunk compression information format v2 is used or not.
    pub fn set_chunk_info_v2(&mut self, enable: bool) {
        if enable {
            self.s_features |= BlobFeatures::CHUNK_INFO_V2.bits();
        } else {
            self.s_features &= !BlobFeatures::CHUNK_INFO_V2.bits();
        }
    }

    /// Set flag indicating whether it's a ZRan blob or not.
    pub fn set_ci_zran(&mut self, enable: bool) {
        if enable {
            self.s_features |= BlobFeatures::ZRAN.bits();
        } else {
            self.s_features &= !BlobFeatures::ZRAN.bits();
        }
    }

    /// Set flag indicating whether blob.data and blob.meta are stored in separated blobs.
    pub fn set_separate_blob(&mut self, enable: bool) {
        if enable {
            self.s_features |= BlobFeatures::SEPARATE.bits();
        } else {
            self.s_features &= !BlobFeatures::SEPARATE.bits();
        }
    }

    /// Set flag indicating whether it's a blob for batch chunk or not.
    pub fn set_ci_batch(&mut self, enable: bool) {
        if enable {
            self.s_features |= BlobFeatures::BATCH.bits();
        } else {
            self.s_features &= !BlobFeatures::BATCH.bits();
        }
    }

    /// Set flag indicating whether chunk digest is inlined in the data blob or not.
    pub fn set_inlined_chunk_digest(&mut self, enable: bool) {
        if enable {
            self.s_features |= BlobFeatures::INLINED_CHUNK_DIGEST.bits();
        } else {
            self.s_features &= !BlobFeatures::INLINED_CHUNK_DIGEST.bits();
        }
    }

    /// Set flag indicating new blob format with tar headers.
    pub fn set_has_tar_header(&mut self, enable: bool) {
        if enable {
            self.s_features |= BlobFeatures::HAS_TAR_HEADER.bits();
        } else {
            self.s_features &= !BlobFeatures::HAS_TAR_HEADER.bits();
        }
    }

    /// Set flag indicating new blob format with toc headers.
    pub fn set_has_toc(&mut self, enable: bool) {
        if enable {
            self.s_features |= BlobFeatures::HAS_TOC.bits();
        } else {
            self.s_features &= !BlobFeatures::HAS_TOC.bits();
        }
    }

    /// Set flag indicating having inlined-meta capability.
    pub fn set_cap_tar_toc(&mut self, enable: bool) {
        if enable {
            self.s_features |= BlobFeatures::CAP_TAR_TOC.bits();
        } else {
            self.s_features &= !BlobFeatures::CAP_TAR_TOC.bits();
        }
    }

    /// Set flag indicating the blob is for RAFS filesystem in TARFS mode.
    pub fn set_tarfs(&mut self, enable: bool) {
        if enable {
            self.s_features |= BlobFeatures::TARFS.bits();
        } else {
            self.s_features &= !BlobFeatures::TARFS.bits();
        }
    }

    /// Set flag indicating the blob is encrypted.
    pub fn set_encrypted(&mut self, enable: bool) {
        if enable {
            self.s_features |= BlobFeatures::ENCRYPTED.bits();
        } else {
            self.s_features &= !BlobFeatures::ENCRYPTED.bits();
        }
    }

    /// Get blob meta feature flags.
    pub fn features(&self) -> u32 {
        self.s_features
    }

    /// Convert the header as an `&[u8]`.
    pub fn as_bytes(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(
                self as *const BlobCompressionContextHeader as *const u8,
                size_of::<BlobCompressionContextHeader>(),
            )
        }
    }
}

/// Struct to manage blob chunk compression information, a wrapper over [BlobCompressionContext].
///
/// A [BlobCompressionContextInfo] object is loaded from on disk [BlobCompressionContextHeader]
/// object, and provides methods to query compression information about chunks in the blob.
#[derive(Clone)]
pub struct BlobCompressionContextInfo {
    pub(crate) state: Arc<BlobCompressionContext>,
}

impl BlobCompressionContextInfo {
    /// Create a new instance of [BlobCompressionContextInfo].
    ///
    /// If a blob compression context cache file is present and is valid, it will be reused.
    /// Otherwise download compression context content from backend if `reader` is valid.
    ///
    /// The downloaded compression context table will be cached into a file named as
    /// `[blob_id].blob.meta`. The cache file is readonly once created and may be accessed
    /// concurrently by multiple clients.
    pub fn new(
        blob_path: &str,
        blob_info: &BlobInfo,
        reader: Option<&Arc<dyn BlobReader>>,
        load_chunk_digest: bool,
    ) -> Result<Self> {
        assert_eq!(
            size_of::<BlobCompressionContextHeader>() as u64,
            BLOB_CCT_HEADER_SIZE
        );
        assert_eq!(size_of::<BlobChunkInfoV1Ondisk>(), 16);
        assert_eq!(size_of::<BlobChunkInfoV2Ondisk>(), 24);
        assert_eq!(size_of::<ZranInflateContext>(), 40);

        let chunk_count = blob_info.chunk_count();
        if chunk_count == 0 || chunk_count > RAFS_MAX_CHUNKS_PER_BLOB {
            return Err(einval!("invalid chunk count in blob meta header"));
        }

        let uncompressed_size = blob_info.meta_ci_uncompressed_size() as usize;
        let meta_path = format!("{}.{}", blob_path, BLOB_CCT_FILE_SUFFIX);
        trace!(
            "try to open blob meta file: path {:?} uncompressed_size {} chunk_count {}",
            meta_path,
            uncompressed_size,
            chunk_count
        );
        let enable_write = reader.is_some();
        let file = OpenOptions::new()
            .read(true)
            .write(enable_write)
            .create(enable_write)
            .open(&meta_path)
            .map_err(|err| {
                einval!(format!(
                    "failed to open/create blob meta file {}: {}",
                    meta_path, err
                ))
            })?;

        let aligned_uncompressed_size = round_up_4k(uncompressed_size);
        let expected_size = BLOB_CCT_HEADER_SIZE as usize + aligned_uncompressed_size;
        let mut file_size = file.metadata()?.len();
        if file_size == 0 && enable_write {
            file.set_len(expected_size as u64)?;
            file_size = expected_size as u64;
        }
        if file_size != expected_size as u64 {
            return Err(einval!(format!(
                "size of blob meta file '{}' doesn't match, expect {:x}, got {:x}",
                meta_path, expected_size, file_size
            )));
        }

        let mut filemap = FileMapState::new(file, 0, expected_size, enable_write)?;
        let base = filemap.validate_range(0, expected_size)?;
        let header =
            filemap.get_mut::<BlobCompressionContextHeader>(aligned_uncompressed_size as usize)?;
        if !Self::validate_header(blob_info, header)? {
            if let Some(reader) = reader {
                let buffer =
                    unsafe { std::slice::from_raw_parts_mut(base as *mut u8, expected_size) };
                buffer[0..].fill(0);
                Self::read_metadata(blob_info, reader, buffer)?;
                Self::validate_header(blob_info, header)?;
                filemap.sync_data()?;
            } else {
                return Err(enoent!(format!(
                    "blob meta header from file '{}' is invalid",
                    meta_path
                )));
            }
        }

        let chunk_infos = BlobMetaChunkArray::from_file_map(&filemap, blob_info)?;
        let chunk_infos = ManuallyDrop::new(chunk_infos);
        let mut state = BlobCompressionContext {
            blob_index: blob_info.blob_index(),
            blob_features: blob_info.features().bits(),
            compressed_size: blob_info.compressed_data_size(),
            uncompressed_size: round_up_4k(blob_info.uncompressed_size()),
            chunk_info_array: chunk_infos,
            blob_meta_file_map: filemap,
            ..Default::default()
        };

        if blob_info.has_feature(BlobFeatures::BATCH) {
            let header = state
                .blob_meta_file_map
                .get_mut::<BlobCompressionContextHeader>(aligned_uncompressed_size as usize)?;
            let inflate_offset = header.s_ci_zran_offset as usize;
            let inflate_count = header.s_ci_zran_count as usize;
            let batch_inflate_size = inflate_count * size_of::<BatchInflateContext>();
            let ptr = state
                .blob_meta_file_map
                .validate_range(inflate_offset, batch_inflate_size)?;
            let array = unsafe {
                Vec::from_raw_parts(
                    ptr as *mut u8 as *mut BatchInflateContext,
                    inflate_count,
                    inflate_count,
                )
            };
            state.batch_info_array = ManuallyDrop::new(array);
        } else if blob_info.has_feature(BlobFeatures::ZRAN) {
            let header = state
                .blob_meta_file_map
                .get_mut::<BlobCompressionContextHeader>(aligned_uncompressed_size as usize)?;
            let zran_offset = header.s_ci_zran_offset as usize;
            let zran_count = header.s_ci_zran_count as usize;
            let ci_zran_size = header.s_ci_zran_size as usize;
            let zran_size = zran_count * size_of::<ZranInflateContext>();
            let ptr = state
                .blob_meta_file_map
                .validate_range(zran_offset, zran_size)?;
            let array = unsafe {
                Vec::from_raw_parts(
                    ptr as *mut u8 as *mut ZranInflateContext,
                    zran_count,
                    zran_count,
                )
            };
            state.zran_info_array = ManuallyDrop::new(array);

            let zran_dict_size = ci_zran_size - zran_size;
            let ptr = state
                .blob_meta_file_map
                .validate_range(zran_offset + zran_size, zran_dict_size)?;
            let array =
                unsafe { Vec::from_raw_parts(ptr as *mut u8, zran_dict_size, zran_dict_size) };
            state.zran_dict_table = ManuallyDrop::new(array);
        }

        if load_chunk_digest && blob_info.has_feature(BlobFeatures::INLINED_CHUNK_DIGEST) {
            let digest_path = PathBuf::from(format!("{}.{}", blob_path, BLOB_DIGEST_FILE_SUFFIX));
            if let Some(reader) = reader {
                let toc_path = format!("{}.{}", blob_path, BLOB_TOC_FILE_SUFFIX);
                let location = if blob_info.blob_toc_size() != 0 {
                    let blob_size = reader
                        .blob_size()
                        .map_err(|_e| eio!("failed to get blob size"))?;
                    let offset = blob_size - blob_info.blob_toc_size() as u64;
                    let mut location = TocLocation::new(offset, blob_info.blob_toc_size() as u64);
                    let digest = blob_info.blob_toc_digest();
                    for c in digest {
                        if *c != 0 {
                            location.validate_digest = true;
                            location.digest.data = *digest;
                            break;
                        }
                    }
                    location
                } else {
                    TocLocation::default()
                };
                let toc_list =
                    TocEntryList::read_from_cache_file(&toc_path, reader.as_ref(), &location)?;
                toc_list.extract_from_blob(reader.clone(), None, Some(&digest_path))?;
            }
            if !digest_path.exists() {
                return Err(eother!("failed to download chunk digest file from blob"));
            }

            let file = OpenOptions::new().read(true).open(&digest_path)?;
            let md = file.metadata()?;
            let size = 32 * blob_info.chunk_count() as usize;
            if md.len() != size as u64 {
                return Err(eother!(format!(
                    "size of chunk digest file doesn't match, expect {}, got {}",
                    size,
                    md.len()
                )));
            }

            let file_map = FileMapState::new(file, 0, size, false)?;
            let ptr = file_map.validate_range(0, size)?;
            let array = unsafe {
                Vec::from_raw_parts(
                    ptr as *mut u8 as *mut _,
                    chunk_count as usize,
                    chunk_count as usize,
                )
            };
            state.chunk_digest_file_map = file_map;
            state.chunk_digest_array = ManuallyDrop::new(array);
        }

        Ok(BlobCompressionContextInfo {
            state: Arc::new(state),
        })
    }

    /// Get data chunks covering uncompressed data range `[start, start + size)`.
    ///
    /// For 4k-aligned uncompressed data chunks, there may be padding areas between data chunks.
    ///
    /// The method returns error if any of following condition is true:
    /// - range [start, start + size) is invalid.
    /// - `start` is bigger than blob size.
    /// - some portions of the range [start, start + size) is not covered by chunks.
    /// - blob meta is invalid.
    pub fn get_chunks_uncompressed(
        &self,
        start: u64,
        size: u64,
        batch_size: u64,
    ) -> Result<Vec<Arc<dyn BlobChunkInfo>>> {
        let end = start.checked_add(size).ok_or_else(|| {
            einval!(format!(
                "get_chunks_uncompressed: invalid start {}/size {}",
                start, size
            ))
        })?;
        if end > self.state.uncompressed_size {
            return Err(einval!(format!(
                "get_chunks_uncompressed: invalid end {}/uncompressed_size {}",
                end, self.state.uncompressed_size
            )));
        }
        let batch_end = if batch_size <= size {
            end
        } else {
            std::cmp::min(
                start.checked_add(batch_size).unwrap_or(end),
                self.state.uncompressed_size,
            )
        };
        let batch_size = if batch_size < size { size } else { batch_size };

        self.state
            .get_chunks_uncompressed(start, end, batch_end, batch_size)
    }

    /// Get data chunks covering compressed data range `[start, start + size)`.
    ///
    /// The method returns error if any of following condition is true:
    /// - range [start, start + size) is invalid.
    /// - `start` is bigger than blob size.
    /// - some portions of the range [start, start + size) is not covered by chunks.
    /// - blob meta is invalid.
    pub fn get_chunks_compressed(
        &self,
        start: u64,
        size: u64,
        batch_size: u64,
        prefetch: bool,
    ) -> Result<Vec<Arc<dyn BlobChunkInfo>>> {
        let end = start.checked_add(size).ok_or_else(|| {
            einval!(einval!(format!(
                "get_chunks_compressed: invalid start {}/size {}",
                start, size
            )))
        })?;
        if end > self.state.compressed_size {
            return Err(einval!(format!(
                "get_chunks_compressed: invalid end {}/compressed_size {}",
                end, self.state.compressed_size
            )));
        }
        let batch_end = if batch_size <= size {
            end
        } else {
            std::cmp::min(
                start.checked_add(batch_size).unwrap_or(end),
                self.state.compressed_size,
            )
        };

        self.state
            .get_chunks_compressed(start, end, batch_end, batch_size, prefetch)
    }

    /// Amplify the request by appending more continuous chunks to the chunk array.
    pub fn add_more_chunks(
        &self,
        chunks: &[Arc<dyn BlobChunkInfo>],
        max_size: u64,
    ) -> Result<Vec<Arc<dyn BlobChunkInfo>>> {
        self.state.add_more_chunks(chunks, max_size)
    }

    /// Get number of chunks in the data blob.
    pub fn get_chunk_count(&self) -> usize {
        self.state.chunk_info_array.len()
    }

    /// Get index of chunk covering uncompressed `addr`.
    pub fn get_chunk_index(&self, addr: u64) -> Result<usize> {
        self.state.get_chunk_index(addr)
    }

    /// Get uncompressed offset of the chunk at `chunk_index`.
    pub fn get_uncompressed_offset(&self, chunk_index: usize) -> u64 {
        self.state.get_uncompressed_offset(chunk_index)
    }

    /// Get chunk digest for the chunk at `chunk_index`.
    pub fn get_chunk_digest(&self, chunk_index: usize) -> Option<&[u8]> {
        self.state.get_chunk_digest(chunk_index)
    }

    /// Get `BlobChunkInfo` object for the chunk at `chunk_index`.
    pub fn get_chunk_info(&self, chunk_index: usize) -> Arc<dyn BlobChunkInfo> {
        BlobMetaChunk::new(chunk_index, &self.state)
    }

    /// Get whether chunk at `chunk_index` is batch chunk.
    /// Some chunks build in batch mode can also be non-batch chunks,
    /// that they are too big to be put into a batch.
    pub fn is_batch_chunk(&self, chunk_index: u32) -> bool {
        self.state.is_batch_chunk(chunk_index as usize)
    }

    /// Get Batch index associated with the chunk at `chunk_index`.
    pub fn get_batch_index(&self, chunk_index: u32) -> u32 {
        self.state.get_batch_index(chunk_index as usize)
    }

    /// Get uncompressed batch offset associated with the chunk at `chunk_index`.
    pub fn get_uncompressed_offset_in_batch_buf(&self, chunk_index: u32) -> u32 {
        self.state
            .get_uncompressed_offset_in_batch_buf(chunk_index as usize)
    }

    /// Get Batch context information at `batch_index`.
    pub fn get_batch_context(&self, batch_index: u32) -> Option<&BatchInflateContext> {
        self.state.get_batch_context(batch_index as usize)
    }

    /// Get compressed offset and size associated with the chunk at `chunk_index`.
    /// Capabale of handling both batch and non-batch chunks.
    /// Return `compressed_offset` and `compressed_size`.
    pub fn get_compressed_info(&self, chunk_index: u32) -> Result<(u64, u32)> {
        self.state.get_compressed_info(chunk_index as usize)
    }

    /// Get ZRan index associated with the chunk at `chunk_index`.
    pub fn get_zran_index(&self, chunk_index: u32) -> u32 {
        self.state.get_zran_index(chunk_index as usize)
    }

    /// Get ZRan offset associated with the chunk at `chunk_index`.
    pub fn get_zran_offset(&self, chunk_index: u32) -> u32 {
        self.state.get_zran_offset(chunk_index as usize)
    }

    /// Get ZRan context information at `zran_index`.
    pub fn get_zran_context(&self, zran_index: u32) -> Option<(ZranContext, &[u8])> {
        self.state.get_zran_context(zran_index as usize)
    }

    fn read_metadata(
        blob_info: &BlobInfo,
        reader: &Arc<dyn BlobReader>,
        buffer: &mut [u8],
    ) -> Result<()> {
        trace!(
            "blob_info compressor {} ci_compressor {} ci_compressed_size {} ci_uncompressed_size {}",
            blob_info.compressor(),
            blob_info.meta_ci_compressor(),
            blob_info.meta_ci_compressed_size(),
            blob_info.meta_ci_uncompressed_size(),
        );

        let compressed_size = blob_info.meta_ci_compressed_size();
        let uncompressed_size = blob_info.meta_ci_uncompressed_size();
        let aligned_uncompressed_size = round_up_4k(uncompressed_size);
        let expected_raw_size = (compressed_size + BLOB_CCT_HEADER_SIZE) as usize;
        let mut raw_data = alloc_buf(expected_raw_size);

        let read_size = reader
            .read_all(&mut raw_data, blob_info.meta_ci_offset())
            .map_err(|e| {
                eio!(format!(
                    "failed to read metadata for blob {} from backend, {}",
                    blob_info.blob_id(),
                    e
                ))
            })?;
        if read_size != expected_raw_size {
            return Err(eio!(format!(
                "failed to read metadata for blob {} from backend, compressor {}, got {} bytes, expect {} bytes",
                blob_info.blob_id(),
                blob_info.meta_ci_compressor(),
                read_size,
                expected_raw_size
            )));
        }

        let decrypted = match decrypt_with_context(
            &raw_data[0..compressed_size as usize],
            &blob_info.cipher_object(),
            &blob_info.cipher_context(),
            blob_info.cipher() != crypt::Algorithm::None,
        ){
            Ok(data) => data,
            Err(e) => return Err(eio!(format!(
                "failed to decrypt metadata for blob {} from backend, cipher {}, encrypted data size {}, {}",
                blob_info.blob_id(),
                blob_info.cipher(),
                compressed_size,
                e
            ))),
        };
        let header = match decrypt_with_context(
            &raw_data[compressed_size as usize..expected_raw_size],
            &blob_info.cipher_object(),
            &blob_info.cipher_context(),
            blob_info.cipher() != crypt::Algorithm::None,
        ){
            Ok(data) => data,
            Err(e) => return Err(eio!(format!(
                "failed to decrypt meta header for blob {} from backend, cipher {}, encrypted data size {}, {}",
                blob_info.blob_id(),
                blob_info.cipher(),
                compressed_size,
                e
            ))),
        };

        let uncompressed = if blob_info.meta_ci_compressor() != compress::Algorithm::None {
            // Lz4 does not support concurrent decompression of the same data into
            // the same piece of memory. There will be multiple containers mmap the
            // same file, causing the buffer to be shared between different
            // processes. This will cause data errors due to race issues when
            // decompressing with lz4. We solve this problem by creating a temporary
            // memory to hold the decompressed data.
            //
            // Because this process will only be executed when the blob.meta file is
            // created for the first time, which means that a machine will only
            // execute the process once when the blob.meta is created for the first
            // time, the memory consumption and performance impact are relatively
            // small.
            let mut uncompressed = vec![0u8; uncompressed_size as usize];
            compress::decompress(
                &decrypted,
                &mut uncompressed,
                blob_info.meta_ci_compressor(),
            )
            .map_err(|e| {
                error!("failed to decompress blob meta data: {}", e);
                e
            })?;
            Cow::Owned(uncompressed)
        } else {
            decrypted
        };
        buffer[0..uncompressed_size as usize].copy_from_slice(&uncompressed);
        buffer[aligned_uncompressed_size as usize
            ..(aligned_uncompressed_size + BLOB_CCT_HEADER_SIZE) as usize]
            .copy_from_slice(&header);
        Ok(())
    }

    fn validate_header(
        blob_info: &BlobInfo,
        header: &BlobCompressionContextHeader,
    ) -> Result<bool> {
        trace!("blob meta header magic {:x}/{:x}, entries {:x}/{:x}, features {:x}/{:x}, compressor {:x}/{:x}, ci_offset {:x}/{:x}, compressed_size {:x}/{:x}, uncompressed_size {:x}/{:x}",
                u32::from_le(header.s_magic),
                BLOB_CCT_MAGIC,
                u32::from_le(header.s_ci_entries),
                blob_info.chunk_count(),
                u32::from_le(header.s_features),
                blob_info.features().bits(),
                u32::from_le(header.s_ci_compressor),
                blob_info.meta_ci_compressor() as u32,
                u64::from_le(header.s_ci_offset),
                blob_info.meta_ci_offset(),
                u64::from_le(header.s_ci_compressed_size),
                blob_info.meta_ci_compressed_size(),
                u64::from_le(header.s_ci_uncompressed_size),
                blob_info.meta_ci_uncompressed_size());

        if u32::from_le(header.s_magic) != BLOB_CCT_MAGIC
            || u32::from_le(header.s_magic2) != BLOB_CCT_MAGIC
            || u32::from_le(header.s_ci_entries) != blob_info.chunk_count()
            || u32::from_le(header.s_features) != blob_info.features().bits()
            || u32::from_le(header.s_ci_compressor) != blob_info.meta_ci_compressor() as u32
            || u64::from_le(header.s_ci_offset) != blob_info.meta_ci_offset()
            || u64::from_le(header.s_ci_compressed_size) != blob_info.meta_ci_compressed_size()
            || u64::from_le(header.s_ci_uncompressed_size) != blob_info.meta_ci_uncompressed_size()
        {
            return Ok(false);
        }

        let chunk_count = blob_info.chunk_count();
        if chunk_count == 0 || chunk_count > RAFS_MAX_CHUNKS_PER_BLOB {
            return Err(einval!(format!(
                "chunk count {:x} in blob meta header is invalid!",
                chunk_count
            )));
        }

        let info_size = u64::from_le(header.s_ci_uncompressed_size) as usize;
        let aligned_info_size = round_up_4k(info_size);
        if blob_info.has_feature(BlobFeatures::CHUNK_INFO_V2)
            && (blob_info.has_feature(BlobFeatures::ZRAN)
                || blob_info.has_feature(BlobFeatures::BATCH))
        {
            if info_size < (chunk_count as usize) * (size_of::<BlobChunkInfoV2Ondisk>()) {
                return Err(einval!("uncompressed size in blob meta header is invalid!"));
            }
        } else if blob_info.has_feature(BlobFeatures::CHUNK_INFO_V2) {
            if info_size != (chunk_count as usize) * (size_of::<BlobChunkInfoV2Ondisk>())
                || (aligned_info_size as u64) > BLOB_CCT_V2_MAX_SIZE
            {
                return Err(einval!("uncompressed size in blob meta header is invalid!"));
            }
        } else if blob_info.has_feature(BlobFeatures::ZRAN)
            || blob_info.has_feature(BlobFeatures::BATCH)
        {
            return Err(einval!("invalid feature flags in blob meta header!"));
        } else if info_size != (chunk_count as usize) * (size_of::<BlobChunkInfoV1Ondisk>())
            || (aligned_info_size as u64) > BLOB_CCT_V1_MAX_SIZE
        {
            return Err(einval!("uncompressed size in blob meta header is invalid!"));
        }

        if blob_info.has_feature(BlobFeatures::ZRAN) {
            let offset = header.s_ci_zran_offset;
            if offset != (chunk_count as u64) * (size_of::<BlobChunkInfoV2Ondisk>() as u64) {
                return Ok(false);
            }
            if offset + header.s_ci_zran_size > info_size as u64 {
                return Ok(false);
            }
            let zran_count = header.s_ci_zran_count as u64;
            let size = zran_count * size_of::<ZranInflateContext>() as u64;
            if zran_count > chunk_count as u64 {
                return Ok(false);
            }
            if size > header.s_ci_zran_size {
                return Ok(false);
            }
        }

        Ok(true)
    }
}

/// Struct to maintain compression context information for all chunks in a blob.
#[derive(Default)]
pub struct BlobCompressionContext {
    pub(crate) blob_index: u32,
    pub(crate) blob_features: u32,
    pub(crate) compressed_size: u64,
    pub(crate) uncompressed_size: u64,
    pub(crate) chunk_info_array: ManuallyDrop<BlobMetaChunkArray>,
    pub(crate) chunk_digest_array: ManuallyDrop<Vec<DigestData>>,
    pub(crate) batch_info_array: ManuallyDrop<Vec<BatchInflateContext>>,
    pub(crate) zran_info_array: ManuallyDrop<Vec<ZranInflateContext>>,
    pub(crate) zran_dict_table: ManuallyDrop<Vec<u8>>,
    blob_meta_file_map: FileMapState,
    chunk_digest_file_map: FileMapState,
    chunk_digest_default: RafsDigest,
}

impl BlobCompressionContext {
    fn get_chunks_uncompressed(
        self: &Arc<BlobCompressionContext>,
        start: u64,
        end: u64,
        batch_end: u64,
        batch_size: u64,
    ) -> Result<Vec<Arc<dyn BlobChunkInfo>>> {
        self.chunk_info_array
            .get_chunks_uncompressed(self, start, end, batch_end, batch_size)
    }

    fn get_chunks_compressed(
        self: &Arc<BlobCompressionContext>,
        start: u64,
        end: u64,
        batch_end: u64,
        batch_size: u64,
        prefetch: bool,
    ) -> Result<Vec<Arc<dyn BlobChunkInfo>>> {
        self.chunk_info_array
            .get_chunks_compressed(self, start, end, batch_end, batch_size, prefetch)
    }

    fn add_more_chunks(
        self: &Arc<BlobCompressionContext>,
        chunks: &[Arc<dyn BlobChunkInfo>],
        max_size: u64,
    ) -> Result<Vec<Arc<dyn BlobChunkInfo>>> {
        self.chunk_info_array
            .add_more_chunks(self, chunks, max_size)
    }

    fn get_uncompressed_offset(&self, chunk_index: usize) -> u64 {
        self.chunk_info_array.uncompressed_offset(chunk_index)
    }

    fn get_chunk_digest(&self, chunk_index: usize) -> Option<&[u8]> {
        if chunk_index < self.chunk_digest_array.len() {
            Some(&self.chunk_digest_array[chunk_index])
        } else {
            None
        }
    }

    fn get_chunk_index(&self, addr: u64) -> Result<usize> {
        self.chunk_info_array
            .get_chunk_index_nocheck(self, addr, false)
    }

    /// Get whether chunk at `chunk_index` is batch chunk.
    /// Some chunks build in batch mode can also be non-batch chunks,
    /// that they are too big to be put into a batch.
    fn is_batch_chunk(&self, chunk_index: usize) -> bool {
        self.chunk_info_array.is_batch(chunk_index)
    }

    fn get_batch_index(&self, chunk_index: usize) -> u32 {
        self.chunk_info_array.batch_index(chunk_index)
    }

    fn get_uncompressed_offset_in_batch_buf(&self, chunk_index: usize) -> u32 {
        self.chunk_info_array
            .uncompressed_offset_in_batch_buf(chunk_index)
    }

    /// Get Batch context information for decoding.
    fn get_batch_context(&self, batch_index: usize) -> Option<&BatchInflateContext> {
        if batch_index < self.batch_info_array.len() {
            let ctx = &self.batch_info_array[batch_index];
            Some(ctx)
        } else {
            None
        }
    }

    /// Get compressed offset and size associated with the chunk at `chunk_index`.
    /// Capabale of handling both batch and non-batch chunks.
    /// Return `compressed_offset` and `compressed_size`.
    pub fn get_compressed_info(&self, chunk_index: usize) -> Result<(u64, u32)> {
        if self.is_batch_chunk(chunk_index) {
            let ctx = self
                .get_batch_context(self.get_batch_index(chunk_index) as usize)
                .unwrap();
            Ok((ctx.compressed_offset(), ctx.compressed_size()))
        } else {
            Ok((
                self.chunk_info_array.compressed_offset(chunk_index),
                self.chunk_info_array.compressed_size(chunk_index),
            ))
        }
    }

    fn get_zran_index(&self, chunk_index: usize) -> u32 {
        self.chunk_info_array.zran_index(chunk_index)
    }

    fn get_zran_offset(&self, chunk_index: usize) -> u32 {
        self.chunk_info_array.zran_offset(chunk_index)
    }

    /// Get ZRan context information for decoding.
    fn get_zran_context(&self, zran_index: usize) -> Option<(ZranContext, &[u8])> {
        if zran_index < self.zran_info_array.len() {
            let entry = &self.zran_info_array[zran_index];
            let dict_off = entry.dict_offset() as usize;
            let dict_size = entry.dict_size() as usize;
            if dict_off.checked_add(dict_size).is_none()
                || dict_off + dict_size > self.zran_dict_table.len()
            {
                return None;
            };
            let dict = &self.zran_dict_table[dict_off..dict_off + dict_size];
            let ctx = ZranContext::from(entry);
            Some((ctx, dict))
        } else {
            None
        }
    }

    pub(crate) fn is_separate(&self) -> bool {
        self.blob_features & BlobFeatures::SEPARATE.bits() != 0
    }

    pub(crate) fn is_encrypted(&self) -> bool {
        self.blob_features & BlobFeatures::ENCRYPTED.bits() != 0
    }
}

/// A customized array to host chunk information table for a blob.
pub enum BlobMetaChunkArray {
    /// V1 chunk compression information array.
    V1(Vec<BlobChunkInfoV1Ondisk>),
    /// V2 chunk compression information array.
    V2(Vec<BlobChunkInfoV2Ondisk>),
}

impl Default for BlobMetaChunkArray {
    fn default() -> Self {
        BlobMetaChunkArray::new_v2()
    }
}

// Methods for RAFS filesystem builder.
impl BlobMetaChunkArray {
    /// Create a [BlobMetaChunkArray] with v1 chunk compression information format.
    pub fn new_v1() -> Self {
        BlobMetaChunkArray::V1(Vec::new())
    }

    /// Create a [BlobMetaChunkArray] with v2 chunk compression information format.
    pub fn new_v2() -> Self {
        BlobMetaChunkArray::V2(Vec::new())
    }

    /// Get number of entries in the chunk compression information array.
    pub fn len(&self) -> usize {
        match self {
            BlobMetaChunkArray::V1(v) => v.len(),
            BlobMetaChunkArray::V2(v) => v.len(),
        }
    }

    /// Check whether the chunk compression information array is empty or not.
    pub fn is_empty(&self) -> bool {
        match self {
            BlobMetaChunkArray::V1(v) => v.is_empty(),
            BlobMetaChunkArray::V2(v) => v.is_empty(),
        }
    }

    /// Convert the chunk compression information array as a u8 slice.
    pub fn as_byte_slice(&self) -> &[u8] {
        match self {
            BlobMetaChunkArray::V1(v) => unsafe {
                std::slice::from_raw_parts(
                    v.as_ptr() as *const u8,
                    v.len() * size_of::<BlobChunkInfoV1Ondisk>(),
                )
            },
            BlobMetaChunkArray::V2(v) => unsafe {
                std::slice::from_raw_parts(
                    v.as_ptr() as *const u8,
                    v.len() * size_of::<BlobChunkInfoV2Ondisk>(),
                )
            },
        }
    }

    /// Add an entry of v1 chunk compression information into the array.
    pub fn add_v1(
        &mut self,
        compressed_offset: u64,
        compressed_size: u32,
        uncompressed_offset: u64,
        uncompressed_size: u32,
    ) {
        match self {
            BlobMetaChunkArray::V1(v) => {
                let mut meta = BlobChunkInfoV1Ondisk::default();
                meta.set_compressed_offset(compressed_offset);
                meta.set_compressed_size(compressed_size);
                meta.set_uncompressed_offset(uncompressed_offset);
                meta.set_uncompressed_size(uncompressed_size);
                v.push(meta);
            }
            BlobMetaChunkArray::V2(_v) => unimplemented!(),
        }
    }

    /// Add an entry of v2 chunk compression information into the array.
    #[allow(clippy::too_many_arguments)]
    pub fn add_v2(
        &mut self,
        compressed_offset: u64,
        compressed_size: u32,
        uncompressed_offset: u64,
        uncompressed_size: u32,
        compressed: bool,
        encrypted: bool,
        is_batch: bool,
        data: u64,
    ) {
        match self {
            BlobMetaChunkArray::V2(v) => {
                let mut meta = BlobChunkInfoV2Ondisk::default();
                meta.set_compressed_offset(compressed_offset);
                meta.set_compressed_size(compressed_size);
                meta.set_uncompressed_offset(uncompressed_offset);
                meta.set_uncompressed_size(uncompressed_size);
                meta.set_compressed(compressed);
                meta.set_encrypted(encrypted);
                meta.set_batch(is_batch);
                meta.set_data(data);
                v.push(meta);
            }
            BlobMetaChunkArray::V1(_v) => unimplemented!(),
        }
    }

    /// Add an entry of pre-built v2 chunk compression information into the array.
    pub fn add_v2_info(&mut self, chunk_info: BlobChunkInfoV2Ondisk) {
        match self {
            BlobMetaChunkArray::V2(v) => v.push(chunk_info),
            BlobMetaChunkArray::V1(_v) => unimplemented!(),
        }
    }
}

impl BlobMetaChunkArray {
    fn from_file_map(filemap: &FileMapState, blob_info: &BlobInfo) -> Result<Self> {
        let chunk_count = blob_info.chunk_count();
        if blob_info.has_feature(BlobFeatures::CHUNK_INFO_V2) {
            let chunk_size = chunk_count as usize * size_of::<BlobChunkInfoV2Ondisk>();
            let base = filemap.validate_range(0, chunk_size)?;
            let v = unsafe {
                Vec::from_raw_parts(
                    base as *mut u8 as *mut BlobChunkInfoV2Ondisk,
                    chunk_count as usize,
                    chunk_count as usize,
                )
            };
            Ok(BlobMetaChunkArray::V2(v))
        } else {
            let chunk_size = chunk_count as usize * size_of::<BlobChunkInfoV1Ondisk>();
            let base = filemap.validate_range(0, chunk_size)?;
            let v = unsafe {
                Vec::from_raw_parts(
                    base as *mut u8 as *mut BlobChunkInfoV1Ondisk,
                    chunk_count as usize,
                    chunk_count as usize,
                )
            };
            Ok(BlobMetaChunkArray::V1(v))
        }
    }

    fn get_chunk_index_nocheck(
        &self,
        state: &BlobCompressionContext,
        addr: u64,
        compressed: bool,
    ) -> Result<usize> {
        match self {
            BlobMetaChunkArray::V1(v) => {
                Self::_get_chunk_index_nocheck(state, v, addr, compressed, false)
            }
            BlobMetaChunkArray::V2(v) => {
                Self::_get_chunk_index_nocheck(state, v, addr, compressed, false)
            }
        }
    }

    fn get_chunks_compressed(
        &self,
        state: &Arc<BlobCompressionContext>,
        start: u64,
        end: u64,
        batch_end: u64,
        batch_size: u64,
        prefetch: bool,
    ) -> Result<Vec<Arc<dyn BlobChunkInfo>>> {
        match self {
            BlobMetaChunkArray::V1(v) => {
                Self::_get_chunks_compressed(state, v, start, end, batch_end, batch_size, prefetch)
            }
            BlobMetaChunkArray::V2(v) => {
                Self::_get_chunks_compressed(state, v, start, end, batch_end, batch_size, prefetch)
            }
        }
    }

    fn get_chunks_uncompressed(
        &self,
        state: &Arc<BlobCompressionContext>,
        start: u64,
        end: u64,
        batch_end: u64,
        batch_size: u64,
    ) -> Result<Vec<Arc<dyn BlobChunkInfo>>> {
        match self {
            BlobMetaChunkArray::V1(v) => {
                Self::_get_chunks_uncompressed(state, v, start, end, batch_end, batch_size)
            }
            BlobMetaChunkArray::V2(v) => {
                Self::_get_chunks_uncompressed(state, v, start, end, batch_end, batch_size)
            }
        }
    }

    fn add_more_chunks(
        &self,
        state: &Arc<BlobCompressionContext>,
        chunks: &[Arc<dyn BlobChunkInfo>],
        max_size: u64,
    ) -> Result<Vec<Arc<dyn BlobChunkInfo>>> {
        match self {
            BlobMetaChunkArray::V1(v) => Self::_add_more_chunks(state, v, chunks, max_size),
            BlobMetaChunkArray::V2(v) => Self::_add_more_chunks(state, v, chunks, max_size),
        }
    }

    fn compressed_offset(&self, index: usize) -> u64 {
        match self {
            BlobMetaChunkArray::V1(v) => v[index].compressed_offset(),
            BlobMetaChunkArray::V2(v) => v[index].compressed_offset(),
        }
    }

    fn compressed_size(&self, index: usize) -> u32 {
        match self {
            BlobMetaChunkArray::V1(v) => v[index].compressed_size(),
            BlobMetaChunkArray::V2(v) => v[index].compressed_size(),
        }
    }

    fn uncompressed_offset(&self, index: usize) -> u64 {
        match self {
            BlobMetaChunkArray::V1(v) => v[index].uncompressed_offset(),
            BlobMetaChunkArray::V2(v) => v[index].uncompressed_offset(),
        }
    }

    fn uncompressed_size(&self, index: usize) -> u32 {
        match self {
            BlobMetaChunkArray::V1(v) => v[index].uncompressed_size(),
            BlobMetaChunkArray::V2(v) => v[index].uncompressed_size(),
        }
    }

    fn is_batch(&self, index: usize) -> bool {
        match self {
            BlobMetaChunkArray::V1(v) => v[index].is_batch(),
            BlobMetaChunkArray::V2(v) => v[index].is_batch(),
        }
    }

    fn batch_index(&self, index: usize) -> u32 {
        match self {
            BlobMetaChunkArray::V1(v) => v[index].get_batch_index(),
            BlobMetaChunkArray::V2(v) => v[index].get_batch_index(),
        }
    }

    fn uncompressed_offset_in_batch_buf(&self, index: usize) -> u32 {
        match self {
            BlobMetaChunkArray::V1(v) => v[index].get_uncompressed_offset_in_batch_buf(),
            BlobMetaChunkArray::V2(v) => v[index].get_uncompressed_offset_in_batch_buf(),
        }
    }

    fn zran_index(&self, index: usize) -> u32 {
        match self {
            BlobMetaChunkArray::V1(v) => v[index].get_zran_index(),
            BlobMetaChunkArray::V2(v) => v[index].get_zran_index(),
        }
    }

    fn zran_offset(&self, index: usize) -> u32 {
        match self {
            BlobMetaChunkArray::V1(v) => v[index].get_zran_offset(),
            BlobMetaChunkArray::V2(v) => v[index].get_zran_offset(),
        }
    }

    fn is_compressed(&self, index: usize) -> bool {
        match self {
            BlobMetaChunkArray::V1(v) => v[index].is_compressed(),
            BlobMetaChunkArray::V2(v) => v[index].is_compressed(),
        }
    }

    fn is_encrypted(&self, index: usize) -> bool {
        match self {
            BlobMetaChunkArray::V1(v) => v[index].is_encrypted(),
            BlobMetaChunkArray::V2(v) => v[index].is_encrypted(),
        }
    }

    fn _get_chunk_index_nocheck<T: BlobMetaChunkInfo>(
        state: &BlobCompressionContext,
        chunks: &[T],
        addr: u64,
        compressed: bool,
        prefetch: bool,
    ) -> Result<usize> {
        let mut size = chunks.len();
        let mut left = 0;
        let mut right = size;
        let mut start = 0;
        let mut end = 0;

        while left < right {
            let mid = left + size / 2;
            // SAFETY: the call is made safe by the following invariants:
            // - `mid >= 0`
            // - `mid < size`: `mid` is limited by `[left; right)` bound.
            let entry = &chunks[mid];
            if compressed {
                // Capabale of handling both batch and non-batch chunks.
                let (c_offset, c_size) = state.get_compressed_info(mid)?;
                (start, end) = (c_offset, c_offset + c_size as u64);
            } else {
                start = entry.uncompressed_offset();
                end = entry.uncompressed_end();
            };

            if start > addr {
                right = mid;
            } else if end <= addr {
                left = mid + 1;
            } else {
                // Find the first chunk in the batch.
                if entry.is_batch() && entry.get_uncompressed_offset_in_batch_buf() > 0 {
                    right = mid;
                } else {
                    return Ok(mid);
                }
            }

            size = right - left;
        }

        // Special handling prefetch for ZRan blobs because they may have holes.
        if prefetch {
            if right < chunks.len() {
                let entry = &chunks[right];
                if entry.compressed_offset() > addr {
                    return Ok(right);
                }
            }
            if left < chunks.len() {
                let entry = &chunks[left];
                if entry.compressed_offset() > addr {
                    return Ok(left);
                }
            }
        }

        // if addr == self.chunks[last].compressed_offset, return einval with error msg.
        Err(einval!(format!(
            "failed to get chunk index, prefetch {}, left {}, right {}, start: {}, end: {}, addr: {}",
            prefetch, left, right, start, end, addr
        )))
    }

    fn _get_chunks_uncompressed<T: BlobMetaChunkInfo>(
        state: &Arc<BlobCompressionContext>,
        chunk_info_array: &[T],
        start: u64,
        end: u64,
        batch_end: u64,
        batch_size: u64,
    ) -> Result<Vec<Arc<dyn BlobChunkInfo>>> {
        let mut vec = Vec::with_capacity(512);
        let mut index =
            Self::_get_chunk_index_nocheck(state, chunk_info_array, start, false, false)?;
        let entry = Self::get_chunk_entry(state, chunk_info_array, index)?;
        trace!(
            "get_chunks_uncompressed: entry {} {}",
            entry.uncompressed_offset(),
            entry.uncompressed_end()
        );

        // Special handling of ZRan chunks
        if entry.is_zran() {
            let zran_index = entry.get_zran_index();
            let mut count = state.zran_info_array[zran_index as usize].out_size() as u64;
            let mut zran_last = zran_index;
            let mut zran_end = entry.aligned_uncompressed_end();

            while index > 0 {
                let entry = Self::get_chunk_entry(state, chunk_info_array, index - 1)?;
                if !entry.is_zran() {
                    return Err(einval!(
                        "inconsistent ZRan and non-ZRan chunk compression information entries"
                    ));
                } else if entry.get_zran_index() != zran_index {
                    // reach the header chunk associated with the same ZRan context.
                    break;
                } else {
                    index -= 1;
                }
            }

            for entry in &chunk_info_array[index..] {
                entry.validate(state)?;
                if !entry.is_zran() {
                    return Err(einval!(
                        "inconsistent ZRan and non-ZRan chunk compression information entries"
                    ));
                }
                if entry.get_zran_index() != zran_last {
                    let ctx = &state.zran_info_array[entry.get_zran_index() as usize];
                    if count + ctx.out_size() as u64 >= batch_size
                        && entry.uncompressed_offset() >= end
                    {
                        return Ok(vec);
                    }
                    count += ctx.out_size() as u64;
                    zran_last = entry.get_zran_index();
                }
                zran_end = entry.aligned_uncompressed_end();
                vec.push(BlobMetaChunk::new(index, state));
                index += 1;
            }

            if zran_end >= end {
                return Ok(vec);
            }
            return Err(einval!(format!(
                "entry not found index {} chunk_info_array.len {}, end 0x{:x}, range [0x{:x}-0x{:x}]",
                index,
                chunk_info_array.len(),
                vec.last().map(|v| v.uncompressed_end()).unwrap_or_default(),
                start,
                end,
            )));
        }

        vec.push(BlobMetaChunk::new(index, state));
        let mut last_end = entry.aligned_uncompressed_end();
        if last_end >= batch_end {
            Ok(vec)
        } else {
            while index + 1 < chunk_info_array.len() {
                index += 1;

                let entry = Self::get_chunk_entry(state, chunk_info_array, index)?;
                if entry.uncompressed_offset() != last_end {
                    return Err(einval!(format!(
                        "mismatch uncompressed {} size {} last_end {}",
                        entry.uncompressed_offset(),
                        entry.uncompressed_size(),
                        last_end
                    )));
                } else if last_end >= end && entry.aligned_uncompressed_end() >= batch_end {
                    // Avoid read amplify if next chunk is too big.
                    return Ok(vec);
                }

                vec.push(BlobMetaChunk::new(index, state));
                last_end = entry.aligned_uncompressed_end();
                if last_end >= batch_end {
                    return Ok(vec);
                }
            }

            if last_end >= end {
                Ok(vec)
            } else {
                Err(einval!(format!(
                    "entry not found index {} chunk_info_array.len {}, last_end 0x{:x}, end 0x{:x}, blob compressed size 0x{:x}",
                    index,
                    chunk_info_array.len(),
                    last_end,
                    end,
                    state.uncompressed_size,
                )))
            }
        }
    }

    fn _get_chunks_compressed<T: BlobMetaChunkInfo>(
        state: &Arc<BlobCompressionContext>,
        chunk_info_array: &[T],
        start: u64,
        end: u64,
        batch_end: u64,
        batch_size: u64,
        prefetch: bool,
    ) -> Result<Vec<Arc<dyn BlobChunkInfo>>> {
        let mut vec = Vec::with_capacity(512);
        let mut index =
            Self::_get_chunk_index_nocheck(state, chunk_info_array, start, true, prefetch)?;
        let entry = Self::get_chunk_entry(state, chunk_info_array, index)?;

        // Special handling of ZRan chunks
        if entry.is_zran() {
            let zran_index = entry.get_zran_index();
            let pos = state.zran_info_array[zran_index as usize].in_offset();
            let mut zran_last = zran_index;

            while index > 0 {
                let entry = Self::get_chunk_entry(state, chunk_info_array, index - 1)?;
                if !entry.is_zran() {
                    return Err(einval!(
                        "inconsistent ZRan and non-ZRan chunk compression information entries"
                    ));
                } else if entry.get_zran_index() != zran_index {
                    // reach the header chunk associated with the same ZRan context.
                    break;
                } else {
                    index -= 1;
                }
            }

            for entry in &chunk_info_array[index..] {
                entry.validate(state)?;
                if !entry.is_zran() {
                    return Err(einval!(
                        "inconsistent ZRan and non-ZRan chunk compression information entries"
                    ));
                }
                if entry.get_zran_index() != zran_last {
                    let ctx = &state.zran_info_array[entry.get_zran_index() as usize];
                    if ctx.in_offset() + ctx.in_size() as u64 - pos > batch_size
                        && entry.compressed_offset() > end
                    {
                        return Ok(vec);
                    }
                    zran_last = entry.get_zran_index();
                }
                vec.push(BlobMetaChunk::new(index, state));
                index += 1;
            }

            if let Some(c) = vec.last() {
                if c.uncompressed_end() >= end {
                    return Ok(vec);
                }
                // Special handling prefetch for ZRan blobs
                if prefetch && index >= chunk_info_array.len() {
                    return Ok(vec);
                }
            }
            return Err(einval!(format!(
                "entry not found index {} chunk_info_array.len {}",
                index,
                chunk_info_array.len(),
            )));
        }

        vec.push(BlobMetaChunk::new(index, state));
        let mut last_end = entry.compressed_end();
        if last_end >= batch_end {
            Ok(vec)
        } else {
            while index + 1 < chunk_info_array.len() {
                index += 1;

                let entry = Self::get_chunk_entry(state, chunk_info_array, index)?;
                // Avoid read amplify if next chunk is too big.
                if last_end >= end && entry.compressed_end() > batch_end {
                    return Ok(vec);
                }

                vec.push(BlobMetaChunk::new(index, state));
                last_end = entry.compressed_end();
                if last_end >= batch_end {
                    return Ok(vec);
                }
            }

            if last_end >= end || (prefetch && !vec.is_empty()) {
                Ok(vec)
            } else {
                Err(einval!(format!(
                    "entry not found index {} chunk_info_array.len {}, last_end 0x{:x}, end 0x{:x}, blob compressed size 0x{:x}",
                    index,
                    chunk_info_array.len(),
                    last_end,
                    end,
                    state.compressed_size,
                )))
            }
        }
    }

    fn _add_more_chunks<T: BlobMetaChunkInfo>(
        state: &Arc<BlobCompressionContext>,
        chunk_info_array: &[T],
        chunks: &[Arc<dyn BlobChunkInfo>],
        max_size: u64,
    ) -> Result<Vec<Arc<dyn BlobChunkInfo>>> {
        // `batch_end` is only valid for non-batch chunk.
        let batch_end = chunks[0].compressed_offset() + max_size;
        let first_idx = chunks[0].id() as usize;
        let first_entry = Self::get_chunk_entry(state, chunk_info_array, first_idx)?;
        let mut last_idx = chunks[chunks.len() - 1].id() as usize;
        let last_entry = Self::get_chunk_entry(state, chunk_info_array, last_idx)?;
        let mut vec = Vec::with_capacity(128);

        // Special handling of ZRan chunks
        if first_entry.is_zran() {
            let first_zran_idx = first_entry.get_zran_index();
            let mut last_zran_idx = last_entry.get_zran_index();
            let mut index = first_idx;
            while index > 0 {
                let entry = Self::get_chunk_entry(state, chunk_info_array, index - 1)?;
                if !entry.is_zran() {
                    // All chunks should be ZRan chunks.
                    return Err(einval!("invalid ZRan compression information data"));
                } else if entry.get_zran_index() != first_zran_idx {
                    // reach the header chunk associated with the same ZRan context.
                    break;
                } else {
                    index -= 1;
                }
            }

            for entry in &chunk_info_array[index..] {
                if entry.validate(state).is_err() || !entry.is_zran() {
                    return Err(einval!("invalid ZRan compression information data"));
                } else if entry.get_zran_index() > last_zran_idx {
                    if entry.compressed_end() + RAFS_MAX_CHUNK_SIZE <= batch_end
                        && entry.get_zran_index() == last_zran_idx + 1
                    {
                        vec.push(BlobMetaChunk::new(index, state));
                        last_zran_idx += 1;
                    } else {
                        return Ok(vec);
                    }
                } else {
                    vec.push(BlobMetaChunk::new(index, state));
                }
                index += 1;
            }
        } else if first_entry.is_batch() {
            // Assert each entry in chunks is Batch chunk.

            let first_batch_idx = first_entry.get_batch_index();
            let last_batch_idx = last_entry.get_batch_index();
            let mut index = first_idx;
            if first_batch_idx != last_batch_idx {
                return Err(einval!(
                    "a single region cannot include multiple batch chunks"
                ));
            }

            while index > 0 {
                let entry = Self::get_chunk_entry(state, chunk_info_array, index - 1)?;
                if !entry.is_batch() || entry.get_batch_index() != first_batch_idx {
                    // Reach the previous non-batch chunk,
                    // or reach the header chunk associated with the same Batch context.
                    break;
                } else {
                    index -= 1;
                }
            }

            for entry in &chunk_info_array[index..] {
                if entry.validate(state).is_err() {
                    return Err(einval!("invalid Batch compression information data"));
                } else if !entry.is_batch() {
                    return Err(einval!(
                        "non-batch chunks cannot be inside the range of batch chunks"
                    ));
                } else if entry.get_batch_index() > last_batch_idx {
                    return Ok(vec);
                } else {
                    vec.push(BlobMetaChunk::new(index, state));
                }
                index += 1;
            }
        } else {
            // Assert each entry in chunks is not Batch chunk.

            for idx in 0..chunks.len() - 1 {
                let chunk = &chunks[idx];
                let next = &chunks[idx + 1];
                let next_end = next.compressed_offset() + next.compressed_size() as u64;
                vec.push(chunk.clone());
                if chunk.id() + 1 != next.id() && next_end <= batch_end {
                    for i in chunk.id() + 1..next.id() {
                        let entry = &chunk_info_array[i as usize];
                        if entry.validate(state).is_ok() {
                            vec.push(BlobMetaChunk::new(i as usize, state));
                        }
                    }
                }
            }
            vec.push(chunks[chunks.len() - 1].clone());

            last_idx += 1;
            while last_idx < chunk_info_array.len() {
                let entry = &chunk_info_array[last_idx];
                // Avoid read amplification if next chunk is too big.
                if entry.validate(state).is_err() || entry.compressed_end() > batch_end {
                    break;
                }
                if !entry.is_batch() {
                    vec.push(BlobMetaChunk::new(last_idx, state));
                }
                last_idx += 1;
            }
        }

        Ok(vec)
    }

    fn get_chunk_entry<'a, T: BlobMetaChunkInfo>(
        state: &Arc<BlobCompressionContext>,
        chunk_info_array: &'a [T],
        index: usize,
    ) -> Result<&'a T> {
        assert!(index < chunk_info_array.len());
        let entry = &chunk_info_array[index];
        entry.validate(state)?;
        Ok(entry)
    }
}

/// An implementation of `trait BlobChunkInfo` based on blob meta information.
#[derive(Clone)]
pub struct BlobMetaChunk {
    chunk_index: usize,
    meta: Arc<BlobCompressionContext>,
}

impl BlobMetaChunk {
    #[allow(clippy::new_ret_no_self)]
    pub(crate) fn new(
        chunk_index: usize,
        meta: &Arc<BlobCompressionContext>,
    ) -> Arc<dyn BlobChunkInfo> {
        assert!(chunk_index <= RAFS_MAX_CHUNKS_PER_BLOB as usize);
        Arc::new(BlobMetaChunk {
            chunk_index,
            meta: meta.clone(),
        }) as Arc<dyn BlobChunkInfo>
    }
}

impl BlobChunkInfo for BlobMetaChunk {
    fn chunk_id(&self) -> &RafsDigest {
        if self.chunk_index < self.meta.chunk_digest_array.len() {
            let digest = &self.meta.chunk_digest_array[self.chunk_index];
            digest.into()
        } else {
            &self.meta.chunk_digest_default
        }
    }

    fn id(&self) -> u32 {
        self.chunk_index as u32
    }

    fn blob_index(&self) -> u32 {
        self.meta.blob_index
    }

    fn compressed_offset(&self) -> u64 {
        self.meta
            .chunk_info_array
            .compressed_offset(self.chunk_index)
    }

    fn compressed_size(&self) -> u32 {
        self.meta.chunk_info_array.compressed_size(self.chunk_index)
    }

    fn uncompressed_offset(&self) -> u64 {
        self.meta
            .chunk_info_array
            .uncompressed_offset(self.chunk_index)
    }

    fn uncompressed_size(&self) -> u32 {
        self.meta
            .chunk_info_array
            .uncompressed_size(self.chunk_index)
    }

    fn is_compressed(&self) -> bool {
        self.meta.chunk_info_array.is_compressed(self.chunk_index)
    }

    fn is_encrypted(&self) -> bool {
        self.meta.chunk_info_array.is_encrypted(self.chunk_index)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl BlobV5ChunkInfo for BlobMetaChunk {
    fn index(&self) -> u32 {
        self.chunk_index as u32
    }

    fn file_offset(&self) -> u64 {
        // Not used for RAFS v6
        0
    }

    fn flags(&self) -> BlobChunkFlags {
        let mut flags = BlobChunkFlags::empty();
        if self.is_compressed() {
            flags |= BlobChunkFlags::COMPRESSED;
        }
        flags
    }

    fn as_base(&self) -> &dyn BlobChunkInfo {
        self
    }
}

/// Trait to manage compression information about chunks based on blob meta.
pub trait BlobMetaChunkInfo {
    /// Get compressed offset of the chunk.
    fn compressed_offset(&self) -> u64;

    /// Set compressed offset of the chunk.
    fn set_compressed_offset(&mut self, offset: u64);

    /// Get compressed size of the chunk.
    fn compressed_size(&self) -> u32;

    /// Set compressed size of the chunk.
    fn set_compressed_size(&mut self, size: u32);

    /// Get end of compressed data of the chunk.
    fn compressed_end(&self) -> u64 {
        self.compressed_offset() + self.compressed_size() as u64
    }

    /// Get uncompressed offset of the chunk.
    fn uncompressed_offset(&self) -> u64;

    /// Set uncompressed offset of the chunk.
    fn set_uncompressed_offset(&mut self, offset: u64);

    /// Get uncompressed end of the chunk.
    fn uncompressed_size(&self) -> u32;

    /// Set uncompressed end of the chunk.
    fn set_uncompressed_size(&mut self, size: u32);

    /// Get end of uncompressed data of the chunk.
    fn uncompressed_end(&self) -> u64 {
        self.uncompressed_offset() + self.uncompressed_size() as u64
    }

    /// Get 4K-aligned end of uncompressed data of the chunk.
    fn aligned_uncompressed_end(&self) -> u64 {
        round_up_4k(self.uncompressed_end())
    }

    /// Check whether chunk data is encrypted or not.
    fn is_encrypted(&self) -> bool;

    /// Check whether the blob chunk is compressed or not.
    ///
    /// Assume the image builder guarantee that compress_size < uncompress_size if the chunk is
    /// compressed.
    fn is_compressed(&self) -> bool;

    /// Check whether the chunk has associated Batch context data.
    fn is_batch(&self) -> bool;

    /// Check whether the chunk has associated ZRan context data.
    fn is_zran(&self) -> bool;

    /// Get index of the ZRan context data associated with the chunk.
    fn get_zran_index(&self) -> u32;

    /// Get offset to get context data from the associated ZRan context.
    fn get_zran_offset(&self) -> u32;

    /// Get index of the Batch context data associated with the chunk.
    fn get_batch_index(&self) -> u32;

    /// Get offset of uncompressed chunk data inside the batch chunk.
    fn get_uncompressed_offset_in_batch_buf(&self) -> u32;

    /// Get data associated with the entry. V2 only, V1 just returns zero.
    fn get_data(&self) -> u64;

    /// Check whether the chunk compression information is valid or not.
    fn validate(&self, state: &BlobCompressionContext) -> Result<()>;
}

/// Generate description string for blob meta features.
pub fn format_blob_features(features: BlobFeatures) -> String {
    let mut output = String::new();
    if features.contains(BlobFeatures::ALIGNED) {
        output += "aligned ";
    }
    if features.contains(BlobFeatures::BATCH) {
        output += "batch ";
    }
    if features.contains(BlobFeatures::CAP_TAR_TOC) {
        output += "cap_toc ";
    }
    if features.contains(BlobFeatures::INLINED_CHUNK_DIGEST) {
        output += "chunk-digest ";
    }
    if features.contains(BlobFeatures::CHUNK_INFO_V2) {
        output += "chunk-v2 ";
    }
    if features.contains(BlobFeatures::INLINED_FS_META) {
        output += "fs-meta ";
    }
    if features.contains(BlobFeatures::SEPARATE) {
        output += "separate ";
    }
    if features.contains(BlobFeatures::HAS_TAR_HEADER) {
        output += "tar-header ";
    }
    if features.contains(BlobFeatures::HAS_TOC) {
        output += "toc ";
    }
    if features.contains(BlobFeatures::ZRAN) {
        output += "zran ";
    }
    if features.contains(BlobFeatures::ENCRYPTED) {
        output += "encrypted ";
    }
    output.trim_end().to_string()
}

fn round_up_4k<T: Add<Output = T> + BitAnd<Output = T> + Not<Output = T> + From<u16>>(val: T) -> T {
    (val + T::from(0xfff)) & !T::from(0xfff)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::backend::{BackendResult, BlobReader};
    use crate::device::BlobFeatures;
    use crate::RAFS_DEFAULT_CHUNK_SIZE;
    use nix::sys::uio;
    use nydus_utils::metrics::BackendMetrics;
    use std::fs::File;
    use std::os::unix::io::AsRawFd;
    use std::path::PathBuf;

    pub(crate) struct DummyBlobReader {
        pub metrics: Arc<BackendMetrics>,
        pub file: File,
    }

    impl BlobReader for DummyBlobReader {
        fn blob_size(&self) -> BackendResult<u64> {
            Ok(0)
        }

        fn try_read(&self, buf: &mut [u8], offset: u64) -> BackendResult<usize> {
            let ret = uio::pread(self.file.as_raw_fd(), buf, offset as i64).unwrap();
            Ok(ret)
        }

        fn metrics(&self) -> &BackendMetrics {
            &self.metrics
        }
    }

    #[test]
    fn test_round_up_4k() {
        assert_eq!(round_up_4k(0), 0x0u32);
        assert_eq!(round_up_4k(1), 0x1000u32);
        assert_eq!(round_up_4k(0xfff), 0x1000u32);
        assert_eq!(round_up_4k(0x1000), 0x1000u32);
        assert_eq!(round_up_4k(0x1001), 0x2000u32);
        assert_eq!(round_up_4k(0x1fff), 0x2000u64);
    }

    #[test]
    fn test_load_meta_ci_zran_add_more_chunks() {
        let root_dir = &std::env::var("CARGO_MANIFEST_DIR").expect("$CARGO_MANIFEST_DIR");
        let path = PathBuf::from(root_dir).join("../tests/texture/zran/233c72f2b6b698c07021c4da367cfe2dff4f049efbaa885ca0ff760ea297865a");

        let features = BlobFeatures::ALIGNED
            | BlobFeatures::INLINED_FS_META
            | BlobFeatures::CHUNK_INFO_V2
            | BlobFeatures::ZRAN;
        let mut blob_info = BlobInfo::new(
            0,
            "233c72f2b6b698c07021c4da367cfe2dff4f049efbaa885ca0ff760ea297865a".to_string(),
            0x16c6000,
            9839040,
            RAFS_DEFAULT_CHUNK_SIZE as u32,
            0xa3,
            features,
        );
        blob_info.set_blob_meta_info(0, 0xa1290, 0xa1290, compress::Algorithm::None as u32);
        let meta =
            BlobCompressionContextInfo::new(&path.display().to_string(), &blob_info, None, false)
                .unwrap();
        assert_eq!(meta.state.chunk_info_array.len(), 0xa3);
        assert_eq!(meta.state.zran_info_array.len(), 0x15);
        assert_eq!(meta.state.zran_dict_table.len(), 0xa0348 - 0x15 * 40);

        let chunks = vec![BlobMetaChunk::new(0, &meta.state)];
        let chunks = meta.add_more_chunks(chunks.as_slice(), 0x30000).unwrap();
        assert_eq!(chunks.len(), 67);

        let chunks = vec![BlobMetaChunk::new(0, &meta.state)];
        let chunks = meta
            .add_more_chunks(chunks.as_slice(), RAFS_DEFAULT_CHUNK_SIZE)
            .unwrap();
        assert_eq!(chunks.len(), 67);

        let chunks = vec![BlobMetaChunk::new(66, &meta.state)];
        let chunks = meta
            .add_more_chunks(chunks.as_slice(), RAFS_DEFAULT_CHUNK_SIZE)
            .unwrap();
        assert_eq!(chunks.len(), 67);

        let chunks = vec![BlobMetaChunk::new(116, &meta.state)];
        let chunks = meta
            .add_more_chunks(chunks.as_slice(), RAFS_DEFAULT_CHUNK_SIZE)
            .unwrap();
        assert_eq!(chunks.len(), 1);

        let chunks = vec![BlobMetaChunk::new(162, &meta.state)];
        let chunks = meta
            .add_more_chunks(chunks.as_slice(), RAFS_DEFAULT_CHUNK_SIZE)
            .unwrap();
        assert_eq!(chunks.len(), 12);
    }

    #[test]
    fn test_load_meta_ci_zran_get_chunks_uncompressed() {
        let root_dir = &std::env::var("CARGO_MANIFEST_DIR").expect("$CARGO_MANIFEST_DIR");
        let path = PathBuf::from(root_dir).join("../tests/texture/zran/233c72f2b6b698c07021c4da367cfe2dff4f049efbaa885ca0ff760ea297865a");

        let features = BlobFeatures::ALIGNED
            | BlobFeatures::INLINED_FS_META
            | BlobFeatures::CHUNK_INFO_V2
            | BlobFeatures::ZRAN;
        let mut blob_info = BlobInfo::new(
            0,
            "233c72f2b6b698c07021c4da367cfe2dff4f049efbaa885ca0ff760ea297865a".to_string(),
            0x16c6000,
            9839040,
            RAFS_DEFAULT_CHUNK_SIZE as u32,
            0xa3,
            features,
        );
        blob_info.set_blob_meta_info(0, 0xa1290, 0xa1290, compress::Algorithm::None as u32);
        let meta =
            BlobCompressionContextInfo::new(&path.display().to_string(), &blob_info, None, false)
                .unwrap();
        assert_eq!(meta.state.chunk_info_array.len(), 0xa3);
        assert_eq!(meta.state.zran_info_array.len(), 0x15);
        assert_eq!(meta.state.zran_dict_table.len(), 0xa0348 - 0x15 * 40);

        let chunks = meta.get_chunks_uncompressed(0, 1, 0x30000).unwrap();
        assert_eq!(chunks.len(), 67);

        let chunks = meta
            .get_chunks_uncompressed(0, 1, RAFS_DEFAULT_CHUNK_SIZE)
            .unwrap();
        assert_eq!(chunks.len(), 67);

        let chunks = meta
            .get_chunks_uncompressed(0x112000, 0x10000, RAFS_DEFAULT_CHUNK_SIZE)
            .unwrap();
        assert_eq!(chunks.len(), 116);

        let chunks = meta
            .get_chunks_uncompressed(0xf9b000, 0x100, RAFS_DEFAULT_CHUNK_SIZE)
            .unwrap();
        assert_eq!(chunks.len(), 12);

        let chunks = meta
            .get_chunks_uncompressed(0xf9b000, 0x100, 4 * RAFS_DEFAULT_CHUNK_SIZE)
            .unwrap();
        assert_eq!(chunks.len(), 13);

        let chunks = meta
            .get_chunks_uncompressed(0x16c5000, 0x100, 4 * RAFS_DEFAULT_CHUNK_SIZE)
            .unwrap();
        assert_eq!(chunks.len(), 12);

        assert!(meta
            .get_chunks_uncompressed(0x2000000, 0x100, 4 * RAFS_DEFAULT_CHUNK_SIZE)
            .is_err());
    }

    #[test]
    fn test_load_meta_ci_zran_get_chunks_compressed() {
        let root_dir = &std::env::var("CARGO_MANIFEST_DIR").expect("$CARGO_MANIFEST_DIR");
        let path = PathBuf::from(root_dir).join("../tests/texture/zran/233c72f2b6b698c07021c4da367cfe2dff4f049efbaa885ca0ff760ea297865a");

        let features = BlobFeatures::ALIGNED
            | BlobFeatures::INLINED_FS_META
            | BlobFeatures::CHUNK_INFO_V2
            | BlobFeatures::ZRAN;
        let mut blob_info = BlobInfo::new(
            0,
            "233c72f2b6b698c07021c4da367cfe2dff4f049efbaa885ca0ff760ea297865a".to_string(),
            0x16c6000,
            9839040,
            RAFS_DEFAULT_CHUNK_SIZE as u32,
            0xa3,
            features,
        );
        blob_info.set_blob_meta_info(0, 0xa1290, 0xa1290, compress::Algorithm::None as u32);
        let meta =
            BlobCompressionContextInfo::new(&path.display().to_string(), &blob_info, None, false)
                .unwrap();
        assert_eq!(meta.state.chunk_info_array.len(), 0xa3);
        assert_eq!(meta.state.zran_info_array.len(), 0x15);
        assert_eq!(meta.state.zran_dict_table.len(), 0xa0348 - 0x15 * 40);

        let chunks = meta.get_chunks_compressed(0xb8, 1, 0x30000, false).unwrap();
        assert_eq!(chunks.len(), 67);

        let chunks = meta
            .get_chunks_compressed(0xb8, 1, RAFS_DEFAULT_CHUNK_SIZE, false)
            .unwrap();
        assert_eq!(chunks.len(), 116);

        let chunks = meta
            .get_chunks_compressed(0xb8, 1, 2 * RAFS_DEFAULT_CHUNK_SIZE, false)
            .unwrap();
        assert_eq!(chunks.len(), 120);

        let chunks = meta
            .get_chunks_compressed(0x5fd41e, 1, RAFS_DEFAULT_CHUNK_SIZE / 2, false)
            .unwrap();
        assert_eq!(chunks.len(), 3);

        let chunks = meta
            .get_chunks_compressed(0x95d55d, 0x20, RAFS_DEFAULT_CHUNK_SIZE, false)
            .unwrap();
        assert_eq!(chunks.len(), 12);

        assert!(meta
            .get_chunks_compressed(0x0, 0x1, RAFS_DEFAULT_CHUNK_SIZE, false)
            .is_err());
        assert!(meta
            .get_chunks_compressed(0x1000000, 0x1, RAFS_DEFAULT_CHUNK_SIZE, false)
            .is_err());
    }
}

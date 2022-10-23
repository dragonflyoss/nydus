// Copyright (C) 2021 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Struct to generate and access blob meta data.
//!
//! RAFS v6 filesystem includes three types data:
//! - RAFS v6 meta blob: contain filesystem meta data including super block, inode table, dirent etc.
//! - RAFS v6 data blob: contain chunked file data in compressed or uncompressed form.
//! - RAFS v6 blob meta: contain information to extra file chunk data from the data blob.
//!
//! A blob meta data is associated with each data blob, which contains information about how to
//! extract file chunks from the data blob. The blob meta data includes a data and a header,
//! and the header is actually located at the tail. The RAFS v6 blob meta data may be embedded
//! in the corresponding data blob, or packed into the RAFS meta blob. When packed in the RAFS meta
//! blob, it will have the BLOB_META_FEATURE_SEPARATE flag set.
//!
//! The blob meta data contains following information:
//! - chunk compression information table: to locate compressed/uncompressed chunks in the data blob
//! - optional ZRan context table: to support randomly access/decompress gzip file
//! - optional ZRan dictionary table: to support randomly access/decompress gzip file
//!
//! The blob meta data is laid as below:
//! |chunk compression info table|optional ZRan context table|optional ZRan dictionary table|
//!
//! RAFS v6 supports several types of data blob:
//! - RAFS v6 native data blob
//! - OCIv1 tarball (targz) for backward compatibility
//! - EStargz tarball (stargz) for backward compatibility
//!
//! For native RAFS v6 filesystems, native data blobs will be generated and laid out as below:
//! - RAFS V6 meta blob: |RAFS v6 meta data|
//! - RAFS V6 data blob file: |blob data|blob meta data|blob meta data header|
//!
//! For compatible RAFS v6 filesystems, it references the original targz/stargz blobs instead of
//! generating new native RAFS data blobs. And it's laid out as below:
//! -- RAFS v6 meta blob: |tar header|RAFS v6 meta data|tar header|blob meta data|blob meta data header|
//! -- targz/stargz (unchanged): |tar header|tar header|file data|tar header|

use std::any::Any;
use std::fs::OpenOptions;
use std::io::Result;
use std::mem::{size_of, ManuallyDrop};
use std::ops::{Add, BitAnd, Not};
use std::sync::Arc;

use nydus_utils::compress;
use nydus_utils::digest::RafsDigest;
use nydus_utils::filemap::FileMapState;

use crate::backend::BlobReader;
use crate::device::{BlobChunkInfo, BlobInfo};
use crate::utils::alloc_buf;
use crate::{RAFS_MAX_CHUNKS_PER_BLOB, RAFS_MAX_CHUNK_SIZE};

mod chunk_info_v1;
pub use chunk_info_v1::BlobChunkInfoV1Ondisk;
mod chunk_info_v2;
pub use chunk_info_v2::BlobChunkInfoV2Ondisk;
mod zran;
pub use zran::{ZranContextGenerator, ZranInflateContext};

const BLOB_METADATA_MAGIC: u32 = 0xb10bb10bu32;
const BLOB_METADATA_HEADER_SIZE: u64 = 0x1000u64;
const BLOB_METADATA_CHUNK_SIZE_MASK: u64 = 0xff_ffff;

const BLOB_METADATA_V1_MAX_SIZE: u64 = RAFS_MAX_CHUNK_SIZE * 16;
const BLOB_METADATA_V2_MAX_SIZE: u64 = RAFS_MAX_CHUNK_SIZE * 24;
//const BLOB_METADATA_V1_RESERVED_SIZE: u64 = BLOB_METADATA_HEADER_SIZE - 44;
// Add three more fields: s_ci_zran_offset/size/count
const BLOB_METADATA_V2_RESERVED_SIZE: u64 = BLOB_METADATA_HEADER_SIZE - 64;

/// File suffix for blob meta file.
pub const FILE_SUFFIX: &str = "blob.meta";
/// Uncompressed chunk data is 4K aligned.
pub const BLOB_META_FEATURE_4K_ALIGNED: u32 = 0x1;
/// Blob meta information data is stored in a separate file.
pub const BLOB_META_FEATURE_SEPARATE: u32 = 0x2;
/// Blob chunk information format v2.
pub const BLOB_META_FEATURE_CHUNK_INFO_V2: u32 = 0x4;
/// Blob compression information data include context data for zlib random access.
pub const BLOB_META_FEATURE_ZRAN: u32 = 0x8;
/// All valid blob feature bits.
pub const BLOB_META_FEATURE_MASK: u32 = 0xf;

/// On disk format for blob meta data header, containing meta information for a data blob.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct BlobMetaHeaderOndisk {
    /// Magic number to identify the blob meta data header.
    s_magic: u32,
    /// Feature flags for the data blob.
    s_features: u32,
    /// Compression algorithm to compress/uncompress chunk information array.
    s_ci_compressor: u32,
    /// Number of entries in chunk information array.
    s_ci_entries: u32,
    /// File offset to get the blob meta data.
    ///
    /// If embedded in the data blob itself, the blob meta data will be compressed.
    /// If stored into a separate file, the blob meta data will be uncompressed.
    s_ci_offset: u64,
    /// Size of compressed blob meta data.
    ///
    /// If stored into a separate file, the blob meta data will be uncompressed and
    /// s_ci_compressed_size should be equal to s_ci_uncompressed_size.
    s_ci_compressed_size: u64,
    /// Size of uncompressed blob meta data.
    s_ci_uncompressed_size: u64,
    /// File offset to get the optional ZRan context data.
    s_ci_zran_offset: u64,
    /// Size of ZRan context data, including the ZRan context information table and dictionary table.
    s_ci_zran_size: u64,
    /// Number of entries in the ZRan context information table.
    s_ci_zran_count: u32,
    s_reserved: [u8; BLOB_METADATA_V2_RESERVED_SIZE as usize],
    /// Second magic number to identify the blob meta data header.
    s_magic2: u32,
}

impl Default for BlobMetaHeaderOndisk {
    fn default() -> Self {
        BlobMetaHeaderOndisk {
            s_magic: BLOB_METADATA_MAGIC,
            s_features: 0,
            s_ci_compressor: compress::Algorithm::Lz4Block as u32,
            s_ci_entries: 0,
            s_ci_offset: 0,
            s_ci_compressed_size: 0,
            s_ci_uncompressed_size: 0,
            s_ci_zran_offset: 0,
            s_ci_zran_size: 0,
            s_ci_zran_count: 0,
            s_reserved: [0u8; BLOB_METADATA_V2_RESERVED_SIZE as usize],
            s_magic2: BLOB_METADATA_MAGIC,
        }
    }
}

impl BlobMetaHeaderOndisk {
    /// Get compression algorithm to compress chunk information array.
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

    /// Set compression algorithm to compress chunk information array.
    pub fn set_ci_compressor(&mut self, algo: compress::Algorithm) {
        self.s_ci_compressor = algo as u32;
    }

    /// Get number of entries in chunk information array.
    pub fn ci_entries(&self) -> u32 {
        self.s_ci_entries
    }

    /// Set number of entries in chunk information array.
    pub fn set_ci_entries(&mut self, entries: u32) {
        self.s_ci_entries = entries;
    }

    /// Get offset of compressed chunk information array.
    pub fn ci_compressed_offset(&self) -> u64 {
        self.s_ci_offset
    }

    /// Set offset of compressed chunk information array.
    pub fn set_ci_compressed_offset(&mut self, offset: u64) {
        self.s_ci_offset = offset;
    }

    /// Get size of compressed chunk information array.
    pub fn ci_compressed_size(&self) -> u64 {
        self.s_ci_compressed_size
    }

    /// Set size of compressed chunk information array.
    pub fn set_ci_compressed_size(&mut self, size: u64) {
        self.s_ci_compressed_size = size;
    }

    /// Get size of uncompressed chunk information array.
    pub fn ci_uncompressed_size(&self) -> u64 {
        self.s_ci_uncompressed_size
    }

    /// Set size of uncompressed chunk information array.
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

    /// Check whether the uncompressed data chunk is 4k aligned.
    pub fn is_4k_aligned(&self) -> bool {
        self.s_features & BLOB_META_FEATURE_4K_ALIGNED != 0
    }

    /// Set flag indicating whether the uncompressed data chunk is 4k aligned.
    pub fn set_4k_aligned(&mut self, aligned: bool) {
        if aligned {
            self.s_features |= BLOB_META_FEATURE_4K_ALIGNED;
        } else {
            self.s_features &= !BLOB_META_FEATURE_4K_ALIGNED;
        }
    }

    /// Set flag indicating whether to chunk information format v2 is used or not.
    pub fn set_chunk_info_v2(&mut self, enable: bool) {
        if enable {
            self.s_features |= BLOB_META_FEATURE_CHUNK_INFO_V2;
        } else {
            self.s_features &= !BLOB_META_FEATURE_CHUNK_INFO_V2;
        }
    }

    /// Set flag indicating whether the blob compression information data is stored in a separate
    /// file or embedded in the blob itserlf.
    pub fn set_ci_separate(&mut self, enable: bool) {
        if enable {
            self.s_features |= BLOB_META_FEATURE_SEPARATE;
        } else {
            self.s_features &= !BLOB_META_FEATURE_SEPARATE;
        }
    }

    /// Set flag indicating whether the blob meta contains data for ZRan or not.
    pub fn set_ci_zran(&mut self, enable: bool) {
        if enable {
            self.s_features |= BLOB_META_FEATURE_ZRAN;
        } else {
            self.s_features &= !BLOB_META_FEATURE_ZRAN;
        }
    }

    /// Get blob meta feature flags.
    pub fn meta_flags(&self) -> u32 {
        self.s_features
    }

    /// Convert the header as an `&[u8]`.
    pub fn as_bytes(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(
                self as *const BlobMetaHeaderOndisk as *const u8,
                size_of::<BlobMetaHeaderOndisk>(),
            )
        }
    }
}

/// Struct to maintain metadata information for a blob object.
///
/// Currently, the major responsibility of the `BlobMetaInfo` object is to query chunks covering
/// a specific uncompressed data range by
/// [BlobMetaInfo::get_chunks()](struct.BlobMetaInfo.html#method.get_chunks).
#[derive(Clone)]
pub struct BlobMetaInfo {
    pub(crate) state: Arc<BlobMetaState>,
}

impl BlobMetaInfo {
    /// Create a new instance of `BlobMetaInfo`.
    ///
    /// The blob manager should create and maintain the consistence of the blob metadata file.
    /// Blob manager's clients, such as virtiofsd, may open the same blob metadata file to
    /// query chunks covering a specific uncompressed data range.
    ///
    /// When `reader` contains a valid value and the metadata is not ready yet, a new metadata file
    /// will be created.
    pub fn new(
        blob_path: &str,
        blob_info: &BlobInfo,
        reader: Option<&Arc<dyn BlobReader>>,
    ) -> Result<Self> {
        assert_eq!(
            size_of::<BlobMetaHeaderOndisk>() as u64,
            BLOB_METADATA_HEADER_SIZE
        );
        assert_eq!(size_of::<BlobChunkInfoV1Ondisk>(), 16);
        assert_eq!(size_of::<BlobChunkInfoV2Ondisk>(), 24);
        assert_eq!(size_of::<ZranInflateContext>(), 40);

        let chunk_count = blob_info.chunk_count();
        if chunk_count == 0 || chunk_count > RAFS_MAX_CHUNKS_PER_BLOB {
            return Err(einval!("invalid chunk count in blob meta header"));
        }

        let info_size = blob_info.meta_ci_uncompressed_size() as usize;
        let meta_path = format!("{}.{}", blob_path, FILE_SUFFIX);
        trace!(
            "meta_path {:?} info_size {} chunk_count {}",
            meta_path,
            info_size,
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
                    "failed to open/create blob chunk_map file {:?}: {:?}",
                    meta_path, err
                ))
            })?;

        let aligned_info_size = round_up_4k(info_size);
        let expected_size = BLOB_METADATA_HEADER_SIZE as usize + aligned_info_size;
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
        let header = filemap.get_mut::<BlobMetaHeaderOndisk>(aligned_info_size as usize)?;
        if !Self::validate_header(blob_info, header)? {
            if !enable_write {
                return Err(enoent!(format!(
                    "blob metadata file '{}' header is invalid",
                    meta_path
                )));
            }

            let buffer = unsafe { std::slice::from_raw_parts_mut(base as *mut u8, expected_size) };
            buffer[info_size..].fill(0);
            Self::read_metadata(
                blob_info,
                reader.as_ref().unwrap(),
                &mut buffer[..info_size],
            )?;

            header.s_features = u32::to_le(blob_info.meta_flags());
            header.s_ci_compressor = u32::to_le(blob_info.meta_ci_compressor() as u32);
            header.s_ci_entries = u32::to_le(blob_info.chunk_count());
            header.s_ci_offset = u64::to_le(blob_info.meta_ci_offset());
            header.s_ci_compressed_size = u64::to_le(blob_info.meta_ci_compressed_size());
            header.s_ci_uncompressed_size = u64::to_le(blob_info.meta_ci_uncompressed_size());
            if blob_info.meta_flags() & BLOB_META_FEATURE_ZRAN != 0 {
                header.s_ci_zran_count = u32::to_le(blob_info.meta_ci_zran_count());
                header.s_ci_zran_offset = u64::to_le(blob_info.meta_ci_zran_offset());
                header.s_ci_zran_size = u64::to_le(blob_info.meta_ci_zran_size());
            }
            filemap.sync_data()?;

            let header = filemap.get_mut::<BlobMetaHeaderOndisk>(aligned_info_size as usize)?;
            header.s_magic = u32::to_le(BLOB_METADATA_MAGIC);
            header.s_magic2 = u32::to_le(BLOB_METADATA_MAGIC);
            assert!(Self::validate_header(blob_info, header).is_ok());
            filemap.sync_data()?;
        }

        let chunk_infos = BlobMetaChunkArray::from_file_map(&filemap, blob_info)?;
        let chunk_infos = ManuallyDrop::new(chunk_infos);
        let mut state = BlobMetaState {
            blob_index: blob_info.blob_index(),
            meta_flags: blob_info.meta_flags(),
            compressed_size: blob_info.compressed_size(),
            uncompressed_size: round_up_4k(blob_info.uncompressed_size()),
            chunk_info_array: chunk_infos,
            zran_info_array: Default::default(),
            zran_dict_table: Default::default(),
            filemap,
        };

        if blob_info.meta_flags() & BLOB_META_FEATURE_ZRAN != 0 {
            let zran_offset = blob_info.meta_ci_zran_offset() as usize;
            let zran_count = blob_info.meta_ci_zran_count() as usize;
            let zran_size = zran_count * size_of::<ZranInflateContext>();
            let ptr = state.filemap.validate_range(zran_offset, zran_size)?;
            let array = unsafe {
                Vec::from_raw_parts(
                    ptr as *mut u8 as *mut ZranInflateContext,
                    zran_count,
                    zran_count,
                )
            };
            state.zran_info_array = ManuallyDrop::new(array);

            let zran_dict_size = blob_info.meta_ci_zran_size() as usize - zran_size;
            let ptr = state
                .filemap
                .validate_range(zran_offset + zran_size, zran_dict_size)?;
            let array =
                unsafe { Vec::from_raw_parts(ptr as *mut u8, zran_dict_size, zran_dict_size) };
            state.zran_dict_table = ManuallyDrop::new(array);
        }

        Ok(BlobMetaInfo {
            state: Arc::new(state),
        })
    }

    /// Get blob chunks covering uncompressed data range [start, start + size).
    ///
    /// `size` also includes chunks alignment. It is a range on blob with chunks and alignments between them.
    /// The method returns error if any of following condition is true:
    /// - range [start, start + size) is invalid.
    /// - `start` is bigger than blob size.
    /// - some portion of the range [start, start + size) is not covered by chunks.
    /// - the blob metadata is invalid.
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

    /// Get blob chunks covering compressed data range [start, start + size).
    ///
    /// The method returns error if any of following condition is true:
    /// - range [start, start + size) is invalid.
    /// - `start` is bigger than blob size.
    /// - some portion of the range [start, start + size) is not covered by chunks.
    /// - the blob metadata is invalid.
    pub fn get_chunks_compressed(
        &self,
        start: u64,
        size: u64,
        batch_size: u64,
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
            .get_chunks_compressed(start, end, batch_end, batch_size)
    }

    /// Try to amplify the request by appending more continuous chunks.
    pub fn add_more_chunks(
        &self,
        chunks: &[Arc<dyn BlobChunkInfo>],
        max_size: u64,
    ) -> Option<Vec<Arc<dyn BlobChunkInfo>>> {
        self.state.add_more_chunks(chunks, max_size)
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

        if blob_info.meta_ci_compressor() == compress::Algorithm::None {
            let size = reader
                .read(buffer, blob_info.meta_ci_offset())
                .map_err(|e| {
                    eio!(format!(
                        "failed to read metadata from backend(compressor is None), {:?}",
                        e
                    ))
                })?;
            if size as u64 != blob_info.meta_ci_uncompressed_size() {
                return Err(eio!(
                    "failed to read blob metadata from backend(compressor is None)"
                ));
            }
        } else {
            let compressed_size = blob_info.meta_ci_compressed_size();
            let mut buf = alloc_buf(compressed_size as usize);
            let size = reader
                .read(&mut buf, blob_info.meta_ci_offset())
                .map_err(|e| eio!(format!("failed to read metadata from backend, {:?}", e)))?;
            if size as u64 != compressed_size {
                return Err(eio!("failed to read blob metadata from backend"));
            }

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
            let mut uncom_buf = vec![0u8; buffer.len()];
            compress::decompress(&buf, None, &mut uncom_buf, blob_info.meta_ci_compressor())
                .map_err(|e| {
                    error!("failed to decompress blob meta data: {}", e);
                    e
                })?;
            buffer.copy_from_slice(&uncom_buf);
        }

        Ok(())
    }

    fn validate_header(blob_info: &BlobInfo, header: &BlobMetaHeaderOndisk) -> Result<bool> {
        trace!("blob meta header magic {:x}/{:x}, entries {:x}/{:x}, features {:x}/{:x}, compressor {:x}/{:x}, ci_offset {:x}/{:x}, compressed_size {:x}/{:x}, uncompressed_size {:x}/{:x}",
                u32::from_le(header.s_magic),
                BLOB_METADATA_MAGIC,
                u32::from_le(header.s_ci_entries),
                blob_info.chunk_count(),
                u32::from_le(header.s_features),
                blob_info.meta_flags(),
                u32::from_le(header.s_ci_compressor),
                blob_info.meta_ci_compressor() as u32,
                u64::from_le(header.s_ci_offset),
                blob_info.meta_ci_offset(),
                u64::from_le(header.s_ci_compressed_size),
                blob_info.meta_ci_compressed_size(),
                u64::from_le(header.s_ci_uncompressed_size),
                blob_info.meta_ci_uncompressed_size());

        if u32::from_le(header.s_magic) != BLOB_METADATA_MAGIC
            || u32::from_le(header.s_magic2) != BLOB_METADATA_MAGIC
            || u32::from_le(header.s_ci_entries) != blob_info.chunk_count()
            || u32::from_le(header.s_features) != blob_info.meta_flags()
            || u32::from_le(header.s_ci_compressor) != blob_info.meta_ci_compressor() as u32
            || u64::from_le(header.s_ci_offset) != blob_info.meta_ci_offset()
            || u64::from_le(header.s_ci_compressed_size) != blob_info.meta_ci_compressed_size()
            || u64::from_le(header.s_ci_uncompressed_size) != blob_info.meta_ci_uncompressed_size()
        {
            return Ok(false);
        } else if blob_info.meta_flags() & BLOB_META_FEATURE_ZRAN != 0 {
            trace!(
                "blob meta header zran: count {:x}/{:x}, offset {:x}/{:x}, size {:x}/{:x}",
                u32::from_le(header.s_ci_zran_count),
                blob_info.meta_ci_zran_count(),
                u64::from_le(header.s_ci_zran_offset),
                blob_info.meta_ci_zran_offset(),
                u64::from_le(header.s_ci_zran_size),
                blob_info.meta_ci_zran_size()
            );
            if u32::from_le(header.s_ci_zran_count) != blob_info.meta_ci_zran_count()
                || u64::from_le(header.s_ci_zran_offset) != blob_info.meta_ci_zran_offset()
                || u64::from_le(header.s_ci_zran_size) != blob_info.meta_ci_zran_size()
            {
                return Ok(false);
            }
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
        const ZRAN: u32 = BLOB_META_FEATURE_CHUNK_INFO_V2 | BLOB_META_FEATURE_ZRAN;
        match blob_info.meta_flags() & ZRAN {
            ZRAN => {
                if info_size < (chunk_count as usize) * (size_of::<BlobChunkInfoV2Ondisk>()) {
                    return Err(einval!("uncompressed size in blob meta header is invalid!"));
                }
            }
            BLOB_META_FEATURE_CHUNK_INFO_V2 => {
                if info_size != (chunk_count as usize) * (size_of::<BlobChunkInfoV2Ondisk>())
                    || (aligned_info_size as u64) > BLOB_METADATA_V2_MAX_SIZE
                {
                    return Err(einval!("uncompressed size in blob meta header is invalid!"));
                }
            }
            0 => {
                if info_size != (chunk_count as usize) * (size_of::<BlobChunkInfoV1Ondisk>())
                    || (aligned_info_size as u64) > BLOB_METADATA_V1_MAX_SIZE
                {
                    return Err(einval!("uncompressed size in blob meta header is invalid!"));
                }
            }
            _ => return Err(einval!("invalid feature flags in blob meta header!")),
        }

        if blob_info.meta_flags() & BLOB_META_FEATURE_ZRAN != 0 {
            let offset = blob_info.meta_ci_zran_offset();
            if offset != (chunk_count as u64) * (size_of::<BlobChunkInfoV2Ondisk>() as u64) {
                return Err(einval!("ZRan information in blob meta header is invalid!"));
            }
            if offset + blob_info.meta_ci_zran_size() > info_size as u64 {
                return Err(einval!("ZRan information in blob meta header is invalid!"));
            }
            let zran_count = blob_info.meta_ci_zran_count() as u64;
            let size = zran_count * size_of::<ZranInflateContext>() as u64;
            if zran_count > chunk_count as u64 {
                return Err(einval!("count of ZRan context entries is too big!"));
            }
            if size > blob_info.meta_ci_zran_size() {
                return Err(einval!("ZRan information in blob meta header is invalid!"));
            }
        }

        Ok(true)
    }
}

/// Struct to maintain state and provide accessors to blob meta information.
pub struct BlobMetaState {
    pub(crate) blob_index: u32,
    pub(crate) meta_flags: u32,
    pub(crate) compressed_size: u64,
    pub(crate) uncompressed_size: u64,
    pub(crate) chunk_info_array: ManuallyDrop<BlobMetaChunkArray>,
    pub(crate) zran_info_array: ManuallyDrop<Vec<ZranInflateContext>>,
    pub(crate) zran_dict_table: ManuallyDrop<Vec<u8>>,
    filemap: FileMapState,
}

impl BlobMetaState {
    fn get_chunks_uncompressed(
        self: &Arc<BlobMetaState>,
        start: u64,
        end: u64,
        batch_end: u64,
        batch_size: u64,
    ) -> Result<Vec<Arc<dyn BlobChunkInfo>>> {
        self.chunk_info_array
            .get_chunks_uncompressed(self, start, end, batch_end, batch_size)
    }

    fn get_chunks_compressed(
        self: &Arc<BlobMetaState>,
        start: u64,
        end: u64,
        batch_end: u64,
        batch_size: u64,
    ) -> Result<Vec<Arc<dyn BlobChunkInfo>>> {
        self.chunk_info_array
            .get_chunks_compressed(self, start, end, batch_end, batch_size)
    }

    fn add_more_chunks(
        self: &Arc<BlobMetaState>,
        chunks: &[Arc<dyn BlobChunkInfo>],
        max_size: u64,
    ) -> Option<Vec<Arc<dyn BlobChunkInfo>>> {
        self.chunk_info_array
            .add_more_chunks(self, chunks, max_size)
    }
}

/// A customized array to generate chunk information array.
pub enum BlobMetaChunkArray {
    /// V1 chunk information array.
    V1(Vec<BlobChunkInfoV1Ondisk>),
    /// V2 chunk information array.
    V2(Vec<BlobChunkInfoV2Ondisk>),
}

// Methods for RAFS filesystem builder.
impl BlobMetaChunkArray {
    /// Create a `BlokMetaChunkArray` with v2 chunk information format.
    pub fn new_v1() -> Self {
        BlobMetaChunkArray::V1(Vec::new())
    }

    /// Create a `BlokMetaChunkArray` with v2 chunk information format.
    pub fn new_v2() -> Self {
        BlobMetaChunkArray::V2(Vec::new())
    }

    /// Get number of entry in the blob chunk information array.
    pub fn len(&self) -> usize {
        match self {
            BlobMetaChunkArray::V1(v) => v.len(),
            BlobMetaChunkArray::V2(v) => v.len(),
        }
    }

    /// Check whether the chunk information array is empty.
    pub fn is_empty(&self) -> bool {
        match self {
            BlobMetaChunkArray::V1(v) => v.is_empty(),
            BlobMetaChunkArray::V2(v) => v.is_empty(),
        }
    }

    /// Get the chunk information data as a u8 slice.
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

    /// Add an v1 chunk information entry.
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

    /// Add an v2 chunk information entry.
    pub fn add_v2(
        &mut self,
        compressed_offset: u64,
        compressed_size: u32,
        uncompressed_offset: u64,
        uncompressed_size: u32,
        compressed: bool,
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
                meta.set_data(data);
                v.push(meta);
            }
            BlobMetaChunkArray::V1(_v) => unimplemented!(),
        }
    }

    /// Add an v2 chunk information entry with pre-built entry.
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
        if blob_info.meta_flags() & BLOB_META_FEATURE_CHUNK_INFO_V2 != 0 {
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

    #[cfg(test)]
    fn get_chunk_index_nocheck(&self, addr: u64, compressed: bool) -> Result<usize> {
        match self {
            BlobMetaChunkArray::V1(v) => Self::_get_chunk_index_nocheck(v, addr, compressed),
            BlobMetaChunkArray::V2(v) => Self::_get_chunk_index_nocheck(v, addr, compressed),
        }
    }

    fn get_chunks_compressed(
        &self,
        state: &Arc<BlobMetaState>,
        start: u64,
        end: u64,
        batch_end: u64,
        batch_size: u64,
    ) -> Result<Vec<Arc<dyn BlobChunkInfo>>> {
        match self {
            BlobMetaChunkArray::V1(v) => {
                Self::_get_chunks_compressed(state, v, start, end, batch_end, batch_size)
            }
            BlobMetaChunkArray::V2(v) => {
                Self::_get_chunks_compressed(state, v, start, end, batch_end, batch_size)
            }
        }
    }

    fn get_chunks_uncompressed(
        &self,
        state: &Arc<BlobMetaState>,
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
        state: &Arc<BlobMetaState>,
        chunks: &[Arc<dyn BlobChunkInfo>],
        max_size: u64,
    ) -> Option<Vec<Arc<dyn BlobChunkInfo>>> {
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

    /*
    #[cfg(test)]
    fn zran_index(&self, index: usize) -> u32 {
        match self {
            BlobMetaChunkArray::V1(v) => v[index].get_zran_index(),
            BlobMetaChunkArray::V2(v) => v[index].get_zran_index(),
        }
    }

    #[cfg(test)]
    fn zran_offset(&self, index: usize) -> u32 {
        match self {
            BlobMetaChunkArray::V1(v) => v[index].get_zran_offset(),
            BlobMetaChunkArray::V2(v) => v[index].get_zran_offset(),
        }
    }
     */

    fn is_compressed(&self, index: usize) -> bool {
        match self {
            BlobMetaChunkArray::V1(v) => v[index].is_compressed(),
            BlobMetaChunkArray::V2(v) => v[index].is_compressed(),
        }
    }

    fn _get_chunk_index_nocheck<T: BlobMetaChunkInfo>(
        chunks: &[T],
        addr: u64,
        compressed: bool,
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
                start = entry.compressed_offset();
                end = entry.compressed_end();
            } else {
                start = entry.uncompressed_offset();
                end = entry.uncompressed_end();
            };

            if start > addr {
                right = mid;
            } else if end <= addr {
                left = mid + 1;
            } else {
                return Ok(mid);
            }

            size = right - left;
        }

        // if addr == self.chunks[last].compressed_offset, return einval with error msg.
        Err(einval!(format!(
            "start: {}, end: {}, addr: {}",
            start, end, addr
        )))
    }

    fn _get_chunks_uncompressed<T: BlobMetaChunkInfo>(
        state: &Arc<BlobMetaState>,
        chunk_info_array: &[T],
        start: u64,
        end: u64,
        batch_end: u64,
        batch_size: u64,
    ) -> Result<Vec<Arc<dyn BlobChunkInfo>>> {
        let mut vec = Vec::with_capacity(512);
        let mut index = Self::_get_chunk_index_nocheck(chunk_info_array, start, false)?;
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

            while index > 0 {
                let entry = Self::get_chunk_entry(state, chunk_info_array, index - 1)?;
                if !entry.is_zran() {
                    return Err(einval!(
                        "inconsistent ZRan and non-ZRan chunk information entries"
                    ));
                } else if entry.get_zran_index() != zran_index {
                    // reach the header chunk associated with the same ZRan context.
                    break;
                } else {
                    index -= 1;
                }
            }

            let mut vec = Vec::with_capacity(128);
            for entry in &chunk_info_array[index..] {
                entry.validate(state)?;
                if !entry.is_zran() {
                    return Err(einval!(
                        "inconsistent ZRan and non-ZRan chunk information entries"
                    ));
                }
                if entry.get_zran_index() != zran_last {
                    let ctx = &state.zran_info_array[entry.get_zran_index() as usize];
                    if count + ctx.out_size() as u64 > batch_size
                        && entry.uncompressed_offset() > end
                    {
                        return Ok(vec);
                    }
                    count += ctx.out_size() as u64;
                    zran_last = entry.get_zran_index();
                }
                vec.push(BlobMetaChunk::new(index, state));
            }
            return Ok(vec);
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
                } else if last_end >= end && entry.aligned_uncompressed_end() > batch_end {
                    // Avoid read amplify if next chunk is too big.
                    return Ok(vec);
                }

                vec.push(BlobMetaChunk::new(index, state));
                last_end = entry.aligned_uncompressed_end();
                if last_end >= batch_end {
                    return Ok(vec);
                }
            }

            Err(einval!(format!(
                "entry not found index {} chunk_info_array.len {}",
                index,
                chunk_info_array.len(),
            )))
        }
    }

    fn _get_chunks_compressed<T: BlobMetaChunkInfo>(
        state: &Arc<BlobMetaState>,
        chunk_info_array: &[T],
        start: u64,
        end: u64,
        batch_end: u64,
        batch_size: u64,
    ) -> Result<Vec<Arc<dyn BlobChunkInfo>>> {
        let mut vec = Vec::with_capacity(512);
        let mut index = Self::_get_chunk_index_nocheck(chunk_info_array, start, true)?;
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
                        "inconsistent ZRan and non-ZRan chunk information entries"
                    ));
                } else if entry.get_zran_index() != zran_index {
                    // reach the header chunk associated with the same ZRan context.
                    break;
                } else {
                    index -= 1;
                }
            }

            let mut vec = Vec::with_capacity(128);
            for entry in &chunk_info_array[index..] {
                entry.validate(state)?;
                if !entry.is_zran() {
                    return Err(einval!(
                        "inconsistent ZRan and non-ZRan chunk information entries"
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
            }
            return Ok(vec);
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

            Err(einval!(format!(
                "entry not found index {} chunk_info_array.len {}",
                index,
                chunk_info_array.len(),
            )))
        }
    }

    fn _add_more_chunks<T: BlobMetaChunkInfo>(
        state: &Arc<BlobMetaState>,
        chunk_info_array: &[T],
        chunks: &[Arc<dyn BlobChunkInfo>],
        max_size: u64,
    ) -> Option<Vec<Arc<dyn BlobChunkInfo>>> {
        let mut index = chunks[chunks.len() - 1].id() as usize;
        let entry = Self::get_chunk_entry(state, chunk_info_array, index).ok()?;

        // Special handling of ZRan chunks
        if entry.is_zran() {
            let zran_last = entry.get_zran_index();
            let mut index = chunks[0].id() as usize;
            let entry = Self::get_chunk_entry(state, chunk_info_array, index).ok()?;
            let zran_index = entry.get_zran_index();

            while index > 0 {
                let entry = Self::get_chunk_entry(state, chunk_info_array, index - 1).ok()?;
                if !entry.is_zran() {
                    // All chunks should be ZRan chunks.
                    return None;
                } else if entry.get_zran_index() != zran_index {
                    // reach the header chunk associated with the same ZRan context.
                    break;
                } else {
                    index -= 1;
                }
            }

            let mut vec = Vec::with_capacity(128);
            for entry in &chunk_info_array[index..] {
                if entry.validate(state).is_err() || !entry.is_zran() {
                    return None;
                } else if entry.get_zran_index() > zran_last {
                    return Some(vec);
                } else {
                    vec.push(BlobMetaChunk::new(index, state));
                }
            }
            return Some(vec);
        }

        let end = entry.compressed_end();
        if end > state.compressed_size {
            return None;
        }
        let batch_end = std::cmp::min(
            end.checked_add(max_size).unwrap_or(end),
            state.compressed_size,
        );
        if batch_end <= end {
            return None;
        }

        let mut last_end = end;
        let mut vec = chunks.to_vec();
        while index + 1 < chunk_info_array.len() {
            index += 1;
            let entry = &chunk_info_array[index];
            // Avoid read amplification if next chunk is too big.
            if entry.validate(state).is_err() || entry.compressed_end() > batch_end {
                break;
            }

            vec.push(BlobMetaChunk::new(index, state));
            last_end = entry.compressed_end();
            if last_end >= batch_end {
                break;
            }
        }

        trace!("try to extend request with {} more bytes", last_end - end);
        Some(vec)
    }

    fn get_chunk_entry<'a, T: BlobMetaChunkInfo>(
        state: &Arc<BlobMetaState>,
        chunk_info_array: &'a [T],
        index: usize,
    ) -> Result<&'a T> {
        assert!(index < chunk_info_array.len());
        let entry = &chunk_info_array[index];
        entry.validate(state)?;
        Ok(entry)
    }
}

/// A fake `BlobChunkInfo` object created from RAFS V6 blob metadata.
#[derive(Clone)]
pub struct BlobMetaChunk {
    chunk_index: usize,
    meta: Arc<BlobMetaState>,
}

impl BlobMetaChunk {
    #[allow(clippy::new_ret_no_self)]
    pub(crate) fn new(chunk_index: usize, meta: &Arc<BlobMetaState>) -> Arc<dyn BlobChunkInfo> {
        assert!(chunk_index <= RAFS_MAX_CHUNKS_PER_BLOB as usize);
        Arc::new(BlobMetaChunk {
            chunk_index,
            meta: meta.clone(),
        }) as Arc<dyn BlobChunkInfo>
    }
}

impl BlobChunkInfo for BlobMetaChunk {
    fn chunk_id(&self) -> &RafsDigest {
        panic!("BlobMetaChunk doesn't support `chunk_id()`");
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

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Trait to get blob meta chunk information.
pub trait BlobMetaChunkInfo {
    /// Get compressed offset of the chunk.
    fn compressed_offset(&self) -> u64;

    /// Set compressed offset of the chunk.
    fn set_compressed_offset(&mut self, offset: u64);

    /// Get compressed size of the chunk.
    fn compressed_size(&self) -> u32;

    /// Set compressed size of the chunk.
    fn set_compressed_size(&mut self, size: u32);

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

    /// Get uncompressed size of the chunk.
    fn uncompressed_end(&self) -> u64 {
        self.uncompressed_offset() + self.uncompressed_size() as u64
    }

    /// Get 4k aligned uncompressed size of the chunk.
    fn aligned_uncompressed_end(&self) -> u64 {
        round_up_4k(self.uncompressed_end())
    }

    /// Check whether the blob chunk is compressed or not.
    ///
    /// Assume the image builder guarantee that compress_size < uncompress_size if the chunk is
    /// compressed.
    fn is_compressed(&self) -> bool;

    /// Check whether this chunk has assoicated Zran data.
    fn is_zran(&self) -> bool;

    /// Get the index of the ZRan context associated with this chunk.
    fn get_zran_index(&self) -> u32;

    /// Get the offset to get decompressed data from the associated ZRan context.
    fn get_zran_offset(&self) -> u32;

    /// Get misc data associated with the entry. V2 only, V1 just returns zero.
    fn get_data(&self) -> u64;

    /// Check whether the chunk info is valid or not.
    fn validate(&self, state: &BlobMetaState) -> Result<()>;
}

/// Generate description string for blob meta features.
pub fn format_blob_meta_features(features: u32) -> String {
    let mut output = String::new();
    if features & BLOB_META_FEATURE_4K_ALIGNED != 0 {
        output += "4K-align ";
    }
    if features & BLOB_META_FEATURE_SEPARATE != 0 {
        output += "separate ";
    }
    if features & BLOB_META_FEATURE_CHUNK_INFO_V2 != 0 {
        output += "chunk-v2 ";
    }
    if features & BLOB_META_FEATURE_ZRAN != 0 {
        output += "zran ";
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

        let mut blob_info = BlobInfo::new(
            0,
            "233c72f2b6b698c07021c4da367cfe2dff4f049efbaa885ca0ff760ea297865a".to_string(),
            0x16c6000,
            9839040,
            RAFS_DEFAULT_CHUNK_SIZE as u32,
            0xa3,
            BlobFeatures::empty(),
        );
        let features = BLOB_META_FEATURE_4K_ALIGNED
            | BLOB_META_FEATURE_SEPARATE
            | BLOB_META_FEATURE_CHUNK_INFO_V2
            | BLOB_META_FEATURE_ZRAN;
        blob_info.set_blob_meta_info(
            features,
            0,
            0xa1290,
            0xa1290,
            compress::Algorithm::None as u32,
        );
        blob_info.set_blob_meta_zran_info(0x15, 0xf48, 0xa0348);
        let meta = BlobMetaInfo::new(&path.display().to_string(), &blob_info, None).unwrap();
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

        let mut blob_info = BlobInfo::new(
            0,
            "233c72f2b6b698c07021c4da367cfe2dff4f049efbaa885ca0ff760ea297865a".to_string(),
            0x16c6000,
            9839040,
            RAFS_DEFAULT_CHUNK_SIZE as u32,
            0xa3,
            BlobFeatures::empty(),
        );
        let features = BLOB_META_FEATURE_4K_ALIGNED
            | BLOB_META_FEATURE_SEPARATE
            | BLOB_META_FEATURE_CHUNK_INFO_V2
            | BLOB_META_FEATURE_ZRAN;
        blob_info.set_blob_meta_info(
            features,
            0,
            0xa1290,
            0xa1290,
            compress::Algorithm::None as u32,
        );
        blob_info.set_blob_meta_zran_info(0x15, 0xf48, 0xa0348);
        let meta = BlobMetaInfo::new(&path.display().to_string(), &blob_info, None).unwrap();
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

        let mut blob_info = BlobInfo::new(
            0,
            "233c72f2b6b698c07021c4da367cfe2dff4f049efbaa885ca0ff760ea297865a".to_string(),
            0x16c6000,
            9839040,
            RAFS_DEFAULT_CHUNK_SIZE as u32,
            0xa3,
            BlobFeatures::empty(),
        );
        let features = BLOB_META_FEATURE_4K_ALIGNED
            | BLOB_META_FEATURE_SEPARATE
            | BLOB_META_FEATURE_CHUNK_INFO_V2
            | BLOB_META_FEATURE_ZRAN;
        blob_info.set_blob_meta_info(
            features,
            0,
            0xa1290,
            0xa1290,
            compress::Algorithm::None as u32,
        );
        blob_info.set_blob_meta_zran_info(0x15, 0xf48, 0xa0348);
        let meta = BlobMetaInfo::new(&path.display().to_string(), &blob_info, None).unwrap();
        assert_eq!(meta.state.chunk_info_array.len(), 0xa3);
        assert_eq!(meta.state.zran_info_array.len(), 0x15);
        assert_eq!(meta.state.zran_dict_table.len(), 0xa0348 - 0x15 * 40);

        let chunks = meta.get_chunks_compressed(0xb8, 1, 0x30000).unwrap();
        assert_eq!(chunks.len(), 67);

        let chunks = meta
            .get_chunks_compressed(0xb8, 1, RAFS_DEFAULT_CHUNK_SIZE)
            .unwrap();
        assert_eq!(chunks.len(), 116);

        let chunks = meta
            .get_chunks_compressed(0xb8, 1, 2 * RAFS_DEFAULT_CHUNK_SIZE)
            .unwrap();
        assert_eq!(chunks.len(), 120);

        let chunks = meta
            .get_chunks_compressed(0x5fd41e, 1, RAFS_DEFAULT_CHUNK_SIZE / 2)
            .unwrap();
        assert_eq!(chunks.len(), 3);

        let chunks = meta
            .get_chunks_compressed(0x95d55d, 0x20, RAFS_DEFAULT_CHUNK_SIZE)
            .unwrap();
        assert_eq!(chunks.len(), 12);

        assert!(meta
            .get_chunks_compressed(0x0, 0x1, RAFS_DEFAULT_CHUNK_SIZE)
            .is_err());
        assert!(meta
            .get_chunks_compressed(0x1000000, 0x1, RAFS_DEFAULT_CHUNK_SIZE)
            .is_err());
    }
}

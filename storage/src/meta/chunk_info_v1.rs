// Copyright (C) 2021-2022 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use crate::meta::{BlobCompressionContext, BlobMetaChunkInfo, BLOB_CCT_CHUNK_SIZE_MASK};

const BLOB_CC_V1_CHUNK_COMP_OFFSET_MASK: u64 = 0xff_ffff_ffff;
const BLOB_CC_V1_CHUNK_UNCOMP_OFFSET_MASK: u64 = 0xfff_ffff_f000;
const BLOB_CC_V1_CHUNK_SIZE_LOW_MASK: u64 = 0x0f_ffff;
const BLOB_CC_V1_CHUNK_SIZE_HIGH_MASK: u64 = 0xf0_0000;
const BLOB_CC_V1_CHUNK_SIZE_LOW_SHIFT: u64 = 44;
const BLOB_CC_V1_CHUNK_SIZE_HIGH_COMP_SHIFT: u64 = 20;
const BLOB_CC_V1_CHUNK_SIZE_HIGH_UNCOMP_SHIFT: u64 = 12;

/// Chunk compression information on disk format V1.
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct BlobChunkInfoV1Ondisk {
    // 20bits: size (low), 32bits: offset, 4bits: size (high), 8bits reserved
    pub(crate) uncomp_info: u64,
    // 20bits: size (low), 4bits: size (high), offset: 40bits
    pub(crate) comp_info: u64,
}

impl BlobMetaChunkInfo for BlobChunkInfoV1Ondisk {
    fn compressed_offset(&self) -> u64 {
        u64::from_le(self.comp_info) & BLOB_CC_V1_CHUNK_COMP_OFFSET_MASK
    }

    fn set_compressed_offset(&mut self, offset: u64) {
        assert_eq!(offset & !BLOB_CC_V1_CHUNK_COMP_OFFSET_MASK, 0);
        self.comp_info &= u64::to_le(!BLOB_CC_V1_CHUNK_COMP_OFFSET_MASK);
        self.comp_info |= u64::to_le(offset & BLOB_CC_V1_CHUNK_COMP_OFFSET_MASK);
    }

    fn compressed_size(&self) -> u32 {
        let bit20 = u64::from_le(self.comp_info) >> BLOB_CC_V1_CHUNK_SIZE_LOW_SHIFT;
        let bit4 =
            (u64::from_le(self.comp_info) & 0xf0000000000) >> BLOB_CC_V1_CHUNK_SIZE_HIGH_COMP_SHIFT;
        (bit4 | bit20) as u32 + 1
    }

    fn set_compressed_size(&mut self, size: u32) {
        let size = size as u64;
        assert!(size > 0 && size <= BLOB_CCT_CHUNK_SIZE_MASK + 1);

        let size_low =
            ((size - 1) & BLOB_CC_V1_CHUNK_SIZE_LOW_MASK) << BLOB_CC_V1_CHUNK_SIZE_LOW_SHIFT;
        let size_high =
            ((size - 1) & BLOB_CC_V1_CHUNK_SIZE_HIGH_MASK) << BLOB_CC_V1_CHUNK_SIZE_HIGH_COMP_SHIFT;
        let offset = u64::from_le(self.comp_info) & BLOB_CC_V1_CHUNK_COMP_OFFSET_MASK;

        self.comp_info = u64::to_le(size_low | size_high | offset);
    }

    fn uncompressed_offset(&self) -> u64 {
        u64::from_le(self.uncomp_info) & BLOB_CC_V1_CHUNK_UNCOMP_OFFSET_MASK
    }

    fn set_uncompressed_offset(&mut self, offset: u64) {
        assert_eq!(offset & !BLOB_CC_V1_CHUNK_UNCOMP_OFFSET_MASK, 0);
        self.uncomp_info &= u64::to_le(!BLOB_CC_V1_CHUNK_UNCOMP_OFFSET_MASK);
        self.uncomp_info |= u64::to_le(offset & BLOB_CC_V1_CHUNK_UNCOMP_OFFSET_MASK);
    }

    fn uncompressed_size(&self) -> u32 {
        let size_high =
            (u64::from_le(self.uncomp_info) & 0xf00) << BLOB_CC_V1_CHUNK_SIZE_HIGH_UNCOMP_SHIFT;
        let size_low = u64::from_le(self.uncomp_info) >> BLOB_CC_V1_CHUNK_SIZE_LOW_SHIFT;
        (size_high | size_low) as u32 + 1
    }

    fn set_uncompressed_size(&mut self, size: u32) {
        let size = size as u64;
        assert!(size != 0 && size <= BLOB_CCT_CHUNK_SIZE_MASK + 1);

        let size_low =
            ((size - 1) & BLOB_CC_V1_CHUNK_SIZE_LOW_MASK) << BLOB_CC_V1_CHUNK_SIZE_LOW_SHIFT;
        let size_high = ((size - 1) & BLOB_CC_V1_CHUNK_SIZE_HIGH_MASK)
            >> BLOB_CC_V1_CHUNK_SIZE_HIGH_UNCOMP_SHIFT;
        let offset = u64::from_le(self.uncomp_info) & BLOB_CC_V1_CHUNK_UNCOMP_OFFSET_MASK;

        self.uncomp_info = u64::to_le(size_low | offset | size_high);
    }

    fn is_encrypted(&self) -> bool {
        false
    }

    fn is_compressed(&self) -> bool {
        self.compressed_size() != self.uncompressed_size()
    }

    fn is_zran(&self) -> bool {
        false
    }

    fn is_batch(&self) -> bool {
        false
    }

    fn get_zran_index(&self) -> u32 {
        unimplemented!()
    }

    fn get_zran_offset(&self) -> u32 {
        unimplemented!()
    }

    fn get_batch_index(&self) -> u32 {
        unimplemented!()
    }

    fn get_uncompressed_offset_in_batch_buf(&self) -> u32 {
        unimplemented!()
    }

    fn get_data(&self) -> u64 {
        0
    }

    fn validate(&self, state: &BlobCompressionContext) -> std::io::Result<()> {
        if self.compressed_end() > state.compressed_size
            || self.uncompressed_end() > state.uncompressed_size
            || self.uncompressed_size() == 0
            || (!self.is_compressed() && self.uncompressed_size() != self.compressed_size())
        {
            return Err(einval!(format!(
                "invalid chunk, blob: index {}/c_end 0x{:}/d_end 0x{:x}, chunk: c_end 0x{:x}/d_end 0x{:x}/compressed {}",
                state.blob_index,
                state.compressed_size,
                state.uncompressed_size,
                self.compressed_end(),
                self.uncompressed_end(),
                self.is_compressed(),
            )));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::mem::ManuallyDrop;
    use std::sync::Arc;

    use nydus_utils::compress;
    use nydus_utils::metrics::BackendMetrics;
    use vmm_sys_util::tempfile::TempFile;

    use super::*;
    use crate::backend::BlobReader;
    use crate::device::{BlobFeatures, BlobInfo};
    use crate::meta::tests::DummyBlobReader;
    use crate::meta::{
        round_up_4k, BlobCompressionContext, BlobCompressionContextHeader,
        BlobCompressionContextInfo, BlobMetaChunkArray,
    };
    use crate::utils::alloc_buf;
    use crate::RAFS_MAX_CHUNK_SIZE;

    #[test]
    fn test_new_chunk_on_disk() {
        let mut chunk = BlobChunkInfoV1Ondisk::default();

        assert_eq!(chunk.compressed_offset(), 0);
        assert_eq!(chunk.compressed_size(), 1);
        assert_eq!(chunk.compressed_end(), 1);
        assert_eq!(chunk.uncompressed_offset(), 0);
        assert_eq!(chunk.uncompressed_size(), 1);
        assert_eq!(chunk.aligned_uncompressed_end(), 0x1000);

        chunk.set_compressed_offset(0x1000);
        chunk.set_compressed_size(0x100);
        assert_eq!(chunk.compressed_offset(), 0x1000);
        assert_eq!(chunk.compressed_size(), 0x100);

        chunk.set_uncompressed_offset(0x1000);
        chunk.set_uncompressed_size(0x100);
        assert_eq!(chunk.uncompressed_offset(), 0x1000);
        assert_eq!(chunk.uncompressed_size(), 0x100);

        chunk.set_compressed_offset(0xffffffffff);
        chunk.set_compressed_size(0x1000000);
        assert_eq!(chunk.compressed_offset(), 0xffffffffff);
        assert_eq!(chunk.compressed_size(), 0x1000000);

        chunk.set_uncompressed_offset(0xffffffff000);
        chunk.set_uncompressed_size(0x1000000);
        assert_eq!(chunk.uncompressed_offset(), 0xffffffff000);
        assert_eq!(chunk.uncompressed_size(), 0x1000000);

        // For testing old format compatibility.
        let chunk = BlobChunkInfoV1Ondisk {
            uncomp_info: u64::to_le(0xffff_ffff_f100_0000),
            comp_info: u64::to_le(0xffff_f0ff_ffff_ffff),
        };
        assert_eq!(chunk.uncompressed_size(), 0x000f_ffff + 1);
        assert_eq!(chunk.uncompressed_offset(), 0xffff_1000 * 0x1000);
        assert_eq!(chunk.compressed_size(), 0x000f_ffff + 1);
        assert_eq!(chunk.compressed_offset(), 0x00ff_ffff_ffff);
    }

    #[test]
    fn test_get_chunk_index_with_hole() {
        let state = BlobCompressionContext {
            chunk_info_array: ManuallyDrop::new(BlobMetaChunkArray::V1(vec![
                BlobChunkInfoV1Ondisk {
                    uncomp_info: u64::to_le(0x01ff_f000_0000_0000),
                    comp_info: u64::to_le(0x00ff_f000_0000_0000),
                },
                BlobChunkInfoV1Ondisk {
                    uncomp_info: u64::to_le(0x01ff_f000_0010_0000),
                    comp_info: u64::to_le(0x00ff_f000_0010_0000),
                },
            ])),
            ..Default::default()
        };

        assert_eq!(
            state
                .chunk_info_array
                .get_chunk_index_nocheck(&state, 0, false)
                .unwrap(),
            0
        );
        assert_eq!(
            state
                .chunk_info_array
                .get_chunk_index_nocheck(&state, 0x1fff, false)
                .unwrap(),
            0
        );
        assert_eq!(
            state
                .chunk_info_array
                .get_chunk_index_nocheck(&state, 0x100000, false)
                .unwrap(),
            1
        );
        assert_eq!(
            state
                .chunk_info_array
                .get_chunk_index_nocheck(&state, 0x101fff, false)
                .unwrap(),
            1
        );
        state
            .chunk_info_array
            .get_chunk_index_nocheck(&state, 0x2000, false)
            .unwrap_err();
        state
            .chunk_info_array
            .get_chunk_index_nocheck(&state, 0xfffff, false)
            .unwrap_err();
        state
            .chunk_info_array
            .get_chunk_index_nocheck(&state, 0x102000, false)
            .unwrap_err();
    }

    #[test]
    fn test_get_chunks() {
        let state = BlobCompressionContext {
            blob_index: 1,
            blob_features: 0,
            compressed_size: 0x6001,
            uncompressed_size: 0x102001,
            chunk_info_array: ManuallyDrop::new(BlobMetaChunkArray::V1(vec![
                BlobChunkInfoV1Ondisk {
                    uncomp_info: u64::to_le(0x0100_0000_0000_0000),
                    comp_info: u64::to_le(0x00ff_f000_0000_0000),
                },
                BlobChunkInfoV1Ondisk {
                    uncomp_info: u64::to_le(0x01ff_f000_0000_2000),
                    comp_info: u64::to_le(0x01ff_f000_0000_1000),
                },
                BlobChunkInfoV1Ondisk {
                    uncomp_info: u64::to_le(0x01ff_f000_0000_4000),
                    comp_info: u64::to_le(0x00ff_f000_0000_3000),
                },
                BlobChunkInfoV1Ondisk {
                    uncomp_info: u64::to_le(0x01ff_f000_0010_0000),
                    comp_info: u64::to_le(0x00ff_f000_0000_4000),
                },
                BlobChunkInfoV1Ondisk {
                    uncomp_info: u64::to_le(0x01ff_f000_0010_2000),
                    comp_info: u64::to_le(0x00ff_f000_0000_5000),
                },
            ])),
            ..Default::default()
        };
        let info = BlobCompressionContextInfo {
            state: Arc::new(state),
        };

        let vec = info.get_chunks_uncompressed(0x0, 0x1001, 0).unwrap();
        assert_eq!(vec.len(), 1);
        assert_eq!(vec[0].blob_index(), 1);
        assert_eq!(vec[0].id(), 0);
        assert_eq!(vec[0].compressed_offset(), 0);
        assert_eq!(vec[0].compressed_size(), 0x1000);
        assert_eq!(vec[0].uncompressed_offset(), 0);
        assert_eq!(vec[0].uncompressed_size(), 0x1001);
        assert!(vec[0].is_compressed());

        let vec = info.get_chunks_uncompressed(0x0, 0x4000, 0).unwrap();
        assert_eq!(vec.len(), 2);
        assert_eq!(vec[1].blob_index(), 1);
        assert_eq!(vec[1].id(), 1);
        assert_eq!(vec[1].compressed_offset(), 0x1000);
        assert_eq!(vec[1].compressed_size(), 0x2000);
        assert_eq!(vec[1].uncompressed_offset(), 0x2000);
        assert_eq!(vec[1].uncompressed_size(), 0x2000);
        assert!(!vec[1].is_compressed());

        let vec = info.get_chunks_uncompressed(0x0, 0x4001, 0).unwrap();
        assert_eq!(vec.len(), 3);

        let vec = info.get_chunks_uncompressed(0x100000, 0x2000, 0).unwrap();
        assert_eq!(vec.len(), 1);

        assert!(info.get_chunks_uncompressed(0x0, 0x6001, 0).is_err());
        assert!(info.get_chunks_uncompressed(0x0, 0xfffff, 0).is_err());
        assert!(info.get_chunks_uncompressed(0x0, 0x100000, 0).is_err());
        assert!(info.get_chunks_uncompressed(0x0, 0x104000, 0).is_err());
        assert!(info.get_chunks_uncompressed(0x0, 0x104001, 0).is_err());
        assert!(info.get_chunks_uncompressed(0x100000, 0x2001, 0).is_err());
        assert!(info.get_chunks_uncompressed(0x100000, 0x4000, 0).is_err());
        assert!(info.get_chunks_uncompressed(0x100000, 0x4001, 0).is_err());
        assert!(info
            .get_chunks_uncompressed(0x102000, 0xffff_ffff_ffff_ffff, 0)
            .is_err());
        assert!(info.get_chunks_uncompressed(0x104000, 0x1, 0).is_err());
    }

    #[test]
    fn test_read_metadata_compressor_none() {
        let temp = TempFile::new().unwrap();
        let mut w = OpenOptions::new()
            .read(true)
            .write(true)
            .open(temp.as_path())
            .unwrap();
        let r = OpenOptions::new()
            .read(true)
            .write(false)
            .open(temp.as_path())
            .unwrap();

        let chunks = vec![
            BlobChunkInfoV1Ondisk {
                uncomp_info: 0x01ff_f000_0000_0000,
                comp_info: 0x00ff_f000_0000_0000,
            },
            BlobChunkInfoV1Ondisk {
                uncomp_info: 0x01ff_f000_0010_0000,
                comp_info: 0x00ff_f000_0010_0000,
            },
        ];

        let data = unsafe {
            std::slice::from_raw_parts(
                chunks.as_ptr() as *const u8,
                chunks.len() * std::mem::size_of::<BlobChunkInfoV1Ondisk>(),
            )
        };
        let uncompressed_size = data.len();

        let pos = 0;
        w.write_all(data).unwrap();
        let header = BlobCompressionContextHeader::default();
        w.write_all(header.as_bytes()).unwrap();

        let mut blob_info = BlobInfo::new(
            0,
            "dummy".to_string(),
            0,
            0,
            RAFS_MAX_CHUNK_SIZE as u32,
            0,
            BlobFeatures::default(),
        );
        blob_info.set_blob_meta_info(
            pos,
            data.len() as u64,
            data.len() as u64,
            compress::Algorithm::None as u32,
        );

        let mut buffer = alloc_buf(
            round_up_4k(uncompressed_size) + std::mem::size_of::<BlobCompressionContextHeader>(),
        );
        let reader: Arc<dyn BlobReader> = Arc::new(DummyBlobReader {
            metrics: BackendMetrics::new("dummy", "localfs"),
            file: r,
        });
        BlobCompressionContextInfo::read_metadata(&blob_info, &reader, &mut buffer).unwrap();

        assert_eq!(&buffer[0..data.len()], data);
    }

    #[test]
    fn test_read_metadata_compressor_lz4() {
        let temp = TempFile::new().unwrap();
        let mut w = OpenOptions::new()
            .read(true)
            .write(true)
            .open(temp.as_path())
            .unwrap();
        let r = OpenOptions::new()
            .read(true)
            .write(false)
            .open(temp.as_path())
            .unwrap();

        let chunks = vec![
            BlobChunkInfoV1Ondisk {
                uncomp_info: 0x01ff_f000_0000_0000,
                comp_info: 0x00ff_f000_0000_0000,
            },
            BlobChunkInfoV1Ondisk {
                uncomp_info: 0x01ff_f000_0010_0000,
                comp_info: 0x00ff_f000_0010_0000,
            },
        ];

        let data = unsafe {
            std::slice::from_raw_parts(
                chunks.as_ptr() as *const u8,
                chunks.len() * std::mem::size_of::<BlobChunkInfoV1Ondisk>(),
            )
        };

        let (buf, compressed) = compress::compress(data, compress::Algorithm::Lz4Block).unwrap();
        assert!(compressed);

        let pos = 0;
        w.write_all(&buf).unwrap();
        let header = BlobCompressionContextHeader::default();
        w.write_all(header.as_bytes()).unwrap();

        let compressed_size = buf.len();
        let uncompressed_size = data.len();
        let mut blob_info = BlobInfo::new(
            0,
            "dummy".to_string(),
            0,
            0,
            RAFS_MAX_CHUNK_SIZE as u32,
            0,
            BlobFeatures::default(),
        );
        blob_info.set_blob_meta_info(
            pos,
            compressed_size as u64,
            uncompressed_size as u64,
            compress::Algorithm::Lz4Block as u32,
        );

        let mut buffer = alloc_buf(
            round_up_4k(uncompressed_size) + std::mem::size_of::<BlobCompressionContextHeader>(),
        );
        let reader: Arc<dyn BlobReader> = Arc::new(DummyBlobReader {
            metrics: BackendMetrics::new("dummy", "localfs"),
            file: r,
        });
        BlobCompressionContextInfo::read_metadata(&blob_info, &reader, &mut buffer).unwrap();

        assert_eq!(&buffer[0..uncompressed_size], data);
    }
}

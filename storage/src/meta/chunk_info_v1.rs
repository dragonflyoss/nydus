// Copyright (C) 2021-2022 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use crate::meta::{BlobMetaChunkInfo, BLOB_METADATA_CHUNK_SIZE_MASK};

const BLOB_METADATA_V1_CHUNK_COMP_OFFSET_MASK: u64 = 0xff_ffff_ffff;
const BLOB_METADATA_V1_CHUNK_UNCOMP_OFFSET_MASK: u64 = 0xfff_ffff_f000;
const BLOB_METADATA_V1_CHUNK_SIZE_LOW_MASK: u64 = 0x0f_ffff;
const BLOB_METADATA_V1_CHUNK_SIZE_HIGH_MASK: u64 = 0xf0_0000;
const BLOB_METADATA_V1_CHUNK_SIZE_LOW_SHIFT: u64 = 44;
const BLOB_METADATA_V1_CHUNK_SIZE_HIGH_COMP_SHIFT: u64 = 20;
const BLOB_METADATA_V1_CHUNK_SIZE_HIGH_UNCOMP_SHIFT: u64 = 12;

/// Blob chunk compression information on disk format V1.
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
        self.comp_info & BLOB_METADATA_V1_CHUNK_COMP_OFFSET_MASK
    }

    fn set_compressed_offset(&mut self, offset: u64) {
        assert!(offset & !BLOB_METADATA_V1_CHUNK_COMP_OFFSET_MASK == 0);
        self.comp_info &= !BLOB_METADATA_V1_CHUNK_COMP_OFFSET_MASK;
        self.comp_info |= offset & BLOB_METADATA_V1_CHUNK_COMP_OFFSET_MASK;
    }

    fn compressed_size(&self) -> u32 {
        let bit20 = self.comp_info >> BLOB_METADATA_V1_CHUNK_SIZE_LOW_SHIFT;
        let bit4 = (self.comp_info & 0xf0000000000) >> BLOB_METADATA_V1_CHUNK_SIZE_HIGH_COMP_SHIFT;
        (bit4 | bit20) as u32 + 1
    }

    fn set_compressed_size(&mut self, size: u32) {
        let size = size as u64;
        assert!(size > 0 && size <= BLOB_METADATA_CHUNK_SIZE_MASK + 1);

        let size_low = ((size - 1) & BLOB_METADATA_V1_CHUNK_SIZE_LOW_MASK)
            << BLOB_METADATA_V1_CHUNK_SIZE_LOW_SHIFT;
        let size_high = ((size - 1) & BLOB_METADATA_V1_CHUNK_SIZE_HIGH_MASK)
            << BLOB_METADATA_V1_CHUNK_SIZE_HIGH_COMP_SHIFT;
        let offset = self.comp_info & BLOB_METADATA_V1_CHUNK_COMP_OFFSET_MASK;

        self.comp_info = size_low | size_high | offset;
    }

    fn uncompressed_offset(&self) -> u64 {
        self.uncomp_info & BLOB_METADATA_V1_CHUNK_UNCOMP_OFFSET_MASK
    }

    fn set_uncompressed_offset(&mut self, offset: u64) {
        assert!(offset & !BLOB_METADATA_V1_CHUNK_UNCOMP_OFFSET_MASK == 0);
        self.uncomp_info &= !BLOB_METADATA_V1_CHUNK_UNCOMP_OFFSET_MASK;
        self.uncomp_info |= offset & BLOB_METADATA_V1_CHUNK_UNCOMP_OFFSET_MASK;
    }

    fn uncompressed_size(&self) -> u32 {
        let size_high = (self.uncomp_info & 0xf00) << BLOB_METADATA_V1_CHUNK_SIZE_HIGH_UNCOMP_SHIFT;
        let size_low = self.uncomp_info >> BLOB_METADATA_V1_CHUNK_SIZE_LOW_SHIFT;
        (size_high | size_low) as u32 + 1
    }

    fn set_uncompressed_size(&mut self, size: u32) {
        let size = size as u64;
        assert!(size != 0 && size <= BLOB_METADATA_CHUNK_SIZE_MASK + 1);

        let size_low = ((size - 1) & BLOB_METADATA_V1_CHUNK_SIZE_LOW_MASK)
            << BLOB_METADATA_V1_CHUNK_SIZE_LOW_SHIFT;
        let size_high = ((size - 1) & BLOB_METADATA_V1_CHUNK_SIZE_HIGH_MASK)
            >> BLOB_METADATA_V1_CHUNK_SIZE_HIGH_UNCOMP_SHIFT;
        let offset = self.uncomp_info & BLOB_METADATA_V1_CHUNK_UNCOMP_OFFSET_MASK;

        self.uncomp_info = size_low | offset | size_high;
    }

    fn is_compressed(&self) -> bool {
        self.compressed_size() != self.uncompressed_size()
    }

    fn get_data(&self) -> u64 {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::meta::{BlobMetaChunkArray, BlobMetaInfo, BlobMetaState};
    use nydus_utils::filemap::FileMapState;
    use std::mem::ManuallyDrop;
    use std::sync::Arc;

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
            uncomp_info: 0xffff_ffff_f100_0000,
            comp_info: 0xffff_f0ff_ffff_ffff,
        };
        assert_eq!(chunk.uncompressed_size(), 0x000f_ffff + 1);
        assert_eq!(chunk.uncompressed_offset(), 0xffff_1000 * 0x1000);
        assert_eq!(chunk.compressed_size(), 0x000f_ffff + 1);
        assert_eq!(chunk.compressed_offset(), 0x00ff_ffff_ffff);
    }

    #[test]
    fn test_get_chunk_index_with_hole() {
        let state = BlobMetaState {
            blob_index: 0,
            compressed_size: 0,
            uncompressed_size: 0,
            chunk_info_array: ManuallyDrop::new(BlobMetaChunkArray::V1(vec![
                BlobChunkInfoV1Ondisk {
                    uncomp_info: 0x01ff_f000_0000_0000,
                    comp_info: 0x00ff_f000_0000_0000,
                },
                BlobChunkInfoV1Ondisk {
                    uncomp_info: 0x01ff_f000_0010_0000,
                    comp_info: 0x00ff_f000_0010_0000,
                },
            ])),
            _filemap: FileMapState::default(),
        };

        assert_eq!(
            state
                .chunk_info_array
                .get_chunk_index_nocheck(0, false)
                .unwrap(),
            0
        );
        assert_eq!(
            state
                .chunk_info_array
                .get_chunk_index_nocheck(0x1fff, false)
                .unwrap(),
            0
        );
        assert_eq!(
            state
                .chunk_info_array
                .get_chunk_index_nocheck(0x100000, false)
                .unwrap(),
            1
        );
        assert_eq!(
            state
                .chunk_info_array
                .get_chunk_index_nocheck(0x101fff, false)
                .unwrap(),
            1
        );
        state
            .chunk_info_array
            .get_chunk_index_nocheck(0x2000, false)
            .unwrap_err();
        state
            .chunk_info_array
            .get_chunk_index_nocheck(0xfffff, false)
            .unwrap_err();
        state
            .chunk_info_array
            .get_chunk_index_nocheck(0x102000, false)
            .unwrap_err();
    }

    #[test]
    fn test_get_chunks() {
        let state = BlobMetaState {
            blob_index: 1,
            compressed_size: 0x6001,
            uncompressed_size: 0x102001,
            chunk_info_array: ManuallyDrop::new(BlobMetaChunkArray::V1(vec![
                BlobChunkInfoV1Ondisk {
                    uncomp_info: 0x0100_0000_0000_0000,
                    comp_info: 0x00ff_f000_0000_0000,
                },
                BlobChunkInfoV1Ondisk {
                    uncomp_info: 0x01ff_f000_0000_2000,
                    comp_info: 0x01ff_f000_0000_1000,
                },
                BlobChunkInfoV1Ondisk {
                    uncomp_info: 0x01ff_f000_0000_4000,
                    comp_info: 0x00ff_f000_0000_3000,
                },
                BlobChunkInfoV1Ondisk {
                    uncomp_info: 0x01ff_f000_0010_0000,
                    comp_info: 0x00ff_f000_0000_4000,
                },
                BlobChunkInfoV1Ondisk {
                    uncomp_info: 0x01ff_f000_0010_2000,
                    comp_info: 0x00ff_f000_0000_5000,
                },
            ])),
            _filemap: FileMapState::default(),
        };
        let info = BlobMetaInfo {
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
}

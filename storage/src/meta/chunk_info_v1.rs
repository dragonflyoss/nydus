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

/// Blob chunk compression information on disk format.
#[repr(C)]
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
}

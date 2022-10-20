// Copyright (C) 2021-2022 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::fmt::{Display, Formatter};

use crate::meta::{BlobMetaChunkInfo, BLOB_METADATA_CHUNK_SIZE_MASK};

const CHUNK_V2_COMP_OFFSET_MASK: u64 = 0xff_ffff_ffff;
const CHUNK_V2_COMP_SIZE_SHIFT: u64 = 40;
const CHUNK_V2_UNCOMP_OFFSET_MASK: u64 = 0xffff_ffff;
const CHUNK_V2_UNCOMP_OFFSET_SHIFT: u64 = 12;
const CHUNK_V2_UNCOMP_SIZE_SHIFT: u64 = 32;
//const CHUNK_V2_FLAG_MASK: u64 = 0xff00_0000_0000_0000;
const CHUNK_V2_FLAG_COMPRESSED: u64 = 0x1 << 56;

/// Blob chunk compression information on disk format V2.
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct BlobChunkInfoV2Ondisk {
    // 32bits: offset, 24bits: size, 8bits: flags
    pub(crate) uncomp_info: u64,
    // offset: 40bits, 24bits: size
    pub(crate) comp_info: u64,
    // attached misc data
    pub(crate) data: u64,
}

impl BlobChunkInfoV2Ondisk {
    pub(crate) fn set_compressed(&mut self, compressed: bool) {
        if compressed {
            self.uncomp_info |= CHUNK_V2_FLAG_COMPRESSED;
        } else {
            self.uncomp_info &= !CHUNK_V2_FLAG_COMPRESSED;
        }
    }

    pub(crate) fn set_data(&mut self, data: u64) {
        self.data = data;
    }
}

impl BlobMetaChunkInfo for BlobChunkInfoV2Ondisk {
    fn compressed_offset(&self) -> u64 {
        self.comp_info & CHUNK_V2_COMP_OFFSET_MASK
    }

    fn set_compressed_offset(&mut self, offset: u64) {
        assert_eq!(offset & !CHUNK_V2_COMP_OFFSET_MASK, 0);
        self.comp_info &= !CHUNK_V2_COMP_OFFSET_MASK;
        self.comp_info |= offset & CHUNK_V2_COMP_OFFSET_MASK;
    }

    fn compressed_size(&self) -> u32 {
        ((self.comp_info >> CHUNK_V2_COMP_SIZE_SHIFT) & BLOB_METADATA_CHUNK_SIZE_MASK) as u32 + 1
    }

    fn set_compressed_size(&mut self, size: u32) {
        let size = size as u64;
        assert!(size > 0 && size - 1 <= BLOB_METADATA_CHUNK_SIZE_MASK);
        self.comp_info &= !(BLOB_METADATA_CHUNK_SIZE_MASK << CHUNK_V2_COMP_SIZE_SHIFT);
        self.comp_info |= (size - 1) << CHUNK_V2_COMP_SIZE_SHIFT;
    }

    fn uncompressed_offset(&self) -> u64 {
        (self.uncomp_info & CHUNK_V2_UNCOMP_OFFSET_MASK) << CHUNK_V2_UNCOMP_OFFSET_SHIFT
    }

    fn set_uncompressed_offset(&mut self, offset: u64) {
        let off = (offset >> CHUNK_V2_UNCOMP_OFFSET_SHIFT) & CHUNK_V2_UNCOMP_OFFSET_MASK;
        assert_eq!(offset, off << CHUNK_V2_UNCOMP_OFFSET_SHIFT);
        self.uncomp_info &= !CHUNK_V2_UNCOMP_OFFSET_MASK;
        self.uncomp_info |= off;
    }

    fn uncompressed_size(&self) -> u32 {
        let size = self.uncomp_info >> CHUNK_V2_UNCOMP_SIZE_SHIFT;
        (size & BLOB_METADATA_CHUNK_SIZE_MASK) as u32 + 1
    }

    fn set_uncompressed_size(&mut self, size: u32) {
        let size = size as u64;
        assert!(size != 0 && size - 1 <= BLOB_METADATA_CHUNK_SIZE_MASK);
        self.uncomp_info &= !(BLOB_METADATA_CHUNK_SIZE_MASK << CHUNK_V2_UNCOMP_SIZE_SHIFT);
        self.uncomp_info |= (size - 1) << CHUNK_V2_UNCOMP_SIZE_SHIFT;
    }

    fn is_compressed(&self) -> bool {
        self.uncomp_info & CHUNK_V2_FLAG_COMPRESSED != 0
    }

    fn get_data(&self) -> u64 {
        self.data
    }
}

impl Display for BlobChunkInfoV2Ondisk {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{{ comp:{:x}/{:x}, uncomp:{:x}/{:x} data:{:x} }}",
            self.compressed_offset(),
            self.compressed_size(),
            self.uncompressed_offset(),
            self.uncompressed_size(),
            self.get_data()
        )
    }
}

// Copyright (C) 2021-2022 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::fmt::{Display, Formatter};

use crate::meta::{
    BlobMetaChunkInfo, BlobMetaState, BLOB_METADATA_CHUNK_SIZE_MASK, BLOB_META_FEATURE_ZRAN,
};

const CHUNK_V2_COMP_OFFSET_MASK: u64 = 0xff_ffff_ffff;
const CHUNK_V2_COMP_SIZE_SHIFT: u64 = 40;
const CHUNK_V2_UNCOMP_OFFSET_MASK: u64 = 0xffff_ffff;
const CHUNK_V2_UNCOMP_OFFSET_SHIFT: u64 = 12;
const CHUNK_V2_UNCOMP_SIZE_SHIFT: u64 = 32;
//const CHUNK_V2_FLAG_MASK: u64 = 0xff00_0000_0000_0000;
const CHUNK_V2_FLAG_COMPRESSED: u64 = 0x1 << 56;
const CHUNK_V2_FLAG_ZRAN: u64 = 0x2 << 56;
const CHUNK_V2_FLAG_MASK: u64 = 0x3 << 56;

/// Blob chunk compression information on disk format V2.
#[repr(C, packed)]
#[derive(Clone, Copy, Default, Debug)]
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

    pub(crate) fn set_zran(&mut self, zran: bool) {
        if zran {
            self.uncomp_info |= CHUNK_V2_FLAG_ZRAN;
        } else {
            self.uncomp_info &= !CHUNK_V2_FLAG_ZRAN;
        }
    }

    pub(crate) fn set_data(&mut self, data: u64) {
        self.data = data;
    }

    pub(crate) fn set_zran_index(&mut self, index: u32) {
        let mut data = u64::from_le(self.data) & !0xffff_ffff_0000_0000;
        data |= (index as u64) << 32;
        self.data = u64::to_le(data);
    }

    pub(crate) fn set_zran_offset(&mut self, offset: u32) {
        let mut data = u64::from_le(self.data) & !0x0000_0000_ffff_ffff;
        data |= offset as u64;
        self.data = u64::to_le(data);
    }

    fn check_flags(&self) -> u8 {
        ((self.uncomp_info & !CHUNK_V2_FLAG_MASK) >> 56) as u8
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

    fn is_zran(&self) -> bool {
        self.uncomp_info & CHUNK_V2_FLAG_ZRAN != 0
    }

    fn get_zran_index(&self) -> u32 {
        assert!(self.is_zran());
        (u64::from_le(self.data) >> 32) as u32
    }

    fn get_zran_offset(&self) -> u32 {
        assert!(self.is_zran());
        u64::from_le(self.data) as u32
    }

    fn get_data(&self) -> u64 {
        self.data
    }

    fn validate(&self, state: &BlobMetaState) -> std::io::Result<()> {
        if self.compressed_end() > state.compressed_size
            || self.uncompressed_end() > state.uncompressed_size
            || self.uncompressed_size() == 0
            || self.compressed_size() == 0
            || (!self.is_compressed() && self.uncompressed_size() != self.compressed_size())
        {
            return Err(einval!(format!(
                "invalid chunk, blob_index {} compressed_end {} compressed_size {} uncompressed_end {} uncompressed_size {} is_compressed {}",
                state.blob_index,
                self.compressed_end(),
                self.compressed_size(),
                self.uncompressed_end(),
                self.uncompressed_size(),
                self.is_compressed(),
            )));
        }

        let invalid_flags = self.check_flags();
        if invalid_flags != 0 {
            return Err(einval!(format!("unknown chunk flags {:x}", invalid_flags)));
        }

        if state.meta_flags & BLOB_META_FEATURE_ZRAN == 0 && self.is_zran() {
            return Err(einval!("invalid chunk flag ZRan for non-ZRan blob"));
        } else if self.is_zran() {
            let index = self.get_zran_index() as usize;
            if index >= state.zran_info_array.len() {
                return Err(einval!(format!(
                    "ZRan index {:x} is too big, max {:x}",
                    self.get_zran_index(),
                    state.zran_info_array.len()
                )));
            }
            let ctx = &state.zran_info_array[index];
            if self.get_zran_offset() >= ctx.out_size()
                || self.get_zran_offset() + self.uncompressed_size() > ctx.out_size()
            {
                return Err(einval!(format!(
                    "ZRan range {:x}/{:x} is invalid, should be with in 0/{:x}",
                    self.get_zran_offset(),
                    self.uncompressed_size(),
                    ctx.out_size()
                )));
            }
        }

        Ok(())
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

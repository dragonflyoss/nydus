// Copyright (C) 2022 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::fmt::{Display, Formatter};

use crate::device::BlobFeatures;
use crate::meta::{BlobCompressionContext, BlobMetaChunkInfo, BLOB_CCT_CHUNK_SIZE_MASK};

const CHUNK_V2_COMP_OFFSET_MASK: u64 = 0xff_ffff_ffff;
const CHUNK_V2_COMP_SIZE_SHIFT: u64 = 40;
const CHUNK_V2_UNCOMP_OFFSET_MASK: u64 = 0xffff_ffff;
const CHUNK_V2_UNCOMP_OFFSET_SHIFT: u64 = 12;
const CHUNK_V2_UNCOMP_SIZE_SHIFT: u64 = 32;
const CHUNK_V2_FLAG_MASK: u64 = 0xff << 56;
const CHUNK_V2_FLAG_COMPRESSED: u64 = 0x1 << 56;
const CHUNK_V2_FLAG_ZRAN: u64 = 0x2 << 56;
const CHUNK_V2_FLAG_BATCH: u64 = 0x4 << 56;
const CHUNK_V2_FLAG_ENCRYPTED: u64 = 0x8 << 56;
const CHUNK_V2_FLAG_VALID: u64 = 0xf << 56;

/// Chunk compression information on disk format V2.
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
            self.uncomp_info |= u64::to_le(CHUNK_V2_FLAG_COMPRESSED);
        } else {
            self.uncomp_info &= u64::to_le(!CHUNK_V2_FLAG_COMPRESSED);
        }
    }

    pub(crate) fn set_encrypted(&mut self, encrypted: bool) {
        if encrypted {
            self.uncomp_info |= u64::to_le(CHUNK_V2_FLAG_ENCRYPTED);
        } else {
            self.uncomp_info &= u64::to_le(!CHUNK_V2_FLAG_ENCRYPTED);
        }
    }

    pub(crate) fn set_zran(&mut self, zran: bool) {
        if zran {
            self.uncomp_info |= u64::to_le(CHUNK_V2_FLAG_ZRAN);
        } else {
            self.uncomp_info &= u64::to_le(!CHUNK_V2_FLAG_ZRAN);
        }
    }

    pub(crate) fn set_batch(&mut self, batch: bool) {
        if batch {
            self.uncomp_info |= u64::to_le(CHUNK_V2_FLAG_BATCH);
        } else {
            self.uncomp_info &= u64::to_le(!CHUNK_V2_FLAG_BATCH);
        }
    }

    pub(crate) fn set_data(&mut self, data: u64) {
        self.data = u64::to_le(data);
    }

    pub(crate) fn set_zran_index(&mut self, index: u32) {
        assert!(self.is_zran());
        let mut data = u64::from_le(self.data) & 0x0000_0000_ffff_ffff;
        data |= (index as u64) << 32;
        self.data = u64::to_le(data);
    }

    pub(crate) fn set_zran_offset(&mut self, offset: u32) {
        assert!(self.is_zran());
        let mut data = u64::from_le(self.data) & 0xffff_ffff_0000_0000;
        data |= offset as u64;
        self.data = u64::to_le(data);
    }

    pub(crate) fn set_batch_index(&mut self, index: u32) {
        assert!(self.is_batch());
        let mut data = u64::from_le(self.data) & 0x0000_0000_ffff_ffff;
        data |= (index as u64) << 32;
        self.data = u64::to_le(data);
    }

    pub(crate) fn set_uncompressed_offset_in_batch_buf(&mut self, offset: u32) {
        assert!(self.is_batch());
        let mut data = u64::from_le(self.data) & 0xffff_ffff_0000_0000;
        data |= offset as u64;
        self.data = u64::to_le(data);
    }

    fn flags(&self) -> u8 {
        ((u64::from_le(self.uncomp_info) & CHUNK_V2_FLAG_MASK) >> 56) as u8
    }

    fn check_flags(&self) -> u8 {
        ((u64::from_le(self.uncomp_info) & !CHUNK_V2_FLAG_VALID) >> 56) as u8
    }
}

impl BlobMetaChunkInfo for BlobChunkInfoV2Ondisk {
    fn compressed_offset(&self) -> u64 {
        u64::from_le(self.comp_info) & CHUNK_V2_COMP_OFFSET_MASK
    }

    fn set_compressed_offset(&mut self, offset: u64) {
        assert_eq!(offset & !CHUNK_V2_COMP_OFFSET_MASK, 0);
        self.comp_info &= u64::to_le(!CHUNK_V2_COMP_OFFSET_MASK);
        self.comp_info |= u64::to_le(offset & CHUNK_V2_COMP_OFFSET_MASK);
    }

    fn compressed_size(&self) -> u32 {
        ((u64::from_le(self.comp_info) >> CHUNK_V2_COMP_SIZE_SHIFT) & BLOB_CCT_CHUNK_SIZE_MASK)
            as u32
    }

    fn set_compressed_size(&mut self, size: u32) {
        let size = size as u64;
        assert!(size <= BLOB_CCT_CHUNK_SIZE_MASK);
        self.comp_info &= u64::to_le(!(BLOB_CCT_CHUNK_SIZE_MASK << CHUNK_V2_COMP_SIZE_SHIFT));
        self.comp_info |= u64::to_le(size << CHUNK_V2_COMP_SIZE_SHIFT);
    }

    fn uncompressed_offset(&self) -> u64 {
        (u64::from_le(self.uncomp_info) & CHUNK_V2_UNCOMP_OFFSET_MASK)
            << CHUNK_V2_UNCOMP_OFFSET_SHIFT
    }

    fn set_uncompressed_offset(&mut self, offset: u64) {
        let off = (offset >> CHUNK_V2_UNCOMP_OFFSET_SHIFT) & CHUNK_V2_UNCOMP_OFFSET_MASK;
        assert_eq!(offset, off << CHUNK_V2_UNCOMP_OFFSET_SHIFT);
        self.uncomp_info &= u64::to_le(!CHUNK_V2_UNCOMP_OFFSET_MASK);
        self.uncomp_info |= u64::to_le(off);
    }

    fn uncompressed_size(&self) -> u32 {
        let size = u64::from_le(self.uncomp_info) >> CHUNK_V2_UNCOMP_SIZE_SHIFT;
        (size & BLOB_CCT_CHUNK_SIZE_MASK) as u32 + 1
    }

    fn set_uncompressed_size(&mut self, size: u32) {
        let size = size as u64;
        assert!(size != 0 && size - 1 <= BLOB_CCT_CHUNK_SIZE_MASK);
        self.uncomp_info &= u64::to_le(!(BLOB_CCT_CHUNK_SIZE_MASK << CHUNK_V2_UNCOMP_SIZE_SHIFT));
        self.uncomp_info |= u64::to_le((size - 1) << CHUNK_V2_UNCOMP_SIZE_SHIFT);
    }

    fn is_encrypted(&self) -> bool {
        u64::from_le(self.uncomp_info) & CHUNK_V2_FLAG_ENCRYPTED != 0
    }

    fn is_compressed(&self) -> bool {
        u64::from_le(self.uncomp_info) & CHUNK_V2_FLAG_COMPRESSED != 0
    }

    fn is_zran(&self) -> bool {
        u64::from_le(self.uncomp_info) & CHUNK_V2_FLAG_ZRAN != 0
    }

    fn is_batch(&self) -> bool {
        u64::from_le(self.uncomp_info) & CHUNK_V2_FLAG_BATCH != 0
    }

    fn get_zran_index(&self) -> u32 {
        assert!(self.is_zran());
        (u64::from_le(self.data) >> 32) as u32
    }

    fn get_zran_offset(&self) -> u32 {
        assert!(self.is_zran());
        u64::from_le(self.data) as u32
    }

    fn get_batch_index(&self) -> u32 {
        assert!(self.is_batch());
        (u64::from_le(self.data) >> 32) as u32
    }

    fn get_uncompressed_offset_in_batch_buf(&self) -> u32 {
        assert!(self.is_batch());
        u64::from_le(self.data) as u32
    }

    fn get_data(&self) -> u64 {
        u64::from_le(self.data)
    }

    fn validate(&self, state: &BlobCompressionContext) -> std::io::Result<()> {
        if self.compressed_end() > state.compressed_size
            || self.uncompressed_end() > state.uncompressed_size
            || self.uncompressed_size() == 0
            || (!state.is_separate() && !self.is_batch() && self.compressed_size() == 0)
            || (!self.is_encrypted()
                && !self.is_compressed()
                && self.uncompressed_size() != self.compressed_size())
        {
            return Err(einval!(format!(
                "invalid chunk, blob: index {}/c_size 0x{:}/d_size 0x{:x}, chunk: c_end 0x{:x}/d_end 0x{:x}/compressed {} batch {} zran {} encrypted {}",
                state.blob_index,
                state.compressed_size,
                state.uncompressed_size,
                self.compressed_end(),
                self.uncompressed_end(),
                self.is_compressed(),
                self.is_batch(),
                self.is_zran(),
                self.is_encrypted()
            )));
        }

        let invalid_flags = self.check_flags();
        if invalid_flags != 0 {
            return Err(einval!(format!("unknown chunk flags {:x}", invalid_flags)));
        }

        if state.blob_features & BlobFeatures::ZRAN.bits() == 0 && self.is_zran() {
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
            "{{ comp:{:x}/{:x}, uncomp:{:x}/{:x} data:{:x} flags:{:x}}}",
            self.compressed_offset(),
            self.compressed_size(),
            self.uncompressed_offset(),
            self.uncompressed_size(),
            self.get_data(),
            self.flags(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::meta::BlobMetaChunkArray;
    use std::mem::ManuallyDrop;

    #[test]
    fn test_new_chunk_on_disk() {
        let mut chunk = BlobChunkInfoV2Ondisk::default();

        assert_eq!(chunk.compressed_offset(), 0);
        assert_eq!(chunk.compressed_size(), 0);
        assert_eq!(chunk.compressed_end(), 0);
        assert_eq!(chunk.uncompressed_offset(), 0);
        assert_eq!(chunk.uncompressed_size(), 1);
        assert!(!chunk.is_zran());
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
        chunk.set_compressed_size(0x1000000 - 1);
        assert_eq!(chunk.compressed_offset(), 0xffffffffff);
        assert_eq!(chunk.compressed_size(), 0x1000000 - 1);

        chunk.set_uncompressed_offset(0xffffffff000);
        chunk.set_uncompressed_size(0x1000000);
        assert_eq!(chunk.uncompressed_offset(), 0xffffffff000);
        assert_eq!(chunk.uncompressed_size(), 0x1000000);

        chunk.set_zran(true);
        chunk.set_zran_index(3);
        chunk.set_zran_offset(5);
        assert_eq!(chunk.get_zran_index(), 3);
        assert_eq!(chunk.get_zran_offset(), 5);

        // For testing old format compatibility.
        let chunk = BlobChunkInfoV2Ondisk {
            uncomp_info: u64::to_le(0x0300_0100_0000_0100),
            comp_info: u64::to_le(0x0fff_ffff_ffff_ffff),
            data: u64::from_le(0x0000_0003_0000_0005),
        };
        assert_eq!(chunk.uncompressed_offset(), 0x100000);
        assert_eq!(chunk.uncompressed_size(), 0x100 + 1);
        assert_eq!(chunk.compressed_size(), 0x000f_ffff);
        assert_eq!(chunk.compressed_offset(), 0x00ff_ffff_ffff);
        assert_eq!(chunk.get_zran_index(), 3);
        assert_eq!(chunk.get_zran_offset(), 5);
    }

    #[test]
    fn test_get_chunk_index_with_hole() {
        let state = BlobCompressionContext {
            chunk_info_array: ManuallyDrop::new(BlobMetaChunkArray::V2(vec![
                BlobChunkInfoV2Ondisk {
                    uncomp_info: u64::to_le(0x0100_1fff_0000_0000),
                    comp_info: u64::to_le(0x000f_ff00_0000_0000),
                    data: 0,
                },
                BlobChunkInfoV2Ondisk {
                    uncomp_info: u64::to_le(0x0100_1fff_0000_0100),
                    comp_info: u64::to_le(0x001f_ff00_0010_0000),
                    data: 0,
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
}

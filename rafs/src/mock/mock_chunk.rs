// Copyright 2020 Ant Group. All rights reserved.
// Copyright (C) 2020 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use nydus_utils::digest::RafsDigest;

use crate::metadata::layout::v5::{RafsChunkFlags, RafsChunkInfo};

/// Cached information about an Rafs Data Chunk.
#[derive(Clone, Default, Debug)]
pub struct MockChunkInfo {
    // block hash
    c_block_id: Arc<RafsDigest>,
    // blob containing the block
    c_blob_index: u32,
    // chunk index in blob
    c_index: u32,
    // position of the block within the file
    c_file_offset: u64,
    // offset of the block within the blob
    c_compress_offset: u64,
    c_decompress_offset: u64,
    // size of the block, compressed
    c_compr_size: u32,
    c_decompress_size: u32,
    c_flags: RafsChunkFlags,
}

impl MockChunkInfo {
    pub fn mock(
        file_offset: u64,
        compress_offset: u64,
        compress_size: u32,
        decompress_offset: u64,
        decompress_size: u32,
    ) -> Self {
        MockChunkInfo {
            c_file_offset: file_offset,
            c_compress_offset: compress_offset,
            c_compr_size: compress_size,
            c_decompress_offset: decompress_offset,
            c_decompress_size: decompress_size,
            ..Default::default()
        }
    }
}

impl RafsChunkInfo for MockChunkInfo {
    fn block_id(&self) -> &RafsDigest {
        &self.c_block_id
    }

    fn is_compressed(&self) -> bool {
        self.c_flags.contains(RafsChunkFlags::COMPRESSED)
    }

    fn is_hole(&self) -> bool {
        self.c_flags.contains(RafsChunkFlags::HOLECHUNK)
    }

    impl_getter!(blob_index, c_blob_index, u32);
    impl_getter!(index, c_index, u32);
    impl_getter!(compress_offset, c_compress_offset, u64);
    impl_getter!(compress_size, c_compr_size, u32);
    impl_getter!(decompress_offset, c_decompress_offset, u64);
    impl_getter!(decompress_size, c_decompress_size, u32);
    impl_getter!(file_offset, c_file_offset, u64);
    impl_getter!(flags, c_flags, RafsChunkFlags);
}

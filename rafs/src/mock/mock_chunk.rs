// Copyright 2020 Ant Group. All rights reserved.
// Copyright (C) 2020 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::any::Any;
use std::sync::Arc;

use nydus_utils::digest::RafsDigest;
use storage::device::v5::BlobV5ChunkInfo;
use storage::device::{BlobChunkFlags, BlobChunkInfo};

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
    c_flags: BlobChunkFlags,
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

impl BlobChunkInfo for MockChunkInfo {
    fn chunk_id(&self) -> &RafsDigest {
        &self.c_block_id
    }

    fn id(&self) -> u32 {
        self.c_index
    }

    fn is_compressed(&self) -> bool {
        self.c_flags.contains(BlobChunkFlags::COMPRESSED)
    }

    fn is_encrypted(&self) -> bool {
        false
    }

    fn is_deduped(&self) -> bool {
        self.c_flags.contains(BlobChunkFlags::DEDUPED)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    impl_getter!(blob_index, c_blob_index, u32);
    impl_getter!(compressed_offset, c_compress_offset, u64);
    impl_getter!(compressed_size, c_compr_size, u32);
    impl_getter!(uncompressed_offset, c_decompress_offset, u64);
    impl_getter!(uncompressed_size, c_decompress_size, u32);
}

impl BlobV5ChunkInfo for MockChunkInfo {
    fn index(&self) -> u32 {
        self.c_index
    }

    fn file_offset(&self) -> u64 {
        self.c_file_offset
    }

    fn flags(&self) -> BlobChunkFlags {
        self.c_flags
    }

    fn as_base(&self) -> &dyn BlobChunkInfo {
        self
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use nydus_utils::digest::{Algorithm, RafsDigest};
    use storage::device::{v5::BlobV5ChunkInfo, BlobChunkFlags, BlobChunkInfo};

    use super::MockChunkInfo;

    #[test]
    fn test_mock_chunk_info() {
        let mut info = MockChunkInfo::mock(0, 1024, 512, 2048, 512);
        let digest = RafsDigest::from_buf("foobar".as_bytes(), Algorithm::Blake3);
        info.c_block_id = Arc::new(digest);
        info.c_blob_index = 1;
        info.c_flags = BlobChunkFlags::COMPRESSED;
        info.c_index = 2;

        let base = info.as_base();
        let any = info.as_any();
        let rev = any.downcast_ref::<MockChunkInfo>().unwrap();

        assert_eq!(info.chunk_id().data, digest.data);
        assert_eq!(info.id(), 2);
        assert_eq!(base.id(), rev.id());
        assert!(info.is_compressed());
        assert!(!info.is_encrypted());
        assert_eq!(info.blob_index(), 1);
        assert_eq!(info.flags(), BlobChunkFlags::COMPRESSED);
        assert_eq!(info.compressed_offset(), 1024);
        assert_eq!(info.compressed_size(), 512);
        assert_eq!(info.compressed_end(), 1024 + 512);

        assert_eq!(info.uncompressed_offset(), 2048);
        assert_eq!(info.uncompressed_size(), 512);
        assert_eq!(info.uncompressed_end(), 2048 + 512);
        assert_eq!(info.file_offset(), 0);
    }
}

// Copyright 2020 Ant Group. All rights reserved.
// Copyright (C) 2020 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::io::Result;
use std::sync::Arc;

use nydus_storage::device::{BlobChunkInfo, BlobDevice, BlobInfo};

use crate::metadata::{Inode, RafsInode, RafsSuperBlock, RafsSuperInodes};
use crate::mock::MockInode;
use crate::{RafsInodeExt, RafsIoReader, RafsResult};

#[derive(Default)]
pub struct MockSuperBlock {
    pub inodes: HashMap<Inode, Arc<MockInode>>,
}

pub const CHUNK_SIZE: u32 = 200;

impl MockSuperBlock {
    pub fn new() -> Self {
        Self {
            inodes: HashMap::new(),
        }
    }
}

impl RafsSuperInodes for MockSuperBlock {
    fn get_max_ino(&self) -> Inode {
        unimplemented!()
    }

    fn get_inode(&self, ino: Inode, _validate_inode: bool) -> Result<Arc<dyn RafsInode>> {
        self.inodes
            .get(&ino)
            .map_or(Err(enoent!()), |i| Ok(i.clone()))
    }

    fn get_extended_inode(
        &self,
        ino: Inode,
        _validate_inode: bool,
    ) -> Result<Arc<dyn RafsInodeExt>> {
        self.inodes
            .get(&ino)
            .map_or(Err(enoent!()), |i| Ok(i.clone()))
    }
}

impl RafsSuperBlock for MockSuperBlock {
    fn load(&mut self, _r: &mut RafsIoReader) -> Result<()> {
        unimplemented!()
    }
    fn update(&self, _r: &mut RafsIoReader) -> RafsResult<()> {
        unimplemented!()
    }
    fn destroy(&mut self) {}
    fn get_blob_infos(&self) -> Vec<Arc<BlobInfo>> {
        unimplemented!()
    }

    fn root_ino(&self) -> u64 {
        unimplemented!()
    }

    fn get_chunk_info(&self, _idx: usize) -> Result<Arc<dyn BlobChunkInfo>> {
        unimplemented!()
    }

    fn set_blob_device(&self, _blob_device: BlobDevice) {
        unimplemented!()
    }
}

#[cfg(test)]
mod tests {
    use std::fs::OpenOptions;

    use vmm_sys_util::tempfile::TempFile;

    use crate::{mock::MockChunkInfo, RafsIoRead};

    use super::*;

    #[test]
    fn test_mock_super_block() {
        let chunks = Vec::<Arc<MockChunkInfo>>::new();
        let node1 = MockInode::mock(0, 20, chunks.clone());
        let node2 = MockInode::mock(1, 20, chunks);
        let mut blk = MockSuperBlock::new();
        blk.inodes.insert(node1.ino(), Arc::new(node1));
        blk.inodes.insert(node2.ino(), Arc::new(node2));
        assert!(blk.get_inode(0, false).is_ok());
        assert!(blk.get_inode(1, false).is_ok());
        assert!(blk.get_inode(2, false).is_err());

        assert!(blk.get_extended_inode(0, false).is_ok());
        assert!(blk.get_extended_inode(1, false).is_ok());
        assert!(blk.get_extended_inode(2, false).is_err());
    }
    #[test]
    #[should_panic]
    fn test_get_max_ino() {
        let blk = MockSuperBlock::new();
        blk.get_max_ino();
    }

    fn get_reader() -> Box<dyn RafsIoRead> {
        let temp = TempFile::new().unwrap();
        let r = OpenOptions::new()
            .read(true)
            .write(false)
            .open(temp.as_path())
            .unwrap();
        let reader: Box<dyn RafsIoRead> = Box::new(r);
        reader
    }

    #[test]
    #[should_panic]
    fn test_load() {
        let mut blk = MockSuperBlock::new();
        let mut reader: Box<dyn RafsIoRead> = get_reader();
        blk.load(&mut reader).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_update() {
        let blk = MockSuperBlock::new();
        let mut reader: Box<dyn RafsIoRead> = get_reader();
        blk.update(&mut reader).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_rootino() {
        let blk = MockSuperBlock::new();
        blk.root_ino();
    }
    #[test]
    #[should_panic]
    fn test_get_chunk_info() {
        let blk = MockSuperBlock::new();
        blk.get_chunk_info(0).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_set_blob_device() {
        let blk = MockSuperBlock::new();
        blk.set_blob_device(BlobDevice::default());
    }

    #[test]
    fn test_mock_super_block_func() {
        let mut blk = MockSuperBlock::new();
        assert!(blk.get_inode(0, true).is_err());
        assert!(blk.get_extended_inode(0, true).is_err());
        blk.inodes.insert(0, Arc::new(MockInode::default()));
        assert!(blk.get_inode(0, true).is_ok());
        assert!(blk.get_extended_inode(0, true).is_ok());
        blk.destroy();
    }
}

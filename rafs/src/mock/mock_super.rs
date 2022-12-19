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

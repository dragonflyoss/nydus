// Copyright 2020 Ant Group. All rights reserved.
// Copyright (C) 2020 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::io::Result;
use std::sync::Arc;

use crate::metadata::layout::v5::RafsV5BlobTable;
use crate::metadata::{Inode, RafsInode, RafsSuperBlobs, RafsSuperBlock, RafsSuperInodes};
use crate::{RafsIoReader, RafsResult};
use nydus_utils::digest;

pub struct MockSuperBlock {
    pub inodes: HashMap<Inode, Arc<dyn RafsInode + Send + Sync>>,
}

pub const CHUNK_SIZE: u32 = 200;

impl Default for MockSuperBlock {
    fn default() -> Self {
        Self {
            inodes: HashMap::new(),
        }
    }
}

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
    fn get_inode(&self, ino: Inode, _digest_validate: bool) -> Result<Arc<dyn RafsInode>> {
        self.inodes
            .get(&ino)
            .map_or(Err(enoent!()), |i| Ok(i.clone()))
    }
    fn validate_digest(
        &self,
        _inode: Arc<dyn RafsInode>,
        _recursive: bool,
        _digester: digest::Algorithm,
    ) -> Result<bool> {
        unimplemented!()
    }
}

impl RafsSuperBlobs for MockSuperBlock {
    fn get_blob_table(&self) -> Arc<RafsV5BlobTable> {
        unimplemented!()
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
}

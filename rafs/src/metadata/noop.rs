// Copyright (C) 2020 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! A noop meta data driver for place-holding.

use std::io::Result;
use std::sync::Arc;

use nydus_utils::digest;

use crate::metadata::layout::v5::RafsV5BlobTable;
use crate::metadata::{Inode, RafsInode, RafsSuperBlobs, RafsSuperBlock, RafsSuperInodes};
use crate::{RafsIoReader, RafsResult};

pub struct NoopSuperBlock {}

impl Default for NoopSuperBlock {
    fn default() -> Self {
        Self {}
    }
}

impl NoopSuperBlock {
    pub fn new() -> Self {
        Self::default()
    }
}

impl RafsSuperInodes for NoopSuperBlock {
    fn get_max_ino(&self) -> Inode {
        unimplemented!()
    }

    fn get_inode(&self, _ino: Inode, _digest_validate: bool) -> Result<Arc<dyn RafsInode>> {
        unimplemented!()
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

impl RafsSuperBlobs for NoopSuperBlock {
    fn get_blob_table(&self) -> Arc<RafsV5BlobTable> {
        unimplemented!()
    }
}

impl RafsSuperBlock for NoopSuperBlock {
    fn load(&mut self, _r: &mut RafsIoReader) -> Result<()> {
        unimplemented!()
    }

    fn update(&self, _r: &mut RafsIoReader) -> RafsResult<()> {
        unimplemented!()
    }

    fn destroy(&mut self) {}
}

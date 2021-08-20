// Copyright (C) 2020 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! A noop meta data driver for place-holding.

use std::io::Result;
use std::sync::Arc;

use crate::metadata::layout::v5::OndiskBlobTable;
use crate::metadata::{Inode, RafsInode, RafsSuperInodes};
use crate::{RafsIoReader, RafsResult};

pub struct NoopInodes {}

impl Default for NoopInodes {
    fn default() -> Self {
        Self {}
    }
}

impl NoopInodes {
    pub fn new() -> Self {
        Self::default()
    }
}

impl RafsSuperInodes for NoopInodes {
    fn load(&mut self, _r: &mut RafsIoReader) -> Result<()> {
        unimplemented!()
    }

    fn destroy(&mut self) {}

    fn get_inode(&self, _ino: Inode, _digest_validate: bool) -> Result<Arc<dyn RafsInode>> {
        unimplemented!()
    }

    fn get_max_ino(&self) -> Inode {
        unimplemented!()
    }

    fn get_blob_table(&self) -> Arc<OndiskBlobTable> {
        unimplemented!()
    }

    fn update(&self, _r: &mut RafsIoReader) -> RafsResult<()> {
        unimplemented!()
    }
}

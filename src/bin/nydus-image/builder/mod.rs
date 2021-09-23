// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

pub mod directory;
pub mod stargz;

use anyhow::Result;

use crate::core::context::{BlobManager, BootstrapContext, BuildContext};

pub trait Builder {
    fn build(
        &mut self,
        build_ctx: &mut BuildContext,
        bootstrap_ctx: &mut BootstrapContext,
        blob_mgr: &mut BlobManager,
    ) -> Result<(Vec<String>, u64)>;
}

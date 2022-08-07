// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;

use crate::core::context::{BlobManager, BootstrapManager, BuildContext, BuildOutput};

pub(crate) use self::diff::DiffBuilder;
pub(crate) use self::directory::DirectoryBuilder;
pub(crate) use self::stargz::StargzBuilder;

mod diff;
mod directory;
mod stargz;

/// Trait to generate a Nydus image from the source.
pub(crate) trait Builder {
    fn build(
        &mut self,
        build_ctx: &mut BuildContext,
        bootstrap_mgr: &mut BootstrapManager,
        blob_mgr: &mut BlobManager,
    ) -> Result<BuildOutput>;
}

// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Validator for RAFS format

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use nydus_api::ConfigV2;
use nydus_builder::Tree;
use nydus_rafs::metadata::RafsSuper;
use nydus_storage::device::BlobInfo;

pub struct Validator {
    sb: RafsSuper,
}

impl Validator {
    pub fn new(bootstrap_path: &Path, config: Arc<ConfigV2>) -> Result<Self> {
        let (sb, _) = RafsSuper::load_from_file(bootstrap_path, config, false)?;

        Ok(Self { sb })
    }

    pub fn check(&mut self, verbosity: bool) -> Result<Vec<Arc<BlobInfo>>> {
        let err = "failed to load bootstrap for validator";
        let tree = Tree::from_bootstrap(&self.sb, &mut ()).context(err)?;

        let pre = &mut |t: &Tree| -> Result<()> {
            let node = t.lock_node();
            if verbosity {
                println!("inode: {}", node);
                for chunk in &node.chunks {
                    println!("\t chunk: {}", chunk);
                }
            }
            Ok(())
        };
        tree.walk_dfs_pre(pre)?;

        Ok(self.sb.superblock.get_blob_infos())
    }
}

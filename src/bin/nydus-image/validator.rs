// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Validator for RAFS format

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use nydus_rafs::metadata::{RafsMode, RafsSuper};
use nydus_storage::device::BlobInfo;

use crate::tree::Tree;

pub struct Validator {
    sb: RafsSuper,
}

impl Validator {
    pub fn new(bootstrap_path: &Path) -> Result<Self> {
        let sb = RafsSuper::load_from_metadata(bootstrap_path, RafsMode::Direct, true)?;

        Ok(Self { sb })
    }

    pub fn check(&mut self, verbosity: bool) -> Result<Vec<Arc<BlobInfo>>> {
        let err = "failed to load bootstrap for validator";
        let tree = Tree::from_bootstrap(&self.sb, &mut ()).context(err)?;

        tree.iterate(&mut |node| {
            if verbosity {
                println!("inode: {}", node);
                for chunk in &node.chunks {
                    println!("\t chunk: {}", chunk);
                }
            }
            true
        })?;

        Ok(self.sb.superblock.get_blob_infos())
    }
}

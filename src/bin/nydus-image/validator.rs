// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Validator for RAFS format

use std::path::Path;

use anyhow::{Context, Error, Result};
use rafs::metadata::{RafsMode, RafsSuper};

use crate::tree::Tree;

pub struct Validator {
    sb: RafsSuper,
}

impl Validator {
    pub fn new(bootstrap_path: &Path) -> Result<Self> {
        let path = bootstrap_path
            .to_str()
            .ok_or_else(|| Error::msg("bootstrap path is invalid"))?;
        let sb = RafsSuper::load_from_metadata(path, RafsMode::Direct, true)?;

        Ok(Self { sb })
    }

    pub fn check(&mut self, verbosity: bool) -> Result<Vec<String>> {
        let err = "failed to load bootstrap for validator";
        let tree = Tree::from_bootstrap(&self.sb, &mut ()).context(err)?;

        tree.iterate(&mut |node| {
            if verbosity {
                info!("{}", node);
                for chunk in &node.chunks {
                    debug!("chunk {}", chunk);
                }
            }
            true
        })?;

        let blob_ids = self
            .sb
            .superblock
            .get_blob_infos()
            .iter()
            .map(|entry| entry.blob_id().to_owned())
            .collect::<Vec<String>>();

        Ok(blob_ids)
    }
}

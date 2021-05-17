// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Validator for RAFS format

use anyhow::{Context, Result};
use std::fs::OpenOptions;
use std::path::Path;

use rafs::metadata::{RafsMode, RafsSuper};
use rafs::RafsIoReader;

use crate::tree::Tree;

pub struct Validator {
    /// Bootstrap file reader.
    f_bootstrap: RafsIoReader,
}

impl Validator {
    pub fn new(bootstrap_path: &Path) -> Result<Self> {
        let f_bootstrap = Box::new(
            OpenOptions::new()
                .read(true)
                .write(false)
                .open(bootstrap_path)
                .context(format!(
                    "failed to open bootstrap file {:?} for validator",
                    bootstrap_path
                ))?,
        );
        Ok(Self { f_bootstrap })
    }

    pub fn check(&mut self, verbosity: bool) -> Result<Vec<String>> {
        let err = "failed to load bootstrap for validator";
        let mut rs = RafsSuper {
            mode: RafsMode::Direct,
            digest_validate: true,
            ..Default::default()
        };
        rs.load(&mut self.f_bootstrap).context(err)?;

        let tree = Tree::from_bootstrap(&rs, None).context(err)?;
        tree.iterate(&|node| {
            if verbosity {
                info!("{}", node);
                for chunk in &node.chunks {
                    debug!("chunk {}", chunk);
                }
            }
            true
        })?;

        let blob_ids = rs
            .inodes
            .get_blob_table()
            .entries
            .iter()
            .map(|entry| entry.blob_id.to_string())
            .collect::<Vec<String>>();

        Ok(blob_ids)
    }
}

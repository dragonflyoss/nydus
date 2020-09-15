// Copyright 2020 Ant Financial. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Validator for RAFS format

use std::fs::OpenOptions;
use std::io::Result;
use std::path::Path;

use rafs::metadata::{RafsMode, RafsSuper};
use rafs::RafsIoRead;

use crate::tree::Tree;

pub struct Validator {
    /// Bootstrap file reader.
    f_bootstrap: Box<dyn RafsIoRead>,
}

impl Validator {
    pub fn new(bootstrap_path: &Path) -> Result<Self> {
        let f_bootstrap = Box::new(
            OpenOptions::new()
                .read(true)
                .write(false)
                .open(bootstrap_path)?,
        );
        Ok(Self { f_bootstrap })
    }

    pub fn check(&mut self, verbosity: bool) -> Result<bool> {
        let mut rs = RafsSuper::default();
        rs.mode = RafsMode::Direct;
        rs.digest_validate = true;
        rs.load(&mut self.f_bootstrap)?;

        let tree = Tree::from_bootstrap(&rs)?;
        tree.iterate(&|node| {
            if verbosity {
                info!("{}", node);
                for chunk in &node.chunks {
                    debug!("chunk {}", chunk);
                }
            }
            true
        })?;

        Ok(true)
    }
}

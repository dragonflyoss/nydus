// Copyright (C) 2022 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::{bail, Result};
use std::collections::HashSet;
use std::convert::TryFrom;

const ERR_UNSUPPORTED_FEATURE: &str = "unsupported feature";

/// Feature bits for RAFS filesystem builder.
#[derive(Clone, Hash, PartialEq, Eq)]
pub enum Feature {
    /// Enable to append TOC footer to rafs blob.
    BlobToc,
}

/// Feature set for RAFS filesystem builder.
pub struct Features(HashSet<Feature>);

impl Features {
    /// Create a new instance of [Features].
    pub fn new() -> Self {
        Self(HashSet::new())
    }

    /// Create a new instance of [Features] from a string.
    pub fn from(features: &str) -> Result<Self> {
        let mut list = Features::new();
        let features = features.trim();
        if features.is_empty() {
            return Ok(list);
        }
        for feat in features.split(',') {
            let feature = Feature::try_from(feat.trim())?;
            list.0.insert(feature);
        }
        Ok(list)
    }

    /// Check whether feature is enabled or not.
    pub fn is_enabled(&self, feature: Feature) -> bool {
        self.0.contains(&feature)
    }
}

impl TryFrom<&str> for Feature {
    type Error = anyhow::Error;

    fn try_from(f: &str) -> Result<Self> {
        match f {
            "blob-toc" => Ok(Self::BlobToc),
            _ => bail!(
                "{} `{}`, please try upgrading to the latest nydus-image",
                ERR_UNSUPPORTED_FEATURE,
                f,
            ),
        }
    }
}

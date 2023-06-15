// Copyright (C) 2022 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashSet;
use std::convert::TryFrom;

use anyhow::{bail, Result};

const ERR_UNSUPPORTED_FEATURE: &str = "unsupported feature";

/// Feature flags to control behavior of RAFS filesystem builder.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub enum Feature {
    /// Append a Table Of Content footer to RAFS v6 data blob, to help locate data sections.
    BlobToc,
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

/// A set of enabled feature flags to control behavior of RAFS filesystem builder
#[derive(Clone, Debug)]
pub struct Features(HashSet<Feature>);

impl Default for Features {
    fn default() -> Self {
        Self::new()
    }
}

impl Features {
    /// Create a new instance of [Features].
    pub fn new() -> Self {
        Self(HashSet::new())
    }

    /// Check whether a feature is enabled or not.
    pub fn is_enabled(&self, feature: Feature) -> bool {
        self.0.contains(&feature)
    }
}

impl TryFrom<&str> for Features {
    type Error = anyhow::Error;

    fn try_from(features: &str) -> Result<Self> {
        let mut list = Features::new();
        for feat in features.trim().split(',') {
            if !feat.is_empty() {
                let feature = Feature::try_from(feat.trim())?;
                list.0.insert(feature);
            }
        }
        Ok(list)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_feature() {
        assert_eq!(Feature::try_from("blob-toc").unwrap(), Feature::BlobToc);
        Feature::try_from("unknown-feature-bit").unwrap_err();
    }

    #[test]
    fn test_features() {
        let features = Features::try_from("blob-toc").unwrap();
        assert!(features.is_enabled(Feature::BlobToc));
        let features = Features::try_from("blob-toc,").unwrap();
        assert!(features.is_enabled(Feature::BlobToc));
        let features = Features::try_from("blob-toc, ").unwrap();
        assert!(features.is_enabled(Feature::BlobToc));
        let features = Features::try_from("blob-toc ").unwrap();
        assert!(features.is_enabled(Feature::BlobToc));
        let features = Features::try_from(" blob-toc ").unwrap();
        assert!(features.is_enabled(Feature::BlobToc));
    }
}

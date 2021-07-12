// Copyright 2020 Ant Group. All rights reserved.
// Copyright (C) 2020 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Struct for RAFS digest algorithm.

use std::fmt;

use sha2::digest::Digest;
use sha2::Sha256;
use std::io::Error;
use std::str::FromStr;

pub const RAFS_DIGEST_LENGTH: usize = 32;
type DigestData = [u8; RAFS_DIGEST_LENGTH];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Algorithm {
    Blake3,
    Sha256,
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl FromStr for Algorithm {
    type Err = Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "blake3" => Ok(Self::Blake3),
            "sha256" => Ok(Self::Sha256),
            _ => Err(einval!("digest algorithm should be blake3 or sha256")),
        }
    }
}

pub trait DigestHasher {
    fn digest_update(&mut self, buf: &[u8]);
    fn digest_finalize(&mut self) -> RafsDigest;
}

impl DigestHasher for blake3::Hasher {
    fn digest_update(&mut self, buf: &[u8]) {
        self.update(buf);
    }
    fn digest_finalize(&mut self) -> RafsDigest {
        RafsDigest {
            data: self.clone().finalize().into(),
        }
    }
}

impl DigestHasher for Sha256 {
    fn digest_update(&mut self, buf: &[u8]) {
        self.update(buf);
    }
    fn digest_finalize(&mut self) -> RafsDigest {
        RafsDigest {
            data: self.clone().finalize().into(),
        }
    }
}

#[derive(Clone, Copy, Hash, PartialEq, Eq, Debug, Default)]
pub struct RafsDigest {
    pub data: DigestData,
}

impl RafsDigest {
    pub fn from_buf(buf: &[u8], algorithm: Algorithm) -> Self {
        let data: DigestData = match algorithm {
            Algorithm::Blake3 => blake3::hash(buf).into(),
            Algorithm::Sha256 => {
                let mut hasher = Sha256::new();
                hasher.update(buf);
                hasher.finalize().into()
            }
        };

        RafsDigest { data }
    }
    pub fn hasher(algorithm: Algorithm) -> Box<dyn DigestHasher> {
        match algorithm {
            Algorithm::Blake3 => Box::new(blake3::Hasher::new()) as Box<dyn DigestHasher>,
            Algorithm::Sha256 => Box::new(Sha256::new()) as Box<dyn DigestHasher>,
        }
    }
}

impl From<DigestData> for RafsDigest {
    fn from(data: DigestData) -> Self {
        Self { data }
    }
}

impl AsRef<[u8]> for RafsDigest {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl fmt::Display for RafsDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for c in &self.data {
            write!(f, "{:02x}", c).unwrap()
        }
        Ok(())
    }
}

impl Into<String> for RafsDigest {
    fn into(self) -> String {
        format!("{}", self)
    }
}

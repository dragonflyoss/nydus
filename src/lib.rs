// Copyright 2021 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

extern crate serde_json;

use std::fmt::{self, Display};
use std::str::FromStr;

use nydus_api::ConfigV2;
use serde::{Deserialize, Serialize};

/// Error code related to Nydus library.
#[derive(Debug)]
pub enum NydusError {
    InvalidArguments(String),
}

impl Display for NydusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// Specialized `Result` for Nydus library.
pub type Result<T> = std::result::Result<T, NydusError>;

/// Supported filesystem types.
#[derive(Clone, Debug, Serialize, PartialEq, Deserialize)]
pub enum FsBackendType {
    Rafs,
    PassthroughFs,
}

impl FromStr for FsBackendType {
    type Err = NydusError;
    fn from_str(s: &str) -> Result<FsBackendType> {
        match s {
            "rafs" => Ok(FsBackendType::Rafs),
            "passthrough_fs" => Ok(FsBackendType::PassthroughFs),
            o => Err(NydusError::InvalidArguments(format!(
                "Fs backend type only accepts 'rafs' and 'passthrough_fs', but {} was specified",
                o
            ))),
        }
    }
}

impl Display for FsBackendType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Serialize, Clone, Deserialize)]
pub struct FsBackendDesc {
    pub backend_type: FsBackendType,
    pub mountpoint: String,
    pub mounted_time: time::OffsetDateTime,
    pub config: Option<ConfigV2>,
}

pub fn ensure_threads<V: AsRef<str>>(v: V) -> std::result::Result<usize, String> {
    if let Ok(t) = v.as_ref().parse::<usize>() {
        if t > 0 && t <= 1024 {
            Ok(t)
        } else {
            Err("Invalid working thread number {}, valid values: [1-1024]".to_string())
        }
    } else {
        Err("Input thread number is invalid".to_string())
    }
}

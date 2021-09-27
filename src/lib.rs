// Copyright 2021 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::fmt::{self, Display};
use std::str::FromStr;

use chrono::{self, DateTime, Local};
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DisplayFromStr};

extern crate serde_json;

#[allow(dead_code)]
#[derive(Debug)]
pub enum NydusError {
    InvalidArguments(String),
}

pub type Result<T> = std::result::Result<T, NydusError>;

#[derive(Clone, Serialize, PartialEq, Deserialize)]
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

impl Display for NydusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[serde_as]
#[derive(Serialize, Clone, Deserialize)]
pub struct FsBackendDesc {
    pub backend_type: FsBackendType,
    pub mountpoint: String,
    #[serde_as(as = "DisplayFromStr")]
    pub mounted_time: DateTime<Local>,
    pub config: serde_json::Value,
}

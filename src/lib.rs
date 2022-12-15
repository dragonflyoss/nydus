// Copyright 2021 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

#[macro_use]
extern crate log;
#[macro_use]
extern crate nydus_error;

use std::fmt::{self, Display};
use std::str::FromStr;

use nydus_api::ConfigV2;
use serde::{Deserialize, Serialize};

pub mod blob_cache;

/// Error code related to Nydus library.
#[derive(Debug)]
pub enum NydusError {
    /// Invalid argument.
    InvalidArguments(String),
}

impl Display for NydusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NydusError::InvalidArguments(s) => write!(f, "invalid argument: {}", s),
        }
    }
}

/// Specialized `Result` for Nydus library.
pub type Result<T> = std::result::Result<T, NydusError>;

/// Type of supported backend filesystems.
#[derive(Clone, Debug, Serialize, PartialEq, Deserialize)]
pub enum FsBackendType {
    /// Registry Accelerated File System
    Rafs,
    /// Share an underlying directory as a FUSE filesystem.
    PassthroughFs,
}

impl FromStr for FsBackendType {
    type Err = NydusError;

    fn from_str(s: &str) -> Result<FsBackendType> {
        match s {
            "rafs" => Ok(FsBackendType::Rafs),
            "passthrough" => Ok(FsBackendType::PassthroughFs),
            "passthroughfs" => Ok(FsBackendType::PassthroughFs),
            "passthrough_fs" => Ok(FsBackendType::PassthroughFs),
            o => Err(NydusError::InvalidArguments(format!(
                "only 'rafs' and 'passthrough_fs' are supported, but {} was specified",
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

/// Backend filesystem descriptor.
#[derive(Serialize, Clone, Deserialize)]
pub struct FsBackendDescriptor {
    /// Type of backend filesystem.
    pub backend_type: FsBackendType,
    /// Mount point for the filesystem.
    pub mountpoint: String,
    /// Timestamp for the mount operation.
    pub mounted_time: time::OffsetDateTime,
    /// Optional configuration information for the backend filesystem.
    pub config: Option<ConfigV2>,
}

/// Validate thread number configuration, valid range is `[1-1024]`.
pub fn validate_threads_configuration<V: AsRef<str>>(v: V) -> std::result::Result<usize, String> {
    if let Ok(t) = v.as_ref().parse::<usize>() {
        if t > 0 && t <= 1024 {
            Ok(t)
        } else {
            Err(format!(
                "invalid thread number {}, valid range: [1-1024]",
                t
            ))
        }
    } else {
        Err(format!(
            "invalid thread number configuration: {}",
            v.as_ref()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backend_fs_type() {
        assert_eq!(
            FsBackendType::from_str("rafs").unwrap(),
            FsBackendType::Rafs
        );
        assert_eq!(
            FsBackendType::from_str("passthrough").unwrap(),
            FsBackendType::PassthroughFs
        );
        assert_eq!(
            FsBackendType::from_str("passthroughfs").unwrap(),
            FsBackendType::PassthroughFs
        );
        assert_eq!(
            FsBackendType::from_str("passthrough_fs").unwrap(),
            FsBackendType::PassthroughFs
        );
        assert!(FsBackendType::from_str("passthroug").is_err());

        assert_eq!(format!("{}", FsBackendType::Rafs), "Rafs");
        assert_eq!(format!("{}", FsBackendType::PassthroughFs), "PassthroughFs");
    }

    #[test]
    fn test_validate_thread_configuration() {
        assert_eq!(validate_threads_configuration("1").unwrap(), 1);
        assert_eq!(validate_threads_configuration("1024").unwrap(), 1024);
        assert!(validate_threads_configuration("0").is_err());
        assert!(validate_threads_configuration("-1").is_err());
        assert!(validate_threads_configuration("1.0").is_err());
        assert!(validate_threads_configuration("1025").is_err());
        assert!(validate_threads_configuration("test").is_err());
    }
}

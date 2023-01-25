// Copyright 2021 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

#[macro_use]
extern crate log;
#[macro_use]
extern crate nydus_error;

use std::fmt::{self, Display};
use std::io;
use std::str::FromStr;

use clap::parser::ValuesRef;
use clap::ArgMatches;
use fuse_backend_rs::api::vfs::VfsError;
use fuse_backend_rs::transport::Error as FuseTransportError;
use fuse_backend_rs::Error as FuseError;
use nydus_api::{ConfigV2, DaemonErrorKind};
use nydus_rafs::RafsError;
use serde::{Deserialize, Serialize};
use serde_json::Error as SerdeError;

pub mod blob_cache;
pub mod daemon;
#[cfg(target_os = "linux")]
pub mod fs_cache;
pub mod fs_service;
pub mod fusedev;
pub mod singleton;
pub mod upgrade;

/// Error code related to Nydus library.
#[derive(Debug)]
pub enum Error {
    /// Object already exists.
    AlreadyExists,
    /// Generic error message.
    Common(String),
    /// Invalid arguments provided.
    InvalidArguments(String),
    /// Invalid config provided
    InvalidConfig(String),
    /// Object not found.
    NotFound,
    /// Daemon does not reach the stable working state yet,
    /// some capabilities may not be provided.
    NotReady,
    /// Request not supported.
    Unsupported,
    /// Failed to serialize/deserialize message.
    Serde(SerdeError),
    /// Cannot spawn a new thread
    ThreadSpawn(io::Error),
    /// Cannot create FUSE server
    CreateFuseServer(io::Error),
    /*
    /// Failed to upgrade the mount
    UpgradeManager(UpgradeMgrError),
     */
    /// State-machine related error codes if something bad happens when to communicate with state-machine
    Channel(String),
    /// Failed to start service.
    StartService(String),
    /// Failed to stop service
    ServiceStop,
    /// Input event to stat-machine is not expected.
    UnexpectedEvent(String),
    /// Wait daemon failure
    WaitDaemon(io::Error),

    // Filesystem type mismatch.
    FsTypeMismatch(String),
    /// Failure occurred in the Passthrough subsystem.
    PassthroughFs(io::Error),
    /// Failure occurred in the Rafs subsystem.
    Rafs(RafsError),
    /// Failure occurred in the VFS subsystem.
    Vfs(VfsError),

    // virtio-fs
    /// Failed to handle event other than input event.
    HandleEventNotEpollIn,
    /// Failed to handle unknown event.
    HandleEventUnknownEvent,
    /// Fail to walk descriptor chain
    IterateQueue,
    /// Invalid Virtio descriptor chain.
    InvalidDescriptorChain(FuseTransportError),
    /// Processing queue failed.
    ProcessQueue(FuseError),
    /// Cannot create epoll context.
    Epoll(io::Error),
    /// Daemon related error
    DaemonFailure(String),
    /// Missing virtqueue memory
    QueueMemoryUnset,

    // Fuse session has been shutdown.
    SessionShutdown(FuseTransportError),
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidArguments(s) => write!(f, "Invalid argument: {}", s),
            Self::InvalidConfig(s) => write!(f, "Invalid config: {}", s),
            Self::DaemonFailure(s) => write!(f, "Daemon error: {}", s),
            _ => write!(f, "{:?}", self),
        }
    }
}

impl std::error::Error for Error {}

impl From<Error> for io::Error {
    fn from(e: Error) -> Self {
        einval!(e)
    }
}

impl From<VfsError> for Error {
    fn from(e: VfsError) -> Self {
        Error::Vfs(e)
    }
}

impl From<RafsError> for Error {
    fn from(error: RafsError) -> Self {
        Error::Rafs(error)
    }
}

impl From<Error> for DaemonErrorKind {
    fn from(e: Error) -> Self {
        use Error::*;
        match e {
            //UpgradeManager(_) => DaemonErrorKind::UpgradeManager,
            NotReady => DaemonErrorKind::NotReady,
            Unsupported => DaemonErrorKind::Unsupported,
            Serde(e) => DaemonErrorKind::Serde(e),
            UnexpectedEvent(e) => DaemonErrorKind::UnexpectedEvent(e),
            o => DaemonErrorKind::Other(o.to_string()),
        }
    }
}

/// Specialized `Result` for Nydus library.
pub type Result<T> = std::result::Result<T, Error>;

/// Type of supported backend filesystems.
#[derive(Clone, Debug, Serialize, PartialEq, Deserialize)]
pub enum FsBackendType {
    /// Registry Accelerated File System
    Rafs,
    /// Share an underlying directory as a FUSE filesystem.
    PassthroughFs,
}

impl FromStr for FsBackendType {
    type Err = Error;

    fn from_str(s: &str) -> Result<FsBackendType> {
        match s {
            "rafs" => Ok(FsBackendType::Rafs),
            "passthrough" => Ok(FsBackendType::PassthroughFs),
            "passthroughfs" => Ok(FsBackendType::PassthroughFs),
            "passthrough_fs" => Ok(FsBackendType::PassthroughFs),
            o => Err(Error::InvalidArguments(format!(
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

pub struct SubCmdArgs<'a> {
    args: &'a ArgMatches,
    subargs: &'a ArgMatches,
}

impl<'a> SubCmdArgs<'a> {
    pub fn new(args: &'a ArgMatches, subargs: &'a ArgMatches) -> Self {
        SubCmdArgs { args, subargs }
    }

    pub fn value_of(&self, key: &str) -> Option<&String> {
        if let Some(v) = self.subargs.get_one::<String>(key) {
            Some(v)
        } else {
            self.args.get_one::<String>(key)
        }
    }

    pub fn values_of(&self, key: &str) -> Option<ValuesRef<String>> {
        if let Some(v) = self.subargs.get_many::<String>(key) {
            Some(v)
        } else {
            self.args.get_many::<String>(key)
        }
    }

    pub fn is_present(&self, key: &str) -> bool {
        self.subargs.get_flag(key) || self.args.get_flag(key)
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

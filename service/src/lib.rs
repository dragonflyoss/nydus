// Copyright 2021 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Nydus Image Service Management Framework
//!
//! The `nydus-service` crate provides facilities to manage Nydus services, such as:
//! - `blobfs`: share processed RAFS metadata/data blobs to guest by virtio-fs, so the RAFS
//!    filesystem can be mounted by EROFS inside guest.
//! - `blockdev`: compose processed RAFS metadata/data as a block device, so it can be used as
//!   backend for virtio-blk.
//! - `fscache`: cooperate Linux fscache subsystem to mount RAFS filesystems by EROFS.
//! - `fuse`: mount RAFS filesystems as FUSE filesystems.

#[macro_use]
extern crate log;
#[macro_use]
extern crate nydus_api;

use std::fmt::{self, Display};
use std::io;
use std::str::FromStr;
use std::sync::mpsc::{RecvError, SendError};

use fuse_backend_rs::api::vfs::VfsError;
use fuse_backend_rs::transport::Error as FuseTransportError;
use fuse_backend_rs::Error as FuseError;
use nydus_api::{ConfigV2, DaemonErrorKind};
use nydus_rafs::RafsError;
use serde::{Deserialize, Serialize};
use serde_json::Error as SerdeError;

pub mod daemon;
mod fs_service;
mod fusedev;
mod singleton;
pub mod upgrade;

pub use blob_cache::BlobCacheMgr;
pub use fs_service::{FsBackendCollection, FsBackendMountCmd, FsBackendUmountCmd, FsService};
pub use fusedev::{create_fuse_daemon, create_vfs_backend, FusedevDaemon};
pub use singleton::create_daemon;

#[cfg(target_os = "linux")]
pub mod blob_cache;
#[cfg(all(target_os = "linux", feature = "block-device"))]
pub mod block_device;
#[cfg(all(target_os = "linux", feature = "block-nbd"))]
pub mod block_nbd;
#[cfg(target_os = "linux")]
mod fs_cache;

#[cfg(target_os = "linux")]
pub use fs_cache::FsCacheHandler;

/// Error code related to Nydus library.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("object or filesystem already exists")]
    AlreadyExists,
    /// Invalid arguments provided.
    #[error("invalid argument `{0}`")]
    InvalidArguments(String),
    #[error("invalid configuration, {0}")]
    InvalidConfig(String),
    #[error("invalid prefetch file list")]
    InvalidPrefetchList,
    #[error("object or filesystem doesn't exist")]
    NotFound,
    #[error("daemon is not ready yet")]
    NotReady,
    #[error("unsupported request or operation")]
    Unsupported,
    #[error("failed to serialize/deserialize message, {0}")]
    Serde(SerdeError),
    #[error("failed to spawn thread, {0}")]
    ThreadSpawn(io::Error),
    #[error("failed to send message to channel, {0}")]
    ChannelSend(#[from] SendError<crate::daemon::DaemonStateMachineInput>),
    #[error("failed to receive message from channel, {0}")]
    ChannelReceive(#[from] RecvError),
    #[error(transparent)]
    UpgradeManager(upgrade::UpgradeMgrError),
    #[error("failed to start service, {0}")]
    StartService(String),
    /// Input event to stat-machine is not expected.
    #[error("unexpect state machine transition event `{0:?}`")]
    UnexpectedEvent(crate::daemon::DaemonStateMachineInput),
    #[error("failed to wait daemon, {0}")]
    WaitDaemon(#[source] io::Error),

    #[error("filesystem type mismatch, expect {0}")]
    FsTypeMismatch(String),
    #[error("passthroughfs failed to handle request, {0}")]
    PassthroughFs(#[source] io::Error),
    #[error("RAFS failed to handle request, {0}")]
    Rafs(#[from] RafsError),
    #[error("VFS failed to handle request, {0:?}")]
    Vfs(VfsError),

    // fusedev
    #[error("failed to create FUSE server, {0}")]
    CreateFuseServer(io::Error),
    // Fuse session has been shutdown.
    #[error("FUSE session has been shut down, {0}")]
    SessionShutdown(FuseTransportError),

    // virtio-fs
    #[error("failed to handle event other than input event")]
    HandleEventNotEpollIn,
    #[error("failed to handle unknown event")]
    HandleEventUnknownEvent,
    #[error("fail to walk descriptor chain")]
    IterateQueue,
    #[error("invalid Virtio descriptor chain, {0}")]
    InvalidDescriptorChain(#[from] FuseTransportError),
    #[error("failed to process FUSE request, {0}")]
    ProcessQueue(#[from] FuseError),
    #[error("failed to create epoll context, {0}")]
    Epoll(#[source] io::Error),
    #[error("vhost-user failed to process request, {0}")]
    VhostUser(String),
    #[error("missing memory configuration for virtio queue")]
    QueueMemoryUnset,
}

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

impl From<Error> for DaemonErrorKind {
    fn from(e: Error) -> Self {
        use Error::*;
        match e {
            UpgradeManager(_) => DaemonErrorKind::UpgradeManager,
            NotReady => DaemonErrorKind::NotReady,
            Unsupported => DaemonErrorKind::Unsupported,
            Serde(e) => DaemonErrorKind::Serde(e),
            UnexpectedEvent(e) => DaemonErrorKind::UnexpectedEvent(format!("{:?}", e)),
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

/// Trait to get configuration options for services.
pub trait ServiceArgs {
    /// Get value of commandline option `key`.
    fn value_of(&self, key: &str) -> Option<&String>;

    /// Check whether commandline optio `key` is present.
    fn is_present(&self, key: &str) -> bool;
}

#[cfg(not(target_os = "linux"))]
mod blob_cache {
    use super::*;

    pub struct BlobCacheMgr {}

    impl Default for BlobCacheMgr {
        fn default() -> Self {
            Self::new()
        }
    }

    impl BlobCacheMgr {
        pub fn new() -> Self {
            BlobCacheMgr {}
        }

        pub fn add_blob_list(&self, _blobs: &nydus_api::BlobCacheList) -> io::Result<()> {
            unimplemented!()
        }

        pub fn add_blob_entry(&self, _entry: &nydus_api::BlobCacheEntry) -> Result<()> {
            unimplemented!()
        }

        pub fn remove_blob_entry(&self, _param: &nydus_api::BlobCacheObjectId) -> Result<()> {
            unimplemented!()
        }
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

// Copyright 2021 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Online upgrade manager for Nydus daemons and filesystems.

use std::convert::{TryFrom, TryInto};
use std::path::PathBuf;

use crate::fs_service::{FsBackendMountCmd, FsBackendUmountCmd};
use crate::Result;

/// Error codes related to upgrade manager.
#[derive(thiserror::Error, Debug)]
pub enum UpgradeMgrError {}

/// FUSE fail-over policies.
#[derive(PartialEq, Eq)]
pub enum FailoverPolicy {
    /// Flush pending requests.
    Flush,
    /// Resend pending requests.
    Resend,
}

impl TryFrom<&str> for FailoverPolicy {
    type Error = std::io::Error;

    fn try_from(p: &str) -> std::result::Result<Self, Self::Error> {
        match p {
            "flush" => Ok(FailoverPolicy::Flush),
            "resend" => Ok(FailoverPolicy::Resend),
            x => Err(einval!(format!("invalid FUSE fail-over mode {}", x))),
        }
    }
}

impl TryFrom<&String> for FailoverPolicy {
    type Error = std::io::Error;

    fn try_from(p: &String) -> std::result::Result<Self, Self::Error> {
        p.as_str().try_into()
    }
}

/// Online upgrade manager.
pub struct UpgradeManager {}

impl UpgradeManager {
    /// Create a new instance of [UpgradeManager].
    pub fn new(_: PathBuf) -> Self {
        UpgradeManager {}
    }

    /// Add a filesystem instance into the upgrade manager.
    pub fn add_mounts_state(&mut self, _cmd: FsBackendMountCmd, _vfs_index: u8) -> Result<()> {
        Ok(())
    }

    /// Update a filesystem instance in the upgrade manager.
    pub fn update_mounts_state(&mut self, _cmd: FsBackendMountCmd) -> Result<()> {
        Ok(())
    }

    /// Remove a filesystem instance from the upgrade manager.
    pub fn remove_mounts_state(&mut self, _cmd: FsBackendUmountCmd) -> Result<()> {
        Ok(())
    }

    /// Disable online upgrade capability.
    pub fn disable_upgrade(&mut self) {}
}

/// Online upgrade utilities for FUSE daemon.
pub mod fusedev_upgrade {
    use super::*;
    use crate::fusedev::FusedevDaemon;

    /// Save state information for a FUSE daemon.
    pub fn save(_daemon: &FusedevDaemon) -> Result<()> {
        Ok(())
    }

    /// Restore state information for a FUSE daemon.
    pub fn restore(_daemon: &FusedevDaemon) -> Result<()> {
        Ok(())
    }
}

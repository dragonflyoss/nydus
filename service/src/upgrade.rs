// Copyright 2021 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Online upgrade manager for Nydus daemons and filesystems.

use std::any::TypeId;
use std::collections::HashMap;
use std::convert::{TryFrom, TryInto};
use std::io;
use std::os::fd::RawFd;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};

use nydus_upgrade::backend::unix_domain_socket::UdsStorageBackend;
use nydus_upgrade::backend::{StorageBackend, StorageBackendErr};

use crate::fs_service::{FsBackendMountCmd, FsBackendUmountCmd};
use crate::{Error, Result};

/// Error codes related to upgrade manager.
#[derive(thiserror::Error, Debug)]
pub enum UpgradeMgrError {
    #[error("missing supervisor path")]
    MissingSupervisorPath,

    #[error("failed to save/restore data via the backend, {0}")]
    StorageBackendError(StorageBackendErr),

    #[error("failed to serialize, {0}")]
    Serialize(io::Error),
    #[error("failed to deserialize, {0}")]
    Deserialize(io::Error),
}

impl From<UpgradeMgrError> for Error {
    fn from(e: UpgradeMgrError) -> Self {
        Error::UpgradeManager(e)
    }
}

/// FUSE fail-over policies.
#[derive(PartialEq, Eq, Debug)]
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

const MAX_STATE_DATA_LENGTH: usize = 1024 * 32;

/// Online upgrade manager.
pub struct UpgradeManager {
    // backend_mount_cmd_map records the mount command of each backend filesystem.
    // the structure is: mountpoint -> (FsBackendMountCmd, vfs_index)
    backend_mount_cmd_map: HashMap<String, (FsBackendMountCmd, u8)>,
    fds: Vec<RawFd>,
    backend: Box<dyn StorageBackend>,

    disabled: AtomicBool,
}

impl UpgradeManager {
    /// Create a new instance of [UpgradeManager].
    pub fn new(socket_path: PathBuf) -> Self {
        UpgradeManager {
            backend_mount_cmd_map: HashMap::new(),
            backend: Box::new(UdsStorageBackend::new(socket_path)),
            fds: Vec::new(),
            disabled: AtomicBool::new(false),
        }
    }

    /// Add a filesystem instance into the upgrade manager.
    pub fn add_mounts_state(&mut self, cmd: FsBackendMountCmd, vfs_index: u8) -> Result<()> {
        if self.disabled.load(Ordering::Acquire) {
            return Err(Error::Unsupported);
        }

        let cmd_map = &mut self.backend_mount_cmd_map;
        if cmd_map.contains_key(&cmd.mountpoint) {
            return Err(Error::AlreadyExists);
        }

        cmd_map.insert(cmd.mountpoint.clone(), (cmd, vfs_index));
        Ok(())
    }

    /// Update a filesystem instance in the upgrade manager.
    pub fn update_mounts_state(&mut self, cmd: FsBackendMountCmd) -> Result<()> {
        if self.disabled.load(Ordering::Acquire) {
            return Err(Error::Unsupported);
        }

        let cmd_map = &mut self.backend_mount_cmd_map;
        match cmd_map.get_mut(&cmd.mountpoint) {
            Some(cmd_with_vfs_idx) => {
                cmd_with_vfs_idx.0 = cmd;
                Ok(())
            }
            None => Err(Error::NotFound),
        }
    }

    /// Remove a filesystem instance from the upgrade manager.
    pub fn remove_mounts_state(&mut self, cmd: FsBackendUmountCmd) -> Result<()> {
        if self.disabled.load(Ordering::Acquire) {
            return Err(Error::Unsupported);
        }

        let cmd_map = &mut self.backend_mount_cmd_map;
        match cmd_map.get_mut(&cmd.mountpoint) {
            Some(_) => {
                cmd_map.remove(&cmd.mountpoint);
                Ok(())
            }
            None => Err(Error::NotFound),
        }
    }

    /// Disable online upgrade capability.
    pub fn disable_upgrade(&mut self) {
        self.disabled.store(true, Ordering::Release);
    }

    /// Save the fuse fds and fuse state data for online upgrade.
    fn save(&mut self, data: &Vec<u8>) -> Result<()> {
        self.backend
            .save(&self.fds, data)
            .map_err(UpgradeMgrError::StorageBackendError)?;
        Ok(())
    }

    /// Restore the fuse fds and fuse state data for online upgrade.
    fn restore(&mut self) -> Result<Vec<u8>> {
        let mut fds = vec![0 as RawFd; 8];
        let mut state_data = vec![0u8; MAX_STATE_DATA_LENGTH];
        let (state_data_len, fds_len) = self
            .backend
            .restore(&mut fds, &mut state_data)
            .map_err(UpgradeMgrError::StorageBackendError)?;
        fds.truncate(fds_len);
        state_data.truncate(state_data_len);

        self.fds = fds;
        Ok(state_data)
    }

    fn add_fd(&mut self, fd: RawFd) {
        self.fds.push(fd);
    }
}

/// Online upgrade utilities for FUSE daemon.
pub mod fusedev_upgrade {
    use std::fs::File;
    use std::os::fd::{FromRawFd, RawFd};
    use std::os::unix::io::AsRawFd;
    use std::sync::atomic::Ordering;

    use nydus_upgrade::persist::Snapshotter;
    use versionize::{VersionMap, Versionize, VersionizeResult};
    use versionize_derive::Versionize;

    use super::*;
    use crate::daemon::NydusDaemon;
    use crate::fusedev::{FusedevDaemon, FusedevFsService};

    #[derive(Versionize, Clone, Default)]
    struct FusedevState {
        backend_fs_mount_cmd_list: Vec<(FsBackendMountCmd, u8)>,
        vfs_state_data: Vec<u8>,
        fuse_conn_id: u64,
    }

    impl Snapshotter for FusedevState {
        fn get_versions() -> Vec<HashMap<TypeId, u16>> {
            vec![
                // version 1
                HashMap::from([(FusedevState::type_id(), 1)]),
                // more versions for the future
            ]
        }
    }

    /// Save state information for a FUSE daemon.
    pub fn save(daemon: &FusedevDaemon) -> Result<()> {
        let svc = daemon.get_default_fs_service().ok_or(Error::NotFound)?;

        if !svc.get_vfs().initialized() {
            return Err(Error::NotReady);
        }

        let mut mgr = svc.upgrade_mgr().unwrap();

        // set fd
        let fd = svc
            .as_ref()
            .as_any()
            .downcast_ref::<FusedevFsService>()
            .unwrap()
            .session
            .lock()
            .unwrap()
            .get_fuse_file()
            .unwrap()
            .as_raw_fd();
        mgr.add_fd(fd);

        // save vfs state
        let vfs_state_data = svc.get_vfs().save_to_bytes().map_err(|e| {
            let io_err = io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to save vfs state: {:?}", e),
            );
            UpgradeMgrError::Serialize(io_err)
        })?;

        let backend_fs_mount_cmd_list = mgr
            .backend_mount_cmd_map
            .iter()
            .map(|(_, (cmd, vfs_idx))| (cmd.clone(), *vfs_idx))
            .collect();

        let fuse_conn_id = svc
            .as_any()
            .downcast_ref::<FusedevFsService>()
            .unwrap()
            .conn
            .load(Ordering::Acquire);

        let state = FusedevState {
            backend_fs_mount_cmd_list,
            vfs_state_data,
            fuse_conn_id,
        };
        let state = state.save().map_err(UpgradeMgrError::Serialize)?;

        // save the mgr state via the backend in the mgr
        mgr.save(&state)?;

        Ok(())
    }

    /// Restore state information for a FUSE daemon.
    pub fn restore(daemon: &FusedevDaemon) -> Result<()> {
        if daemon.supervisor.is_none() {
            return Err(UpgradeMgrError::MissingSupervisorPath.into());
        }

        let svc = daemon.get_default_fs_service().ok_or(Error::NotFound)?;

        let mut mgr = svc.upgrade_mgr().unwrap();

        // restore the mgr state via the backend in the mgr
        let mut state_data = mgr.restore()?;

        let mut state =
            FusedevState::restore(&mut state_data).map_err(UpgradeMgrError::Deserialize)?;

        // restore the backend fs mount cmd map
        state
            .backend_fs_mount_cmd_list
            .iter()
            .for_each(|(cmd, vfs_idx)| {
                mgr.backend_mount_cmd_map
                    .insert(cmd.mountpoint.clone(), (cmd.clone(), *vfs_idx));
            });

        // restore the fuse daemon
        svc.as_any()
            .downcast_ref::<FusedevFsService>()
            .unwrap()
            .conn
            .store(state.fuse_conn_id, Ordering::Release);

        // restore fuse fd
        svc.as_any()
            .downcast_ref::<FusedevFsService>()
            .unwrap()
            .session
            .lock()
            .unwrap()
            .set_fuse_file(unsafe { File::from_raw_fd(mgr.fds[0] as RawFd) });

        // restore vfs
        svc.get_vfs()
            .restore_from_bytes(&mut state.vfs_state_data)?;
        state
            .backend_fs_mount_cmd_list
            .iter()
            .try_for_each(|(cmd, vfs_idx)| -> Result<()> {
                svc.restore_mount(cmd, *vfs_idx)?;
                // as we are in upgrade stage and obtain the lock, `unwrap` is safe here
                mgr.add_mounts_state(cmd.clone(), *vfs_idx).unwrap();
                Ok(())
            })?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_failover_policy() {
        assert_eq!(
            FailoverPolicy::try_from("flush").unwrap(),
            FailoverPolicy::Flush
        );
        assert_eq!(
            FailoverPolicy::try_from("resend").unwrap(),
            FailoverPolicy::Resend
        );

        let strs = vec!["flash", "Resend"];
        for s in strs.clone().into_iter() {
            assert!(FailoverPolicy::try_from(s).is_err());
        }

        let str = String::from("flush");
        assert_eq!(
            FailoverPolicy::try_from(&str).unwrap(),
            FailoverPolicy::Flush
        );
        let str = String::from("resend");
        assert_eq!(
            FailoverPolicy::try_from(&str).unwrap(),
            FailoverPolicy::Resend
        );

        let strings: Vec<String> = strs.into_iter().map(|s| s.to_owned()).collect();
        for s in strings.iter() {
            assert!(FailoverPolicy::try_from(s).is_err());
        }
    }
}

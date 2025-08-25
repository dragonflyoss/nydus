// Copyright 2021 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Online upgrade manager for Nydus daemons and filesystems.

use std::any::TypeId;
use std::collections::HashMap;
use std::convert::{TryFrom, TryInto};
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd};
use std::path::PathBuf;

use nydus_api::BlobCacheEntry;
use nydus_upgrade::backend::unix_domain_socket::UdsStorageBackend;
use nydus_upgrade::backend::{StorageBackend, StorageBackendErr};

use crate::fs_service::{FsBackendMountCmd, FsBackendUmountCmd};
use crate::{Error, Result};
use fuse_backend_rs::api::Vfs;
use versionize::{VersionMap, Versionize, VersionizeResult};
use versionize_derive::Versionize;

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
    #[error("failed to clone file, {0}")]
    CloneFile(io::Error),
    #[error("failed to initialize fscache driver, {0}")]
    InitializeFscache(io::Error),
}

impl From<UpgradeMgrError> for Error {
    fn from(e: UpgradeMgrError) -> Self {
        Error::UpgradeManager(e)
    }
}

/// FUSE fail-over policies.
#[derive(PartialEq, Eq, Debug)]
pub enum FailoverPolicy {
    /// Do nothing.
    None,
    /// Flush pending requests.
    Flush,
    /// Resend pending requests.
    Resend,
}

impl TryFrom<&str> for FailoverPolicy {
    type Error = std::io::Error;

    fn try_from(p: &str) -> std::result::Result<Self, Self::Error> {
        match p {
            "none" => Ok(FailoverPolicy::None),
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

struct FscacheState {
    blob_entry_map: HashMap<String, BlobCacheEntry>,
    threads: usize,
    path: String,
}

#[derive(Versionize, Clone, Debug)]
struct MountStateWrapper {
    cmd: FsBackendMountCmd,
    vfs_index: u8,
}

struct FusedevState {
    fs_mount_cmd_map: HashMap<String, MountStateWrapper>,
    vfs_state_data: Vec<u8>,
    fuse_conn_id: u64,
}

/// Online upgrade manager.
pub struct UpgradeManager {
    fscache_deamon_stat: FscacheState,
    fuse_deamon_stat: FusedevState,
    file: Option<File>,
    backend: Box<dyn StorageBackend>,
}

impl UpgradeManager {
    /// Create a new instance of [UpgradeManager].
    pub fn new(socket_path: PathBuf) -> Self {
        UpgradeManager {
            fscache_deamon_stat: FscacheState {
                blob_entry_map: HashMap::new(),
                threads: 1,
                path: "".to_string(),
            },
            fuse_deamon_stat: FusedevState {
                fs_mount_cmd_map: HashMap::new(),
                vfs_state_data: vec![],
                fuse_conn_id: 0,
            },
            file: None,
            backend: Box::new(UdsStorageBackend::new(socket_path)),
        }
    }
    pub fn add_blob_entry_state(&mut self, entry: BlobCacheEntry) {
        let mut blob_state_id = entry.domain_id.to_string();
        blob_state_id.push('/');
        blob_state_id.push_str(&entry.blob_id);

        self.fscache_deamon_stat
            .blob_entry_map
            .insert(blob_state_id, entry);
    }

    pub fn remove_blob_entry_state(&mut self, domain_id: &str, blob_id: &str) {
        let mut blob_state_id = domain_id.to_string();
        blob_state_id.push('/');
        // for no shared domain mode, snapshotter will call unbind without blob_id
        if !blob_id.is_empty() {
            blob_state_id.push_str(blob_id);
        } else {
            blob_state_id.push_str(domain_id);
        }

        if self
            .fscache_deamon_stat
            .blob_entry_map
            .remove(&blob_state_id)
            .is_none()
        {
            warn!("blob {}: state was not saved before!", blob_state_id)
        }
    }

    pub fn save_fscache_states(&mut self, threads: usize, path: String) {
        self.fscache_deamon_stat.path = path;
        self.fscache_deamon_stat.threads = threads;
    }

    pub fn save_fuse_cid(&mut self, fuse_conn_id: u64) {
        self.fuse_deamon_stat.fuse_conn_id = fuse_conn_id;
    }

    pub fn save_vfs_stat(&mut self, vfs: &Vfs) -> Result<()> {
        let vfs_state_data = vfs.save_to_bytes().map_err(|e| {
            let io_err = io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to save vfs state: {:?}", e),
            );
            UpgradeMgrError::Serialize(io_err)
        })?;
        self.fuse_deamon_stat.vfs_state_data = vfs_state_data;
        Ok(())
    }

    /// Add a filesystem instance into the upgrade manager.
    pub fn add_mounts_state(&mut self, cmd: FsBackendMountCmd, vfs_index: u8) {
        let cmd_wrapper = MountStateWrapper {
            cmd: cmd.clone(),
            vfs_index,
        };
        self.fuse_deamon_stat
            .fs_mount_cmd_map
            .insert(cmd.mountpoint, cmd_wrapper);
    }

    /// Update a filesystem instance in the upgrade manager.
    pub fn update_mounts_state(&mut self, cmd: FsBackendMountCmd) -> Result<()> {
        match self
            .fuse_deamon_stat
            .fs_mount_cmd_map
            .get_mut(&cmd.mountpoint)
        {
            Some(cmd_wrapper) => {
                cmd_wrapper.cmd = cmd;
                Ok(())
            }
            None => Err(Error::NotFound),
        }
    }

    /// Remove a filesystem instance from the upgrade manager.
    pub fn remove_mounts_state(&mut self, cmd: FsBackendUmountCmd) {
        if self
            .fuse_deamon_stat
            .fs_mount_cmd_map
            .remove(&cmd.mountpoint)
            .is_none()
        {
            warn!(
                "mount state for {}: state was not saved before!",
                cmd.mountpoint
            )
        }
    }

    /// Save the fd and daemon state data for online upgrade.
    fn save(&mut self, data: &[u8]) -> Result<()> {
        let mut fds = Vec::new();
        if let Some(ref f) = self.file {
            fds.push(f.as_raw_fd())
        }

        self.backend
            .save(&fds, data)
            .map_err(UpgradeMgrError::StorageBackendError)?;
        Ok(())
    }

    /// Restore the fd and daemon state data for online upgrade.
    fn restore(&mut self) -> Result<Vec<u8>> {
        let (fds, state_data) = self
            .backend
            .restore()
            .map_err(UpgradeMgrError::StorageBackendError)?;
        if fds.len() != 1 {
            warn!("Too many fds {}, we may not correctly handle it", fds.len());
        }
        self.file = Some(unsafe { File::from_raw_fd(fds[0]) });
        Ok(state_data)
    }

    pub fn hold_file(&mut self, fd: &File) -> Result<()> {
        let f = fd.try_clone().map_err(UpgradeMgrError::CloneFile)?;
        self.file = Some(f);

        Ok(())
    }

    pub fn return_file(&mut self) -> Option<File> {
        if let Some(ref f) = self.file {
            // Basically, this can hardly fail.
            f.try_clone()
                .map_err(|e| {
                    error!("Clone file error, {}", e);
                    e
                })
                .ok()
        } else {
            warn!("No file can be returned");
            None
        }
    }
}
#[cfg(target_os = "linux")]
/// Online upgrade utilities for fscache daemon.
pub mod fscache_upgrade {
    use std::convert::TryFrom;
    use std::str::FromStr;

    use super::*;
    use crate::daemon::NydusDaemon;
    use crate::singleton::ServiceController;
    use nydus_upgrade::persist::Snapshotter;
    use versionize::{VersionMap, Versionize, VersionizeResult};
    use versionize_derive::Versionize;

    #[derive(Versionize, Clone, Debug)]
    pub struct BlobCacheEntryState {
        json_str: String,
    }

    #[derive(Versionize, Clone, Default, Debug)]
    pub struct FscacheBackendState {
        blob_entry_list: Vec<(String, BlobCacheEntryState)>,
        threads: usize,
        path: String,
    }

    impl Snapshotter for FscacheBackendState {
        fn get_versions() -> Vec<HashMap<TypeId, u16>> {
            vec![
                // version 1
                HashMap::from([(FscacheBackendState::type_id(), 1)]),
                // more versions for the future
            ]
        }
    }

    impl TryFrom<&FscacheBackendState> for FscacheState {
        type Error = std::io::Error;
        fn try_from(backend_stat: &FscacheBackendState) -> std::result::Result<Self, Self::Error> {
            let mut map = HashMap::new();
            for (id, entry_stat) in &backend_stat.blob_entry_list {
                let entry = BlobCacheEntry::from_str(&entry_stat.json_str)?;
                map.insert(id.to_string(), entry);
            }
            Ok(FscacheState {
                blob_entry_map: map,
                threads: backend_stat.threads,
                path: backend_stat.path.clone(),
            })
        }
    }

    impl TryFrom<&FscacheState> for FscacheBackendState {
        type Error = std::io::Error;
        fn try_from(stat: &FscacheState) -> std::result::Result<Self, Self::Error> {
            let mut list = Vec::new();
            for (id, entry) in &stat.blob_entry_map {
                let entry_stat = serde_json::to_string(&entry)?;
                list.push((
                    id.to_string(),
                    BlobCacheEntryState {
                        json_str: entry_stat,
                    },
                ));
            }
            Ok(FscacheBackendState {
                blob_entry_list: list,
                threads: stat.threads,
                path: stat.path.clone(),
            })
        }
    }

    pub fn save(daemon: &ServiceController) -> Result<()> {
        if let Some(mut mgr) = daemon.upgrade_mgr() {
            let backend_stat = FscacheBackendState::try_from(&mgr.fscache_deamon_stat)
                .map_err(UpgradeMgrError::Serialize)?;
            let stat = backend_stat.save().map_err(UpgradeMgrError::Serialize)?;
            mgr.save(&stat)?;
        }
        Ok(())
    }

    pub fn restore(daemon: &ServiceController) -> Result<()> {
        if let Some(mut mgr) = daemon.upgrade_mgr() {
            if let Some(blob_mgr) = daemon.get_blob_cache_mgr() {
                // restore the mgr state via the backend in the mgr
                let mut state_data = mgr.restore()?;

                let backend_stat = FscacheBackendState::restore(&mut state_data)
                    .map_err(UpgradeMgrError::Deserialize)?;

                let stat =
                    FscacheState::try_from(&backend_stat).map_err(UpgradeMgrError::Deserialize)?;
                // restore blob entry
                stat.blob_entry_map
                    .iter()
                    .try_for_each(|(_, entry)| -> Result<()> {
                        blob_mgr
                            .add_blob_entry(entry)
                            .map_err(UpgradeMgrError::Deserialize)?;
                        Ok(())
                    })?;

                // init fscache daemon with restored fd
                if let Some(f) = mgr.return_file() {
                    daemon
                        .initialize_fscache_service(None, stat.threads, &stat.path, Some(&f))
                        .map_err(UpgradeMgrError::InitializeFscache)?;
                }

                //restore upgrade manager fscache stat
                mgr.fscache_deamon_stat = stat;
                return Ok(());
            }
        }
        Err(UpgradeMgrError::MissingSupervisorPath.into())
    }
}

/// Online upgrade utilities for FUSE daemon.
pub mod fusedev_upgrade {
    use std::sync::atomic::Ordering;

    use super::*;
    use crate::daemon::NydusDaemon;
    use crate::fusedev::{FusedevDaemon, FusedevFsService};
    use nydus_upgrade::persist::Snapshotter;
    use versionize::{VersionMap, Versionize, VersionizeResult};
    use versionize_derive::Versionize;

    #[derive(Versionize, Clone, Default, Debug)]
    pub struct FusedevBackendState {
        fs_mount_cmd_list: Vec<(String, MountStateWrapper)>,
        vfs_state_data: Vec<u8>,
        fuse_conn_id: u64,
    }

    impl Snapshotter for FusedevBackendState {
        fn get_versions() -> Vec<HashMap<TypeId, u16>> {
            vec![
                // version 1
                HashMap::from([(FusedevBackendState::type_id(), 1)]),
                // more versions for the future
            ]
        }
    }

    impl From<&FusedevBackendState> for FusedevState {
        fn from(backend_stat: &FusedevBackendState) -> Self {
            let mut map = HashMap::new();
            for (mp, mw) in &backend_stat.fs_mount_cmd_list {
                map.insert(mp.to_string(), mw.clone());
            }
            FusedevState {
                fs_mount_cmd_map: map,
                vfs_state_data: backend_stat.vfs_state_data.clone(),
                fuse_conn_id: backend_stat.fuse_conn_id,
            }
        }
    }

    impl From<&FusedevState> for FusedevBackendState {
        fn from(stat: &FusedevState) -> Self {
            let mut list = Vec::new();
            for (mp, mw) in &stat.fs_mount_cmd_map {
                list.push((mp.to_string(), mw.clone()));
            }
            FusedevBackendState {
                fs_mount_cmd_list: list,
                vfs_state_data: stat.vfs_state_data.clone(),
                fuse_conn_id: stat.fuse_conn_id,
            }
        }
    }

    /// Save state information for a FUSE daemon.
    pub fn save(daemon: &FusedevDaemon) -> Result<()> {
        let svc = daemon.get_default_fs_service().ok_or(Error::NotFound)?;
        if !svc.get_vfs().initialized() {
            return Err(Error::NotReady);
        }

        let mut mgr = svc.upgrade_mgr().unwrap();
        let backend_stat = FusedevBackendState::from(&mgr.fuse_deamon_stat);

        let state = backend_stat.save().map_err(UpgradeMgrError::Serialize)?;
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

        let backend_state =
            FusedevBackendState::restore(&mut state_data).map_err(UpgradeMgrError::Deserialize)?;

        let mut state = FusedevState::from(&backend_state);

        // restore the fuse daemon
        svc.as_any()
            .downcast_ref::<FusedevFsService>()
            .unwrap()
            .conn
            .store(state.fuse_conn_id, Ordering::Release);

        // restore fuse fd
        if let Some(f) = mgr.return_file() {
            let fuse_svc = svc.as_any().downcast_ref::<FusedevFsService>().unwrap();
            fuse_svc.session.lock().unwrap().set_fuse_file(f);
            // do failover policy
            fuse_svc.do_failover()?;
        }

        // restore vfs
        svc.get_vfs()
            .restore_from_bytes(&mut state.vfs_state_data)?;
        state
            .fs_mount_cmd_map
            .iter()
            .try_for_each(|(_, mount_wrapper)| -> Result<()> {
                svc.restore_mount(&mount_wrapper.cmd, mount_wrapper.vfs_index)?;
                // as we are in upgrade stage and obtain the lock, `unwrap` is safe here
                //mgr.add_mounts_state(cmd.clone(), *vfs_idx);
                Ok(())
            })?;

        //restore upgrade manager fuse stat
        mgr.fuse_deamon_stat = state;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs_service::{FsBackendMountCmd, FsBackendUmountCmd};
    #[cfg(target_os = "linux")]
    use crate::upgrade::fscache_upgrade::FscacheBackendState;
    use crate::upgrade::fusedev_upgrade::FusedevBackendState;
    use crate::FsBackendType;
    use nydus_upgrade::persist::Snapshotter;
    use vmm_sys_util::tempfile::TempFile;

    #[test]
    fn test_failover_policy() {
        assert_eq!(
            FailoverPolicy::try_from("none").unwrap(),
            FailoverPolicy::None
        );
        assert_eq!(
            FailoverPolicy::try_from("flush").unwrap(),
            FailoverPolicy::Flush
        );
        assert_eq!(
            FailoverPolicy::try_from("resend").unwrap(),
            FailoverPolicy::Resend
        );

        let strs = vec!["null", "flash", "Resend"];
        for s in strs.clone().into_iter() {
            assert!(FailoverPolicy::try_from(s).is_err());
        }

        let str = String::from("none");
        assert_eq!(
            FailoverPolicy::try_from(&str).unwrap(),
            FailoverPolicy::None
        );
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

    #[test]
    #[cfg(target_os = "linux")]
    fn test_upgrade_manager_for_fscache() {
        let mut upgrade_mgr = UpgradeManager::new("dummy_socket".into());

        let content = r#"{
            "type": "bootstrap",
            "id": "blob1",
            "config": {
                "id": "cache1",
                "backend_type": "localfs",
                "backend_config": {},
                "cache_type": "fscache",
                "cache_config": {},
                "metadata_path": "/tmp/metadata1"
            },
            "domain_id": "domain1"
        }"#;
        let entry: BlobCacheEntry = serde_json::from_str(content).unwrap();
        upgrade_mgr.save_fscache_states(4, "/tmp/fscache_dir".to_string());
        assert_eq!(upgrade_mgr.fscache_deamon_stat.threads, 4);
        assert_eq!(upgrade_mgr.fscache_deamon_stat.path, "/tmp/fscache_dir");

        upgrade_mgr.add_blob_entry_state(entry);
        assert!(upgrade_mgr
            .fscache_deamon_stat
            .blob_entry_map
            .contains_key("domain1/blob1"));

        assert!(FscacheBackendState::try_from(&upgrade_mgr.fscache_deamon_stat).is_ok());

        let backend_stat = FscacheBackendState::try_from(&upgrade_mgr.fscache_deamon_stat).unwrap();
        assert!(backend_stat.save().is_ok());
        assert!(FscacheState::try_from(&backend_stat).is_ok());
        let stat = FscacheState::try_from(&backend_stat).unwrap();
        assert_eq!(stat.path, upgrade_mgr.fscache_deamon_stat.path);
        assert_eq!(stat.threads, upgrade_mgr.fscache_deamon_stat.threads);
        assert!(stat.blob_entry_map.contains_key("domain1/blob1"));

        upgrade_mgr.remove_blob_entry_state("domain1", "blob1");
        assert!(!upgrade_mgr
            .fscache_deamon_stat
            .blob_entry_map
            .contains_key("domain1/blob1"));
    }

    #[test]
    fn test_upgrade_manager_for_fusedev() {
        let mut upgrade_mgr = UpgradeManager::new("dummy_socket".into());

        let config = r#"{
            "version": 2,
            "id": "factory1",
            "backend": {
                "type": "localfs",
                "localfs": {
                    "dir": "/tmp/nydus"
                }
            },
            "cache": {
                "type": "fscache",
                "fscache": {
                    "work_dir": "/tmp/nydus"
                }
            },
            "metadata_path": "/tmp/nydus/bootstrap1"
        }"#;
        let cmd = FsBackendMountCmd {
            fs_type: FsBackendType::Rafs,
            config: config.to_string(),
            mountpoint: "testmonutount".to_string(),
            source: "testsource".to_string(),
            prefetch_files: Some(vec!["testfile".to_string()]),
        };

        upgrade_mgr.save_fuse_cid(10);
        assert_eq!(upgrade_mgr.fuse_deamon_stat.fuse_conn_id, 10);
        upgrade_mgr.add_mounts_state(cmd.clone(), 5);
        assert!(upgrade_mgr
            .fuse_deamon_stat
            .fs_mount_cmd_map
            .contains_key("testmonutount"));
        assert!(upgrade_mgr.update_mounts_state(cmd).is_ok());

        let backend_stat = FusedevBackendState::from(&upgrade_mgr.fuse_deamon_stat);
        assert!(backend_stat.save().is_ok());

        let stat = FusedevState::from(&backend_stat);
        assert_eq!(stat.fuse_conn_id, upgrade_mgr.fuse_deamon_stat.fuse_conn_id);
        assert!(stat.fs_mount_cmd_map.contains_key("testmonutount"));

        let umount_cmd: FsBackendUmountCmd = FsBackendUmountCmd {
            mountpoint: "testmonutount".to_string(),
        };
        upgrade_mgr.remove_mounts_state(umount_cmd);
        assert!(!upgrade_mgr
            .fuse_deamon_stat
            .fs_mount_cmd_map
            .contains_key("testmonutount"));
    }

    #[test]
    fn test_upgrade_manager_hold_fd() {
        let mut upgrade_mgr = UpgradeManager::new("dummy_socket".into());

        let temp = TempFile::new().unwrap().into_file();
        assert!(upgrade_mgr.hold_file(&temp).is_ok());
        assert!(upgrade_mgr.return_file().is_some());
    }
}

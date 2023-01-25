// Copyright (C) 2020-2022 Alibaba Cloud. All rights reserved.
// Copyright 2020 Ant Group. All rights reserved.
// Copyright 2019 Intel Corporation. All Rights Reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

use std::any::Any;
use std::collections::HashMap;
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Arc, MutexGuard};

use fuse_backend_rs::api::{BackFileSystem, Vfs};
#[cfg(target_os = "linux")]
use fuse_backend_rs::passthrough::{Config, PassthroughFs};
use nydus::{FsBackendDescriptor, FsBackendType};
use nydus_api::ConfigV2;
use nydus_rafs::fs::Rafs;
use nydus_rafs::{RafsError, RafsIoRead};
use nydus_storage::factory::BLOB_FACTORY;
use serde::{self, Deserialize, Serialize};

use crate::daemon::DaemonResult;
use crate::upgrade::{self, UpgradeManager};
use crate::DaemonError;

/// Command to mount a filesystem.
#[derive(Clone)]
pub struct FsBackendMountCmd {
    pub fs_type: FsBackendType,
    pub source: String,
    pub config: String,
    pub mountpoint: String,
    pub prefetch_files: Option<Vec<String>>,
}

/// Command to unmount a filesystem.
#[derive(Clone, Deserialize, Serialize, Debug)]
pub struct FsBackendUmountCmd {
    pub mountpoint: String,
}

/// List of filesystem backend information.
#[derive(Default, Serialize, Clone)]
pub struct FsBackendCollection(HashMap<String, FsBackendDescriptor>);

impl FsBackendCollection {
    pub fn add(&mut self, id: &str, cmd: &FsBackendMountCmd) -> DaemonResult<()> {
        // We only wash Rafs backend now.
        let fs_config = match cmd.fs_type {
            FsBackendType::Rafs => {
                let cfg = ConfigV2::from_str(&cmd.config)
                    .map_err(|e| DaemonError::InvalidConfig(format!("{}", e)))?;
                let cfg = cfg.clone_without_secrets();
                Some(cfg)
            }
            FsBackendType::PassthroughFs => {
                // Passthrough Fs has no config ever input.
                None
            }
        };

        let desc = FsBackendDescriptor {
            backend_type: cmd.fs_type.clone(),
            mountpoint: cmd.mountpoint.clone(),
            mounted_time: time::OffsetDateTime::now_utc(),
            config: fs_config,
        };

        self.0.insert(id.to_string(), desc);

        Ok(())
    }

    pub fn del(&mut self, id: &str) {
        self.0.remove(id);
    }
}

/// Define services provided by a filesystem provider.
pub trait FsService: Send + Sync {
    fn get_vfs(&self) -> &Vfs;
    fn upgrade_mgr(&self) -> Option<MutexGuard<UpgradeManager>>;
    fn backend_collection(&self) -> MutexGuard<FsBackendCollection>;

    // NOTE: This method is not thread-safe, however, it is acceptable as
    // mount/umount/remount/restore_mount is invoked from single thread in FSM
    fn mount(&self, cmd: FsBackendMountCmd) -> DaemonResult<()> {
        if self.backend_from_mountpoint(&cmd.mountpoint)?.is_some() {
            return Err(DaemonError::AlreadyExists);
        }
        let backend = fs_backend_factory(&cmd)?;
        let index = self.get_vfs().mount(backend, &cmd.mountpoint)?;
        info!("{} filesystem mounted at {}", &cmd.fs_type, &cmd.mountpoint);
        self.backend_collection().add(&cmd.mountpoint, &cmd)?;

        // Add mounts opaque to UpgradeManager
        if let Some(mut mgr_guard) = self.upgrade_mgr() {
            upgrade::add_mounts_state(&mut mgr_guard, cmd, index)?;
        }

        Ok(())
    }

    fn remount(&self, cmd: FsBackendMountCmd) -> DaemonResult<()> {
        let rootfs = self
            .backend_from_mountpoint(&cmd.mountpoint)?
            .ok_or(DaemonError::NotFound)?;
        let mut bootstrap = <dyn RafsIoRead>::from_file(&&cmd.source)?;
        let any_fs = rootfs.deref().as_any();
        let rafs = any_fs
            .downcast_ref::<Rafs>()
            .ok_or_else(|| DaemonError::FsTypeMismatch("to rafs".to_string()))?;
        let rafs_cfg = ConfigV2::from_str(&cmd.config).map_err(RafsError::LoadConfig)?;
        let rafs_cfg = Arc::new(rafs_cfg);

        rafs.update(&mut bootstrap, &rafs_cfg)
            .map_err(|e| match e {
                RafsError::Unsupported => DaemonError::Unsupported,
                e => DaemonError::Rafs(e),
            })?;

        // To update mounted time and backend configurations.
        self.backend_collection().add(&cmd.mountpoint, &cmd)?;

        // Update mounts opaque from UpgradeManager
        if let Some(mut mgr_guard) = self.upgrade_mgr() {
            upgrade::update_mounts_state(&mut mgr_guard, cmd)?;
        }

        Ok(())
    }

    fn umount(&self, cmd: FsBackendUmountCmd) -> DaemonResult<()> {
        let _ = self
            .backend_from_mountpoint(&cmd.mountpoint)?
            .ok_or(DaemonError::NotFound)?;

        self.get_vfs().umount(&cmd.mountpoint)?;
        self.backend_collection().del(&cmd.mountpoint);
        if let Some(mut mgr_guard) = self.upgrade_mgr() {
            // Remove mount opaque from UpgradeManager
            upgrade::remove_mounts_state(&mut mgr_guard, cmd)?;
        }

        debug!("try to gc unused blobs");
        BLOB_FACTORY.gc(None);

        Ok(())
    }

    fn backend_from_mountpoint(&self, mp: &str) -> DaemonResult<Option<Arc<BackFileSystem>>> {
        self.get_vfs().get_rootfs(mp).map_err(|e| e.into())
    }

    fn export_backend_info(&self, mountpoint: &str) -> DaemonResult<String> {
        let fs = self
            .backend_from_mountpoint(mountpoint)?
            .ok_or(DaemonError::NotFound)?;
        let any_fs = fs.deref().as_any();
        let rafs = any_fs
            .downcast_ref::<Rafs>()
            .ok_or_else(|| DaemonError::FsTypeMismatch("to rafs".to_string()))?;
        let resp = serde_json::to_string(rafs.metadata()).map_err(DaemonError::Serde)?;
        Ok(resp)
    }

    fn export_inflight_ops(&self) -> DaemonResult<Option<String>>;

    /// Provides a reference to the Any trait. This is useful to let the call access the underlying fs service.
    fn as_any(&self) -> &dyn Any;
}

/// Validate prefetch file list from user input.
///
/// Validation rules:
/// - an item may be file or directroy.
/// - items must be separated by space, such as "<path1> <path2> <path3>".
/// - each item must be absolute path, such as "/foo1/bar1 /foo2/bar2".
fn validate_prefetch_file_list(input: &Option<Vec<String>>) -> DaemonResult<Option<Vec<PathBuf>>> {
    if let Some(list) = input {
        let list: Vec<PathBuf> = list.iter().map(PathBuf::from).collect();
        for elem in list.iter() {
            if !elem.is_absolute() {
                return Err(DaemonError::Common("Illegal prefetch list".to_string()));
            }
        }
        Ok(Some(list))
    } else {
        Ok(None)
    }
}

pub fn fs_backend_factory(cmd: &FsBackendMountCmd) -> DaemonResult<BackFileSystem> {
    let prefetch_files = validate_prefetch_file_list(&cmd.prefetch_files)?;

    match cmd.fs_type {
        FsBackendType::Rafs => {
            let config = ConfigV2::from_str(cmd.config.as_str()).map_err(RafsError::LoadConfig)?;
            let config = Arc::new(config);
            let (mut rafs, reader) = Rafs::new(&config, &cmd.mountpoint, Path::new(&cmd.source))?;
            rafs.import(reader, prefetch_files)?;
            info!("RAFS filesystem imported");
            Ok(Box::new(rafs))
        }
        FsBackendType::PassthroughFs => {
            #[cfg(target_os = "macos")]
            return Err(DaemonError::InvalidArguments(String::from(
                "not support passthroughfs",
            )));
            #[cfg(target_os = "linux")]
            {
                // Vfs by default enables no_open and writeback, passthroughfs
                // needs to specify them explicitly.
                // TODO(liubo): enable no_open_dir.
                let fs_cfg = Config {
                    root_dir: cmd.source.to_string(),
                    do_import: false,
                    writeback: true,
                    no_open: true,
                    xattr: true,
                    ..Default::default()
                };
                // TODO: Passthrough Fs needs to enlarge rlimit against host. We can exploit `MountCmd`
                // `config` field to pass such a configuration into here.
                let passthrough_fs =
                    PassthroughFs::<()>::new(fs_cfg).map_err(DaemonError::PassthroughFs)?;
                passthrough_fs
                    .import()
                    .map_err(DaemonError::PassthroughFs)?;
                info!("PassthroughFs imported");
                Ok(Box::new(passthrough_fs))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_should_add_new_backend() {
        let mut col: FsBackendCollection = Default::default();
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
        let r = col.add(
            "test",
            &FsBackendMountCmd {
                fs_type: FsBackendType::Rafs,
                config: config.to_string(),
                mountpoint: "testmonutount".to_string(),
                source: "testsource".to_string(),
                prefetch_files: Some(vec!["testfile".to_string()]),
            },
        );
        assert!(r.is_ok(), "failed to add backend collection");

        assert_eq!(col.0.len(), 1);

        col.del("test");
        assert_eq!(col.0.len(), 0);
    }

    #[test]
    fn it_should_verify_prefetch_files() {
        let files = validate_prefetch_file_list(&Some(vec!["/etc/passwd".to_string()]));
        assert!(files.is_ok(), "failed to verify prefetch files");
        assert_eq!(1, files.unwrap().unwrap().len());

        assert!(
            validate_prefetch_file_list(&Some(vec!["etc/passwd".to_string()])).is_err(),
            "should not pass verify"
        );
    }

    #[test]
    fn it_should_create_rafs_backend() {
        let config = r#"
        {
            "device": {
              "backend": {
                "type": "oss",
                "config": {
                  "endpoint": "test",
                  "access_key_id": "test",
                  "access_key_secret": "test",
                  "bucket_name": "antsys-nydus",
                  "object_prefix":"nydus_v2/",
                  "scheme": "http"
                }
              }
            },
            "mode": "direct",
            "digest_validate": false,
            "enable_xattr": true,
            "fs_prefetch": {
              "enable": true,
              "threads_count": 10,
              "merging_size": 131072,
              "bandwidth_rate": 10485760
            }
          }"#;
        let bootstrap = "./tests/texture/bootstrap/nydusd_daemon_test_bootstrap";
        if fs_backend_factory(&FsBackendMountCmd {
            fs_type: FsBackendType::Rafs,
            config: config.to_string(),
            mountpoint: "testmountpoint".to_string(),
            source: bootstrap.to_string(),
            prefetch_files: Some(vec!["/testfile".to_string()]),
        })
        .unwrap()
        .as_any()
        .downcast_ref::<Rafs>()
        .is_none()
        {
            panic!("failed to create rafs backend")
        }
    }
}

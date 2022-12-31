use std::convert::TryFrom;
use std::path::PathBuf;

use nydus::Result;

use crate::fs_service::FsBackendUmountCmd;
use crate::FsBackendMountCmd;

pub struct UpgradeManager {}

impl UpgradeManager {
    pub fn new(_: PathBuf) -> Self {
        UpgradeManager {}
    }
}

#[derive(PartialEq)]
pub enum FailoverPolicy {
    Flush,
    Resend,
}

impl TryFrom<&str> for FailoverPolicy {
    type Error = std::io::Error;

    fn try_from(p: &str) -> std::result::Result<Self, Self::Error> {
        match p {
            "flush" => Ok(FailoverPolicy::Flush),
            "resend" => Ok(FailoverPolicy::Resend),
            x => Err(einval!(x)),
        }
    }
}

impl TryFrom<&String> for FailoverPolicy {
    type Error = std::io::Error;

    fn try_from(p: &String) -> std::result::Result<Self, Self::Error> {
        match p.as_ref() {
            "flush" => Ok(FailoverPolicy::Flush),
            "resend" => Ok(FailoverPolicy::Resend),
            x => Err(einval!(x)),
        }
    }
}

pub fn add_mounts_state(
    _mgr: &mut UpgradeManager,
    _cmd: FsBackendMountCmd,
    _vfs_index: u8,
) -> Result<()> {
    Ok(())
}

pub fn update_mounts_state(_mgr: &mut UpgradeManager, _cmd: FsBackendMountCmd) -> Result<()> {
    Ok(())
}

pub fn remove_mounts_state(_mgr: &mut UpgradeManager, _cmd: FsBackendUmountCmd) -> Result<()> {
    Ok(())
}

pub mod fusedev_upgrade {
    use super::*;
    use crate::fusedev::FusedevDaemon;

    pub fn save(_daemon: &FusedevDaemon) -> Result<()> {
        Ok(())
    }

    pub fn restore(_daemon: &FusedevDaemon) -> Result<()> {
        Ok(())
    }
}

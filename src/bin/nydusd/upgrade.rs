use std::convert::TryFrom;
#[cfg(feature = "fusedev")]
use std::path::PathBuf;

use crate::daemon::{DaemonResult, FsBackendMountCmd, FsBackendUmountCmd};

#[derive(Debug)]
pub enum UpgradeMgrError {}
pub struct UpgradeManager {}

#[cfg(feature = "fusedev")]
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

pub fn add_mounts_state(
    _mgr: &mut UpgradeManager,
    _cmd: FsBackendMountCmd,
    _vfs_index: u8,
) -> DaemonResult<()> {
    Ok(())
}

pub fn update_mounts_state(_mgr: &mut UpgradeManager, _cmd: FsBackendMountCmd) -> DaemonResult<()> {
    Ok(())
}

pub fn remove_mounts_state(
    _mgr: &mut UpgradeManager,
    _cmd: FsBackendUmountCmd,
) -> DaemonResult<()> {
    Ok(())
}

#[cfg(feature = "fusedev")]
pub mod fusedev_upgrade {
    use crate::daemon::DaemonResult;
    use crate::fusedev::FusedevDaemon;
    pub fn save(_daemon: &FusedevDaemon) -> DaemonResult<()> {
        Ok(())
    }

    pub fn restore(_daemon: &FusedevDaemon) -> DaemonResult<()> {
        Ok(())
    }
}

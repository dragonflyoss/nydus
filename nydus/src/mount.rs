//! Mount helpers shared by the fanotify and NBD mount lifecycles.

use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use nydus_core::error::{Context, Error, Result};

/// NUL-check a path before handing it to a `mount(2)`-family syscall.
pub fn path_cstring(path: &Path, kind: &str) -> Result<CString> {
    CString::new(path.as_os_str().as_bytes()).map_err(|err| {
        Error::InvalidParameter(format!("{kind} path contains an interior NUL byte: {err}"))
    })
}

/// Unmount whatever is mounted at `mountpoint`. A plain `umount2(., 0)`; any
/// EBUSY retry loop lives in the caller.
pub fn unmount(mountpoint: &Path) -> Result<()> {
    let target = path_cstring(mountpoint, "mountpoint")?;
    let ret = unsafe { libc::umount2(target.as_ptr(), 0) };
    if ret < 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("failed to unmount {}", mountpoint.display()));
    }
    Ok(())
}

//! NBD block-device mount lifecycle.
//!
//! Unlike fanotify's file-backed multi-device EROFS mount (a bootstrap file as
//! the source plus repeated `device=` options), the NBD daemon exposes a
//! single block device `/dev/nbdX` carrying the whole flattened image, so
//! mounting is a plain `mount(2)` of that device at the target with the image's
//! filesystem type (EROFS for a nydus image). No loop device, no `device=`
//! options, no option-length budget.

use std::ffi::CString;
use std::path::Path;

use nydus_error::{Context, Error, Result};

use crate::mount::path_cstring;

/// Mount the NBD block device `device` at `mountpoint` as `fstype`, read-only.
///
/// Read-only because the daemon only ever writes to the core's cache files
/// through `fetch`, never through the NBD device; `MS_NODEV`/`MS_NOSUID` match
/// the fanotify EROFS mount policy for a content-addressed image.
pub fn mount_nbd(device: &str, mountpoint: &Path, fstype: &str) -> Result<()> {
    let source = CString::new(device).map_err(|err| {
        Error::InvalidParameter(format!("device path contains an interior NUL byte: {err}"))
    })?;
    let target = path_cstring(mountpoint, "mountpoint")?;
    let fs_type = CString::new(fstype).map_err(|err| {
        Error::InvalidParameter(format!(
            "fs type {fstype} contains an interior NUL byte: {err}"
        ))
    })?;

    let ret = unsafe {
        libc::mount(
            source.as_ptr(),
            target.as_ptr(),
            fs_type.as_ptr(),
            libc::MS_RDONLY | libc::MS_NODEV | libc::MS_NOSUID,
            std::ptr::null(),
        )
    };
    if ret < 0 {
        return Err(std::io::Error::last_os_error()).with_context(|| {
            format!(
                "failed to mount {device} at {} (type {fstype})",
                mountpoint.display()
            )
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mount_nbd_rejects_interior_nul_in_device_or_fstype() {
        let mp = Path::new("/mnt/x");
        assert!(mount_nbd("/dev/nbd\0bad", mp, "erofs").is_err());
        assert!(mount_nbd("/dev/nbd0", mp, "ero\0fs").is_err());
    }
}

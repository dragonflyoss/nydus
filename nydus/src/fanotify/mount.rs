//! EROFS file-backed mount lifecycle.
//!
//! A supporting kernel accepts a regular bootstrap file as the mount source and
//! regular decoded blob cache files through repeated `device=<path>` options.
//! No loop, NBD, or block-device attachment is required.

use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use anyhow::{Context, Result};

use super::core::BlobDevice;

/// The kernel copies `mount(2)` data into a single page (`copy_mount_options`),
/// so a longer option string is silently truncated — dropping `device=` slots
/// and failing the mount with a confusing EROFS error. Reject oversized option
/// strings up front instead. 4095 assumes 4 KiB pages (one byte reserved for
/// the terminating NUL); on larger-page kernels the check is merely
/// conservative.
const MOUNT_DATA_MAX: usize = 4095;

/// Mount the file-backed EROFS bootstrap with each blob cache file as a
/// `device=` option. Validates device slot order, option encodability, and
/// total option length before any syscall.
pub fn mount_erofs(bootstrap: &Path, devices: &[BlobDevice], mountpoint: &Path) -> Result<()> {
    let source = path_cstring(bootstrap, "bootstrap")?;
    let target = path_cstring(mountpoint, "mountpoint")?;
    let fs_type = CString::new("erofs").expect("static filesystem type has no NUL");
    let options = CString::new(mount_options(devices)?)
        .expect("mount option builder rejects interior NUL bytes");

    let ret = unsafe {
        libc::mount(
            source.as_ptr(),
            target.as_ptr(),
            fs_type.as_ptr(),
            libc::MS_RDONLY | libc::MS_NODEV | libc::MS_NOSUID,
            options.as_ptr().cast(),
        )
    };
    if ret < 0 {
        return Err(std::io::Error::last_os_error()).with_context(|| {
            format!(
                "failed to mount file-backed EROFS {} at {}",
                bootstrap.display(),
                mountpoint.display()
            )
        });
    }
    Ok(())
}

/// Unmount the EROFS at `mountpoint`.
pub fn unmount_erofs(mountpoint: &Path) -> Result<()> {
    let target = path_cstring(mountpoint, "mountpoint")?;
    let ret = unsafe { libc::umount2(target.as_ptr(), 0) };
    if ret < 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("failed to unmount {}", mountpoint.display()));
    }
    Ok(())
}

fn path_cstring(path: &Path, kind: &str) -> Result<CString> {
    CString::new(path.as_os_str().as_bytes())
        .with_context(|| format!("{kind} path contains an interior NUL byte"))
}

/// Build the binary mount data without lossy UTF-8 conversion. A comma in a
/// device path is rejected because the kernel option grammar cannot distinguish
/// it from the next mount option.
fn mount_options(devices: &[BlobDevice]) -> Result<Vec<u8>> {
    let mut options = b"ro".to_vec();
    let mut expected_index = 1u16;
    for device in devices {
        if device.index != expected_index {
            anyhow::bail!(
                "device slot {} is out of order; expected {}",
                device.index,
                expected_index
            );
        }
        expected_index = expected_index
            .checked_add(1)
            .context("EROFS device index overflow")?;

        let path = device.cache_path.as_os_str().as_bytes();
        if path.contains(&0) {
            anyhow::bail!("device path contains an interior NUL byte");
        }
        if path.contains(&b',') {
            anyhow::bail!(
                "device path contains a comma and cannot be encoded safely: {}",
                device.cache_path.display()
            );
        }
        options.extend_from_slice(b",device=");
        options.extend_from_slice(path);
    }
    if options.len() > MOUNT_DATA_MAX {
        anyhow::bail!(
            "mount options for {} devices are {} bytes, over the {} B mount(2) data limit; \
             use a shorter cache directory path",
            devices.len(),
            options.len(),
            MOUNT_DATA_MAX
        );
    }
    Ok(options)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::str::FromStr;

    use super::*;
    use crate::BlobID;

    fn device(index: u16, path: &str) -> BlobDevice {
        BlobDevice::for_test(
            index,
            BlobID::from_str(&format!("{index:064x}")).unwrap(),
            false,
            PathBuf::from(path),
            4096,
        )
    }

    #[test]
    fn options_preserve_slot_order_and_regular_paths() {
        let devices = [
            device(1, "/cache/a.blob.data"),
            device(2, "/cache/b.blob.data"),
        ];
        assert_eq!(
            mount_options(&devices).unwrap(),
            b"ro,device=/cache/a.blob.data,device=/cache/b.blob.data"
        );
    }

    #[test]
    fn options_reject_reordered_slots_and_commas() {
        assert!(mount_options(&[device(2, "/cache/a")]).is_err());
        assert!(mount_options(&[device(1, "/cache/a,b")]).is_err());
    }

    #[test]
    fn options_reject_oversized_mount_data() {
        let long_dir = format!("/cache/{}", "a".repeat(200));
        let devices: Vec<BlobDevice> = (1..=30)
            .map(|i| device(i, &format!("{long_dir}/{i}.blob.data")))
            .collect();
        let err = mount_options(&devices).unwrap_err();
        assert!(err.to_string().contains("mount(2) data limit"));
    }
}

// Copyright (C) 2021 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Provide structures and functions to open/close/access a filesystem instance.

use std::ffi::CStr;
use std::os::raw::c_char;
use std::path::Path;
use std::ptr::{null, null_mut};
use std::str::FromStr;
use std::sync::Arc;

use nydus_api::ConfigV2;
use nydus_rafs::fs::Rafs;

use crate::{cstr_to_str, set_errno, Inode};

/// Magic number for Nydus filesystem handle.
pub const NYDUS_FS_HANDLE_MAGIC: u64 = 0xedfc_3818_af03_5187;
/// Value representing an invalid Nydus filesystem handle.
pub const NYDUS_INVALID_FS_HANDLE: usize = 0;

/// Handle representing a Nydus filesystem object.
pub type NydusFsHandle = usize;

#[repr(C)]
pub(crate) struct FileSystemState {
    magic: u64,
    pub(crate) root_ino: Inode,
    pub(crate) rafs: Rafs,
}

impl FileSystemState {
    /// Caller needs to ensure the lifetime of returned reference.
    pub(crate) unsafe fn from_handle(hdl: NydusFsHandle) -> &'static mut Self {
        let fs = &mut *(hdl as *const FileSystemState as *mut FileSystemState);
        assert_eq!(fs.magic, NYDUS_FS_HANDLE_MAGIC);
        fs
    }

    /// Caller needs to ensure the lifetime of returned reference.
    pub(crate) unsafe fn try_from_handle(hdl: NydusFsHandle) -> Result<&'static mut Self, i32> {
        if hdl == null::<FileSystemState>() as usize {
            return Err(libc::EINVAL);
        }
        let fs = &mut *(hdl as *const FileSystemState as *mut FileSystemState);
        assert_eq!(fs.magic, NYDUS_FS_HANDLE_MAGIC);
        Ok(fs)
    }
}

fn fs_error_einval() -> NydusFsHandle {
    set_errno(libc::EINVAL);
    null_mut::<FileSystemState>() as NydusFsHandle
}

fn default_localfs_rafs_config(dir: &str) -> String {
    format!(
        r#"
        version = 2
        id = "my_id"
        [backend]
        type = "localfs"
        [backend.localfs]
        dir = "{}"
        [cache]
        type = "dummycache"
        [rafs]
        "#,
        dir
    )
}

fn do_nydus_open_rafs(bootstrap: &str, config: &str) -> NydusFsHandle {
    let cfg = match ConfigV2::from_str(config) {
        Ok(v) => v,
        Err(e) => {
            warn!("failed to parse configuration info: {}", e);
            return fs_error_einval();
        }
    };
    let cfg = Arc::new(cfg);
    let (mut rafs, reader) = match Rafs::new(&cfg, &cfg.id, Path::new(bootstrap)) {
        Err(e) => {
            warn!(
                "failed to open filesystem from bootstrap {}, {}",
                bootstrap, e
            );
            return fs_error_einval();
        }
        Ok(v) => v,
    };
    if let Err(e) = rafs.import(reader, None) {
        warn!("failed to import RAFS filesystem, {}", e);
        return fs_error_einval();
    }

    let root_ino = rafs.metadata().root_inode;
    let fs = Box::new(FileSystemState {
        magic: NYDUS_FS_HANDLE_MAGIC,
        root_ino,
        rafs,
    });
    Box::into_raw(fs) as NydusFsHandle
}

/// Open a RAFS filesystem and return a handle to the filesystem object.
///
/// The returned filesystem handle should be freed by calling `nydus_close_rafs()`, otherwise
/// it will cause memory leak.
///
/// # Safety
/// Caller needs to ensure `bootstrap` and `config` are valid, otherwise it may cause memory access
/// violation.
#[no_mangle]
pub unsafe extern "C" fn nydus_open_rafs(
    bootstrap: *const c_char,
    config: *const c_char,
) -> NydusFsHandle {
    if bootstrap.is_null() || config.is_null() {
        return fs_error_einval();
    }
    let bootstrap = cstr_to_str!(bootstrap, null_mut::<FileSystemState>() as NydusFsHandle);
    let config = cstr_to_str!(config, null_mut::<FileSystemState>() as NydusFsHandle);

    do_nydus_open_rafs(bootstrap, config)
}

/// Open a RAFS filesystem with default configuration and return a handle to the filesystem object.
///
/// The returned filesystem handle should be freed by calling `nydus_close_rafs()`, otherwise
/// it will cause memory leak.
///
/// # Safety
/// Caller needs to ensure `bootstrap` and `dir_path` are valid, otherwise it may cause memory
/// access violation.
#[no_mangle]
pub unsafe extern "C" fn nydus_open_rafs_default(
    bootstrap: *const c_char,
    dir_path: *const c_char,
) -> NydusFsHandle {
    if bootstrap.is_null() || dir_path.is_null() {
        return fs_error_einval();
    }
    let bootstrap = cstr_to_str!(bootstrap, null_mut::<FileSystemState>() as NydusFsHandle);
    let dir_path = cstr_to_str!(dir_path, null_mut::<FileSystemState>() as NydusFsHandle);

    let p_tmp;
    let mut path = Path::new(bootstrap);
    if path.parent().is_none() {
        p_tmp = Path::new(dir_path).join(bootstrap);
        path = &p_tmp
    }
    let bootstrap = match path.to_str() {
        Some(v) => v,
        None => {
            warn!("invalid bootstrap path '{}'", bootstrap);
            return fs_error_einval();
        }
    };
    let config = default_localfs_rafs_config(dir_path);

    do_nydus_open_rafs(bootstrap, &config)
}

/// Close the RAFS filesystem returned by `nydus_open_rafs()` and friends.
///
/// All `NydusFileHandle` objects created from the `NydusFsHandle` should be freed before calling
/// `nydus_close_rafs()`, otherwise it may cause panic.
///
/// # Safety
/// Caller needs to ensure `handle` is valid, otherwise it may cause memory access violation.
#[no_mangle]
pub unsafe extern "C" fn nydus_close_rafs(handle: NydusFsHandle) {
    let mut fs = Box::from_raw(handle as *mut FileSystemState);
    assert_eq!(fs.magic, NYDUS_FS_HANDLE_MAGIC);
    fs.magic -= 0x4fdf_03cd_ae34_9d9a;
    fs.rafs.destroy().unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;
    use std::io::Error;
    use std::path::PathBuf;
    use std::ptr::null;

    pub(crate) fn open_file_system() -> NydusFsHandle {
        let ret = unsafe { nydus_open_rafs(null(), null()) };
        assert_eq!(ret, NYDUS_INVALID_FS_HANDLE);
        assert_eq!(
            Error::raw_os_error(&Error::last_os_error()),
            Some(libc::EINVAL)
        );

        let root_dir = &std::env::var("CARGO_MANIFEST_DIR").expect("$CARGO_MANIFEST_DIR");
        let bootstrap = PathBuf::from(root_dir)
            .join("../tests/texture/repeatable/sha256-nocompress-repeatable");
        let bootstrap = bootstrap.to_str().unwrap();
        let bootstrap = CString::new(bootstrap).unwrap();
        let blob_dir = PathBuf::from(root_dir).join("../tests/texture/repeatable/blobs");

        let config = format!(
            r#"
        version = 2
        id = "my_id"
        [backend]
        type = "localfs"
        [backend.localfs]
        dir = "{}"
        [cache]
        type = "dummycache"
        [rafs]
        "#,
            blob_dir.display()
        );
        let config = CString::new(config).unwrap();
        let fs = unsafe {
            nydus_open_rafs(
                bootstrap.as_ptr() as *const c_char,
                config.as_ptr() as *const c_char,
            )
        };
        assert_ne!(fs, NYDUS_INVALID_FS_HANDLE);

        fs
    }

    #[test]
    fn test_open_rafs() {
        let fs = open_file_system();
        unsafe { nydus_close_rafs(fs) };
    }

    #[test]
    fn test_open_rafs_default() {
        let root_dir = &std::env::var("CARGO_MANIFEST_DIR").expect("$CARGO_MANIFEST_DIR");
        let bootstrap = PathBuf::from(root_dir)
            .join("../tests/texture/repeatable/sha256-nocompress-repeatable");
        let bootstrap = bootstrap.to_str().unwrap();
        let bootstrap = CString::new(bootstrap).unwrap();
        let blob_dir = PathBuf::from(root_dir).join("../tests/texture/repeatable/blobs");
        let blob_dir = blob_dir.to_str().unwrap();
        let fs = unsafe {
            nydus_open_rafs_default(bootstrap.as_ptr(), blob_dir.as_ptr() as *const c_char)
        };
        unsafe { nydus_close_rafs(fs) };
    }
}

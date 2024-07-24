// Copyright (C) 2021 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Implement file operations for RAFS filesystem in userspace.
//!
//! Provide following file operation functions to access files in a RAFS filesystem:
//! - fopen:
//! - fclose:
//! - fread:
//! - fwrite:
//! - fseek:
//! - ftell

use std::os::raw::c_char;
use std::ptr::null_mut;

use fuse_backend_rs::api::filesystem::{Context, FileSystem};

use crate::{set_errno, FileSystemState, Inode, NydusFsHandle};

/// Magic number for Nydus file handle.
pub const NYDUS_FILE_HANDLE_MAGIC: u64 = 0xedfc_3919_afc3_5187;
/// Value representing an invalid Nydus file handle.
pub const NYDUS_INVALID_FILE_HANDLE: usize = 0;

/// Handle representing a Nydus file object.
pub type NydusFileHandle = usize;

#[repr(C)]
pub(crate) struct FileState {
    magic: u64,
    ino: Inode,
    pos: u64,
    fs_handle: NydusFsHandle,
}

/// Open the file with `path` in readonly mode.
///
/// The `NydusFileHandle` returned should be freed by calling `nydus_close()`.
///
/// # Safety
/// Caller needs to ensure `fs_handle` and `path` are valid, otherwise it may cause memory access
/// violation.
#[no_mangle]
pub unsafe extern "C" fn nydus_fopen(
    fs_handle: NydusFsHandle,
    path: *const c_char,
) -> NydusFileHandle {
    if path.is_null() {
        set_errno(libc::EINVAL);
        return null_mut::<FileState>() as NydusFileHandle;
    }
    let fs = match FileSystemState::try_from_handle(fs_handle) {
        Err(e) => {
            set_errno(e);
            return null_mut::<FileState>() as NydusFileHandle;
        }
        Ok(v) => v,
    };

    ////////////////////////////////////////////////////////////
    // TODO: open file;
    //////////////////////////////////////////////////////////////////////////

    let file = Box::new(FileState {
        magic: NYDUS_FILE_HANDLE_MAGIC,
        ino: fs.root_ino,
        pos: 0,
        fs_handle,
    });

    Box::into_raw(file) as NydusFileHandle
}

/// Close the file handle returned by `nydus_fopen()`.
///
/// # Safety
/// Caller needs to ensure `fs_handle` is valid, otherwise it may cause memory access violation.
#[no_mangle]
pub unsafe extern "C" fn nydus_fclose(handle: NydusFileHandle) {
    let mut file = Box::from_raw(handle as *mut FileState);
    assert_eq!(file.magic, NYDUS_FILE_HANDLE_MAGIC);

    let ctx = Context::default();
    let fs = FileSystemState::from_handle(file.fs_handle);
    fs.rafs.forget(&ctx, file.ino, 1);

    file.magic -= 0x4fdf_ae34_9d9a_03cd;
}

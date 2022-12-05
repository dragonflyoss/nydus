// Copyright (C) 2021 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! SDK C wrappers to access `nydus-rafs` and `nydus-storage` functionalities.
//!
//! # Generate Header File
//! Please use cbindgen to generate `nydus.h` header file from rust source code by:
//! ```
//! cargo install cbindgen
//! cbindgen -l c -v -o include/nydus.h
//! ```
//!
//! # Run C Test
//! ```
//! gcc -o nydus -L ../../target/debug/ -lnydus_clib nydus_rafs.c
//! ```

#[macro_use]
extern crate log;
extern crate core;

pub use file::*;
pub use fs::*;

mod file;
mod fs;

/// Type for RAFS filesystem inode number.
pub type Inode = u64;

/// Helper to set libc::errno
#[cfg(target_os = "linux")]
fn set_errno(errno: i32) {
    unsafe { *libc::__errno_location() = errno };
}

/// Helper to set libc::errno
#[cfg(target_os = "macos")]
fn set_errno(errno: i32) {
    unsafe { *libc::__error() = errno };
}

/// Macro to convert C `char *` into rust `&str`.
#[macro_export]
macro_rules! cstr_to_str {
    ($var: ident, $ret: expr) => {{
        let s = CStr::from_ptr($var);
        match s.to_str() {
            Ok(v) => v,
            Err(_e) => {
                set_errno(libc::EINVAL);
                return $ret;
            }
        }
    }};
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Error;

    #[test]
    fn test_set_errno() {
        assert_eq!(Error::raw_os_error(&Error::last_os_error()), Some(0));
        set_errno(libc::EINVAL);
        assert_eq!(
            Error::raw_os_error(&Error::last_os_error()),
            Some(libc::EINVAL)
        );
        set_errno(libc::ENOSYS);
        assert_eq!(
            Error::raw_os_error(&Error::last_os_error()),
            Some(libc::ENOSYS)
        );
        set_errno(0);
        assert_eq!(Error::raw_os_error(&Error::last_os_error()), Some(0));
    }
}

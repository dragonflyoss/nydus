// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::fmt::Debug;

/// Display error messages with line number, file path and optional backtrace.
pub fn make_error(
    err: std::io::Error,
    _raw: impl Debug,
    _file: &str,
    _line: u32,
) -> std::io::Error {
    #[cfg(all(debug_assertions, feature = "error-backtrace"))]
    {
        if let Ok(val) = std::env::var("RUST_BACKTRACE") {
            if val.trim() != "0" {
                log::error!("Stack:\n{:?}", backtrace::Backtrace::new());
                log::error!("Error:\n\t{:?}\n\tat {}:{}", _raw, _file, _line);
                return err;
            }
        }
        log::error!(
            "Error:\n\t{:?}\n\tat {}:{}\n\tnote: enable `RUST_BACKTRACE=1` env to display a backtrace",
            _raw, _file, _line
        );
    }
    err
}

/// Define error macro like `x!()` or `x!(err)`.
/// Note: The `x!()` macro will convert any origin error (Os, Simple, Custom) to Custom error.
macro_rules! define_error_macro {
    ($fn:ident, $err:expr) => {
        #[macro_export]
        macro_rules! $fn {
            () => {
                std::io::Error::new($err.kind(), format!("{}: {}:{}", $err, file!(), line!()))
            };
            ($raw:expr) => {
                $crate::error::make_error($err, &$raw, file!(), line!())
            };
        }
    };
}

/// Define error macro for libc error codes
macro_rules! define_libc_error_macro {
    ($fn:ident, $code:ident) => {
        define_error_macro!($fn, std::io::Error::from_raw_os_error(libc::$code));
    };
}

// TODO: Add format string support
// Add more libc error macro here if necessary
define_libc_error_macro!(einval, EINVAL);
define_libc_error_macro!(enoent, ENOENT);
define_libc_error_macro!(ebadf, EBADF);
define_libc_error_macro!(eacces, EACCES);
define_libc_error_macro!(enotdir, ENOTDIR);
define_libc_error_macro!(eisdir, EISDIR);
define_libc_error_macro!(ealready, EALREADY);
define_libc_error_macro!(enosys, ENOSYS);
define_libc_error_macro!(epipe, EPIPE);
define_libc_error_macro!(eio, EIO);

/// Return EINVAL error with formatted error message.
#[macro_export]
macro_rules! bail_einval {
    ($($arg:tt)*) => {{
        return Err(einval!(format!($($arg)*)))
    }}
}

/// Return EIO error with formatted error message.
#[macro_export]
macro_rules! bail_eio {
    ($($arg:tt)*) => {{
        return Err(eio!(format!($($arg)*)))
    }}
}

// Add more custom error macro here if necessary
define_error_macro!(last_error, std::io::Error::last_os_error());
define_error_macro!(eother, std::io::Error::new(std::io::ErrorKind::Other, ""));

#[cfg(test)]
mod tests {
    fn check_size(size: usize) -> std::io::Result<()> {
        if size > 0x1000 {
            return Err(einval!());
        }

        Ok(())
    }

    #[test]
    fn test_einval() {
        assert_eq!(
            check_size(0x2000).unwrap_err().kind(),
            std::io::Error::from_raw_os_error(libc::EINVAL).kind()
        );
    }
}

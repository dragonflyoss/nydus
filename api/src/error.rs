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
    #[cfg(feature = "error-backtrace")]
    {
        if let Ok(val) = std::env::var("RUST_BACKTRACE") {
            if val.trim() != "0" {
                error!("Stack:\n{:?}", backtrace::Backtrace::new());
                error!("Error:\n\t{:?}\n\tat {}:{}", _raw, _file, _line);
                return err;
            }
        }
        error!(
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
    use std::io::{Error, ErrorKind};

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

    #[test]
    fn test_make_error() {
        let original_error = Error::other("test error");
        let debug_info = "debug information";
        let file = "test.rs";
        let line = 42;

        let result_error = super::make_error(original_error, debug_info, file, line);
        assert_eq!(result_error.kind(), ErrorKind::Other);
    }

    #[test]
    fn test_libc_error_macros() {
        // Test einval macro
        let err = einval!();
        assert_eq!(err.kind(), Error::from_raw_os_error(libc::EINVAL).kind());

        // Test enoent macro
        let err = enoent!();
        assert_eq!(err.kind(), Error::from_raw_os_error(libc::ENOENT).kind());

        // Test ebadf macro
        let err = ebadf!();
        assert_eq!(err.kind(), Error::from_raw_os_error(libc::EBADF).kind());

        // Test eacces macro
        let err = eacces!();
        assert_eq!(err.kind(), Error::from_raw_os_error(libc::EACCES).kind());

        // Test enotdir macro
        let err = enotdir!();
        assert_eq!(err.kind(), Error::from_raw_os_error(libc::ENOTDIR).kind());

        // Test eisdir macro
        let err = eisdir!();
        assert_eq!(err.kind(), Error::from_raw_os_error(libc::EISDIR).kind());

        // Test ealready macro
        let err = ealready!();
        assert_eq!(err.kind(), Error::from_raw_os_error(libc::EALREADY).kind());

        // Test enosys macro
        let err = enosys!();
        assert_eq!(err.kind(), Error::from_raw_os_error(libc::ENOSYS).kind());

        // Test epipe macro
        let err = epipe!();
        assert_eq!(err.kind(), Error::from_raw_os_error(libc::EPIPE).kind());

        // Test eio macro
        let err = eio!();
        assert_eq!(err.kind(), Error::from_raw_os_error(libc::EIO).kind());
    }

    #[test]
    fn test_libc_error_macros_with_context() {
        let test_msg = "test context";

        // Test einval macro with context
        let err = einval!(test_msg);
        assert_eq!(err.kind(), Error::from_raw_os_error(libc::EINVAL).kind());

        // Test enoent macro with context
        let err = enoent!(test_msg);
        assert_eq!(err.kind(), Error::from_raw_os_error(libc::ENOENT).kind());

        // Test eio macro with context
        let err = eio!(test_msg);
        assert_eq!(err.kind(), Error::from_raw_os_error(libc::EIO).kind());
    }

    #[test]
    fn test_custom_error_macros() {
        // Test last_error macro
        let err = last_error!();
        // We can't predict the exact error, but we can check it's a valid error
        assert!(!err.to_string().is_empty());

        // Test eother macro
        let err = eother!();
        assert_eq!(err.kind(), ErrorKind::Other);

        // Test eother macro with context
        let err = eother!("custom context");
        assert_eq!(err.kind(), ErrorKind::Other);
    }

    fn test_bail_einval_function() -> std::io::Result<()> {
        bail_einval!("test error message");
    }

    fn test_bail_eio_function() -> std::io::Result<()> {
        bail_eio!("test error message");
    }

    #[test]
    fn test_bail_macros() {
        // Test bail_einval macro
        let result = test_bail_einval_function();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), Error::from_raw_os_error(libc::EINVAL).kind());
        // The error message format is controlled by the macro, so just check it's not empty
        assert!(!err.to_string().is_empty());

        // Test bail_eio macro
        let result = test_bail_eio_function();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), Error::from_raw_os_error(libc::EIO).kind());
        // The error message format is controlled by the macro, so just check it's not empty
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn test_bail_macros_with_formatting() {
        fn test_bail_with_format(code: i32) -> std::io::Result<()> {
            if code == 1 {
                bail_einval!("error code: {}", code);
            } else if code == 2 {
                bail_eio!("I/O error with code: {}", code);
            }
            Ok(())
        }

        // Test bail_einval with formatting
        let result = test_bail_with_format(1);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), Error::from_raw_os_error(libc::EINVAL).kind());
        // The error message format is controlled by the macro, so just check it's not empty
        assert!(!err.to_string().is_empty());

        // Test bail_eio with formatting
        let result = test_bail_with_format(2);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), Error::from_raw_os_error(libc::EIO).kind());
        // The error message format is controlled by the macro, so just check it's not empty
        assert!(!err.to_string().is_empty());

        // Test success case
        let result = test_bail_with_format(3);
        assert!(result.is_ok());
    }
}

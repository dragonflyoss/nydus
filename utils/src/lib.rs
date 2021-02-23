// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::convert::{From, Infallible, Into, TryInto};
use std::ops::{Add, BitAnd, Not, Sub};

use num_traits::CheckedAdd;
use serde::Serialize;
use std::io::{Error, ErrorKind, Result};
use std::path::Path;

#[macro_use]
pub mod error;
pub use error::*;

pub mod exec;
pub use exec::*;

#[macro_use]
extern crate log;
use flexi_logger::{self, colored_opt_format, opt_format, Logger};
#[cfg(feature = "fusedev")]
pub mod fuse;
#[cfg(feature = "fusedev")]
pub use self::fuse::{FuseChannel, FuseSession};
pub mod logger;
pub mod signal;

pub fn log_level_to_verbosity(level: log::LevelFilter) -> usize {
    level as usize - 1
}

pub fn div_round_up(n: u64, d: u64) -> u64 {
    (n + d - 1) / d
}

/// Overflow can fail this rounder if the base value is large enough with 4095 added.
pub fn try_round_up_4k<
    U,
    E: From<Infallible>,
    T: BitAnd<Output = T>
        + Not<Output = T>
        + Add<Output = T>
        + Sub<Output = T>
        + TryInto<U, Error = E>
        + From<u16>
        + PartialOrd
        + CheckedAdd
        + Copy,
>(
    x: T,
) -> Option<U> {
    let t: T = 4095u16.into();
    if let Some(v) = x.checked_add(&t) {
        let z = v & (!t);
        z.try_into().ok()
    } else {
        None
    }
}

pub fn round_down_4k(x: u64) -> u64 {
    x & (!4095u64)
}

pub mod built_info {
    include!(concat!(env!("OUT_DIR"), "/built.rs"));
}

pub fn dump_program_info() {
    info!(
        "Git Commit: {:?}, Build Time: {:?}, Profile: {:?}, Rustc Version: {:?}",
        built_info::GIT_COMMIT_HASH.unwrap_or_default(),
        built_info::BUILT_TIME_UTC,
        built_info::PROFILE,
        built_info::RUSTC_VERSION,
    );
}

#[derive(Serialize, Clone)]
pub struct BuildTimeInfo {
    package_ver: String,
    git_commit: String,
    build_time: String,
    profile: String,
    rustc: String,
}

impl<'a> BuildTimeInfo {
    pub fn dump(package_ver: &'a str) -> (String, Self) {
        let info_string = format!(
            "\rVersion: \t{}\nGit Commit: \t{}\nBuild Time: \t{}\nProfile: \t{}\nRustc: \t\t{}\n",
            package_ver,
            built_info::GIT_COMMIT_HASH.unwrap_or_default(),
            built_info::BUILT_TIME_UTC,
            built_info::PROFILE,
            built_info::RUSTC_VERSION,
        );

        let info = Self {
            package_ver: package_ver.to_string(),
            git_commit: built_info::GIT_COMMIT_HASH.unwrap_or_default().to_string(),
            build_time: built_info::BUILT_TIME_UTC.to_string(),
            profile: built_info::PROFILE.to_string(),
            rustc: built_info::RUSTC_VERSION.to_string(),
        };

        (info_string, info)
    }
}

// Setup logging
pub fn setup_logging(path: Option<&str>, level: Option<&str>) -> Result<()> {
    if let Some(path) = path {
        let path = Path::new(path);

        // get the log directory
        let mut dir = path
            .parent()
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::InvalidInput,
                    "failed to get log file's directory",
                )
            })?
            .to_str()
            .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "to_str() failed"))?;
        // parent() returns empty string in case only log filename is given, e.g. test.log
        let cwd = std::env::current_dir()?;
        if dir.is_empty() {
            dir = cwd.to_str().ok_or_else(|| {
                Error::new(ErrorKind::InvalidInput, "failed to get CWD directory")
            })?;
        }

        // get the log file basename and suffix
        let basename = path
            .file_stem()
            .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "failed to get log file basename"))?
            .to_str()
            .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "to_str() failed"))?;

        // log filename must have suffix due to this issue: https://github.com/emabee/flexi_logger/issues/74
        let suffix = path
            .extension()
            .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "failed to get log file extension"))?
            .to_str()
            .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "to_str() failed"))?;

        Logger::with_env_or_str("trace")
            .log_to_file()
            .directory(dir)
            .basename(basename)
            .suffix(suffix)
            .suppress_timestamp()
            .append()
            .format(opt_format)
            .start()
            .map_err(|e| Error::new(ErrorKind::Other, e))?;
    } else {
        Logger::with_env_or_str("trace")
            .format(colored_opt_format)
            .start()
            .map_err(|e| Error::new(ErrorKind::Other, e))?;
    }

    // Safe because log level has a default value
    let v = level
        .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "log level is required"))?
        .parse()
        .unwrap_or(log::LevelFilter::Info);
    // We rely on `log` macro to limit current log level rather than `flexi_logger`
    // So we set `flexi_logger` log level to "trace" which is High enough. Otherwise, we
    // can't change log level to a higher level than what is passed to `flexi_logger`.
    log::set_max_level(v);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rounders() {
        assert_eq!(round_down_4k(0), 0);
        assert_eq!(round_down_4k(100), 0);
        assert_eq!(round_down_4k(4300), 4096);
        assert_eq!(round_down_4k(4096), 4096);
        assert_eq!(round_down_4k(4095), 0);
        assert_eq!(round_down_4k(4097), 4096);
        assert_eq!(round_down_4k(u64::MAX - 1), u64::MAX - 4095);
        assert_eq!(round_down_4k(u64::MAX - 4095), u64::MAX - 4095);
        // zero is rounded up to zero
        assert_eq!(try_round_up_4k::<i32, _, _>(0u32), Some(0i32));
        assert_eq!(try_round_up_4k::<u32, _, _>(0u32), Some(0u32));
        assert_eq!(try_round_up_4k::<u32, _, _>(1u32), Some(4096u32));
        assert_eq!(try_round_up_4k::<u32, _, _>(100u32), Some(4096u32));
        assert_eq!(try_round_up_4k::<u32, _, _>(4100u32), Some(8192u32));
        assert_eq!(try_round_up_4k::<u32, _, _>(4096u32), Some(4096u32));
        assert_eq!(try_round_up_4k::<u32, _, _>(4095u32), Some(4096u32));
        assert_eq!(try_round_up_4k::<u32, _, _>(4097u32), Some(8192u32));
        assert_eq!(try_round_up_4k::<u32, _, _>(u32::MAX), None);
        assert_eq!(try_round_up_4k::<u64, _, _>(u32::MAX), None);
        assert_eq!(try_round_up_4k::<u32, _, _>(u64::MAX - 1), None);
        assert_eq!(try_round_up_4k::<u32, _, _>(u64::MAX), None);
        assert_eq!(try_round_up_4k::<u32, _, _>(u64::MAX - 4097), None);
        // success
        assert_eq!(
            try_round_up_4k::<u64, _, _>(u64::MAX - 4096),
            Some(u64::MAX - 4095)
        );
        // overflow
        assert_eq!(try_round_up_4k::<u64, _, _>(u64::MAX - 1), None);
        // fail to convert u64 to u32
        assert_eq!(try_round_up_4k::<u32, _, _>(u64::MAX - 4096), None);
    }
}

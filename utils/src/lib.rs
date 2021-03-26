// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::convert::{From, Infallible, Into, TryInto};
use std::env::current_dir;
use std::io::Result;
use std::ops::{Add, BitAnd, Not, Sub};
use std::path::PathBuf;

use flexi_logger::{self, colored_opt_format, opt_format, Logger};
use log::LevelFilter;
use num_traits::CheckedAdd;
use serde::Serialize;

#[macro_use]
extern crate log;

#[macro_use]
pub mod error;
pub use error::*;

pub mod exec;
pub use exec::*;

pub mod types;
pub use types::*;

#[cfg(feature = "fusedev")]
pub mod fuse;
#[cfg(feature = "fusedev")]
pub use self::fuse::{FuseChannel, FuseSession};
pub mod digest;
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

pub fn dump_program_info(prog_version: &str) {
    info!(
        "Program Version: {}, Git Commit: {:?}, Build Time: {:?}, Profile: {:?}, Rustc Version: {:?}",
        prog_version,
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

/// `log_file_path` absolute path to logging files or relative path from current working
/// directory to logging file.
/// Flexi logger always appends a suffix to file name whose default value is ".log"
/// unless we set it intentionally. I don't like this passion. When the basename of `log_file_path`
/// is "bar", the newly created log file will be "bar.log"
pub fn setup_logging(log_file_path: Option<PathBuf>, level: LevelFilter) -> Result<()> {
    if let Some(ref path) = log_file_path {
        // Do not try to canonicalize the path since the file may not exist yet.

        // We rely on rust `log` macro to limit current log level rather than `flexi_logger`
        // So we set `flexi_logger` log level to "trace" which is High enough. Otherwise, we
        // can't change log level to a higher level than what is passed to `flexi_logger`.
        let mut logger = Logger::with_env_or_str("trace")
            .log_to_file()
            .suppress_timestamp()
            .append()
            .format(opt_format);

        // Parse log file to get the `basename` and `suffix`(extension) because `flexi_logger`
        // will automatically add `.log` suffix if we don't set explicitly, see:
        // https://github.com/emabee/flexi_logger/issues/74
        let basename = path
            .file_stem()
            .ok_or_else(|| {
                eprintln!("invalid file name input {:?}", path);
                einval!()
            })?
            .to_str()
            .ok_or_else(|| {
                eprintln!("invalid file name input {:?}", path);
                einval!()
            })?;
        logger = logger.basename(basename);

        // `flexi_logger` automatically add `.log` suffix if the file name has not extension.
        if let Some(suffix) = path.extension() {
            let suffix = suffix.to_str().ok_or_else(|| {
                eprintln!("invalid file extension {:?}", suffix);
                einval!()
            })?;
            logger = logger.suffix(suffix);
        }

        // Set log directory
        let parent_dir = path.parent();
        if let Some(p) = parent_dir {
            let cwd = current_dir()?;
            let dir = if !p.has_root() {
                cwd.join(p)
            } else {
                p.to_path_buf()
            };
            logger = logger.directory(dir);
        }

        logger.start().map_err(|e| {
            eprintln!("{:?}", e);
            eother!(e)
        })?;
    } else {
        // We rely on rust `log` macro to limit current log level rather than `flexi_logger`
        // So we set `flexi_logger` log level to "trace" which is High enough. Otherwise, we
        // can't change log level to a higher level than what is passed to `flexi_logger`.
        Logger::with_env_or_str("trace")
            .format(colored_opt_format)
            .start()
            .map_err(|e| eother!(e))?;
    }

    log::set_max_level(level);
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

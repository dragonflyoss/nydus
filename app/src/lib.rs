// Copyright 2020 Ant Group. All rights reserved.
// Copyright (C) 2021 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Application framework and utilities for Nydus.
//!
//! The `nydus-app` crates provides common helpers and utilities to support Nydus application:
//! - Application Building Information: [`struct BuildTimeInfo`](struct.BuildTimeInfo.html) and
//!   [`fn dump_program_info()`](fn.dump_program_info.html).
//! - Logging helpers: [`fn setup_logging()`](fn.set_logging.html) and
//!   [`fn log_level_to_verbosity()`](fn.log_level_to_verbosity.html).
//! - Signal handling: [`fn register_signal_handler()`](signal/fn.register_signal_handler.html).
//!
//! ```rust,ignore
//! #[macro_use(crate_authors, crate_version)]
//! extern crate clap;
//!
//! use clap::App;
//! use nydus_app::{BuildTimeInfo, setup_logging};
//! # use std::io::Result;
//!
//! fn main() -> Result<()> {
//!     let level = cmd.value_of("log-level").unwrap().parse().unwrap();
//!     let (bti_string, build_info) = BuildTimeInfo::dump(crate_version!());
//!     let _cmd = App::new("")
//!                 .version(bti_string.as_str())
//!                 .author(crate_authors!())
//!                 .get_matches();
//!
//!     setup_logging(None, level)?;
//!     print!("{}", build_info);
//!
//!     Ok(())
//! }
//! ```

#[macro_use]
extern crate log;
#[macro_use]
extern crate nydus_error;
#[macro_use]
extern crate serde;

use std::env::current_dir;
use std::io::Result;
use std::path::PathBuf;

use flexi_logger::{self, colored_opt_format, opt_format, Logger};
use log::LevelFilter;

pub mod signal;

pub fn log_level_to_verbosity(level: log::LevelFilter) -> usize {
    if level == log::LevelFilter::Off {
        0
    } else {
        level as usize - 1
    }
}

pub mod built_info {
    include!(concat!(env!("OUT_DIR"), "/built.rs"));
}

/// Dump program build and version information.
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

/// Application build and version information.
#[derive(Serialize, Clone)]
pub struct BuildTimeInfo {
    pub package_ver: String,
    pub git_commit: String,
    build_time: String,
    profile: String,
    rustc: String,
}

impl BuildTimeInfo {
    pub fn dump(package_ver: &str) -> (String, Self) {
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

/// Setup logging infrastructure for application.
///
/// `log_file_path` is an absolute path to logging files or relative path from current working
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
    fn test_log_level_to_verbosity() {
        assert_eq!(log_level_to_verbosity(log::LevelFilter::Off), 0);
        assert_eq!(log_level_to_verbosity(log::LevelFilter::Error), 0);
        assert_eq!(log_level_to_verbosity(log::LevelFilter::Warn), 1);
    }
}

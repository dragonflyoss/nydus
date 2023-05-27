// Copyright 2021 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

#[macro_use]
extern crate log;
#[macro_use]
extern crate nydus_api;

use clap::parser::ValuesRef;
use clap::ArgMatches;
use nydus_api::BuildTimeInfo;

pub use logger::{log_level_to_verbosity, setup_logging};
pub use nydus_service::*;
pub use signal::register_signal_handler;

mod logger;
mod signal;

/// Helper to access commandline options.
pub struct SubCmdArgs<'a> {
    args: &'a ArgMatches,
    subargs: &'a ArgMatches,
}

impl<'a> SubCmdArgs<'a> {
    /// Create a new instance of [SubCmdArgs].
    pub fn new(args: &'a ArgMatches, subargs: &'a ArgMatches) -> Self {
        SubCmdArgs { args, subargs }
    }

    /// Get reference to commandline option `key`.
    pub fn values_of(&self, key: &str) -> Option<ValuesRef<String>> {
        if let Some(v) = self.subargs.get_many::<String>(key) {
            Some(v)
        } else {
            self.args.get_many::<String>(key)
        }
    }
}

impl<'a> ServiceArgs for SubCmdArgs<'a> {
    fn value_of(&self, key: &str) -> Option<&String> {
        if let Some(v) = self.subargs.get_one::<String>(key) {
            Some(v)
        } else {
            self.args.try_get_one::<String>(key).unwrap_or_default()
        }
    }

    fn is_present(&self, key: &str) -> bool {
        matches!(self.subargs.try_get_one::<bool>(key), Ok(Some(true)))
            || matches!(self.args.try_get_one::<bool>(key), Ok(Some(true)))
    }
}

pub mod built_info {
    pub const PROFILE: &str = env!("PROFILE");
    pub const RUSTC_VERSION: &str = env!("RUSTC_VERSION");
    pub const BUILT_TIME_UTC: &str = env!("BUILT_TIME_UTC");
    pub const GIT_COMMIT_VERSION: &str = env!("GIT_COMMIT_VERSION");
    pub const GIT_COMMIT_HASH: &str = env!("GIT_COMMIT_HASH");
}

/// Dump program build and version information.
pub fn dump_program_info() {
    info!(
        "Program Version: {}, Git Commit: {:?}, Build Time: {:?}, Profile: {:?}, Rustc Version: {:?}",
        built_info::GIT_COMMIT_VERSION,
        built_info::GIT_COMMIT_HASH,
        built_info::BUILT_TIME_UTC,
        built_info::PROFILE,
        built_info::RUSTC_VERSION,
    );
}

pub fn get_build_time_info() -> (String, BuildTimeInfo) {
    let info_string = format!(
        "\rVersion: \t{}\nGit Commit: \t{}\nBuild Time: \t{}\nProfile: \t{}\nRustc: \t\t{}\n",
        built_info::GIT_COMMIT_VERSION,
        built_info::GIT_COMMIT_HASH,
        built_info::BUILT_TIME_UTC,
        built_info::PROFILE,
        built_info::RUSTC_VERSION,
    );

    let info = BuildTimeInfo {
        package_ver: built_info::GIT_COMMIT_VERSION.to_string(),
        git_commit: built_info::GIT_COMMIT_HASH.to_string(),
        build_time: built_info::BUILT_TIME_UTC.to_string(),
        profile: built_info::PROFILE.to_string(),
        rustc: built_info::RUSTC_VERSION.to_string(),
    };

    (info_string, info)
}

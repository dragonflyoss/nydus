// Copyright 2021 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use clap::parser::ValuesRef;
use clap::ArgMatches;
use nydus_api::BuildTimeInfo;

pub use nydus_service::*;

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

pub fn get_build_time_info() -> (String, BuildTimeInfo) {
    let info_string = format!(
        "\rVersion: \t{}\nGit Commit: \t{}\nBuild Time: \t{}\nProfile: \t{}\nRustc: \t\t{}\n",
        nydus_app::built_info::GIT_COMMIT_VERSION,
        nydus_app::built_info::GIT_COMMIT_HASH,
        nydus_app::built_info::BUILT_TIME_UTC,
        nydus_app::built_info::PROFILE,
        nydus_app::built_info::RUSTC_VERSION,
    );

    let info = BuildTimeInfo {
        package_ver: nydus_app::built_info::GIT_COMMIT_VERSION.to_string(),
        git_commit: nydus_app::built_info::GIT_COMMIT_HASH.to_string(),
        build_time: nydus_app::built_info::BUILT_TIME_UTC.to_string(),
        profile: nydus_app::built_info::PROFILE.to_string(),
        rustc: nydus_app::built_info::RUSTC_VERSION.to_string(),
    };

    (info_string, info)
}

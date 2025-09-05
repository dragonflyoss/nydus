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

impl ServiceArgs for SubCmdArgs<'_> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{Arg, ArgAction, Command};

    #[test]
    fn test_get_build_time_info_consistency() {
        let (info_str, info) = get_build_time_info();
        assert!(info_str.contains("Version:"));
        assert!(info_str.contains("Git Commit:"));
        assert!(info_str.contains("Build Time:"));
        assert!(info_str.contains("Profile:"));
        assert!(info_str.contains("Rustc:"));

        assert_eq!(info.package_ver, built_info::GIT_COMMIT_VERSION.to_string());
        assert_eq!(info.git_commit, built_info::GIT_COMMIT_HASH.to_string());
        assert_eq!(info.build_time, built_info::BUILT_TIME_UTC.to_string());
        assert_eq!(info.profile, built_info::PROFILE.to_string());
        assert_eq!(info.rustc, built_info::RUSTC_VERSION.to_string());
    }

    #[test]
    fn test_subcmdargs_values_and_serviceargs() {
        let cmd = Command::new("nydus-test")
            .arg(
                Arg::new("opt")
                    .long("opt")
                    .num_args(1..)
            )
            .arg(
                Arg::new("only_parent")
                    .long("only-parent")
                    .num_args(1..)
            )
            .arg(
                Arg::new("flag")
                    .long("flag")
                    .action(ArgAction::SetTrue)
            )
            .subcommand(
                Command::new("sub")
                    .arg(
                        Arg::new("opt")
                            .long("opt")
                            .num_args(1..)
                    )
                    .arg(
                        Arg::new("only_parent")
                            .long("only-parent")
                            .num_args(1..)
                    )
            );

        let matches = cmd
            .clone()
            .try_get_matches_from([
                "nydus-test",
                "--only-parent",
                "pval",
                "--flag",
                "sub",
                "--opt",
                "child1",
                "child2",
            ])
            .unwrap();

        let (_, sub_m) = matches.subcommand().expect("subcommand exists");
        let args = SubCmdArgs::new(&matches, sub_m);

        let vals: Vec<&str> = args
            .values_of("opt")
            .map(|v| v.map(|s| s.as_str()).collect())
            .unwrap_or_else(|| Vec::new());
        assert_eq!(vals, vec!["child1", "child2"], "unexpected values for --opt");

        // value_of should fall back to parent when not present in subargs.
        let parent_val = nydus_service::ServiceArgs::value_of(&args, "only_parent").cloned();
        assert_eq!(parent_val.as_deref(), Some("pval"));

        // is_present should check both subargs and parent args.
        let flag_present = nydus_service::ServiceArgs::is_present(&args, "flag");
        assert!(flag_present);
    }

    #[test]
    fn test_register_signal_handler_no_panic() {
        extern "C" fn handler(_: libc::c_int) {}
        // Should not panic when registering a handler for a user signal.
        register_signal_handler(nix::sys::signal::Signal::SIGUSR1, handler);
    }
}

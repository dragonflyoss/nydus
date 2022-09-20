// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::ffi::OsString;
use std::process::Command;
use std::str::FromStr;
use std::{ffi, io};

fn get_version_from_cmd(executable: &ffi::OsStr) -> io::Result<String> {
    let output = Command::new(executable).arg("-V").output()?;
    let mut v = String::from_utf8(output.stdout).unwrap();
    v.pop(); // remove newline
    Ok(v)
}

fn get_git_commit_hash() -> String {
    let commit = Command::new("git")
        .arg("rev-parse")
        .arg("--verify")
        .arg("HEAD")
        .output();
    if let Ok(commit_output) = commit {
        if let Some(commit) = String::from_utf8_lossy(&commit_output.stdout)
            .lines()
            .next()
        {
            return commit.to_string();
        }
    }
    "unknown".to_string()
}

fn get_git_commit_version() -> String {
    let tag = Command::new("git").args(&["describe", "--tags"]).output();
    if let Ok(tag) = tag {
        if let Some(tag) = String::from_utf8_lossy(&tag.stdout).lines().next() {
            return tag.to_string();
        }
    }
    "unknown".to_string()
}

fn main() {
    let rustc_ver = if let Ok(p) = std::env::var("RUSTC") {
        let rustc = OsString::from_str(&p).unwrap();
        get_version_from_cmd(&rustc).unwrap()
    } else {
        "<Unknown>".to_string()
    };
    let profile = std::env::var("PROFILE").unwrap_or_else(|_| "<Unknown>".to_string());
    let build_time = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Iso8601::DEFAULT)
        .unwrap();
    let git_commit_hash = get_git_commit_hash();
    let git_commit_version = get_git_commit_version();

    println!("cargo:rerun-if-changed=../git/HEAD");
    println!("cargo:rustc-env=RUSTC_VERSION={}", rustc_ver);
    println!("cargo:rustc-env=PROFILE={}", profile);
    println!("cargo:rustc-env=BUILT_TIME_UTC={}", build_time);
    println!("cargo:rustc-env=GIT_COMMIT_HASH={}", git_commit_hash);
    println!("cargo:rustc-env=GIT_COMMIT_VERSION={}", git_commit_version);
}

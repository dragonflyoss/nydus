// Copyright 2020 Ant Financial. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::io::Result;
use std::process::{Command, Stdio};

use crate::error::*;

pub fn exec(cmd: &str, output: bool) -> Result<String> {
    info!("exec `{}`", cmd);

    if output {
        let output = Command::new("sh")
            .arg("-c")
            .arg(cmd)
            .env("RUST_BACKTRACE", "1")
            .output()?;

        if !output.status.success() {
            return Err(eother!("exit with non-zero status"));
        }
        let stdout = std::str::from_utf8(&output.stdout).map_err(|e| einval!(e))?;
        let stderr = std::str::from_utf8(&output.stderr).map_err(|e| einval!(e))?;

        return Ok(stdout.to_string() + &stderr.to_string());
    }

    let mut child = Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .env("RUST_BACKTRACE", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()?;

    let status = child.wait()?;
    if !status.success() {
        return Err(eother!("exit with non-zero status"));
    }

    Ok(String::from(""))
}

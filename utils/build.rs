// Copyright 2020 Ant Group. All rights reserved.
// Copyright (C) 2021 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::io::Write;
use std::{env, fs, path};

fn main() {
    built::write_built_file().expect("Failed to acquire build-time information");

    let dst = path::Path::new(&env::var("OUT_DIR").unwrap()).join("built.rs");
    let mut built_file = fs::OpenOptions::new()
        .write(true)
        .append(true)
        .open(&dst)
        .expect("Failed to open file `built.rs`");
    let datatime = format!(
        "/// The built-time in RFC2822, UTC\npub const BUILT_TIME_UTC: &str = \"{}\";\n",
        httpdate::fmt_http_date(std::time::SystemTime::now())
    );

    built_file
        .write(datatime.as_bytes())
        .expect("Failed to write data to `built.rs");
}

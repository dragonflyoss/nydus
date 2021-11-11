// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

fn main() {
    println!("cargo:rerun-if-changed=../git/HEAD");
    built::write_built_file().expect("Failed to acquire build-time information");
}

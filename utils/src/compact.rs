// Copyright 2020 Ant Group. All rights reserved.
// Copyright (C) 2020 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0
use nix::sys::stat::dev_t;

pub fn makedev(major: u64, minor: u64) -> dev_t {
    #[cfg(target_os = "linux")]
    {
        nix::sys::stat::makedev(major, minor)
    }
    #[cfg(target_os = "macos")]
    {
        ((major & 0xff << 24) | (minor & 0xffffff)) as dev_t
    }
}

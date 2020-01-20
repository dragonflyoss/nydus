// Copyright 2020 Ant Financial. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

#[macro_use]
pub mod error;
pub use error::*;

pub mod exec;
pub use exec::*;

#[macro_use]
extern crate log;
#[cfg(feature = "fusedev")]
pub mod fuse;
#[cfg(feature = "fusedev")]
pub use self::fuse::{FuseChannel, FuseSession};
pub mod signal;

pub fn log_level_to_verbosity(level: log::LevelFilter) -> usize {
    level as usize - 1
}

pub fn div_round_up(n: u64, d: u64) -> u64 {
    (n + d - 1) / d
}

pub fn round_up_4k(x: u64) -> Option<u64> {
    ((x - 1) | 4095u64).checked_add(1)
}

pub fn round_down_4k(x: u64) -> u64 {
    x & (!4095u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rounders() {
        assert_eq!(round_down_4k(100), 0);
        assert_eq!(round_down_4k(4300), 4096);
        assert_eq!(round_down_4k(4096), 4096);
        assert_eq!(round_down_4k(4095), 0);
        assert_eq!(round_down_4k(4097), 4096);
        assert_eq!(round_down_4k(u64::MAX - 1), u64::MAX - 4095);
        assert_eq!(round_down_4k(u64::MAX - 4095), u64::MAX - 4095);
        assert_eq!(round_down_4k(0), 0);
        assert_eq!(round_up_4k(100), Some(4096));
        assert_eq!(round_up_4k(4100), Some(8192));
        assert_eq!(round_up_4k(4096), Some(4096));
        assert_eq!(round_up_4k(4095), Some(4096));
        assert_eq!(round_up_4k(4097), Some(8192));
        assert_eq!(round_up_4k(u64::MAX - 1), None);
        assert_eq!(round_up_4k(u64::MAX), None);
        assert_eq!(round_up_4k(u64::MAX - 4096), Some(u64::MAX - 4095));
    }
}

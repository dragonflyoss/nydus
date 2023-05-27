// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

#[macro_use]
extern crate log;
#[macro_use]
extern crate serde;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate nydus_api;

use std::convert::{Into, TryFrom, TryInto};
use std::time::Duration;

pub use self::exec::*;
pub use self::inode_bitmap::InodeBitmap;
pub use self::reader::*;
pub use self::types::*;

pub mod async_helper;
pub mod compact;
pub mod compress;
#[cfg(feature = "encryption")]
pub mod crypt;
pub mod digest;
pub mod exec;
pub mod filemap;
pub mod inode_bitmap;
pub mod logger;
pub mod metrics;
pub mod mpmc;
pub mod reader;
pub mod trace;
pub mod types;
pub mod verity;

/// Round up and divide the value `n` by `d`.
pub fn div_round_up(n: u64, d: u64) -> u64 {
    debug_assert!(d != 0);
    debug_assert!(d.is_power_of_two());
    (n + d - 1) / d
}

/// Round up the value `n` to by `d`.
pub fn round_up(n: u64, d: u64) -> u64 {
    debug_assert!(d != 0);
    debug_assert!(d.is_power_of_two());
    (n + d - 1) / d * d
}

/// Round up the value `n` to by `d`.
pub fn round_up_usize(n: usize, d: usize) -> usize {
    debug_assert!(d != 0);
    debug_assert!(d.is_power_of_two());
    (n + d - 1) / d * d
}

/// Overflow can fail this rounder if the base value is large enough with 4095 added.
pub fn try_round_up_4k<U: TryFrom<u64>, T: Into<u64>>(x: T) -> Option<U> {
    let t = 4095u64;
    if let Some(v) = x.into().checked_add(t) {
        let z = v & (!t);
        z.try_into().ok()
    } else {
        None
    }
}

pub fn round_down_4k(x: u64) -> u64 {
    x & (!4095u64)
}

/// Round down the value `n` to by `d`.
pub fn round_down(n: u64, d: u64) -> u64 {
    debug_assert!(d != 0);
    debug_assert!(d.is_power_of_two());
    n / d * d
}

pub enum DelayType {
    Fixed,
    // an exponential delay between each attempts
    BackOff,
}

pub struct Delayer {
    r#type: DelayType,
    attempts: u32,
    time: Duration,
}

impl Delayer {
    pub fn new(t: DelayType, time: Duration) -> Self {
        Delayer {
            r#type: t,
            attempts: 0,
            time,
        }
    }

    pub fn delay(&mut self) {
        use std::thread::sleep;

        match self.r#type {
            DelayType::Fixed => sleep(self.time),
            DelayType::BackOff => sleep((1 << self.attempts) * self.time),
        }
        self.attempts += 1;
    }
}

struct LazyDrop<T> {
    v: T,
}

unsafe impl<T> Send for LazyDrop<T> {}

/// Lazy drop of object.
pub fn lazy_drop<T: 'static>(v: T) {
    let v = LazyDrop { v };
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(600));
        let _ = v.v;
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rounders() {
        assert_eq!(round_down_4k(0), 0);
        assert_eq!(round_down_4k(100), 0);
        assert_eq!(round_down_4k(4300), 4096);
        assert_eq!(round_down_4k(4096), 4096);
        assert_eq!(round_down_4k(4095), 0);
        assert_eq!(round_down_4k(4097), 4096);
        assert_eq!(round_down_4k(u64::MAX - 1), u64::MAX - 4095);
        assert_eq!(round_down_4k(u64::MAX - 4095), u64::MAX - 4095);
        // zero is rounded up to zero
        assert_eq!(try_round_up_4k::<i32, _>(0u32), Some(0i32));
        assert_eq!(try_round_up_4k::<u32, _>(0u32), Some(0u32));
        assert_eq!(try_round_up_4k::<u32, _>(1u32), Some(4096u32));
        assert_eq!(try_round_up_4k::<u32, _>(100u32), Some(4096u32));
        assert_eq!(try_round_up_4k::<u32, _>(4100u32), Some(8192u32));
        assert_eq!(try_round_up_4k::<u32, _>(4096u32), Some(4096u32));
        assert_eq!(try_round_up_4k::<u32, _>(4095u32), Some(4096u32));
        assert_eq!(try_round_up_4k::<u32, _>(4097u32), Some(8192u32));
        assert_eq!(try_round_up_4k::<u32, _>(u32::MAX), None);
        assert_eq!(try_round_up_4k::<u64, _>(u32::MAX), Some(0x1_0000_0000u64));
        assert_eq!(try_round_up_4k::<u32, _>(u64::MAX - 1), None);
        assert_eq!(try_round_up_4k::<u32, _>(u64::MAX), None);
        assert_eq!(try_round_up_4k::<u32, _>(u64::MAX - 4097), None);
        // success
        assert_eq!(
            try_round_up_4k::<u64, _>(u64::MAX - 4096),
            Some(u64::MAX - 4095)
        );
        // overflow
        assert_eq!(try_round_up_4k::<u64, _>(u64::MAX - 1), None);
        // fail to convert u64 to u32
        assert_eq!(try_round_up_4k::<u32, _>(u64::MAX - 4096), None);
    }
}

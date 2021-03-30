// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

#[macro_use]
extern crate log;
#[macro_use]
extern crate serde;
#[macro_use]
extern crate bitflags;
#[macro_use]
extern crate nydus_utils;

pub mod backend;
pub mod cache;
pub mod compress;
pub mod device;
pub mod factory;
pub mod utils;

// A helper to impl RafsChunkInfo for upper layers like Rafs different metadata mode.
#[macro_export]
macro_rules! impl_getter {
    ($G: ident, $F: ident, $U: ty) => {
        fn $G(&self) -> $U {
            self.$F
        }
    };
}

// FIXME: u64 for this constant is extremely large, which is unnecessary as `u32` can represent block size 4GB.
pub const RAFS_DEFAULT_BLOCK_SIZE: u64 = 1024 * 1024;

#[derive(Debug)]
pub enum StorageError {
    Unsupported,
}

pub type StorageResult<T> = std::result::Result<T, StorageError>;

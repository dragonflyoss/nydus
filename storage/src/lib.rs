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
extern crate nydus_error;

pub mod backend;
pub mod cache;
pub mod compress;
pub mod device;
pub mod factory;
#[cfg(test)]
pub(crate) mod test;
pub mod utils;

// A helper to impl RafsChunkInfo for upper layers like Rafs different metadata mode.
#[doc(hidden)]
#[macro_export]
macro_rules! impl_getter {
    ($G: ident, $F: ident, $U: ty) => {
        fn $G(&self) -> $U {
            self.$F
        }
    };
}

/// Default blob chunk size.
pub const RAFS_DEFAULT_BLOCK_SIZE: u64 = 1024 * 1024;
/// Maxixmum blob chunk size.
pub const RAFS_MAX_BLOCK_SIZE: u64 = 1024 * 1024;

/// Error codes related to storage subsystem.
#[derive(Debug)]
pub enum StorageError {
    Unsupported,
    Timeout,
    VolatileSlice(vm_memory::VolatileMemoryError),
    MemOverflow,
    NotContinuous,
}

/// Specialized std::result::Result for storage subsystem.
pub type StorageResult<T> = std::result::Result<T, StorageError>;

// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

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

// Copyright 2025 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use crc::Crc;
use crc::Table;
use std::fmt;
use std::fmt::Debug;

#[repr(u32)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Algorithm {
    None = 0,
    #[default]
    Crc32Iscsi = 1,
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl TryFrom<u32> for Algorithm {
    type Error = ();

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        if value == Algorithm::None as u32 {
            Ok(Algorithm::None)
        } else if value == Algorithm::Crc32Iscsi as u32 {
            Ok(Algorithm::Crc32Iscsi)
        } else {
            Err(())
        }
    }
}

impl TryFrom<u64> for Algorithm {
    type Error = ();

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        if value == Algorithm::None as u64 {
            Ok(Algorithm::None)
        } else if value == Algorithm::Crc32Iscsi as u64 {
            Ok(Algorithm::Crc32Iscsi)
        } else {
            Err(())
        }
    }
}

pub struct Crc32 {
    crc: Crc<u32, Table<16>>,
}

impl Default for Crc32 {
    fn default() -> Self {
        Self::new(Algorithm::Crc32Iscsi)
    }
}

impl Crc32 {
    pub fn new(algorithm: Algorithm) -> Self {
        let crc = match algorithm {
            Algorithm::Crc32Iscsi => &crc::CRC_32_ISCSI,
            _ => &crc::CRC_32_ISCSI,
        };
        Self {
            crc: Crc::<u32, Table<16>>::new(crc),
        }
    }

    pub fn checksum(&self, bytes: &[u8]) -> u32 {
        self.crc.checksum(bytes)
    }

    pub fn check_crc(&self, bytes: &[u8], crc_result: u32) -> bool {
        self.crc.checksum(bytes) == crc_result
    }
}
